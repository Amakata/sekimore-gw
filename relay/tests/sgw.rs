//! `sgw` end to end, against a fake `docker` on PATH (#234).
//!
//! The binary is run as a process; the fake docker logs every argv it was given and what came
//! down its stdin, and answers the few queries `sgw` makes (`ps -q`, `inspect`, `port`). No
//! Docker is needed. Built only with the `host` feature, like the binary.
#![cfg(feature = "host")]

use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    _tmp: tempfile::TempDir,
    project: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

/// A project directory, a fake docker that logs, and a fake `security` that knows nothing.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(project.join(".devcontainer")).unwrap();
    std::fs::write(
        project.join(".devcontainer/docker-compose.yml"),
        "services:\n  sekimore-gw:\n    image: x\n",
    )
    .unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = tmp.path().join("docker.log");
    let script = format!(
        r#"#!/usr/bin/env bash
# every call: argv on one line, then stdin (if any) marked
printf '%s\n' "$*" >> "{log}"
printf 'HINTS=%s\n' "${{DOCKER_CLI_HINTS:-unset}}" >> "{log}"
case "$1 $2" in
  "ps -q") echo cid123 ;;
  "ps -a") echo "  proj-sekimore-gw-1  Up 2 hours  (ghcr.io/amakata/sekimore-gw:0.2.46)" ;;
  "inspect -f")
    case "$3" in
      *working_dir*) echo "{wd}" ;;
      *config_files*) echo "docker-compose.yml,docker-compose.relay.yml" ;;
      *environment_file*) echo "" ;;
      *"compose.project\""*) echo "proj_devcontainer" ;;
      "{{{{.Config.Image}}}}") echo "ghcr.io/amakata/sekimore-gw:0.2.46" ;;
      "{{{{.Image}}}}") echo "sha256:abc" ;;
      *) echo "" ;;
    esac ;;
  "port cid123") echo "0.0.0.0:8091"; echo "[::]:8091" ;;
  "exec -i")
    if [ ! -t 0 ]; then cat | sed 's/^/STDIN: /' >> "{log}"; fi ;;
esac
exit 0
"#,
        log = log.display(),
        wd = project.join(".devcontainer").display(),
    );
    let docker = bin.join("docker");
    std::fs::write(&docker, script).unwrap();
    chmod_x(&docker);
    Fixture {
        _tmp: tmp,
        project,
        bin,
        log,
    }
}

fn chmod_x(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sgw(f: &Fixture, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sgw"));
    let path = format!(
        "{}:{}",
        f.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    c.env("PATH", path)
        .env_remove("DEVCONTAINER")
        .env_remove("SGW_FORCE")
        .env_remove("SEKIMORE_COLOR")
        .env_remove("NO_COLOR")
        .env("SEKIMORE_LANG", "en")
        .current_dir(&f.project)
        .args(args);
    c
}

fn log(f: &Fixture) -> String {
    std::fs::read_to_string(&f.log).unwrap_or_default()
}

#[test]
fn check_runs_the_relay_in_the_gateway_without_a_pty_when_piped() {
    let f = fixture();
    let out = sgw(&f, &["check"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = log(&f);
    // found by the two labels, then exec'd with -i (stdin and stdout are pipes here)
    assert!(
        log.contains("ps -q --filter label=com.docker.compose.project.working_dir="),
        "{log}"
    );
    assert!(
        log.contains("--filter label=com.docker.compose.service=sekimore-gw"),
        "{log}"
    );
    assert!(
        log.contains("exec -i cid123 sekimore-relay check\n"),
        "{log}"
    );
    // the Docker CLI's hints are off on every call (base #102)
    assert!(!log.contains("HINTS=unset"), "{log}");
    assert!(log.contains("HINTS=false"), "{log}");
}

/// The colour decision is made on the host, where the terminal is: piped, nothing is said;
/// NO_COLOR is handed through when set (the relay inside cannot see the host's stdout).
#[test]
fn colour_is_decided_on_the_host() {
    let f = fixture();
    let out = sgw(&f, &["check"]).env("NO_COLOR", "1").output().unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("exec -i -e NO_COLOR=1 cid123 sekimore-relay check\n"));
    let f = fixture();
    let out = sgw(&f, &["check"])
        .env("SEKIMORE_COLOR", "always")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("exec -i -e SEKIMORE_COLOR=always cid123 sekimore-relay check\n"));
}

#[test]
fn arguments_pass_through_to_the_relay_subcommand() {
    let f = fixture();
    let out = sgw(&f, &["revoke", "--label", "skm_abc"]).output().unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("exec -i cid123 sekimore-relay revoke --label skm_abc\n"));
    let out = sgw(
        &f,
        &["relay", "keyscan", "bastion.example.net", "--port", "2222"],
    )
    .output()
    .unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("sekimore-relay keyscan bastion.example.net --port 2222\n"));
}

/// #230: a command that reads from the terminal refuses a piped stdin instead of hanging or
/// reading garbage — and says so.
#[test]
fn an_interactive_command_refuses_a_pipe() {
    let f = fixture();
    let out = sgw(&f, &["unlock"]).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("needs a terminal on stdin"), "{err}");
    assert!(
        !log(&f).contains("sekimore-relay unlock"),
        "nothing was run"
    );
    // --stdin is the exception, by design
    let out = sgw(&f, &["unlock", "--stdin"]).output().unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("exec -i cid123 sekimore-relay unlock --stdin\n"));
}

/// The passphrase goes down docker exec's stdin and appears in no argv.
#[test]
fn unlock_auto_pipes_the_stored_passphrase_and_never_names_it() {
    let f = fixture();
    let dir = f.project.join("secrets");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("proj.passphrase"), "correct horse\n").unwrap();
    let out = sgw(&f, &["unlock-auto"])
        .env("SGW_PASSPHRASE_DIR", &dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("unlocking from"), "{stdout}");
    let log = log(&f);
    assert!(
        log.contains("exec -i cid123 sekimore-relay unlock --stdin\n"),
        "{log}"
    );
    assert!(log.contains("STDIN: correct horse\n"), "{log}");
    let argv_lines: Vec<&str> = log.lines().filter(|l| l.starts_with("exec")).collect();
    assert!(
        !argv_lines.iter().any(|l| l.contains("correct horse")),
        "{log}"
    );
    assert!(!stdout.contains("correct horse"));
}

#[test]
fn unlock_auto_with_nothing_stored_exits_zero_and_says_where_it_looked() {
    let f = fixture();
    let out = sgw(&f, &["unlock-auto"])
        .env("SGW_PASSPHRASE_DIR", f.project.join("nowhere"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no passphrase stored for 'proj'"),
        "{stdout}"
    );
    assert!(!log(&f).contains("unlock"), "no unlock was attempted");
}

#[test]
fn inside_the_dev_container_it_refuses() {
    let f = fixture();
    let out = sgw(&f, &["check"])
        .env("DEVCONTAINER", "true")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("inside of the dev container"));
    assert!(log(&f).is_empty(), "docker was never called");
}

#[test]
fn the_dev_container_is_reached_as_the_vscode_user() {
    let f = fixture();
    let out = sgw(&f, &["dev", "cat", "/etc/hostname"]).output().unwrap();
    assert!(out.status.success());
    let log = log(&f);
    assert!(
        log.contains("--filter label=com.docker.compose.service=dev"),
        "{log}"
    );
    assert!(
        log.contains("exec -i -u vscode cid123 cat /etc/hostname\n"),
        "{log}"
    );
}

#[test]
fn port_and_id_and_project_answer_from_the_running_container() {
    let f = fixture();
    let out = sgw(&f, &["port", "sekimore-gw"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "8091");
    let out = sgw(&f, &["id", "sekimore-gw"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cid123");
    let out = sgw(&f, &["project"]).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "proj_devcontainer"
    );
}

#[test]
fn recreate_names_every_compose_file_the_container_was_created_with() {
    let f = fixture();
    let dc = f.project.join(".devcontainer");
    std::fs::write(dc.join("docker-compose.relay.yml"), "services: {}\n").unwrap();
    let out = sgw(&f, &["recreate", "--no-unlock"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = log(&f);
    let up = log
        .lines()
        .find(|l| l.contains(" up -d --force-recreate sekimore-gw"))
        .unwrap_or_else(|| panic!("no compose up in {log}"));
    assert!(
        up.starts_with("compose -p proj_devcontainer --project-directory "),
        "{up}"
    );
    assert!(
        up.contains(&format!("-f {}", dc.join("docker-compose.yml").display())),
        "{up}"
    );
    assert!(
        up.contains(&format!(
            "-f {}",
            dc.join("docker-compose.relay.yml").display()
        )),
        "{up}"
    );
    assert!(
        log.contains("pull ghcr.io/amakata/sekimore-gw:0.2.46\n"),
        "{log}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("the store was left locked"), "{stdout}");
}

#[test]
fn help_is_in_the_language_asked_for() {
    let f = fixture();
    let out = sgw(&f, &["--help"]).output().unwrap();
    assert!(out.status.success());
    let en = String::from_utf8_lossy(&out.stdout);
    assert!(en.contains("unlock the secret store"), "{en}");
    let out = sgw(&f, &["--help"])
        .env("SEKIMORE_LANG", "ja")
        .output()
        .unwrap();
    let ja = String::from_utf8_lossy(&out.stdout);
    assert!(ja.contains("秘密ストアを解錠する"), "{ja}");
}
