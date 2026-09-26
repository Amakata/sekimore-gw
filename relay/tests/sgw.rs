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
  "ps -a")
    if [ "$3" = "-q" ]; then [ -n "${{FAKE_EMPTY_STACK:-}}" ] || echo cid123
    else echo "  proj-sekimore-gw-1  Up 2 hours  (ghcr.io/amakata/sekimore-gw:0.2.46)"; fi ;;
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
fn down_removes_the_whole_stack_with_every_compose_file_and_the_orphans() {
    let f = fixture();
    let dc = f.project.join(".devcontainer");
    std::fs::write(dc.join("docker-compose.relay.yml"), "services: {}\n").unwrap();
    let out = sgw(&f, &["down"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = log(&f);
    let down = log
        .lines()
        .find(|l| l.starts_with("compose "))
        .unwrap_or_else(|| panic!("no compose in {log}"));
    assert_eq!(
        down,
        format!(
            "compose -p proj_devcontainer --project-directory {dc} -f {dc}/docker-compose.yml -f {dc}/docker-compose.relay.yml down --remove-orphans",
            dc = dc.display()
        )
    );
}

#[test]
fn down_with_no_container_left_names_the_stack_the_way_dev_containers_does() {
    let f = fixture();
    let dc = f.project.join(".devcontainer");
    let out = sgw(&f, &["down"])
        .env("FAKE_EMPTY_STACK", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = log(&f);
    assert!(!log.contains("inspect"), "no label to read: {log}");
    let down = log
        .lines()
        .find(|l| l.starts_with("compose "))
        .unwrap_or_else(|| panic!("no compose in {log}"));
    assert_eq!(
        down,
        format!(
            "compose -p proj_devcontainer --project-directory {dc} -f {dc}/docker-compose.yml down --remove-orphans",
            dc = dc.display()
        )
    );
}

#[test]
fn a_group_and_its_leaf_run_the_flat_command() {
    let f = fixture();
    let out = sgw(&f, &["store", "status"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        log(&f).contains(" sekimore-relay store-status\n"),
        "{}",
        log(&f)
    );
    let out = sgw(&f, &["token", "list"]).output().unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains(" sekimore-relay tokens\n"), "{}", log(&f));
    let out = sgw(&f, &["gw", "project"]).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "proj_devcontainer"
    );
    // dev is a group and the flat command that runs anything in dev; anything but a leaf is the latter
    let out = sgw(&f, &["dev", "cat", "/etc/hostname"]).output().unwrap();
    assert!(out.status.success());
    assert!(log(&f).contains("cat /etc/hostname"), "{}", log(&f));
}

#[test]
fn a_group_alone_lists_its_commands_and_an_unknown_leaf_is_refused() {
    let f = fixture();
    for args in [&["store"][..], &["store", "--help"], &["store", "-h"]] {
        let out = sgw(&f, args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("sgw store <COMMAND>"), "{text}");
        assert!(
            text.contains("\n  unlock ") && text.contains("\n  keychain-set "),
            "{text}"
        );
        assert!(!text.contains("login"), "{text}");
    }
    let out = sgw(&f, &["store", "foo"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no command 'foo'") && err.contains("\n  unlock "),
        "{err}"
    );
    assert!(log(&f).is_empty(), "nothing ran: {}", log(&f));
}

#[test]
fn a_commands_own_help_spells_it_with_its_group() {
    let f = fixture();
    let out = sgw(&f, &["store", "export", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Usage: sgw store export "), "{text}");
    let out = sgw(&f, &["recreate", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Usage: sgw gw recreate"), "{text}");
    let out = sgw(&f, &["init", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Usage: sgw init"), "{text}");
}

#[test]
fn help_lists_the_commands_by_group() {
    let f = fixture();
    let out = sgw(&f, &["--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let at = |s: &str| text.find(s).unwrap_or_else(|| panic!("no {s:?} in {text}"));
    assert!(
        at("Commands:") < at("\n  init ") && at("\n  init ") < at("\nstore "),
        "{text}"
    );
    assert!(
        at("\nstore ") < at("\n  unlock ") && at("\n  unlock ") < at("\ngithub "),
        "{text}"
    );
    assert!(
        at("\ngw ") < at("\n  recreate ") && at("\n  recreate ") < at("\ndev "),
        "{text}"
    );
    assert!(text.contains("sgw unlock is sgw store unlock"), "{text}");
    assert!(
        text.contains("Usage: sgw [OPTIONS] <COMMAND> [ARGS]"),
        "{text}"
    );
    assert!(text.contains("Options:"), "{text}");
    // no flat command is listed on its own: the groups are the listing
    assert!(!text.contains("\n  store-status "), "{text}");
    // bare sgw: the help, the way clap's arg_required_else_help gives it (stderr, exit 2)
    let out = sgw(&f, &[]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("\nstore "),
        "bare sgw prints the help"
    );
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

/// `verify` runs every item for a dev container, names the ledger rows, and fails when the
/// answers are missing (the fake docker answers nothing to exec).
#[test]
fn verify_reports_every_item_with_its_ledger_rows() {
    let f = fixture();
    let out = sgw(&f, &["verify"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for heading in [
        "== gateway: sekimore-relay check",
        "== dev: only the gateway's filtered signing key may be reachable [dev.signing]",
        "== gateway: the secret store [operator.store]",
        "== dev: git ls-remote through the relay (first repo of the project) [dev.relay.ssh, relay.ssh.upstream]",
        "== dev: a root process must not route past the gateway (host-side FORWARD rules, gateway 0.2.37) [dev.egress.route_past_gateway]",
    ] {
        assert!(stdout.contains(heading), "missing {heading} in {stdout}");
    }
    assert!(stdout.contains("verify: FAILED"), "{stdout}");
    assert!(
        stdout.contains("SKIP: no 443 target configured"),
        "{stdout}"
    );
}

/// `init` makes a project the other commands then find, and refuses to run twice over it.
#[test]
fn init_writes_the_template_and_the_project_is_then_found() {
    let f = fixture();
    let dir = f._tmp.path().join("fresh");
    let out = sgw(
        &f,
        &["init", "--target", "devcontainer", dir.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(".devcontainer/docker-compose.yml"),
        "{stdout}"
    );
    assert!(stdout.contains("sgw verify"), "{stdout}");
    assert!(dir.join(".devcontainer/config/config.yml").is_file());
    assert!(dir.join(".devcontainer/.env").is_file());
    // no mise layer: sgw is the operator's tool (#234 stage 3)
    assert!(
        !dir.join(".devcontainer/sgw").exists(),
        "no .devcontainer/sgw/"
    );
    assert!(!dir.join("mise.toml").exists(), "no mise.toml");
    // sgw.toml records every template file as written
    let toml = std::fs::read_to_string(dir.join("sgw.toml")).unwrap();
    assert!(
        toml.contains(&format!("version = \"{}\"", env!("CARGO_PKG_VERSION"))),
        "{toml}"
    );
    for path in [
        ".devcontainer/docker-compose.yml",
        ".devcontainer/Dockerfile",
        ".devcontainer/config/config.yml",
        ".devcontainer/devcontainer.json",
    ] {
        assert!(
            toml.contains(&format!("\"{path}\" = \"")),
            "{path} in {toml}"
        );
    }
    assert!(
        !toml.contains(".devcontainer/.env\""),
        "the .env copy is not a template file"
    );
    // found from a subdirectory of it, like any project
    let sub = dir.join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let out = sgw(&f, &["check"]).current_dir(&sub).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // a second init refuses
    let out = sgw(&f, &["init", dir.to_str().unwrap()]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("exist already"));
    // a target this version has not got is refused before anything is written
    let other = f._tmp.path().join("sbx");
    let out = sgw(&f, &["init", "--target", "sbx", other.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not implemented"));
    assert!(!other.join(".devcontainer").exists());
}

fn sha(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// sgw.toml with one file's recorded sha replaced: what an older sgw would have written.
fn record(dir: &Path, path: &str, sha: &str) {
    let toml = dir.join("sgw.toml");
    let text = std::fs::read_to_string(&toml).unwrap();
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            if l.starts_with(&format!("\"{path}\" = ")) {
                format!("\"{path}\" = \"{sha}\"")
            } else {
                l.to_string()
            }
        })
        .collect();
    std::fs::write(&toml, out.join("\n") + "\n").unwrap();
}

/// `update` on a project the same sgw wrote: everything current. With older pins: the tags
/// move to this version. A template file as sgw wrote it that this version changes is
/// overwritten; one the project edited is left; one where both happened gets `.sgw-new`.
#[test]
fn update_reports_and_applies_against_the_embedded_template() {
    let f = fixture();
    let dir = f._tmp.path().join("upd");
    let out = sgw(&f, &["init", dir.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success());
    let out = sgw(&f, &["update", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Everything is up to date."), "{stdout}");

    // an older project: pins behind, and three template files in three states
    let version = env!("CARGO_PKG_VERSION");
    let compose = dir.join(".devcontainer/docker-compose.yml");
    let text = std::fs::read_to_string(&compose).unwrap();
    std::fs::write(
        &compose,
        text.replace(&format!("sekimore-gw:{version}"), "sekimore-gw:0.2.40"),
    )
    .unwrap();
    let dockerfile = dir.join(".devcontainer/Dockerfile");
    let text = std::fs::read_to_string(&dockerfile).unwrap();
    std::fs::write(
        &dockerfile,
        text.replace(
            &format!("sgw-devcontainer-base:{version}"),
            "sgw-devcontainer-base:0.2.38",
        ),
    )
    .unwrap();
    // "changes": post-create.sh is as an older sgw wrote it (recorded == current), and this
    // version's differs — it is overwritten
    let post_create = dir.join(".devcontainer/scripts/post-create.sh");
    let older = "#!/bin/sh\n# post-create of an older version\n";
    std::fs::write(&post_create, older).unwrap();
    record(&dir, ".devcontainer/scripts/post-create.sh", &sha(older));
    // "yours": config.yml edited, and this version's template is what was recorded — left alone
    let config = dir.join(".devcontainer/config/config.yml");
    let mine = std::fs::read_to_string(&config).unwrap() + "# mine\n";
    std::fs::write(&config, &mine).unwrap();
    // "conflict": the splash edited, and recorded as something else — .sgw-new beside it
    let splash = dir.join(".devcontainer/zsh-config/rc.d/99-splash.zsh");
    std::fs::write(&splash, "echo mine\n").unwrap();
    record(
        &dir,
        ".devcontainer/zsh-config/rc.d/99-splash.zsh",
        &sha("older\n"),
    );

    let out = sgw(&f, &["update", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("gateway      0.2.40     {version}")),
        "{stdout}"
    );
    let line = |path: &str| {
        stdout
            .lines()
            .find(|l| l.trim_start().starts_with(path))
            .unwrap_or_else(|| panic!("no line for {path} in {stdout}"))
            .to_string()
    };
    assert!(
        line(".devcontainer/scripts/post-create.sh").contains("changes"),
        "{stdout}"
    );
    assert!(
        line(".devcontainer/config/config.yml").contains("yours"),
        "{stdout}"
    );
    assert!(
        line(".devcontainer/zsh-config/rc.d/99-splash.zsh").contains(".sgw-new"),
        "{stdout}"
    );
    assert!(
        line(".devcontainer/docker-compose.yml").contains("yours"),
        "the tag line: {stdout}"
    );
    assert!(stdout.contains("To apply: sgw update --apply"), "{stdout}");
    // --notes: the UPGRADING sections crossed (0.2.44 and 0.2.45 are between 0.2.40 and now)
    let out = sgw(&f, &["update", "--notes", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let notes = String::from_utf8_lossy(&out.stdout);
    assert!(notes.contains("## 0.2.44"), "{notes}");
    // --apply (the gateway is "running" in the fake docker, --yes recreates it)
    let out = sgw(&f, &["update", "--apply", "--offline", "--yes"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("gateway: 0.2.40 → {version}")),
        "{stdout}"
    );
    assert!(
        stdout.contains("wrote .devcontainer/scripts/post-create.sh"),
        "{stdout}"
    );
    assert!(
        stdout.contains("wrote .devcontainer/zsh-config/rc.d/99-splash.zsh.sgw-new"),
        "{stdout}"
    );
    assert!(stdout.contains("wrote sgw.toml"), "{stdout}");
    assert!(std::fs::read_to_string(&compose)
        .unwrap()
        .contains(&format!("sekimore-gw:{version}")));
    assert!(std::fs::read_to_string(&dockerfile)
        .unwrap()
        .contains(&format!("sgw-devcontainer-base:{version}")));
    assert_ne!(
        std::fs::read_to_string(&post_create).unwrap(),
        older,
        "overwritten"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        mine,
        "left alone"
    );
    assert_eq!(
        std::fs::read_to_string(&splash).unwrap(),
        "echo mine\n",
        "left alone"
    );
    assert!(splash.with_extension("zsh.sgw-new").is_file());
    assert!(
        log(&f).contains(" up -d --force-recreate sekimore-gw"),
        "the gateway was recreated"
    );
    assert!(stdout.contains("Rebuild Container"), "{stdout}");
    assert!(
        stdout.contains("99-splash.zsh.sgw-new"),
        "the merge is left for the operator: {stdout}"
    );
    // and now: the edited files are "yours" against the new baseline, nothing to apply
    let out = sgw(&f, &["update", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("Everything is up to date."));
    // --force overwrites the conflict instead
    std::fs::write(&splash, "echo mine\n").unwrap();
    record(
        &dir,
        ".devcontainer/zsh-config/rc.d/99-splash.zsh",
        &sha("older\n"),
    );
    let out = sgw(&f, &["update", "--apply", "--offline", "--yes", "--force"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_ne!(std::fs::read_to_string(&splash).unwrap(), "echo mine\n");
}

/// A project from the mise era: `.devcontainer/sgw/` and a mise.toml that includes it. `update
/// --apply` removes the directory, takes the includes out and keeps the project's own task,
/// writes sgw.toml — and refuses when the directory holds something sgw did not put there.
#[test]
fn update_moves_a_project_off_the_mise_layer() {
    let f = fixture();
    let dir = f._tmp.path().join("old");
    sgw(&f, &["init", dir.to_str().unwrap()]).output().unwrap();
    std::fs::remove_file(dir.join("sgw.toml")).unwrap();
    let old = dir.join(".devcontainer/sgw");
    std::fs::create_dir_all(&old).unwrap();
    for name in [
        "sgw.sh",
        "vscode.sh",
        "upgrade.sh",
        "post-start.sh",
        "tasks.mise.toml",
        "gateway.mise.toml",
        "MANIFEST",
    ] {
        std::fs::write(old.join(name), "old\n").unwrap();
    }
    let mise = dir.join("mise.toml");
    std::fs::write(
        &mise,
        "# The day-to-day operations\n[task_config]\nincludes = [\".devcontainer/sgw/tasks.mise.toml\", \".devcontainer/sgw/gateway.mise.toml\"]\n\n[env]\nSGW = \"{{config_root}}/.devcontainer/sgw/sgw.sh\"\n\n[tasks.mine]\nrun = \"echo mine\"\n",
    )
    .unwrap();
    // the start line of the mise era, which names a file the migration removes
    let dcj = dir.join(".devcontainer/devcontainer.json");
    let text = std::fs::read_to_string(&dcj).unwrap();
    std::fs::write(
        &dcj,
        text.replace(
            "\"postStartCommand\": \"sgw-post-start\"",
            "\"postStartCommand\": \"sh /workspace/.devcontainer/sgw/post-start.sh\"",
        ),
    )
    .unwrap();
    // a file of the project's own in the directory stops the removal
    std::fs::write(old.join("notes.txt"), "keep\n").unwrap();
    let out = sgw(&f, &["update", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(".devcontainer/sgw/ (the mise layer)"),
        "{stdout}"
    );
    assert!(stdout.contains("notes.txt"), "{stdout}");
    let out = sgw(&f, &["update", "--apply", "--offline", "--yes"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("notes.txt"));
    assert!(old.is_dir() && mise.is_file());
    std::fs::remove_file(old.join("notes.txt")).unwrap();
    // now it goes
    let out = sgw(&f, &["update", "--apply", "--offline", "--yes"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("removed .devcontainer/sgw/"), "{stdout}");
    assert!(!old.exists());
    let text = std::fs::read_to_string(&dcj).unwrap();
    assert!(
        text.contains("\"postStartCommand\": \"sgw-post-start\""),
        "the start line follows the removed script: {text}"
    );
    assert!(
        !stdout.contains("make devcontainer.json's postStartCommand"),
        "{stdout}"
    );
    let text = std::fs::read_to_string(&mise).unwrap();
    assert!(!text.contains(".devcontainer/sgw/"), "{text}");
    assert!(
        text.contains("[tasks.mine]\nrun = \"echo mine\"\n"),
        "{text}"
    );
    assert!(
        !stdout.contains("git rm mise.toml"),
        "a task of its own stays: {stdout}"
    );
    assert!(dir.join("sgw.toml").is_file());
    // a second update: nothing left to do
    let out = sgw(&f, &["update", "--offline"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Everything is up to date."), "{stdout}");
    // a mise.toml with nothing of its own is named for removal
    let dir2 = f._tmp.path().join("old2");
    sgw(&f, &["init", dir2.to_str().unwrap()]).output().unwrap();
    std::fs::write(
        dir2.join("mise.toml"),
        "[task_config]\nincludes = [\".devcontainer/sgw/tasks.mise.toml\"]\n",
    )
    .unwrap();
    let out = sgw(&f, &["update", "--apply", "--offline", "--yes"])
        .current_dir(&dir2)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("git rm mise.toml"));
}
