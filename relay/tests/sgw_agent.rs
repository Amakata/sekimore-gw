//! `sgw-agent` end to end, as a process, against the real API server (#257): the env file
//! wins over the environment, a token whose expiry has passed is renewed before the command,
//! and a token the relay rejects is renewed once and the command run again. These are the
//! cases base/tests/test_wrapper_refresh.sh covered for the shell wrapper.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use sekimore_relay::config::BootstrapMode;

struct Agent {
    _dir: tempfile::TempDir,
    env_file: PathBuf,
}

/// An env file the way agent-setup writes one, with the token lines given, and the disposable
/// key beside it.
fn agent(addr: std::net::SocketAddr, token_lines: &str) -> Agent {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519.pub");
    std::fs::write(&key, format!("{}\n", gen_pubkey())).unwrap();
    let env_file = dir.path().join("env");
    std::fs::write(
        &env_file,
        format!(
            "# written by agent-setup\nSEKIMORE_ENDPOINT=http://{addr}\nSEKIMORE_AGENT_KEY={}\n{token_lines}",
            key.display()
        ),
    )
    .unwrap();
    Agent {
        _dir: dir,
        env_file,
    }
}

async fn run(env_file: &Path, extra: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sgw-agent"));
    c.env_remove("SEKIMORE_TOKEN")
        .env_remove("SEKIMORE_TOKEN_EXPIRES")
        .env_remove("SEKIMORE_ENDPOINT")
        .env_remove("SEKIMORE_ENV_OVERRIDE")
        .env_remove("SEKIMORE_REPO")
        .env("SEKIMORE_AGENT_ENV_FILE", env_file)
        .env("SEKIMORE_LANG", "en")
        .args(args);
    for (k, v) in extra {
        c.env(k, v);
    }
    // the server runs on this runtime; the child must not block one of its threads
    let out = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn token_in(env_file: &Path) -> String {
    std::fs::read_to_string(env_file)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("SEKIMORE_TOKEN=").map(str::to_string))
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_token_is_renewed_before_the_command_and_written_back() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let a = agent(
        f.addr,
        "SEKIMORE_TOKEN=skm_stale\nSEKIMORE_TOKEN_EXPIRES=2020-01-01T00:00:00Z\n",
    );
    let (code, out, err) = run(&a.env_file, &[], &["whoami"]).await;
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(
        err.contains("sgw-agent: project token was expired; obtained a new one"),
        "{err}"
    );
    assert!(out.contains("case-a"), "{out}");
    let new = token_in(&a.env_file);
    assert!(new.starts_with("skm_") && new != "skm_stale", "{new}");
    let text = std::fs::read_to_string(&a.env_file).unwrap();
    assert!(
        text.starts_with("# written by agent-setup\nSEKIMORE_ENDPOINT="),
        "{text}"
    );
    assert!(
        !text.contains("2020-01-01"),
        "the old expiry must go: {text}"
    );
    // the token is good now: the next run renews nothing
    let (code, _, err) = run(&a.env_file, &[], &["whoami"]).await;
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("obtained a new one"), "{err}");
    assert_eq!(token_in(&a.env_file), new);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_env_file_wins_over_a_stale_token_in_the_environment() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let a = agent(f.addr, &format!("SEKIMORE_TOKEN={}\n", f.token));
    let bogus = format!("skm_{}", "0".repeat(64));
    let (code, out, err) = run(&a.env_file, &[("SEKIMORE_TOKEN", &bogus)], &["whoami"]).await;
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(!err.contains("obtained a new one"), "{err}");
    // and with the override, the environment is used as it is — the bogus token is refused,
    // and with no key to renew with (the file's is not read either) it stays refused
    let endpoint = format!("http://{}", f.addr);
    let no_key = a._dir.path().join("no-such-key").display().to_string();
    let (code, _, err) = run(
        &a.env_file,
        &[
            ("SEKIMORE_TOKEN", &bogus),
            ("SEKIMORE_ENDPOINT", &endpoint),
            ("SEKIMORE_AGENT_KEY", &no_key),
            ("SEKIMORE_ENV_OVERRIDE", "1"),
        ],
        &["whoami"],
    )
    .await;
    assert_ne!(code, 0);
    assert!(err.contains("unknown token"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_the_relay_rejects_is_renewed_once_and_the_command_run_again() {
    let f = start_api(project_case_a(&["pr:create"]), BootstrapMode::Auto, true).await;
    let bogus = format!("skm_{}", "0".repeat(64));
    let a = agent(f.addr, &format!("SEKIMORE_TOKEN={bogus}\n"));
    let (code, out, err) = run(&a.env_file, &[], &["whoami"]).await;
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(
        err.contains("sgw-agent: the relay rejected the project token; obtained a new one"),
        "{err}"
    );
    assert_ne!(token_in(&a.env_file), bogus);
    // once: with no key to renew with, the failure is reported and the command is not run again
    let b = agent(f.addr, &format!("SEKIMORE_TOKEN={bogus}\n"));
    std::fs::remove_file(b._dir.path().join("id_ed25519.pub")).unwrap();
    let (code, _, err) = run(&b.env_file, &[], &["whoami"]).await;
    assert_ne!(code, 0);
    assert!(err.contains("cannot refresh the token"), "{err}");
    assert_eq!(err.matches("unknown token").count(), 1, "{err}");
    assert_eq!(token_in(&b.env_file), bogus);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn help_names_the_binary_and_the_alias_prints_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out, _) = run(&dir.path().join("none"), &[], &["--help"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("Usage: sgw-agent"), "{out}");
    assert!(out.contains("whoami"), "{out}");
    let (code, out, _) = run(&dir.path().join("none"), &[], &["whoami", "--help"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("Usage: sgw-agent whoami"), "{out}");
}
