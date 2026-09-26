//! `sgw open`: VS Code without the operator's ssh-agent reaching it.
//!
//! The launchd dance (`vscode.sh`: unset `SSH_AUTH_SOCK` in launchd, start the app directly
//! rather than through `open`, check the app's environment afterwards, and put it back before a
//! Docker Desktop restart) is macOS-specific and long. It is embedded here as it is and run with
//! bash, so `sgw` is one binary without porting it line by line; the port waits for the day
//! `open` has to differ per target (a sandbox is reached with Remote-SSH, not this).

use std::path::Path;
use std::process::Command;

use anyhow::Context;

use super::docker::{Docker, GATEWAY};
use crate::i18n::{t, tf};

const VSCODE_SH: &str = include_str!("../../share/vscode.sh");

/// `mode`: None launches; `--check` and `--restore-agent-env` as the script takes them.
pub fn run(docker: &Docker, project_root: &Path, mode: Option<&str>) -> anyhow::Result<i32> {
    if mode.is_none() {
        println!("{}", t("sgw.open.title"));
        println!();
    }
    let dir = tempfile_dir()?;
    let script = dir.join("vscode.sh");
    std::fs::write(&script, VSCODE_SH).context("write the embedded vscode.sh")?;
    let mut cmd = Command::new("bash");
    cmd.arg(&script);
    if let Some(m) = mode {
        cmd.arg(m);
    }
    // the script finds the project through this (its own location is a temporary directory)
    cmd.env("MISE_PROJECT_ROOT", project_root);
    // the script's hints then name sgw's commands, not the mise tasks
    cmd.env("SGW_CLI", "1");
    let st = cmd.status().context("run bash vscode.sh")?;
    let _ = std::fs::remove_dir_all(&dir);
    let code = st.code().unwrap_or(1);
    if mode.is_some() || code != 0 {
        return Ok(code);
    }
    // The secret store: locked, the relay cannot take the upstream credentials out of it. When
    // the gateway is up, the unlock happens here, while the operator is at this terminal; when
    // it is not, it comes after "Reopen in Container" and is one of the next steps.
    println!();
    let mut unlock_later = true;
    if let Ok(cid) = docker.find_container(GATEWAY) {
        let state = docker
            .exec_capture(
                &cid,
                None,
                &["sekimore-relay".into(), "store-status".into()],
            )
            .map(|c| c.stdout.trim().to_string())
            .unwrap_or_default();
        if state == "unlocked" {
            println!("{}", t("sgw.open.store_unlocked"));
            unlock_later = false;
        } else if !state.is_empty() {
            println!("{}", tf("sgw.open.store_locked", &[("state", &state)]));
            match super::ops::relay(docker, &["unlock".into()], false) {
                Ok(0) => unlock_later = false,
                _ => eprintln!("{}", t("sgw.open.store_left_locked")),
            }
        }
    }
    println!();
    println!("{}", t("sgw.open.next_hdr"));
    println!("  1. {}", t("sgw.open.next_reopen"));
    if unlock_later {
        println!("  2. {}", t("sgw.open.next_unlock"));
        println!("  3. {}", t("sgw.open.next_verify"));
    } else {
        println!("  2. {}", t("sgw.open.next_verify"));
    }
    Ok(0)
}

/// A private directory for the script: 0700, under the system's temporary directory.
fn tempfile_dir() -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::temp_dir();
    let dir = base.join(format!("sgw-open-{}", std::process::id()));
    // a run that died before its cleanup, with this pid reused since
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(false)
        .create(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_embedded_script_is_the_distributed_one() {
        // relay/share/vscode.sh; a build embeds whatever is there
        assert!(super::VSCODE_SH.starts_with("#!/usr/bin/env bash"));
        assert!(super::VSCODE_SH.contains("--restore-agent-env"));
        // three lines by default, the full report for --check; the store and the next steps are
        // this module's, so the script has no mise task and no store call left
        assert!(super::VSCODE_SH.contains("report full"));
        assert!(!super::VSCODE_SH.contains("mise run"));
        assert!(!super::VSCODE_SH.contains("store-status"));
    }
}
