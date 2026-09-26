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

const VSCODE_SH: &str = include_str!("../../../base/share/sgw/vscode.sh");

/// `mode`: None launches; `--check` and `--restore-agent-env` as the script takes them.
pub fn run(project_root: &Path, mode: Option<&str>) -> anyhow::Result<i32> {
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
    Ok(st.code().unwrap_or(1))
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
        // the same file base/share/sgw/vscode.sh ships; a build embeds whatever is there
        assert!(super::VSCODE_SH.starts_with("#!/usr/bin/env bash"));
        assert!(super::VSCODE_SH.contains("--restore-agent-env"));
        // its hints name sgw's commands when sgw runs it
        assert!(super::VSCODE_SH.contains("SGW_CLI"));
        assert!(super::VSCODE_SH.contains("H_VERIFY='sgw verify'"));
    }
}
