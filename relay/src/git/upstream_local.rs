//! A test upstream: spawns `git receive-pack` / `git upload-pack` directly against a local bare repository.
//!
//! Scaffolding that exercises the whole pkt-line / side-band rewrite path against a real git client and server.
//! Enabled only under the `test-hooks` feature; it is not part of the image build.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use super::{UpstreamError, UpstreamGit, UpstreamProcess};
use crate::policy::GitAuthorized;

pub struct LocalGitUpstream {
    pub root: PathBuf,
}

impl LocalGitUpstream {
    pub fn new(root: &Path) -> Self {
        LocalGitUpstream {
            root: root.to_path_buf(),
        }
    }
    pub fn repo_dir(&self, full_name: &str) -> PathBuf {
        self.root.join(format!("{full_name}.git"))
    }
}

#[async_trait]
impl UpstreamGit for LocalGitUpstream {
    async fn preflight(&self) -> Result<(), UpstreamError> {
        if self.root.is_dir() {
            Ok(())
        } else {
            Err(UpstreamError {
                kind: "local_root",
                message: format!("local upstream root {} missing", self.root.display()),
            })
        }
    }

    async fn spawn(&self, auth: &GitAuthorized<'_>) -> Result<UpstreamProcess, UpstreamError> {
        let dir = self.repo_dir(auth.repo());
        let child = Command::new("git")
            .arg(auth.verb().as_subcommand())
            .arg(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| UpstreamError {
                kind: "spawn",
                message: format!("cannot start git: {e}"),
            })?;
        UpstreamProcess::from_child(child).map_err(|e| UpstreamError {
            kind: "spawn",
            message: e.to_string(),
        })
    }

    fn describe(&self) -> String {
        format!("local git under {}", self.root.display())
    }
}
