//! 上流 git を OpenSSH クライアントで起動する。
//!
//! `git-receive-pack <url>` は無効（ディレクトリしか受けない）。正しい上流の呼び方は
//! `ssh git@<host> git-receive-pack 'Org/Repo.git'`。`SSH_AUTH_SOCK` を子プロセスに渡し、
//! 依頼者の agent で認証する（鍵は Mac から出ない）。

use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use super::agent_check::{auth_sock_from_env, preflight_agent};
use super::{UpstreamError, UpstreamGit, UpstreamProcess};
use crate::policy::GitAuthorized;

pub struct OpenSshUpstream {
    pub host: String,
    pub port: u16,
    pub known_hosts: PathBuf,
    pub ssh_config: Option<PathBuf>,
    pub auth_sock: Option<PathBuf>,
    pub ssh_bin: String,
    /// 0.2.1: 設定からの追加 `-o`（ProxyJump 等）。関所が強制するオプションの後ろに並べる（先に指定した値が勝つ）
    pub extra_options: Vec<String>,
}

impl OpenSshUpstream {
    pub fn new(host: &str, port: u16, known_hosts: &Path, ssh_config: Option<&Path>) -> Self {
        OpenSshUpstream {
            host: host.to_string(),
            port,
            known_hosts: known_hosts.to_path_buf(),
            ssh_config: ssh_config.map(Path::to_path_buf),
            auth_sock: auth_sock_from_env(),
            ssh_bin: "ssh".to_string(),
            extra_options: Vec::new(),
        }
    }

    /// 0.2.1: 設定の `ssh_options` を足す（検証は config 側で済んでいる）。
    pub fn with_options(mut self, opts: Vec<String>) -> Self {
        self.extra_options = opts;
        self
    }

    /// known_hosts に上流ホストの行があるか。ハッシュ化行（`|1|…`）は照合できないので「ある」とみなす。
    pub fn known_hosts_has_upstream(&self) -> Result<bool, std::io::Error> {
        let text = match std::fs::read_to_string(&self.known_hosts) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let bracketed = format!("[{}]:{}", self.host, self.port);
        let mut hashed = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let hosts = line.split_whitespace().next().unwrap_or("");
            let hosts = hosts
                .strip_prefix('@')
                .map(|_| line.split_whitespace().nth(1).unwrap_or(""))
                .unwrap_or(hosts);
            if hosts.starts_with("|1|") {
                hashed = true;
                continue;
            }
            for h in hosts.split(',') {
                if h.eq_ignore_ascii_case(&self.host) || h.eq_ignore_ascii_case(&bracketed) {
                    return Ok(true);
                }
            }
        }
        Ok(hashed)
    }

    pub fn known_hosts_remedy(&self) -> String {
        format!(
            "known_hosts {} has no entry for {}; run `sekimore-relay login` (fetches the upstream host keys) or \
             `sekimore-relay keyscan {} --port {}` (also for a ProxyJump bastion), or append \
             `ssh-keyscan -t ed25519,ecdsa,rsa -p {} {}` yourself",
            self.known_hosts.display(),
            self.host,
            self.host,
            self.port,
            self.port,
            self.host
        )
    }

    fn command(&self, remote: &str) -> Command {
        let mut cmd = Command::new(&self.ssh_bin);
        cmd.arg("-T").arg("-x").arg("-a");
        cmd.arg("-F")
            .arg(self.ssh_config.as_deref().unwrap_or(Path::new("/dev/null")));
        for opt in [
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "ConnectTimeout=20",
            "ServerAliveInterval=30",
            "ServerAliveCountMax=3",
            "LogLevel=ERROR",
        ] {
            cmd.arg("-o").arg(opt);
        }
        cmd.arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()));
        // 設定からの追加オプション。ssh は先に指定した値を使うので、上の強制オプションは上書きされない
        for opt in &self.extra_options {
            cmd.arg("-o").arg(opt);
        }
        cmd.arg("-p").arg(self.port.to_string());
        cmd.arg(format!("git@{}", self.host));
        cmd.arg(remote);
        cmd.env_clear();
        for var in ["PATH", "HOME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
        if let Some(sock) = &self.auth_sock {
            cmd.env("SSH_AUTH_SOCK", sock);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

#[async_trait]
impl UpstreamGit for OpenSshUpstream {
    async fn preflight(&self) -> Result<(), UpstreamError> {
        preflight_agent(self.auth_sock.as_deref())
            .await
            .map_err(|e| UpstreamError {
                kind: match e {
                    super::agent_check::AgentError::Unset => "agent_unset",
                    super::agent_check::AgentError::Missing(_) => "agent_missing",
                    super::agent_check::AgentError::Connect(..) => "agent_connect",
                    super::agent_check::AgentError::NoIdentities => "agent_no_identities",
                    super::agent_check::AgentError::Protocol(_) => "agent_protocol",
                },
                message: e.to_string(),
            })?;
        match self.known_hosts_has_upstream() {
            Ok(true) => Ok(()),
            Ok(false) => Err(UpstreamError {
                kind: "known_hosts",
                message: self.known_hosts_remedy(),
            }),
            Err(e) => Err(UpstreamError {
                kind: "known_hosts",
                message: format!("cannot read {}: {e}", self.known_hosts.display()),
            }),
        }
    }

    async fn spawn(&self, auth: &GitAuthorized<'_>) -> Result<UpstreamProcess, UpstreamError> {
        // リポジトリ名は config の正規名。policy が [A-Za-z0-9._-] に制限しているので引用は安全
        let remote = format!("{} '{}.git'", auth.verb().as_str(), auth.repo());
        let child = self.command(&remote).spawn().map_err(|e| UpstreamError {
            kind: "spawn",
            message: format!(
                "cannot start {}: {e} (is openssh-client installed in the gateway image?)",
                self.ssh_bin
            ),
        })?;
        UpstreamProcess::from_child(child).map_err(|e| UpstreamError {
            kind: "spawn",
            message: e.to_string(),
        })
    }

    fn describe(&self) -> String {
        format!(
            "ssh git@{}:{} (known_hosts {})",
            self.host,
            self.port,
            self.known_hosts.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hosts_matching() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        let mut up = OpenSshUpstream::new("github.com", 22, &kh, None);
        assert!(!up.known_hosts_has_upstream().unwrap());
        std::fs::write(
            &kh,
            "# c\ngitlab.com ssh-ed25519 AAAA\ngithub.com,140.82.112.3 ssh-ed25519 AAAA\n",
        )
        .unwrap();
        assert!(up.known_hosts_has_upstream().unwrap());
        up.host = "ghe.example.com".into();
        assert!(!up.known_hosts_has_upstream().unwrap());
        up.port = 2222;
        std::fs::write(&kh, "[ghe.example.com]:2222 ssh-ed25519 AAAA\n").unwrap();
        assert!(up.known_hosts_has_upstream().unwrap());
        std::fs::write(&kh, "|1|abc=|def= ssh-ed25519 AAAA\n").unwrap();
        assert!(
            up.known_hosts_has_upstream().unwrap(),
            "hashed lines cannot be checked; assume present"
        );
        assert!(up.known_hosts_remedy().contains("ssh-keyscan"));
    }

    #[test]
    fn command_line_shape() {
        let dir = tempfile::tempdir().unwrap();
        let up = OpenSshUpstream::new("github.com", 22, &dir.path().join("kh"), None);
        let cmd = up.command("git-upload-pack 'Org/Repo.git'");
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"git@github.com".to_string()));
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert_eq!(args.last().unwrap(), "git-upload-pack 'Org/Repo.git'");
        assert!(args.iter().any(|a| a.starts_with("UserKnownHostsFile=")));
    }

    #[test]
    fn extra_options_come_after_enforced_ones() {
        let dir = tempfile::tempdir().unwrap();
        let up = OpenSshUpstream::new("ghe.example.com", 22, &dir.path().join("kh"), None)
            .with_options(vec![
                "ProxyJump=bastion.example.com".into(),
                "StrictHostKeyChecking=no".into(), // config 側で弾かれるが、通っても後ろなので効かない
            ]);
        let cmd = up.command("git-upload-pack 'Org/Repo.git'");
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let pos = |s: &str| args.iter().position(|a| a == s).unwrap();
        assert!(pos("StrictHostKeyChecking=yes") < pos("ProxyJump=bastion.example.com"));
        assert!(pos("ProxyJump=bastion.example.com") < pos("StrictHostKeyChecking=no"));
        assert!(pos("ProxyJump=bastion.example.com") < pos("git@ghe.example.com"));
        assert_eq!(args[pos("ProxyJump=bastion.example.com") - 1], "-o");
    }
}
