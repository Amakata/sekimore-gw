//! Spawning the upstream git through the OpenSSH client.
//!
//! `git-receive-pack <url>` does not work (it only accepts a directory). The correct way to call upstream is
//! `ssh git@<host> git-receive-pack 'Org/Repo.git'`. We pass `SSH_AUTH_SOCK` to the child process and
//! authenticate with the operator's agent, so the key never leaves the Mac.

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
    /// 0.2.1: extra `-o` options from config (ProxyJump and the like). They come after the options the relay enforces, and the first value given wins
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

    /// 0.2.1: add the `ssh_options` from config (already validated on the config side).
    pub fn with_options(mut self, opts: Vec<String>) -> Self {
        self.extra_options = opts;
        self
    }

    /// Whether known_hosts has a line for the upstream host. Hashed lines (`|1|…`) cannot be matched, so we assume they do.
    pub fn known_hosts_has_upstream(&self) -> Result<bool, std::io::Error> {
        self.known_hosts_has(&self.host, self.port)
    }

    /// Whether `known_hosts` names `host` on `port`, as `host` (port 22) or `[host]:port`.
    /// Hashed lines cannot be checked and count as present. Used for the upstream itself and,
    /// since #220, for every ProxyJump bastion in front of it.
    pub fn known_hosts_has(&self, host: &str, port: u16) -> Result<bool, std::io::Error> {
        let text = match std::fs::read_to_string(&self.known_hosts) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let bracketed = format!("[{host}]:{port}");
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
                if (port == 22 && h.eq_ignore_ascii_case(host))
                    || h.eq_ignore_ascii_case(&bracketed)
                {
                    return Ok(true);
                }
            }
        }
        Ok(hashed)
    }

    /// The ProxyJump bastions in front of this upstream, in hop order: (host, port).
    ///
    /// `ProxyJump=[user@]host[:port][,[user@]host2[:port2]…]` from the extra options; `none`
    /// means no jump. The user part is not the relay's concern — the known_hosts entry is
    /// keyed by host and port.
    pub fn bastions(&self) -> Vec<(String, u16)> {
        let mut out = Vec::new();
        for opt in &self.extra_options {
            let Some((key, value)) = opt.split_once('=') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("ProxyJump") {
                continue;
            }
            for hop in value.split(',') {
                let hop = hop.trim();
                if hop.is_empty() || hop.eq_ignore_ascii_case("none") {
                    continue;
                }
                let hop = hop.rsplit_once('@').map(|(_, h)| h).unwrap_or(hop);
                let (host, port) = match hop.rsplit_once(':') {
                    Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
                        (h.trim_matches(['[', ']']), p.parse().unwrap_or(22))
                    }
                    _ => (hop.trim_matches(['[', ']']), 22),
                };
                if !host.is_empty() {
                    out.push((host.to_string(), port));
                }
            }
        }
        out
    }

    /// Where the enforced ssh_config for this upstream lives: next to its known_hosts.
    pub fn ssh_config_path(&self) -> PathBuf {
        self.known_hosts.with_file_name("ssh_config")
    }

    /// The ssh_config the relay writes and passes with `-F` (#220).
    ///
    /// The enforced options used to travel only as `-o` flags. OpenSSH runs a ProxyJump bastion
    /// as a separate `ssh -W`, and that ssh receives the `-F` file but not the command line — so
    /// the bastion hop was verified against `~/.ssh/known_hosts` with `StrictHostKeyChecking=ask`,
    /// outside the relay's control. In a file, the same options reach every hop. The operator's
    /// own file (`relay.ssh_config`) is included after ours: ssh keeps the first value it sees,
    /// so nothing in it can loosen these.
    pub fn enforced_ssh_config(&self) -> String {
        let mut cfg = String::from(
            "# Written by sekimore-relay. Every hop, ProxyJump bastions included, is held to these.\n\
             # Do not edit: it is rewritten on every connection.\n\
             Host *\n\
             \x20 BatchMode yes\n\
             \x20 StrictHostKeyChecking yes\n\
             \x20 GlobalKnownHostsFile /dev/null\n",
        );
        cfg.push_str(&format!(
            "  UserKnownHostsFile {}\n",
            self.known_hosts.display()
        ));
        cfg.push_str(
            "  UpdateHostKeys no\n\
             \x20 ConnectTimeout 20\n\
             \x20 ServerAliveInterval 30\n\
             \x20 ServerAliveCountMax 3\n\
             \x20 LogLevel ERROR\n",
        );
        if let Some(op) = &self.ssh_config {
            cfg.push_str(&format!("  Include {}\n", op.display()));
        }
        cfg
    }

    /// Writes the enforced ssh_config when it differs from what is on disk, and returns its path.
    pub fn ensure_ssh_config(&self) -> std::io::Result<PathBuf> {
        let path = self.ssh_config_path();
        let want = self.enforced_ssh_config();
        if std::fs::read_to_string(&path).ok().as_deref() != Some(want.as_str()) {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            // Written whole, then renamed: a concurrent connection must never read half a file.
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &want)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(path)
    }

    /// What to do about a missing host key, written for whoever reads it on stderr.
    ///
    /// That reader is an agent inside the dev container, where none of these commands exist —
    /// they run in the gateway. Saying so is the difference between the agent relaying a
    /// usable instruction and running `sekimore-relay keyscan` locally, where it fails
    /// against a config.yml the dev container does not have and points at the wrong cause.
    pub fn known_hosts_remedy(&self) -> String {
        format!(
            "known_hosts {} has no entry for {}. This is fixed by the operator, on the host \
             running docker (not in this container): `docker compose exec sekimore-gw \
             sekimore-relay login` fetches the upstream host keys, or `docker compose exec \
             sekimore-gw sekimore-relay keyscan {} --port {}` takes them from the host itself \
             (also for a ProxyJump bastion). In the devcontainer setup that is `mise run gw:login`. \
             Failing those, append the output of `ssh-keyscan -t ed25519,ecdsa,rsa -p {} {}` to \
             that file, again from inside the gateway.",
            self.known_hosts.display(),
            self.host,
            self.host,
            self.port,
            self.port,
            self.host,
        )
    }

    fn command(&self, remote: &str) -> Command {
        let mut cmd = Command::new(&self.ssh_bin);
        cmd.arg("-T").arg("-x").arg("-a");
        // #220: the enforced options in a file, because a ProxyJump hop gets `-F` and not `-o`.
        // The `-o` flags below stay for the first hop; the first value wins either way.
        match self.ensure_ssh_config() {
            Ok(cfg) => {
                cmd.arg("-F").arg(cfg);
            }
            Err(e) => {
                log::warn!(
                    "cannot write {}: {e}; a ProxyJump bastion will not be held to the relay's known_hosts",
                    self.ssh_config_path().display()
                );
                cmd.arg("-F")
                    .arg(self.ssh_config.as_deref().unwrap_or(Path::new("/dev/null")));
            }
        }
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
        // Extra options from config. ssh honors the first value given, so they cannot override the enforced options above.
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
        // The repository name is the canonical one from config; policy restricts it to [A-Za-z0-9._-], so quoting is safe.
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

    /// The agent reads this on stderr from inside the dev container, where none of these
    /// commands exist. Told to run `sekimore-relay keyscan` with no location, it runs it
    /// locally, hits a config.yml the dev container does not have, and reports a missing
    /// domain_handlers entry — a cause that has nothing to do with the real one.
    #[test]
    fn the_known_hosts_remedy_says_where_to_run_it() {
        let dir = tempfile::tempdir().unwrap();
        let up = OpenSshUpstream::new("github.com", 22, &dir.path().join("known_hosts"), None);
        let m = up.known_hosts_remedy();
        assert!(m.contains("not in this container"), "{m}");
        // Every command it names has to carry the way in.
        for cmd in ["sekimore-relay login", "sekimore-relay keyscan"] {
            let at = m
                .find(cmd)
                .unwrap_or_else(|| panic!("{cmd} missing from: {m}"));
            let before = &m[at.saturating_sub(40)..at];
            assert!(
                before.contains("docker compose exec sekimore-gw"),
                "{cmd} is given without saying where: {m}"
            );
        }
        // and the wrapper this project actually uses
        assert!(m.contains("mise run gw:login"), "{m}");
        // the host and port belong to the upstream that failed, not a placeholder
        assert!(m.contains("github.com"), "{m}");
        assert!(m.contains("--port 22"), "{m}");
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

    /// #220: the bastion hop is a separate ssh that gets `-F` and not `-o`, so the enforced
    /// options have to be in the file.
    #[test]
    fn the_enforced_options_are_in_the_config_file_every_hop_reads() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        let up = OpenSshUpstream::new("ghe.example.com", 2222, &kh, None)
            .with_options(vec!["ProxyJump=user@bastion.example.net:2222".into()]);
        let cmd = up.command("git-upload-pack 'Org/Repo.git'");
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let f = args.iter().position(|a| a == "-F").unwrap();
        let cfg = std::path::PathBuf::from(&args[f + 1]);
        assert_eq!(cfg, dir.path().join("ssh_config"));
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert!(text.contains("Host *\n"), "{text}");
        for line in [
            "  BatchMode yes",
            "  StrictHostKeyChecking yes",
            "  GlobalKnownHostsFile /dev/null",
            "  UpdateHostKeys no",
        ] {
            assert!(text.contains(line), "{line} missing from:\n{text}");
        }
        assert!(
            text.contains(&format!("  UserKnownHostsFile {}\n", kh.display())),
            "{text}"
        );
        assert!(
            !text.contains("Include"),
            "no operator file, no Include: {text}"
        );
    }

    #[test]
    fn the_operators_ssh_config_is_included_after_the_enforced_options() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("operator.conf");
        std::fs::write(&theirs, "Host bastion.example.net\n  User alice\n").unwrap();
        let up = OpenSshUpstream::new(
            "ghe.example.com",
            22,
            &dir.path().join("known_hosts"),
            Some(&theirs),
        );
        let text = up.enforced_ssh_config();
        let strict = text.find("StrictHostKeyChecking yes").unwrap();
        let include = text.find("Include ").unwrap();
        assert!(
            strict < include,
            "ours first, so the first value wins: {text}"
        );
        assert!(text.contains(&format!("Include {}", theirs.display())));
        // written to disk, and rewritten only when it changes
        let path = up.ensure_ssh_config().unwrap();
        let m1 = std::fs::metadata(&path).unwrap().modified().unwrap();
        up.ensure_ssh_config().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), m1);
    }

    #[test]
    fn bastions_come_out_of_proxyjump_in_hop_order() {
        let dir = tempfile::tempdir().unwrap();
        let up = |opts: &[&str]| {
            OpenSshUpstream::new("ghe.example.com", 22, &dir.path().join("kh"), None)
                .with_options(opts.iter().map(|s| s.to_string()).collect())
        };
        assert_eq!(
            up(&["ProxyJump=user@bastion.example.net:2222"]).bastions(),
            vec![("bastion.example.net".to_string(), 2222)]
        );
        assert_eq!(
            up(&["ProxyJump=a.example.net,bob@b.example.net:2200"]).bastions(),
            vec![
                ("a.example.net".to_string(), 22),
                ("b.example.net".to_string(), 2200)
            ]
        );
        assert!(up(&["ProxyJump=none"]).bastions().is_empty());
        assert!(up(&["HostKeyAlias=x"]).bastions().is_empty());
        assert_eq!(
            up(&["proxyjump=[2001:db8::1]:2222"]).bastions(),
            vec![("2001:db8::1".to_string(), 2222)]
        );
    }

    #[test]
    fn a_bastion_is_looked_up_by_host_and_port() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        let up = OpenSshUpstream::new("ghe.example.com", 2222, &kh, None);
        std::fs::write(&kh, "[bastion.example.net]:2222 ssh-ed25519 AAAA\n").unwrap();
        assert!(up.known_hosts_has("bastion.example.net", 2222).unwrap());
        assert!(!up.known_hosts_has("bastion.example.net", 22).unwrap());
        assert!(!up.known_hosts_has("ghe.example.com", 2222).unwrap());
        std::fs::write(&kh, "bastion.example.net ssh-ed25519 AAAA\n").unwrap();
        assert!(up.known_hosts_has("bastion.example.net", 22).unwrap());
        assert!(!up.known_hosts_has("bastion.example.net", 2222).unwrap());
    }

    #[test]
    fn extra_options_come_after_enforced_ones() {
        let dir = tempfile::tempdir().unwrap();
        let up = OpenSshUpstream::new("ghe.example.com", 22, &dir.path().join("kh"), None)
            .with_options(vec![
                "ProxyJump=bastion.example.com".into(),
                "StrictHostKeyChecking=no".into(), // config rejects this, and even if it got through it comes later and has no effect
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
