//! `sgw-agent setup`: what the dev container needs from the gateway, on every start (#257).
//!
//! agent-setup.sh, ported. Run as root by postStart; the agent user owns what it writes. Every
//! step is idempotent: a second run changes nothing. The environment variables are the ones the
//! script read, so a project's compose file needs no change.

pub mod discover;
pub mod files;
pub mod instructions;
pub mod proxy_env;
pub mod relay;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use files::{current_user, is_root, passwd, Owner};

/// Everything the environment decides. Read once, at the start.
#[derive(Debug, Clone)]
pub struct Settings {
    pub user: String,
    pub home: Option<PathBuf>,
    pub key_dir: Option<PathBuf>,
    pub env_file: PathBuf,
    pub bootstrap_manual: bool,
    pub webui_port: u16,
    pub api_port: u16,
    pub ssh_port: u16,
    pub proxy_root: PathBuf,
    pub git_domain: Option<String>,
    pub signing_key_comment: Option<String>,
    pub project: Option<String>,
    pub instructions: String,
    pub guide_lang: Option<String>,
    pub allow_credential_helper: bool,
    pub ssh_keygen: String,
    pub ssh_keyscan: String,
    pub ssh_add: String,
}

impl Settings {
    pub fn from_env() -> Settings {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let port = |k: &str, d: u16| var(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        Settings {
            user: var("SEKIMORE_AGENT_USER").unwrap_or_else(|| "vscode".into()),
            home: var("SEKIMORE_AGENT_HOME").map(PathBuf::from),
            key_dir: var("SEKIMORE_KEY_DIR").map(PathBuf::from),
            env_file: var("SEKIMORE_AGENT_ENV_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/sekimore-agent/env")),
            bootstrap_manual: var("SEKIMORE_BOOTSTRAP").as_deref() == Some("manual"),
            webui_port: port("SEKIMORE_WEBUI_PORT", 8080),
            api_port: port("SEKIMORE_RELAY_API_PORT", 8420),
            ssh_port: port("SEKIMORE_RELAY_SSH_PORT", 22),
            proxy_root: var("SEKIMORE_PROXY_ENV_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/")),
            git_domain: var("SEKIMORE_GIT_DOMAIN"),
            signing_key_comment: var("SEKIMORE_SIGNING_KEY_COMMENT"),
            project: var("SEKIMORE_PROJECT"),
            instructions: var("SEKIMORE_AGENT_INSTRUCTIONS")
                .unwrap_or_else(|| "claude,codex".into()),
            guide_lang: var("SEKIMORE_GUIDE_LANG"),
            allow_credential_helper: var("SEKIMORE_ALLOW_CREDENTIAL_HELPER").as_deref()
                == Some("1"),
            ssh_keygen: var("SEKIMORE_SSH_KEYGEN").unwrap_or_else(|| "ssh-keygen".into()),
            ssh_keyscan: var("SEKIMORE_SSH_KEYSCAN").unwrap_or_else(|| "ssh-keyscan".into()),
            ssh_add: var("SEKIMORE_SSH_ADD").unwrap_or_else(|| "ssh-add".into()),
        }
    }

    /// The agent user: `SEKIMORE_AGENT_USER` when it exists, else whoever runs this.
    pub fn owner(&self) -> anyhow::Result<Owner> {
        let mut o = match passwd(&self.user) {
            Some(o) => o,
            None => {
                let me = current_user().context("no passwd entry for the current user")?;
                println!(
                    "[agent] relay: user '{}' not found, using {}",
                    self.user, me.name
                );
                me
            }
        };
        if let Some(h) = &self.home {
            o.home = h.clone();
        }
        Ok(o)
    }

    pub fn keydir(&self, home: &Path) -> PathBuf {
        self.key_dir
            .clone()
            .unwrap_or_else(|| home.join(".ssh/sekimore"))
    }
}

pub struct Options {
    /// The gateway's address, when known: skips the scan, /etc/resolv.conf and the route
    pub gateway: Option<Ipv4Addr>,
}

pub async fn run(opts: Options) -> anyhow::Result<i32> {
    println!("[agent] Starting agent setup...");
    let s = Settings::from_env();
    let gw = match opts.gateway {
        Some(ip) => ip,
        None => {
            if !is_root() {
                bail!("setup has to run as root (sudo -E sgw-agent setup): it writes /etc/resolv.conf, the default route and the agent's files");
            }
            let ip = discover::gateway().await?;
            discover::point_at(ip)?;
            ip
        }
    };
    // the proxy environment (#212): a gateway too old to answer, or one with no upstream proxy,
    // leaves this container as it was
    match proxy_env::fetch(&gw.to_string(), s.webui_port).await {
        Some(env) => {
            if let Err(e) = proxy_env::apply(&env, &gw.to_string(), &s.proxy_root) {
                println!("[agent] WARNING: proxy environment setup failed: {e:#}");
            }
        }
        None => println!(
            "[agent] proxy: /api/proxy-env did not answer; leaving the proxy environment alone"
        ),
    }
    // the relay: does nothing when the gateway has none; a failure still leaves DNS and the
    // route in place
    match relay::setup(&s, gw).await {
        Ok(_) => {}
        Err(e) => println!("[agent] WARNING: relay setup failed; git through the relay will not work until it is fixed: {e:#}"),
    }
    if !s.allow_credential_helper {
        if let Ok(owner) = s.owner() {
            relay::drop_credential_helper(&owner);
        }
    }
    println!("[agent] Setup complete");
    Ok(0)
}
