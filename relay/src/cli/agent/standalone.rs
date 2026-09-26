//! `sgw-agent`: the AI's command in the dev container, as one binary (#257).
//!
//! It is `sekimore-relay agent …` with what the `sekimore` shell wrapper used to do in front of
//! it: the env file that agent-setup wrote (`/etc/sekimore-agent/env`) wins over the process
//! environment, a token whose `SEKIMORE_TOKEN_EXPIRES` has passed is renewed through
//! `POST /bootstrap` with the disposable key before the command runs, and a token the relay
//! rejects is renewed once and the command run again. `sekimore` stays as an alias that execs
//! this binary.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};

use super::{AgentClient, AgentCmd, NAME};
use crate::api::types::{ApiRequest, BootstrapRequest, BootstrapResponse};
use crate::i18n::t;

pub const DEFAULT_ENV_FILE: &str = "/etc/sekimore-agent/env";

#[derive(Parser, Debug)]
#[command(name = "sgw-agent", version, about = t("cli.agent"))]
pub struct AgentCli {
    #[arg(long, global = true, env = "SEKIMORE_REPO", help = t("cli.agent.repo"))]
    pub repo: Option<String>,
    #[arg(short, long, action = clap::ArgAction::Count, global = true, help = t("cli.verbose"))]
    pub verbose: u8,
    #[command(subcommand)]
    pub cmd: Top,
}

/// `setup` is sgw-agent's own; everything else is the relay's agent command set.
#[derive(Subcommand, Debug)]
pub enum Top {
    /// What the dev container needs from the gateway, on every start (run as root by postStart)
    #[command(about = t("cli.agent.setup"))]
    Setup {
        #[arg(long, value_name = "IP", env = "SEKIMORE_IP", help = t("cli.agent.setup.gateway"))]
        gateway: Option<std::net::Ipv4Addr>,
    },
    #[command(flatten)]
    Agent(AgentCmd),
}

/// `KEY=VALUE` lines of the env file, in order. `export KEY=…` and a value in single or double
/// quotes are read the way a shell sourcing the file would read them; comments and blank lines
/// are skipped. Anything else is left out rather than guessed at.
pub fn parse_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let (k, v) = line.split_once('=')?;
            let k = k.trim();
            let mut chars = k.chars();
            let first_ok = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Whether an RFC 3339 expiry has passed. One that does not parse is treated as not expired:
/// the refresh after a rejected token is the fallback, as it was in the wrapper.
pub fn token_expired(expires: &str, now: SystemTime) -> bool {
    match humantime::parse_rfc3339(expires.trim()) {
        Ok(exp) => now >= exp,
        Err(_) => false,
    }
}

/// The env file with the token lines replaced and every other line kept in its place.
pub fn with_new_token(text: &str, token: &str, expires: Option<&str>) -> String {
    let mut out: Vec<String> = text
        .lines()
        .filter(|l| {
            let l = l.trim_start();
            let l = l.strip_prefix("export ").unwrap_or(l);
            !(l.starts_with("SEKIMORE_TOKEN=") || l.starts_with("SEKIMORE_TOKEN_EXPIRES="))
        })
        .map(str::to_string)
        .collect();
    out.push(format!("SEKIMORE_TOKEN={token}"));
    if let Some(e) = expires {
        out.push(format!("SEKIMORE_TOKEN_EXPIRES={e}"));
    }
    out.join("\n") + "\n"
}

/// The label a refreshed token is registered under on the gateway: the hostname, reduced to
/// characters that need no escaping. Only a display name.
fn label() -> String {
    let raw = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let s: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if s.is_empty() {
        "sgw-agent".to_string()
    } else {
        s
    }
}

pub struct Env {
    pub file: PathBuf,
    pub endpoint: String,
    pub key: PathBuf,
}

impl Env {
    /// Where things are, once the env file has been applied to the process environment.
    pub fn from_process() -> Env {
        let var = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        let home = var("HOME").unwrap_or_else(|| "/root".into());
        Env {
            file: var("SEKIMORE_AGENT_ENV_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ENV_FILE)),
            endpoint: var("SEKIMORE_ENDPOINT").unwrap_or_else(|| super::DEFAULT_ENDPOINT.into()),
            key: var("SEKIMORE_AGENT_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|| Path::new(&home).join(".ssh/sekimore/id_ed25519.pub")),
        }
    }
}

/// The env file into the process environment. The file wins over what is already there: a
/// shell opened before a refresh still carries the old token, and the file is the source of
/// truth. `SEKIMORE_ENV_OVERRIDE=1` keeps the environment as it is (manual testing).
pub fn apply_env_file(path: &Path) {
    if std::env::var("SEKIMORE_ENV_OVERRIDE").ok().as_deref() == Some("1") {
        return;
    }
    if let Ok(text) = std::fs::read_to_string(path) {
        for (k, v) in parse_env(&text) {
            std::env::set_var(k, v);
        }
    }
}

/// A new token from `POST /bootstrap` with the disposable key, written into the env file in
/// place (the directory is root's, the file is the agent user's, so no temp file beside it) and
/// into the process environment. The response body is never printed: it is the one place a
/// token could land in a log.
pub async fn refresh(env: &Env) -> anyhow::Result<String> {
    let pub_line = std::fs::read_to_string(&env.key)
        .with_context(|| format!("cannot read the disposable key {}", env.key.display()))?;
    let pub_line = pub_line.lines().next().unwrap_or("").trim().to_string();
    if pub_line.is_empty() {
        bail!("{} is empty", env.key.display());
    }
    if pub_line.contains('"') || pub_line.contains('\\') {
        bail!(
            "{} holds a quote or a backslash, so it is not an ssh public key line",
            env.key.display()
        );
    }
    let current = std::fs::read_to_string(&env.file)
        .with_context(|| format!("cannot read {}", env.file.display()))?;
    let meta = std::fs::metadata(&env.file)?;
    if meta.permissions().readonly() {
        bail!("{} is not writable", env.file.display());
    }
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp = http
        .post(format!("{}/bootstrap", env.endpoint.trim_end_matches('/')))
        .json(&BootstrapRequest {
            public_key: pub_line,
            label: Some(label()),
        })
        .send()
        .await
        .with_context(|| format!("POST {}/bootstrap failed", env.endpoint))?;
    let status = resp.status();
    let body: BootstrapResponse = resp.json().await.map_err(|_| {
        anyhow::anyhow!(
            "{}/bootstrap answered HTTP {status} without a token",
            env.endpoint
        )
    })?;
    let Some(token) = body.token.filter(|t| !t.is_empty()) else {
        bail!(
            "{}/bootstrap answered without a token; the key may no longer be registered{}",
            env.endpoint,
            body.error.map(|e| format!(" ({e})")).unwrap_or_default()
        );
    };
    let expires = body.token_expires.filter(|e| !e.is_empty());
    std::fs::write(
        &env.file,
        with_new_token(&current, &token, expires.as_deref()),
    )
    .with_context(|| format!("could not write the new token to {}", env.file.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env.file, std::fs::Permissions::from_mode(0o600));
    }
    std::env::set_var("SEKIMORE_TOKEN", &token);
    match &expires {
        Some(e) => std::env::set_var("SEKIMORE_TOKEN_EXPIRES", e),
        None => std::env::remove_var("SEKIMORE_TOKEN_EXPIRES"),
    }
    Ok(expires.unwrap_or_else(|| "unknown".into()))
}

/// Whether the relay is refusing the token we hold: the reasons `tokens::VerifyError` prints.
pub fn is_token_error(error: &str) -> bool {
    error.contains("token expired")
        || error.contains("unknown token")
        || error.contains("token revoked")
}

async fn token_rejected() -> bool {
    let Ok(client) = AgentClient::from_env() else {
        return false;
    };
    match client.call("/whoami", &ApiRequest::default()).await {
        Ok(resp) => !resp.ok && resp.error.as_deref().is_some_and(is_token_error),
        Err(_) => false,
    }
}

async fn run_once(argv: &[String]) -> i32 {
    let cli = match AgentCli::try_parse_from(argv) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let result = match cli.cmd {
        Top::Setup { gateway } => {
            crate::agent_setup::run(crate::agent_setup::Options { gateway }).await
        }
        Top::Agent(cmd) => super::run(cli.repo.as_deref(), cmd).await,
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{NAME}: {e:#}");
            1
        }
    }
}

pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    // --help / --version / a parse error: before anything touches the network or the env file
    let cli = match AgentCli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(format!("sekimore_relay={level}")),
    )
    .try_init()
    .ok();
    drop(cli);

    let env_file = std::env::var("SEKIMORE_AGENT_ENV_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENV_FILE));
    apply_env_file(&env_file);
    let env = Env::from_process();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{NAME}: tokio runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async {
        // a refresh that already failed once is not tried again after the command fails
        let mut refresh_failed = false;
        if let Ok(exp) = std::env::var("SEKIMORE_TOKEN_EXPIRES") {
            if token_expired(&exp, SystemTime::now()) {
                match refresh(&env).await {
                    Ok(until) => eprintln!(
                        "{NAME}: project token was expired; obtained a new one (expires {until})"
                    ),
                    Err(e) => {
                        eprintln!("{NAME}: {e:#}; cannot refresh the token");
                        refresh_failed = true;
                    }
                }
            }
        }
        let code = run_once(&argv).await;
        if code == 0 || refresh_failed || !token_rejected().await {
            return code;
        }
        match refresh(&env).await {
            Ok(until) => {
                eprintln!("{NAME}: the relay rejected the project token; obtained a new one (expires {until})");
                run_once(&argv).await
            }
            Err(e) => {
                eprintln!("{NAME}: {e:#}; cannot refresh the token");
                code
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_env_file_is_read_like_a_shell_would_source_it() {
        let text = "# written by agent-setup\nSEKIMORE_ENDPOINT=http://gw:8420\nexport SEKIMORE_TOKEN=\"skm_abc\"\nSEKIMORE_TOKEN_EXPIRES='2026-09-26T19:14:14Z'\n\nnot a line\n1BAD=x\n";
        assert_eq!(
            parse_env(text),
            vec![
                ("SEKIMORE_ENDPOINT".into(), "http://gw:8420".into()),
                ("SEKIMORE_TOKEN".into(), "skm_abc".into()),
                (
                    "SEKIMORE_TOKEN_EXPIRES".into(),
                    "2026-09-26T19:14:14Z".into()
                ),
            ]
        );
    }

    #[test]
    fn an_expiry_in_the_past_is_expired_and_one_that_does_not_parse_is_not() {
        // 2027-01-15
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(token_expired("2026-09-26T00:00:00Z", now));
        assert!(!token_expired("2030-01-01T00:00:00Z", now));
        assert!(!token_expired("yesterday", now));
        assert!(!token_expired("", now));
    }

    #[test]
    fn the_token_lines_are_replaced_and_the_rest_kept_in_place() {
        let text = "SEKIMORE_ENDPOINT=http://gw:8420\nSEKIMORE_TOKEN=skm_old\nSEKIMORE_TOKEN_EXPIRES=2026-01-01T00:00:00Z\nSEKIMORE_AGENT_KEY=/k\n";
        assert_eq!(
            with_new_token(text, "skm_new", Some("2026-02-01T00:00:00Z")),
            "SEKIMORE_ENDPOINT=http://gw:8420\nSEKIMORE_AGENT_KEY=/k\nSEKIMORE_TOKEN=skm_new\nSEKIMORE_TOKEN_EXPIRES=2026-02-01T00:00:00Z\n"
        );
        // no expiry in the answer: the old one must not survive
        assert_eq!(
            with_new_token(
                "SEKIMORE_TOKEN_EXPIRES=2026-01-01T00:00:00Z\n",
                "skm_new",
                None
            ),
            "SEKIMORE_TOKEN=skm_new\n"
        );
    }

    #[test]
    fn only_the_relays_own_token_reasons_trigger_a_refresh() {
        assert!(is_token_error("token expired at 2026-09-26T19:14:14Z"));
        assert!(is_token_error("unknown token"));
        assert!(is_token_error("token revoked"));
        assert!(!is_token_error("denied: pr:merge is not granted"));
        assert!(!is_token_error("the secret store is locked"));
    }
}
