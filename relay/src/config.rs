//! `/etc/sekimore/config.yml` の読み込み。Python（sekimore-gw）と同じファイルを共有する。
//!
//! - トップレベルは寛容（未知キー無視、`handler` の未知値も無視）: Python 側の拡張を壊さない
//! - `relay:` 配下は relay が所有するので厳格（未知キー = typo = エラー）
//! - `git-relay` handler は 1 ドメインのみ（SSH の exec 要求はリポジトリパスしか運ばない）

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::policy::{Mode, Project, RepoPolicy};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/sekimore/config.yml";
/// GitHub CLI の public client id。device flow は client secret を必要としない。
pub const DEFAULT_OAUTH_CLIENT_ID: &str = "178c6fc778ccc68e1d6a";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandlerKind {
    Splice,
    GitRelay,
    Deny,
    /// Python 側が将来足す種類。relay は関知しない
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainHandler {
    #[serde(default = "default_handler")]
    pub handler: HandlerKind,
}

fn default_handler() -> HandlerKind {
    HandlerKind::Splice
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyConfig {
    /// Squid が有効か。Python 側は `enabled` が真のときだけ `upstream_proxy` を使うので、relay も揃える
    /// （sample の config には `enabled: false` のまま `upstream_proxy: proxy.example.com:…` のプレースホルダが残っている）
    #[serde(default)]
    pub enabled: bool,
    pub upstream_proxy: Option<String>,
    #[serde(default)]
    pub upstream_proxy_tls: bool,
    pub upstream_proxy_username: Option<String>,
    pub upstream_proxy_password: Option<String>,
}

/// トップレベル。Python が所有するキーは読み飛ばす。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub domain_handlers: BTreeMap<String, DomainHandler>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub relay: Option<RelayConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpsMode {
    Passthrough,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootstrapMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "d_cmd_max")]
    pub cmd_max_bytes: usize,
    #[serde(default = "d_adv_max")]
    pub adv_max_bytes: usize,
    #[serde(default = "d_api_body_max")]
    pub api_body_max_bytes: usize,
    #[serde(default = "d_session_timeout", with = "humantime_serde")]
    pub session_timeout: Duration,
    #[serde(default = "d_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    #[serde(default = "d_adv_timeout", with = "humantime_serde")]
    pub adv_timeout: Duration,
    #[serde(default = "d_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "d_max_passthrough")]
    pub max_passthrough_conns: usize,
}

fn d_cmd_max() -> usize {
    1 << 20
}
fn d_adv_max() -> usize {
    16 << 20
}
fn d_api_body_max() -> usize {
    1 << 20
}
fn d_session_timeout() -> Duration {
    Duration::from_secs(3600)
}
fn d_idle_timeout() -> Duration {
    Duration::from_secs(300)
}
fn d_adv_timeout() -> Duration {
    Duration::from_secs(60)
}
fn d_max_sessions() -> usize {
    32
}
fn d_max_passthrough() -> usize {
    256
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            cmd_max_bytes: d_cmd_max(),
            adv_max_bytes: d_adv_max(),
            api_body_max_bytes: d_api_body_max(),
            session_timeout: d_session_timeout(),
            idle_timeout: d_idle_timeout(),
            adv_timeout: d_adv_timeout(),
            max_sessions: d_max_sessions(),
            max_passthrough_conns: d_max_passthrough(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub bases: Vec<String>,
    /// 直接 push を許すブランチ glob。省略時は `sekimore/*`
    pub push: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default)]
    pub repos: Vec<RepoConfig>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// `relay:` セクション。relay が所有するので未知キーはエラー。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    #[serde(default = "d_ssh_listen")]
    pub ssh_listen: SocketAddr,
    #[serde(default = "d_api_listen")]
    pub api_listen: SocketAddr,
    #[serde(default = "d_https_listen")]
    pub https_listen: SocketAddr,
    #[serde(default = "d_https")]
    pub https: HttpsMode,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    /// 上流ホスト。省略時は git-relay ドメイン
    pub upstream: Option<String>,
    #[serde(default = "d_upstream_ssh_port")]
    pub upstream_ssh_port: u16,
    /// 上流 ssh に `-F` で渡す設定ファイル（ProxyCommand 等）。既定 /dev/null
    pub ssh_config: Option<PathBuf>,
    pub api_base: Option<Url>,
    pub graphql_base: Option<Url>,
    #[serde(default = "d_client_id")]
    pub oauth_client_id: String,
    #[serde(default = "d_token_ttl", with = "humantime_serde")]
    pub token_ttl: Duration,
    #[serde(default = "d_cache_ttl", with = "humantime_serde")]
    pub upstream_token_cache_ttl: Duration,
    /// `SSL_CERT_FILE` に加えて信頼する PEM バンドル
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_delete: bool,
    #[serde(default = "d_bootstrap")]
    pub bootstrap: BootstrapMode,
    #[serde(default)]
    pub limits: Limits,
    pub project: ProjectConfig,
    /// テスト専用: 上流 ssh の代わりに実行するコマンド（`["git", "receive-pack", "<bare-dir>"]` の親ディレクトリ）
    #[cfg(feature = "test-hooks")]
    pub upstream_local_root: Option<PathBuf>,
}

fn d_ssh_listen() -> SocketAddr {
    "0.0.0.0:22".parse().unwrap()
}
fn d_api_listen() -> SocketAddr {
    "0.0.0.0:8420".parse().unwrap()
}
fn d_https_listen() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}
fn d_https() -> HttpsMode {
    HttpsMode::Passthrough
}
fn d_state_dir() -> PathBuf {
    PathBuf::from("/data/relay")
}
fn d_upstream_ssh_port() -> u16 {
    22
}
fn d_client_id() -> String {
    DEFAULT_OAUTH_CLIENT_ID.to_string()
}
fn d_token_ttl() -> Duration {
    Duration::from_secs(12 * 3600)
}
fn d_cache_ttl() -> Duration {
    Duration::from_secs(2 * 3600)
}
fn d_bootstrap() -> BootstrapMode {
    BootstrapMode::Auto
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    InvalidDomainKey {
        key: String,
        reason: &'static str,
    },
    MultipleGitRelayDomains(Vec<String>),
    NoGitRelayDomain,
    NoRelaySection,
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            ConfigError::Parse { path, message } => write!(f, "cannot parse {}: {message}", path.display()),
            ConfigError::InvalidDomainKey { key, reason } => {
                write!(f, "domain_handlers key {key:?} is invalid: {reason}")
            }
            ConfigError::MultipleGitRelayDomains(domains) => write!(
                f,
                "domain_handlers has {} git-relay entries ({}); only one is supported because the SSH exec request carries only the repository path, not the hostname",
                domains.len(),
                domains.join(", ")
            ),
            ConfigError::NoGitRelayDomain => {
                write!(f, "no domain_handlers entry with handler: git-relay (relay is not needed)")
            }
            ConfigError::NoRelaySection => write!(
                f,
                "domain_handlers has a git-relay entry but the relay: section is missing (project definition required)"
            ),
            ConfigError::Invalid(msg) => write!(f, "invalid relay configuration: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// 読み込み済み設定。`needs_relay` の判定と `resolve` を提供する。
#[derive(Debug, Clone)]
pub struct Loaded {
    pub path: PathBuf,
    pub gateway: GatewayConfig,
    /// 正規化済み（lower、末尾 `.` 除去）の handler マップ
    handlers: BTreeMap<String, HandlerKind>,
}

/// ファイルから読む。存在しなければ空設定（Python の `load_config` と同じ振る舞い）。
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    parse(path, &text)
}

pub fn parse(path: &Path, text: &str) -> Result<Loaded, ConfigError> {
    let gateway: GatewayConfig = if text.trim().is_empty() {
        GatewayConfig::default()
    } else {
        serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?
    };
    let mut handlers = BTreeMap::new();
    for (key, h) in &gateway.domain_handlers {
        let norm = key.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            return Err(ConfigError::InvalidDomainKey {
                key: key.clone(),
                reason: "empty",
            });
        }
        if norm.starts_with('.') || norm.contains('*') {
            return Err(ConfigError::InvalidDomainKey {
                key: key.clone(),
                reason: "must be an exact FQDN (wildcards would redirect every subdomain, e.g. api.github.com)",
            });
        }
        if handlers.insert(norm.clone(), h.handler).is_some() {
            return Err(ConfigError::InvalidDomainKey {
                key: key.clone(),
                reason: "duplicate after normalization",
            });
        }
    }
    Ok(Loaded {
        path: path.to_path_buf(),
        gateway,
        handlers,
    })
}

impl Loaded {
    pub fn handlers(&self) -> &BTreeMap<String, HandlerKind> {
        &self.handlers
    }

    pub fn git_relay_domains(&self) -> Vec<String> {
        self.handlers
            .iter()
            .filter(|(_, k)| **k == HandlerKind::GitRelay)
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// relay を起動すべきか（`git-relay` handler が 1 つ以上）。複数ある場合はエラー（設定不正）。
    pub fn needs_relay(&self) -> Result<bool, ConfigError> {
        let domains = self.git_relay_domains();
        match domains.len() {
            0 => Ok(false),
            1 => {
                if self.gateway.relay.is_none() {
                    return Err(ConfigError::NoRelaySection);
                }
                Ok(true)
            }
            _ => Err(ConfigError::MultipleGitRelayDomains(domains)),
        }
    }

    /// relay の実行に必要な全てを解決する。
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        let domains = self.git_relay_domains();
        let domain = match domains.len() {
            0 => return Err(ConfigError::NoGitRelayDomain),
            1 => domains[0].clone(),
            _ => return Err(ConfigError::MultipleGitRelayDomains(domains)),
        };
        let relay = self
            .gateway
            .relay
            .clone()
            .ok_or(ConfigError::NoRelaySection)?;
        let upstream = relay
            .upstream
            .clone()
            .unwrap_or_else(|| domain.clone())
            .to_ascii_lowercase();
        let (api_base, graphql_base) = derive_api_bases(
            &upstream,
            relay.api_base.clone(),
            relay.graphql_base.clone(),
        )?;

        let mut repos = Vec::new();
        for r in &relay.project.repos {
            let mode = Mode::parse(&r.mode).map_err(ConfigError::Invalid)?;
            let mut rp = RepoPolicy::new(r.name.trim(), mode);
            rp.bases = r.bases.clone();
            if let Some(p) = &r.push {
                rp.push = p.clone();
            }
            repos.push(rp);
        }
        let project = Project::try_new(
            relay.project.name.clone(),
            repos,
            &relay.project.permissions,
        )
        .map_err(ConfigError::Invalid)?;
        if project.name.trim().is_empty() {
            return Err(ConfigError::Invalid("project.name is required".into()));
        }

        let proxy = resolve_proxy(&self.gateway.proxy)?;
        let paths = Paths::under(&relay.state_dir);
        Ok(Resolved {
            domain,
            upstream,
            api_base,
            graphql_base,
            paths,
            proxy,
            project,
            relay,
        })
    }
}

fn derive_api_bases(
    upstream: &str,
    api: Option<Url>,
    graphql: Option<Url>,
) -> Result<(Url, Url), ConfigError> {
    let (da, dg) = if upstream == "github.com" {
        (
            "https://api.github.com".to_string(),
            "https://api.github.com/graphql".to_string(),
        )
    } else {
        (
            format!("https://{upstream}/api/v3"),
            format!("https://{upstream}/api/graphql"),
        )
    };
    let api = match api {
        Some(u) => u,
        None => Url::parse(&da).map_err(|e| ConfigError::Invalid(format!("api_base: {e}")))?,
    };
    let graphql = match graphql {
        Some(u) => u,
        None => Url::parse(&dg).map_err(|e| ConfigError::Invalid(format!("graphql_base: {e}")))?,
    };
    Ok((api, graphql))
}

/// 上位プロキシ。`config.yml` の `proxy.upstream_proxy`（host:port）と資格情報（環境変数で上書き可）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySpec {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

fn resolve_proxy(p: &ProxyConfig) -> Result<Option<ProxySpec>, ConfigError> {
    if !p.enabled {
        return Ok(None);
    }
    let Some(hp) = p
        .upstream_proxy
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let url = if hp.contains("://") {
        hp.to_string()
    } else if p.upstream_proxy_tls {
        format!("https://{hp}")
    } else {
        format!("http://{hp}")
    };
    Url::parse(&url).map_err(|e| ConfigError::Invalid(format!("proxy.upstream_proxy: {e}")))?;
    let username = std::env::var("SEKIMORE_UPSTREAM_PROXY_USERNAME")
        .ok()
        .or_else(|| p.upstream_proxy_username.clone());
    let password = std::env::var("SEKIMORE_UPSTREAM_PROXY_PASSWORD")
        .ok()
        .or_else(|| p.upstream_proxy_password.clone());
    Ok(Some(ProxySpec {
        url,
        username,
        password,
    }))
}

/// `state_dir` 配下のファイル配置。
#[derive(Debug, Clone)]
pub struct Paths {
    pub state_dir: PathBuf,
    pub host_key: PathBuf,
    pub authorized_keys: PathBuf,
    pub known_hosts: PathBuf,
    pub tokens: PathBuf,
    pub upstream_token: PathBuf,
    pub audit: PathBuf,
    pub bootstrap_disabled: PathBuf,
}

impl Paths {
    pub fn under(dir: &Path) -> Self {
        Paths {
            state_dir: dir.to_path_buf(),
            host_key: dir.join("host_key"),
            authorized_keys: dir.join("authorized_keys"),
            known_hosts: dir.join("known_hosts"),
            tokens: dir.join("tokens.json"),
            upstream_token: dir.join("upstream_token"),
            audit: dir.join("audit.jsonl"),
            bootstrap_disabled: dir.join("bootstrap.disabled"),
        }
    }
}

/// relay の実行に必要な解決済み設定。
#[derive(Debug, Clone)]
pub struct Resolved {
    /// DNS で関所に向けられるドメイン
    pub domain: String,
    /// 上流 git / API のホスト
    pub upstream: String,
    pub api_base: Url,
    pub graphql_base: Url,
    pub paths: Paths,
    pub proxy: Option<ProxySpec>,
    pub project: Project,
    pub relay: RelayConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH: &str = include_str!("../../tests/fixtures/config_with_relay.yml");
    const WITHOUT: &str = include_str!("../../tests/fixtures/config_without_relay.yml");
    const SAMPLE: &str = include_str!("../../config/config.sample.yml");

    fn p(text: &str) -> Result<Loaded, ConfigError> {
        parse(Path::new("test.yml"), text)
    }

    #[test]
    fn existing_configs_need_no_relay() {
        assert!(!p(WITHOUT).unwrap().needs_relay().unwrap());
        assert!(!p(SAMPLE).unwrap().needs_relay().unwrap());
        assert!(!p("").unwrap().needs_relay().unwrap());
        assert!(p(WITHOUT).unwrap().resolve().is_err());
    }

    #[test]
    fn fixture_with_relay_resolves() {
        let l = p(WITH).unwrap();
        assert!(l.needs_relay().unwrap());
        assert_eq!(l.git_relay_domains(), vec!["github.com".to_string()]);
        assert_eq!(l.handlers()["telemetry.example.com"], HandlerKind::Deny);
        assert_eq!(l.handlers()["static.example.com"], HandlerKind::Splice);
        let r = l.resolve().unwrap();
        assert_eq!(r.upstream, "github.com");
        assert_eq!(r.api_base.as_str(), "https://api.github.com/");
        assert_eq!(r.graphql_base.as_str(), "https://api.github.com/graphql");
        assert_eq!(r.relay.ssh_listen.port(), 22);
        assert_eq!(r.relay.api_listen.port(), 8420);
        assert_eq!(r.relay.https, HttpsMode::Passthrough);
        assert_eq!(r.relay.bootstrap, BootstrapMode::Auto);
        assert_eq!(r.relay.token_ttl, Duration::from_secs(12 * 3600));
        assert_eq!(r.project.name, "case-a");
        assert_eq!(r.project.repos.len(), 2);
        assert_eq!(
            r.project.granted(),
            vec!["issue:create", "pr:create", "project:read"]
        );
        assert_eq!(r.paths.tokens, PathBuf::from("/data/relay/tokens.json"));
        assert!(r.proxy.is_none());
    }

    #[test]
    fn ghes_upstream_derives_api_bases() {
        let text = "domain_handlers:\n  ghe.example.co.jp: { handler: git-relay }\nrelay:\n  project: { name: x }\n";
        let r = p(text).unwrap().resolve().unwrap();
        assert_eq!(r.upstream, "ghe.example.co.jp");
        assert_eq!(r.api_base.as_str(), "https://ghe.example.co.jp/api/v3");
        assert_eq!(
            r.graphql_base.as_str(),
            "https://ghe.example.co.jp/api/graphql"
        );
    }

    #[test]
    fn two_git_relay_domains_is_an_error_with_explanation() {
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\n  ghe.example.com: { handler: git-relay }\nrelay:\n  project: { name: x }\n";
        let err = p(text).unwrap().needs_relay().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2 git-relay entries"), "{msg}");
        assert!(msg.contains("only one is supported"), "{msg}");
    }

    #[test]
    fn git_relay_without_relay_section_is_an_error() {
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\n";
        assert!(matches!(
            p(text).unwrap().needs_relay(),
            Err(ConfigError::NoRelaySection)
        ));
    }

    #[test]
    fn domain_keys_are_normalized_and_wildcards_rejected() {
        let l = p("domain_handlers:\n  GitHub.COM.: { handler: git-relay }\nrelay:\n  project: { name: x }\n").unwrap();
        assert_eq!(l.git_relay_domains(), vec!["github.com".to_string()]);
        assert!(matches!(
            p("domain_handlers:\n  .github.com: { handler: git-relay }\n"),
            Err(ConfigError::InvalidDomainKey { .. })
        ));
        assert!(matches!(
            p("domain_handlers:\n  '': { handler: deny }\n"),
            Err(ConfigError::InvalidDomainKey { .. })
        ));
    }

    #[test]
    fn unknown_handler_kind_is_ignored_but_relay_typo_is_rejected() {
        let l = p("domain_handlers:\n  x.example.com: { handler: future-kind }\n").unwrap();
        assert_eq!(l.handlers()["x.example.com"], HandlerKind::Other);
        assert!(!l.needs_relay().unwrap());

        let typo = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  tokn_ttl: 1h\n  project: { name: x }\n";
        let err = p(typo).unwrap_err();
        assert!(err.to_string().contains("tokn_ttl"), "{err}");
    }

    #[test]
    fn python_owned_keys_are_ignored() {
        let text = "allow_domains: [a.example.com]\nsomething_new: {a: 1}\nproxy: {enabled: true, port: 3128, cache_size_mb: 10}\n";
        assert!(!p(text).unwrap().needs_relay().unwrap());
    }

    #[test]
    fn invalid_permission_or_mode_is_rejected() {
        let bad_perm = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project:\n    name: x\n    permissions: [pr:delete]\n";
        assert!(matches!(
            p(bad_perm).unwrap().resolve(),
            Err(ConfigError::Invalid(_))
        ));
        let bad_mode = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project:\n    name: x\n    repos: [{ name: A/b, mode: rw }]\n";
        assert!(matches!(
            p(bad_mode).unwrap().resolve(),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn proxy_placeholder_is_ignored_unless_enabled() {
        // 実機の config.yml には enabled: false のまま upstream_proxy のプレースホルダが残っている
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\nproxy:\n  enabled: false\n  upstream_proxy: proxy.example.com:3129\nrelay:\n  project: { name: x }\n";
        assert!(p(text).unwrap().resolve().unwrap().proxy.is_none());
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\nproxy:\n  upstream_proxy: proxy.example.com:3129\nrelay:\n  project: { name: x }\n";
        assert!(p(text).unwrap().resolve().unwrap().proxy.is_none());
    }

    #[test]
    fn proxy_is_resolved_from_python_section() {
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\nproxy:\n  enabled: true\n  upstream_proxy: proxy.corp:3128\n  upstream_proxy_username: u\nrelay:\n  project: { name: x }\n";
        let r = p(text).unwrap().resolve().unwrap();
        let px = r.proxy.unwrap();
        assert_eq!(px.url, "http://proxy.corp:3128");
        assert_eq!(px.username.as_deref(), Some("u"));
    }
}
