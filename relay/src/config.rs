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

use crate::policy::{Mode, Project, RepoPolicy, DEFAULT_PUSH_GLOBS};

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
    /// 0.2.0: この上流を受ける関所側 SSH ポート。省略時は `relay.ssh_listen` のポート（既定上流用）。
    /// 2 つ目以降の git-relay ドメインは別ポートが必須（SSH の exec にホスト名が無いのでポートで区別する）
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// 0.2.0: 上流ホスト。省略時はドメイン名（GHES の API は `https://<upstream>/api/v3` に派生）
    #[serde(default)]
    pub upstream: Option<String>,
    /// 0.2.0: 上流の SSH ポート。省略時は `relay.upstream_ssh_port`
    #[serde(default)]
    pub upstream_ssh_port: Option<u16>,
    /// 0.2.0: device flow の OAuth client id。省略時は `relay.oauth_client_id`（GHES では別 app になる）
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    /// 0.2.0: 既定上流にする（`Org/Repo` と書いた repo はこの上流）。省略時は `ssh_port` を省いたもの、無ければ辞書順の先頭
    #[serde(default)]
    pub default: bool,
    /// 0.2.1: 上流 ssh に `-o` で渡すオプション（`ProxyJump=bastion` など）。この上流だけに効く。
    /// 関所が強制する BatchMode / StrictHostKeyChecking / UserKnownHostsFile 等は上書きできない
    #[serde(default)]
    pub ssh_options: Vec<String>,
    /// 0.2.1: この上流の REST / GraphQL の base URL（省略時は `upstream` から派生。既定上流は `relay.api_base` も見る）
    #[serde(default)]
    pub api_base: Option<Url>,
    #[serde(default)]
    pub graphql_base: Option<Url>,
}

fn default_handler() -> HandlerKind {
    HandlerKind::Splice
}

impl Default for DomainHandler {
    fn default() -> Self {
        DomainHandler {
            handler: default_handler(),
            ssh_port: None,
            upstream: None,
            upstream_ssh_port: None,
            oauth_client_id: None,
            default: false,
            ssh_options: Vec::new(),
            api_base: None,
            graphql_base: None,
        }
    }
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

/// API 権限の書き方。`[pr:create, …]`（allow だけ）か `{allow: […], deny: […]}`。
/// repo 側に書けば案件既定への差分になり、**deny はどの階層に書いても勝つ**（GitHub の rulesets が
/// write 権限より優先して制限をかけるのと同じ向き）。
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PermissionSpec {
    List(Vec<String>),
    Rules {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    },
}

impl PermissionSpec {
    pub fn allow(&self) -> &[String] {
        match self {
            PermissionSpec::List(v) => v,
            PermissionSpec::Rules { allow, .. } => allow,
        }
    }
    pub fn deny(&self) -> &[String] {
        match self {
            PermissionSpec::List(_) => &[],
            PermissionSpec::Rules { deny, .. } => deny,
        }
    }
}

impl Default for PermissionSpec {
    fn default() -> Self {
        PermissionSpec::List(Vec::new())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub bases: Vec<String>,
    /// 直接 push を許すブランチ glob。省略時は案件の `push`（既定 `sekimore/*`）
    pub push: Option<Vec<String>>,
    /// push を許すタグの glob（`refs/tags/` を除いた名前）。省略時は案件の `tags`。`[]` は拒否
    pub tags: Option<Vec<String>>,
    /// ブランチ / タグの削除を許すか。省略時は案件の `delete`
    pub delete: Option<bool>,
    /// 案件既定への差分（allow を足す / deny で消す）。list なら allow の追加
    pub permissions: Option<PermissionSpec>,
}

/// 0.2.1: `project.upstreams.<domain>`。その上流の repo に共通の既定と差分。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPolicyConfig {
    /// 案件既定への差分（allow を足す / deny で消す）。list なら allow の追加。repo の差分より先に適用される
    pub permissions: Option<PermissionSpec>,
    /// この上流の repo の既定（省略時は案件既定）
    pub push: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub delete: Option<bool>,
    /// この上流の repo。`Org/Repo` で書く（host 付きは不要。書いた場合はこの上流と一致しなければエラー）
    #[serde(default)]
    pub repos: Vec<RepoConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default)]
    pub repos: Vec<RepoConfig>,
    /// 0.2.1: 上流（git-relay ドメイン）ごとの層。案件既定と repo の間に入り、
    /// `permissions` は加算 / deny、`push` / `tags` / `delete` はその上流の repo の既定、`repos` はその上流の repo
    #[serde(default)]
    pub upstreams: BTreeMap<String, UpstreamPolicyConfig>,
    /// 案件の既定権限。`[…]` か `{allow, deny}`
    #[serde(default)]
    pub permissions: PermissionSpec,
    /// 直接 push を許すブランチ glob の既定（省略時 `sekimore/*`）
    pub push: Option<Vec<String>>,
    /// push を許すタグ glob の既定（省略時 = 拒否）
    #[serde(default)]
    pub tags: Vec<String>,
    /// ブランチ / タグ削除の既定（省略時 false）
    #[serde(default)]
    pub delete: bool,
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
    /// 0.2.1: 全上流の ssh に `-o` で渡すオプション。handler の `ssh_options` の前に並ぶ
    #[serde(default)]
    pub ssh_options: Vec<String>,
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
    /// 非推奨（0.1.9〜）: `project.delete` に移した。残っていれば既定値として読み、警告を出す
    #[serde(default)]
    pub allow_delete: bool,
    /// 非推奨（0.1.9〜）: `project.tags`（glob）に移した。true は `project.tags: ["*"]` と同じ
    #[serde(default)]
    pub allow_tags: bool,
    #[serde(default = "d_bootstrap")]
    pub bootstrap: BootstrapMode,
    #[serde(default)]
    pub limits: Limits,
    pub project: ProjectConfig,
    /// テスト専用: 上流 ssh の代わりに実行するコマンド（`["git", "receive-pack", "<bare-dir>"]` の親ディレクトリ）
    #[cfg(feature = "test-hooks")]
    pub upstream_local_root: Option<PathBuf>,
    /// テスト専用（0.2.0）: 上流ドメインごとの local root。無いドメインは `upstream_local_root`
    #[cfg(feature = "test-hooks")]
    #[serde(default)]
    pub upstream_local_roots: BTreeMap<String, PathBuf>,
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
    /// 同じキーで handler の全項目（0.2.0: ssh_port / upstream など）
    handler_specs: BTreeMap<String, DomainHandler>,
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
    let mut handler_specs = BTreeMap::new();
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
        handler_specs.insert(norm, h.clone());
    }
    Ok(Loaded {
        path: path.to_path_buf(),
        gateway,
        handlers,
        handler_specs,
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

    /// relay を起動すべきか（`git-relay` handler が 1 つ以上）。
    /// 0.2.0: 複数の git-relay ドメインはポートで分ける。ポート重複などは設定不正（Err）。
    pub fn needs_relay(&self) -> Result<bool, ConfigError> {
        if self.git_relay_domains().is_empty() {
            return Ok(false);
        }
        let relay = self
            .gateway
            .relay
            .as_ref()
            .ok_or(ConfigError::NoRelaySection)?;
        self.resolve_upstreams(relay)?;
        Ok(true)
    }

    /// git-relay ドメインごとの上流を組み立てる（0.2.0）。
    ///
    /// - 既定上流: `default: true` の handler → 無ければ `ssh_port` を省いたもの → 無ければ辞書順の先頭
    /// - 既定上流は `relay.ssh_listen` で listen し、`relay.upstream` / `api_base` / `graphql_base` /
    ///   `paths.upstream_token` / `paths.known_hosts` を使う（0.1.x と同じ）
    /// - それ以外は `ssh_port` 必須（`relay.ssh_listen` と同じ IP で listen）。state は `upstreams/<host>/`
    fn resolve_upstreams(&self, relay: &RelayConfig) -> Result<Vec<Upstream>, ConfigError> {
        let domains = self.git_relay_domains();
        if domains.is_empty() {
            return Err(ConfigError::NoGitRelayDomain);
        }
        let spec = |d: &str| self.handler_specs.get(d).cloned().unwrap_or_default();
        let explicit_default: Vec<&String> = domains.iter().filter(|d| spec(d).default).collect();
        if explicit_default.len() > 1 {
            return Err(ConfigError::Invalid(format!(
                "domain_handlers: more than one git-relay entry has default: true ({})",
                explicit_default
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let no_port: Vec<&String> = domains
            .iter()
            .filter(|d| spec(d).ssh_port.is_none())
            .collect();
        let default_domain = match explicit_default.first() {
            Some(d) => (*d).clone(),
            None => match no_port.as_slice() {
                [] => domains[0].clone(),
                [one] => (*one).clone(),
                many => {
                    return Err(ConfigError::Invalid(format!(
                        "domain_handlers has {} git-relay entries without ssh_port ({}); every git-relay domain but the default one needs its own ssh_port because the SSH exec request carries only the repository path, not the hostname",
                        many.len(),
                        many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )))
                }
            },
        };
        let base_dir = relay.state_dir.join("upstreams");
        let mut out = Vec::new();
        for d in &domains {
            let h = spec(d);
            let is_default = *d == default_domain;
            let host = h
                .upstream
                .clone()
                .or_else(|| {
                    if is_default {
                        relay.upstream.clone()
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| d.clone())
                .trim()
                .to_ascii_lowercase();
            if host.is_empty() || host.contains('/') || host.contains(':') {
                return Err(ConfigError::Invalid(format!(
                    "domain_handlers.{d}.upstream {host:?} must be a bare hostname"
                )));
            }
            let listen = match h.ssh_port {
                Some(port) => SocketAddr::new(relay.ssh_listen.ip(), port),
                None => relay.ssh_listen,
            };
            // 0.2.1: handler の api_base / graphql_base が最優先。既定上流は relay.api_base / graphql_base も見る
            let (api_over, gql_over) = if is_default {
                (
                    h.api_base.clone().or_else(|| relay.api_base.clone()),
                    h.graphql_base
                        .clone()
                        .or_else(|| relay.graphql_base.clone()),
                )
            } else {
                (h.api_base.clone(), h.graphql_base.clone())
            };
            let (api_base, graphql_base) = derive_api_bases(&host, api_over, gql_over)?;
            // 0.2.1: ssh_options の検証（Key=Value、関所が強制するものは上書き不可）
            let mut ssh_options: Vec<String> = Vec::new();
            for opt in relay.ssh_options.iter().chain(h.ssh_options.iter()) {
                let opt = opt.trim();
                validate_ssh_option(opt).map_err(|why| {
                    ConfigError::Invalid(format!("ssh_options for {d}: {opt:?} {why}"))
                })?;
                ssh_options.push(opt.to_string());
            }
            let (upstream_token, known_hosts) = if is_default {
                let p = Paths::under(&relay.state_dir);
                (p.upstream_token, p.known_hosts)
            } else {
                let dir = base_dir.join(&host);
                (dir.join("upstream_token"), dir.join("known_hosts"))
            };
            out.push(Upstream {
                domain: d.clone(),
                host,
                listen,
                upstream_ssh_port: h.upstream_ssh_port.unwrap_or(relay.upstream_ssh_port),
                api_base,
                graphql_base,
                oauth_client_id: h
                    .oauth_client_id
                    .clone()
                    .unwrap_or_else(|| relay.oauth_client_id.clone()),
                upstream_token,
                known_hosts,
                ssh_options,
                is_default,
            });
        }
        // 既定上流を先頭に
        out.sort_by_key(|u| !u.is_default);
        for (i, a) in out.iter().enumerate() {
            for b in &out[i + 1..] {
                if a.listen.port() == b.listen.port() {
                    return Err(ConfigError::Invalid(format!(
                        "git-relay domains {} and {} would both listen on ssh port {}; give one of them a different ssh_port",
                        a.domain,
                        b.domain,
                        a.listen.port()
                    )));
                }
                if a.host == b.host {
                    return Err(ConfigError::Invalid(format!(
                        "git-relay domains {} and {} both point at upstream {}; each domain needs its own upstream",
                        a.domain, b.domain, a.host
                    )));
                }
            }
        }
        Ok(out)
    }

    /// relay の実行に必要な全てを解決する。
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        if self.git_relay_domains().is_empty() {
            return Err(ConfigError::NoGitRelayDomain);
        }
        let relay = self
            .gateway
            .relay
            .clone()
            .ok_or(ConfigError::NoRelaySection)?;
        let upstreams = self.resolve_upstreams(&relay)?;
        let default_up = upstreams[0].clone();
        let domain = default_up.domain.clone();
        let upstream = default_up.host.clone();
        let api_base = default_up.api_base.clone();
        let graphql_base = default_up.graphql_base.clone();

        // 案件の既定（旧 relay.allow_tags / allow_delete は既定へ畳み込む。0.1.9 で project 配下に移した）
        let pc = &relay.project;
        let default_push: Vec<String> = pc
            .push
            .clone()
            .unwrap_or_else(|| DEFAULT_PUSH_GLOBS.iter().map(|s| s.to_string()).collect());
        let mut default_tags = pc.tags.clone();
        if relay.allow_tags && default_tags.is_empty() {
            eprintln!("[relay] WARNING: relay.allow_tags is deprecated; write `tags: [\"*\"]` under relay.project (or per repo)");
            default_tags = vec!["*".to_string()];
        }
        let default_delete = pc.delete || relay.allow_delete;
        if relay.allow_delete {
            eprintln!("[relay] WARNING: relay.allow_delete is deprecated; write `delete: true` under relay.project (or per repo)");
        }
        // 0.2.1: 上流層。キーは git-relay ドメイン（上流ホスト名でも可）
        let known = || {
            upstreams
                .iter()
                .map(|u| u.domain.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let resolve_host = |name: &str| -> Result<String, ConfigError> {
            let h = name.trim().trim_end_matches('.').to_ascii_lowercase();
            upstreams
                .iter()
                .find(|u| u.domain == h || u.host == h)
                .map(|u| u.domain.clone())
                .ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "{name:?} is not a git-relay domain (known: {})",
                        known()
                    ))
                })
        };
        let mut layers: BTreeMap<String, &UpstreamPolicyConfig> = BTreeMap::new();
        for (key, up) in &pc.upstreams {
            let d = resolve_host(key)
                .map_err(|e| ConfigError::Invalid(format!("project.upstreams: {e}")))?;
            if layers.insert(d.clone(), up).is_some() {
                return Err(ConfigError::Invalid(format!(
                    "project.upstreams: {d} is listed more than once"
                )));
            }
        }
        // (repo 設定, 属する上流ドメイン, 上流層) を集める: project.repos（host prefix）と upstreams.<d>.repos
        let mut entries: Vec<(&RepoConfig, String)> = Vec::new();
        for r in &pc.repos {
            // 0.2.0: `host/Org/Repo` で上流を明示できる。`Org/Repo` は既定上流
            let (host, _) = split_repo_host(r.name.trim());
            let d = match host {
                Some(h) => resolve_host(h)
                    .map_err(|e| ConfigError::Invalid(format!("repo {:?}: {e}", r.name)))?,
                None => domain.clone(),
            };
            entries.push((r, d));
        }
        for (d, up) in &layers {
            for r in &up.repos {
                if let (Some(h), _) = split_repo_host(r.name.trim()) {
                    let hd = resolve_host(h)
                        .map_err(|e| ConfigError::Invalid(format!("repo {:?}: {e}", r.name)))?;
                    if &hd != d {
                        return Err(ConfigError::Invalid(format!(
                            "project.upstreams.{d}.repos: {:?} names another upstream ({hd})",
                            r.name
                        )));
                    }
                }
                entries.push((r, d.clone()));
            }
        }
        let mut repos = Vec::new();
        for (r, host) in entries {
            let mode = Mode::parse(&r.mode).map_err(ConfigError::Invalid)?;
            let (_, full_name) = split_repo_host(r.name.trim());
            let layer = layers.get(&host).copied();
            let l_push = layer.and_then(|l| l.push.clone());
            let l_tags = layer.and_then(|l| l.tags.clone());
            let l_delete = layer.and_then(|l| l.delete);
            let mut rp = RepoPolicy::new(full_name, mode);
            rp.host = host;
            rp.bases = r.bases.clone();
            rp.push = r
                .push
                .clone()
                .or(l_push)
                .unwrap_or_else(|| default_push.clone());
            rp.tags = r
                .tags
                .clone()
                .or(l_tags)
                .unwrap_or_else(|| default_tags.clone());
            rp.delete = r.delete.or(l_delete).unwrap_or(default_delete);
            // 権限: 上流層の差分 → repo の差分（どちらも allow は加算、deny は勝つ）
            if let Some(p) = layer.and_then(|l| l.permissions.as_ref()) {
                rp.allow.extend(p.allow().iter().cloned());
                rp.deny.extend(p.deny().iter().cloned());
            }
            if let Some(p) = &r.permissions {
                rp.allow.extend(p.allow().iter().cloned());
                rp.deny.extend(p.deny().iter().cloned());
            }
            rp.allow.sort();
            rp.allow.dedup();
            rp.deny.sort();
            rp.deny.dedup();
            repos.push(rp);
        }
        let mut project = Project::try_new_rules(
            pc.name.clone(),
            repos,
            pc.permissions.allow(),
            pc.permissions.deny(),
        )
        .map_err(ConfigError::Invalid)?;
        project.set_default_host(&domain);
        if project.name.trim().is_empty() {
            return Err(ConfigError::Invalid("project.name is required".into()));
        }
        // 同名の Org/Repo が複数の上流にあるときは、`Org/Repo` だけの API 指定が既定上流に解ける旨を知らせる
        for (i, a) in project.repos.iter().enumerate() {
            if project.repos[i + 1..]
                .iter()
                .any(|b| b.full_name.eq_ignore_ascii_case(&a.full_name))
            {
                eprintln!(
                    "[relay] NOTE: {} exists on more than one upstream; API calls must name the host ({}/{}) unless they mean the default upstream {}",
                    a.full_name, a.host, a.full_name, domain
                );
            }
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
            upstreams,
        })
    }
}

/// 関所が上流 ssh に強制するオプション。`ssh_options` で上書きさせない（先に並べるので実際にも勝つが、設定時に弾く）。
pub const ENFORCED_SSH_OPTIONS: &[&str] = &[
    "batchmode",
    "stricthostkeychecking",
    "userknownhostsfile",
    "globalknownhostsfile",
    "updatehostkeys",
];

/// `Key=Value` 形式で、改行を含まず、強制オプションでないこと。
pub fn validate_ssh_option(opt: &str) -> Result<(), String> {
    let (key, value) = opt
        .split_once('=')
        .ok_or_else(|| "must be Key=Value (e.g. ProxyJump=bastion.example.com)".to_string())?;
    let key = key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("has an invalid option name".into());
    }
    if value.trim().is_empty() {
        return Err("has an empty value".into());
    }
    if opt.contains(['\n', '\r', '\0']) {
        return Err("must be a single line".into());
    }
    if ENFORCED_SSH_OPTIONS.contains(&key.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "cannot override {key}; the relay enforces it (BatchMode / StrictHostKeyChecking / known_hosts files)"
        ));
    }
    Ok(())
}

/// `host/Org/Repo` → (Some(host), "Org/Repo")、`Org/Repo` → (None, "Org/Repo")。
/// 先頭要素に `.` が含まれる 3 要素のときだけ host と見なす（GitHub の org 名に `.` は使えない）。
pub fn split_repo_host(name: &str) -> (Option<&str>, &str) {
    let trimmed = name.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() == 3 && parts[0].contains('.') {
        let rest = &trimmed[parts[0].len() + 1..];
        (Some(parts[0]), rest)
    } else {
        (None, trimmed)
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

/// 1 つの上流（git-relay ドメイン）。0.2.0 で複数持てるようになった。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// DNS で関所に向けられるドメイン（agent が URL に書く名前。repo の host 表記もこれ）
    pub domain: String,
    /// 上流 git / API のホスト
    pub host: String,
    /// 関所がこの上流向けの SSH を受けるアドレス
    pub listen: SocketAddr,
    pub upstream_ssh_port: u16,
    pub api_base: Url,
    pub graphql_base: Url,
    pub oauth_client_id: String,
    pub upstream_token: PathBuf,
    pub known_hosts: PathBuf,
    /// 0.2.1: 上流 ssh に足す `-o` オプション（relay.ssh_options + handler.ssh_options）
    pub ssh_options: Vec<String>,
    pub is_default: bool,
}

/// relay の実行に必要な解決済み設定。
///
/// `domain` / `upstream` / `api_base` / `graphql_base` / `paths` は **既定上流** のもの（0.1.x 互換）。
/// 全上流は `upstreams`（先頭が既定）。
#[derive(Debug, Clone)]
pub struct Resolved {
    /// DNS で関所に向けられるドメイン（既定上流）
    pub domain: String,
    /// 上流 git / API のホスト（既定上流）
    pub upstream: String,
    pub api_base: Url,
    pub graphql_base: Url,
    pub paths: Paths,
    pub proxy: Option<ProxySpec>,
    pub project: Project,
    pub relay: RelayConfig,
    /// 0.2.0: 全上流。先頭が既定上流
    pub upstreams: Vec<Upstream>,
}

impl Resolved {
    pub fn default_upstream(&self) -> &Upstream {
        &self.upstreams[0]
    }
    /// ドメイン名または上流ホスト名で探す。
    pub fn upstream_named(&self, name: &str) -> Option<&Upstream> {
        let want = name.trim().trim_end_matches('.').to_ascii_lowercase();
        self.upstreams
            .iter()
            .find(|u| u.domain == want || u.host == want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Resource};

    const WITH: &str = include_str!("../../tests/fixtures/config_with_relay.yml");
    const WITHOUT: &str = include_str!("../../tests/fixtures/config_without_relay.yml");
    const SAMPLE: &str = include_str!("../../config/config.sample.yml");

    fn p(text: &str) -> Result<Loaded, ConfigError> {
        parse(Path::new("test.yml"), text)
    }

    #[test]
    fn per_repo_permissions_tags_delete_and_legacy_allow_tags() {
        let text = r#"
domain_handlers:
  github.com: { handler: git-relay }
relay:
  allow_tags: true
  project:
    name: case-a
    permissions: { allow: [pr:create, ci:read], deny: [issue:label] }
    repos:
      - { name: Org/App, mode: read-write, bases: [main], tags: ["v*"] }
      - { name: Org/Lib, mode: read-only, permissions: { allow: [pr:merge], deny: [ci:read] }, delete: true }
      - { name: Org/Old, mode: read-only, permissions: [pr:read] }
"#;
        let r = p(text).unwrap().resolve().unwrap();
        assert_eq!(r.project.granted(), vec!["ci:read", "pr:create"]);
        assert_eq!(r.project.denied(), vec!["issue:label"]);
        let app = r.project.find_repo("Org/App").unwrap();
        assert_eq!(app.tags, vec!["v*"]);
        assert!(!app.delete);
        let lib = r.project.find_repo("Org/Lib").unwrap();
        // 旧 relay.allow_tags: true は project.tags が空なら ["*"] として既定に畳み込まれる
        assert_eq!(lib.tags, vec!["*"]);
        assert!(lib.delete);
        assert_eq!(r.project.effective_keys(lib), vec!["pr:create", "pr:merge"]);
        let old = r.project.find_repo("Org/Old").unwrap();
        assert_eq!(
            r.project.effective_keys(old),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        // 既定の push glob は sekimore/*
        assert_eq!(old.push, vec!["sekimore/*"]);
        // list 形式の permissions も従来どおり
        let text2 = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project: { name: x, permissions: [pr:create] }\n";
        assert_eq!(
            p(text2).unwrap().resolve().unwrap().project.granted(),
            vec!["pr:create"]
        );
        // repo の permissions の typo は起動時エラー
        let text3 = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project:\n    name: x\n    repos: [{ name: Org/A, mode: read-only, permissions: [pr:delete] }]\n";
        assert!(p(text3).unwrap().resolve().is_err());
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
        // 0.2.0: 単一上流は upstreams が 1 件で、0.1.x のフィールドと同じ値
        assert_eq!(r.upstreams.len(), 1);
        let u = r.default_upstream();
        assert_eq!(
            (u.domain.as_str(), u.host.as_str()),
            ("github.com", "github.com")
        );
        assert_eq!(u.listen, r.relay.ssh_listen);
        assert_eq!(u.upstream_token, r.paths.upstream_token);
        assert_eq!(u.known_hosts, r.paths.known_hosts);
        assert_eq!(u.api_base, r.api_base);
        assert!(r.project.repos.iter().all(|rp| rp.host == "github.com"));
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
    fn two_git_relay_domains_without_ports_is_an_error_with_explanation() {
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\n  ghe.example.com: { handler: git-relay }\nrelay:\n  project: { name: x }\n";
        let err = p(text).unwrap().needs_relay().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("2 git-relay entries without ssh_port"),
            "{msg}"
        );
        assert!(msg.contains("needs its own ssh_port"), "{msg}");
        // 同じポートを明示しても拒否
        let text = "domain_handlers:\n  github.com: { handler: git-relay }\n  ghe.example.com: { handler: git-relay, ssh_port: 22 }\nrelay:\n  project: { name: x }\n";
        let msg = p(text).unwrap().needs_relay().unwrap_err().to_string();
        assert!(msg.contains("both listen on ssh port 22"), "{msg}");
    }

    #[test]
    fn multiple_upstreams_are_split_by_port() {
        let text = r#"
domain_handlers:
  github.com: { handler: git-relay }
  ghe.example.com: { handler: git-relay, ssh_port: 2222, oauth_client_id: abc123 }
relay:
  project:
    name: x
    repos:
      - { name: Org/App, mode: read-write, bases: [main] }
      - { name: ghe.example.com/Corp/Internal, mode: read-write, bases: [main] }
      - { name: Org/App, mode: read-only }   # DUP
"#;
        // 3 つ目は github.com 側の Org/App と重複 → 起動時エラー
        assert!(p(text).unwrap().resolve().is_err());
        let text = text.replace("      - { name: Org/App, mode: read-only }   # DUP\n", "");
        let l = p(&text).unwrap();
        assert!(l.needs_relay().unwrap());
        let r = l.resolve().unwrap();
        // 既定上流は ssh_port を省いた github.com（0.1.x のフィールドはそのまま既定上流を指す）
        assert_eq!(r.domain, "github.com");
        assert_eq!(r.upstream, "github.com");
        assert_eq!(r.api_base.as_str(), "https://api.github.com/");
        assert_eq!(r.upstreams.len(), 2);
        let gh = &r.upstreams[0];
        let ghe = &r.upstreams[1];
        assert!(gh.is_default && !ghe.is_default);
        assert_eq!(gh.listen.port(), 22);
        assert_eq!(
            gh.upstream_token,
            PathBuf::from("/data/relay/upstream_token")
        );
        assert_eq!(gh.known_hosts, PathBuf::from("/data/relay/known_hosts"));
        assert_eq!(ghe.domain, "ghe.example.com");
        assert_eq!(ghe.host, "ghe.example.com");
        assert_eq!(ghe.listen.port(), 2222);
        assert_eq!(ghe.api_base.as_str(), "https://ghe.example.com/api/v3");
        assert_eq!(ghe.oauth_client_id, "abc123");
        assert_eq!(
            ghe.upstream_token,
            PathBuf::from("/data/relay/upstreams/ghe.example.com/upstream_token")
        );
        assert_eq!(
            ghe.known_hosts,
            PathBuf::from("/data/relay/upstreams/ghe.example.com/known_hosts")
        );
        assert_eq!(
            r.upstream_named("GHE.example.com").map(|u| u.listen.port()),
            Some(2222)
        );
        // repo の host
        let app = r.project.find_repo("Org/App").unwrap();
        assert_eq!(app.host, "github.com");
        let internal = r
            .project
            .find_repo("ghe.example.com/Corp/Internal")
            .unwrap();
        assert_eq!(internal.host, "ghe.example.com");
        assert_eq!(internal.full_name, "Corp/Internal");
        // host 無しでも一意なら解ける。SSH 経路（上流固定）では他方の上流から見えない
        assert!(r.project.find_repo("Corp/Internal").is_ok());
        assert!(r
            .project
            .find_repo_on("github.com", "Corp/Internal")
            .is_err());
        assert!(r
            .project
            .find_repo_on("ghe.example.com", "Corp/Internal")
            .is_ok());
        assert!(r
            .project
            .find_repo_on("ghe.example.com", "Org/App")
            .is_err());
        // 知らない host は起動時エラー
        let bad = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project:\n    name: x\n    repos: [{ name: other.example.com/Org/A, mode: read-only }]\n";
        assert!(matches!(
            p(bad).unwrap().resolve(),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn upstream_layer_sets_defaults_and_permission_diffs_per_upstream() {
        let text = r#"
domain_handlers:
  github.com: { handler: git-relay }
  ghe.example.com: { handler: git-relay, ssh_port: 2222 }
relay:
  project:
    name: case-m
    permissions: [pr:read, ci:read]
    upstreams:
      github.com:
        permissions: { allow: [pr:create, pr:merge] }
        tags: ["v*"]
        repos:
          - { name: Org/App, mode: read-write, bases: [main] }
          - { name: Org/Tool, mode: read-write, bases: [main], tags: [], permissions: { deny: [pr:merge] } }
      ghe.example.com:
        permissions: { allow: [pr:create], deny: [pr:merge] }
        delete: true
        repos:
          - { name: Corp/Internal, mode: read-write, bases: [main] }
    repos:
      - { name: ghe.example.com/Corp/Legacy, mode: read-only }
"#;
        let r = p(text).unwrap().resolve().unwrap();
        let pr = &r.project;
        assert_eq!(pr.granted(), vec!["ci:read", "pr:read"]);
        let app = pr.find_repo("github.com/Org/App").unwrap();
        assert_eq!(
            pr.effective_keys(app),
            vec!["ci:read", "pr:create", "pr:merge", "pr:read"]
        );
        assert_eq!(app.tags, vec!["v*"]);
        assert!(!app.delete);
        // repo の deny は上流層の allow に勝つ。tags は repo 上書き
        let tool = pr.find_repo("Org/Tool").unwrap();
        assert_eq!(
            pr.effective_keys(tool),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        assert!(tool.tags.is_empty());
        // GHES 側: マージ不可、delete は上流層の既定
        let internal = pr.find_repo("ghe.example.com/Corp/Internal").unwrap();
        assert_eq!(internal.host, "ghe.example.com");
        assert_eq!(
            pr.effective_keys(internal),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        assert!(internal.delete && internal.tags.is_empty());
        // project.repos の host prefix 表記も上流層の既定を受ける
        let legacy = pr.find_repo("Corp/Legacy").unwrap();
        assert_eq!(legacy.host, "ghe.example.com");
        assert!(legacy.delete);
        assert_eq!(
            pr.effective_keys(legacy),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        // authorize は上流ごとに違う答えになる
        assert!(pr.authorize("Org/App", Resource::Pr, Action::Merge).is_ok());
        assert!(pr
            .authorize("ghe.example.com/Corp/Internal", Resource::Pr, Action::Merge)
            .is_err());
        // 知らない上流のキー / 別上流を指す repo 名は起動時エラー
        let bad = text.replace(
            "      ghe.example.com:\n        permissions",
            "      other.example.com:\n        permissions",
        );
        assert!(p(&bad).unwrap().resolve().is_err());
        let bad2 = text.replace(
            "          - { name: Corp/Internal, mode: read-write, bases: [main] }",
            "          - { name: github.com/Corp/Internal, mode: read-write, bases: [main] }",
        );
        assert!(p(&bad2).unwrap().resolve().is_err());
    }

    #[test]
    fn ssh_options_and_api_base_per_handler() {
        let text = r#"
domain_handlers:
  github.com: { handler: git-relay }
  ghe.example.com:
    handler: git-relay
    ssh_port: 2222
    upstream: host.docker.internal
    upstream_ssh_port: 2200
    api_base: https://ghe.example.com/api/v3
    graphql_base: https://ghe.example.com/api/graphql
    ssh_options: ["ProxyJump=bastion.example.com", " HostKeyAlias=ghe.example.com "]
relay:
  ssh_options: [ConnectionAttempts=2]
  project: { name: x }
"#;
        let r = p(text).unwrap().resolve().unwrap();
        let gh = &r.upstreams[0];
        let ghe = &r.upstreams[1];
        // relay.ssh_options は全上流に、handler のものはその上流だけに（順序: relay → handler）
        assert_eq!(gh.ssh_options, vec!["ConnectionAttempts=2"]);
        assert_eq!(
            ghe.ssh_options,
            vec![
                "ConnectionAttempts=2",
                "ProxyJump=bastion.example.com",
                "HostKeyAlias=ghe.example.com"
            ]
        );
        // api_base は handler の指定が勝つ（upstream から派生しない）
        assert_eq!(ghe.host, "host.docker.internal");
        assert_eq!(ghe.upstream_ssh_port, 2200);
        assert_eq!(ghe.api_base.as_str(), "https://ghe.example.com/api/v3");
        assert_eq!(
            ghe.graphql_base.as_str(),
            "https://ghe.example.com/api/graphql"
        );
        assert_eq!(gh.api_base.as_str(), "https://api.github.com/");
        // 強制オプションの上書き、形式不正は起動時エラー
        for bad in [
            "StrictHostKeyChecking=no",
            "batchmode=no",
            "UserKnownHostsFile=/tmp/x",
            "ProxyJump",
            "=x",
            "Proxy Jump=x",
        ] {
            let t = format!(
                "domain_handlers:\n  github.com: {{ handler: git-relay, ssh_options: [\"{bad}\"] }}\nrelay:\n  project: {{ name: x }}\n"
            );
            let err = p(&t).unwrap().resolve().unwrap_err().to_string();
            assert!(err.contains("ssh_options"), "{bad}: {err}");
        }
        assert!(validate_ssh_option("ProxyCommand=nc -X connect -x proxy:3128 %h %p").is_ok());
    }

    #[test]
    fn default_upstream_can_be_chosen_explicitly() {
        // 全部に ssh_port があるときは default: true が既定上流。relay.upstream は既定上流にだけ効く
        let text = "domain_handlers:\n  a.example.com: { handler: git-relay, ssh_port: 2201 }\n  b.example.com: { handler: git-relay, ssh_port: 2202, default: true, upstream: b-internal.example.com }\nrelay:\n  ssh_listen: 0.0.0.0:22\n  project: { name: x }\n";
        let r = p(text).unwrap().resolve().unwrap();
        assert_eq!(r.domain, "b.example.com");
        assert_eq!(r.upstream, "b-internal.example.com");
        assert_eq!(r.default_upstream().listen.port(), 2202);
        assert_eq!(r.upstreams[1].domain, "a.example.com");
        // default を 2 つは不可
        let text = "domain_handlers:\n  a.example.com: { handler: git-relay, default: true }\n  b.example.com: { handler: git-relay, ssh_port: 2202, default: true }\nrelay:\n  project: { name: x }\n";
        assert!(p(text).unwrap().resolve().is_err());
    }

    #[test]
    fn split_repo_host_only_when_first_segment_is_a_hostname() {
        assert_eq!(split_repo_host("Org/Repo"), (None, "Org/Repo"));
        assert_eq!(split_repo_host("/Org/Repo"), (None, "Org/Repo"));
        assert_eq!(
            split_repo_host("ghe.example.com/Org/Repo"),
            (Some("ghe.example.com"), "Org/Repo")
        );
        // 3 要素でも先頭に `.` が無ければ host ではない（そのまま Org/Repo 検証で落ちる）
        assert_eq!(split_repo_host("a/b/c"), (None, "a/b/c"));
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
