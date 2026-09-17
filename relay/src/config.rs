//! Loading of `/etc/sekimore/config.yml`, the same file the Python side (sekimore-gw) reads.
//!
//! - The top level is lenient - unknown keys, and unknown `handler` values, are ignored - so that
//!   extensions on the Python side keep working
//! - Everything under `relay:` is owned by the relay, so it is strict: an unknown key is a typo and an error
//! - Only one domain may use the `git-relay` handler, because an SSH exec request carries only the
//!   repository path

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::policy::{Mode, Project, RepoPolicy, DEFAULT_PUSH_GLOBS};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/sekimore/config.yml";
/// The GitHub CLI's public client id. The device flow needs no client secret.
pub const DEFAULT_OAUTH_CLIENT_ID: &str = "178c6fc778ccc68e1d6a";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandlerKind {
    Splice,
    /// SSH git plus the forge's API. `github` is the name to write; `git-relay` is the original
    /// spelling from 0.1.0 and stays accepted, because the SSH git half is not GitHub-specific
    /// but the API half is. 0.3.0 will pick the API dialect with a separate key.
    #[serde(alias = "git-relay")]
    Github,
    /// 0.2.2: pass only 443 through the relay's passthrough, for domains that need an upload cap. No SSH or API
    HttpsRelay,
    Deny,
    /// Kinds the Python side may add later; the relay ignores them
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainHandler {
    #[serde(default = "default_handler")]
    pub handler: HandlerKind,
    /// 0.2.0: the relay-side SSH port that serves this upstream. Defaults to the port of `relay.ssh_listen`,
    /// which belongs to the default upstream. Every git-relay domain after the first needs its own port,
    /// because an SSH exec request has no hostname and the port is the only thing that distinguishes them
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// 0.2.0: the upstream host, defaulting to the domain name. For GHES the API is derived as `https://<upstream>/api/v3`
    #[serde(default)]
    pub upstream: Option<String>,
    /// 0.2.0: the upstream's SSH port. Defaults to `relay.upstream_ssh_port`
    #[serde(default)]
    pub upstream_ssh_port: Option<u16>,
    /// 0.2.0: the OAuth client id for the device flow. Defaults to `relay.oauth_client_id`; GHES uses a different app
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    /// 0.2.0: make this the default upstream, the one a repo written as a bare `Org/Repo` belongs to. If unset,
    /// the entry without an `ssh_port` wins, and failing that the first in lexicographic order
    #[serde(default)]
    pub default: bool,
    /// 0.2.1: options passed to the upstream ssh with `-o`, such as `ProxyJump=bastion`. They apply to this
    /// upstream only, and cannot override what the relay enforces (BatchMode, StrictHostKeyChecking,
    /// UserKnownHostsFile and so on)
    #[serde(default)]
    pub ssh_options: Vec<String>,
    /// 0.2.1: this upstream's REST / GraphQL base URLs. Derived from `upstream` when unset; the default upstream also honours `relay.api_base`
    #[serde(default)]
    pub api_base: Option<Url>,
    #[serde(default)]
    pub graphql_base: Option<Url>,
    /// 0.2.2: the per-connection byte cap on what dev may send upstream through the 443 passthrough
    /// (git-relay and https-relay alike). Defaults to `relay.https_max_upload_bytes`; `-1` means unlimited
    /// and `0` is a configuration error
    #[serde(default)]
    pub max_upload_bytes: Option<i64>,
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
            max_upload_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyConfig {
    /// Whether Squid is enabled. The Python side only uses `upstream_proxy` when `enabled` is true, and the
    /// relay matches that (the sample config leaves an `upstream_proxy: proxy.example.com:…` placeholder in
    /// place with `enabled: false`)
    #[serde(default)]
    pub enabled: bool,
    pub upstream_proxy: Option<String>,
    #[serde(default)]
    pub upstream_proxy_tls: bool,
    pub upstream_proxy_username: Option<String>,
    pub upstream_proxy_password: Option<String>,
}

/// The top level. Keys owned by Python are skipped.
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

/// How API permissions are written: either `[pr:create, …]`, which is allow-only, or `{allow: […], deny: […]}`.
/// Written on a repo it becomes a delta on the project defaults, and **a deny wins at whatever layer it is
/// written** - the same direction as GitHub rulesets, which restrict even where write permission is granted.
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
    /// Branch globs that direct pushes are allowed to. Defaults to the project's `push`, itself `sekimore/*`
    pub push: Option<Vec<String>>,
    /// Tag globs that pushes are allowed to, matched against the name with `refs/tags/` stripped. Defaults to the project's `tags`; `[]` denies everything
    pub tags: Option<Vec<String>>,
    /// Whether deleting branches and tags is allowed. Defaults to the project's `delete`
    pub delete: Option<bool>,
    /// 0.2.9: delete the head branch after a merge through `pr merge`. Defaults to the project's
    /// `delete_merged_branch`. Unrelated to `delete` above, which is about git-level ref deletion
    pub delete_merged_branch: Option<bool>,
    /// Delta on the project defaults: allow adds, deny removes. A plain list means additional allows
    pub permissions: Option<PermissionSpec>,
}

/// 0.2.1: `project.upstreams.<domain>` - defaults and deltas shared by every repo on that upstream.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPolicyConfig {
    /// Delta on the project defaults: allow adds, deny removes. A plain list means additional allows. Applied before the repo's own delta
    pub permissions: Option<PermissionSpec>,
    /// Defaults for repos on this upstream, falling back to the project defaults
    pub push: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub delete: Option<bool>,
    pub delete_merged_branch: Option<bool>,
    /// Repos on this upstream, written as `Org/Repo`. A host prefix is unnecessary, and if given it must match this upstream
    #[serde(default)]
    pub repos: Vec<RepoConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default)]
    pub repos: Vec<RepoConfig>,
    /// 0.2.1: a per-upstream (git-relay domain) layer that sits between the project defaults and the repos.
    /// `permissions` adds and denies, `push` / `tags` / `delete` are the defaults for repos on that upstream,
    /// and `repos` are the repos on it
    #[serde(default)]
    pub upstreams: BTreeMap<String, UpstreamPolicyConfig>,
    /// The project's default permissions, written as `[…]` or `{allow, deny}`
    #[serde(default)]
    pub permissions: PermissionSpec,
    /// Default branch globs that direct pushes are allowed to; `sekimore/*` when unset
    pub push: Option<Vec<String>>,
    /// Default tag globs that pushes are allowed to; denied when unset
    #[serde(default)]
    pub tags: Vec<String>,
    /// Default for deleting branches and tags; false when unset
    #[serde(default)]
    pub delete: bool,
    /// 0.2.9: after `pr merge` succeeds, delete the branch that was merged. False when unset.
    ///
    /// A forge can be configured to do this itself, and many are; this is for the ones that are
    /// not, and it keeps the agent's own `sekimore/*` branches from accumulating. It is not the
    /// same authority as `delete`: this removes only the branch the agent just merged, whereas
    /// `delete` allows deleting any ref the push policy admits
    #[serde(default)]
    pub delete_merged_branch: bool,
    /// 0.2.7: the Projects v2 boards this project may touch.
    ///
    /// A board is named the way it appears in its URL — `github.com/orgs/<org>/projects/<number>`
    /// or `github.com/users/<user>/projects/<number>` — because the node id the API wants
    /// (`PVT_…`) is opaque and appears nowhere a person can copy it from. The relay resolves each
    /// entry to its node id at startup and accepts only those ids afterwards.
    ///
    /// Empty means no board at all: a project id is otherwise unbounded, so `project:add_item`
    /// would reach any board the upstream token can see, whether or not it belongs to this project.
    #[serde(default)]
    pub boards: Vec<BoardRef>,
}

/// One Projects v2 board, written the way its URL reads.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoardRef {
    /// The organization that owns the board (`github.com/orgs/<org>/projects/<n>`)
    #[serde(default)]
    pub org: Option<String>,
    /// The user that owns it (`github.com/users/<user>/projects/<n>`). Exactly one of org / user
    #[serde(default)]
    pub user: Option<String>,
    /// The number in the URL
    pub number: u32,
}

impl BoardRef {
    /// `orgs/acme/projects/3`, for messages and for keying the resolved ids.
    pub fn label(&self) -> String {
        match (&self.org, &self.user) {
            (Some(o), None) => format!("orgs/{o}/projects/{}", self.number),
            (None, Some(u)) => format!("users/{u}/projects/{}", self.number),
            _ => format!("projects/{}", self.number),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match (&self.org, &self.user) {
            (Some(_), Some(_)) => Err(format!(
                "project board {}: give either org or user, not both",
                self.number
            )),
            (None, None) => Err(format!(
                "project board {}: needs an org or a user (from its URL)",
                self.number
            )),
            _ if self.number == 0 => Err("project board: number must not be 0".to_string()),
            _ => Ok(()),
        }
    }
}

/// The `relay:` section. It is owned by the relay, so an unknown key is an error.
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
    /// 0.2.2: the default per-connection byte cap on what dev may send upstream through the 443 passthrough;
    /// downloads are not counted. Exceeding it drops the connection and audits `https_upload_capped`.
    /// `-1` means unlimited, the default is 1 MiB, and a handler's `max_upload_bytes` overrides it.
    /// The cap exists to stop exfiltration over HTTPS with credentials smuggled in by a hostile prompt;
    /// ordinary GET and API calls send far less than this
    #[serde(default = "d_https_max_upload")]
    pub https_max_upload_bytes: i64,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    /// The upstream host. Defaults to the git-relay domain
    pub upstream: Option<String>,
    #[serde(default = "d_upstream_ssh_port")]
    pub upstream_ssh_port: u16,
    /// Config file passed to the upstream ssh with `-F`, for things like ProxyCommand. Defaults to /dev/null
    pub ssh_config: Option<PathBuf>,
    /// 0.2.1: options passed with `-o` to the ssh of every upstream. They come before a handler's `ssh_options`
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
    /// A PEM bundle to trust in addition to `SSL_CERT_FILE`
    pub ca_file: Option<PathBuf>,
    /// Deprecated since 0.1.9, moved to `project.delete`. Still read as the default, with a warning
    #[serde(default)]
    pub allow_delete: bool,
    /// Deprecated since 0.1.9, moved to the `project.tags` globs. true is equivalent to `project.tags: ["*"]`
    #[serde(default)]
    pub allow_tags: bool,
    #[serde(default = "d_bootstrap")]
    pub bootstrap: BootstrapMode,
    #[serde(default)]
    pub limits: Limits,
    pub project: ProjectConfig,
    /// Test only: run a command instead of the upstream ssh (the parent directory for `["git", "receive-pack", "<bare-dir>"]`)
    #[cfg(feature = "test-hooks")]
    pub upstream_local_root: Option<PathBuf>,
    /// Test only (0.2.0): a local root per upstream domain. Domains without one fall back to `upstream_local_root`
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
fn d_https_max_upload() -> i64 {
    1024 * 1024
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

/// A loaded configuration, offering the `needs_relay` decision and `resolve`.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub path: PathBuf,
    pub gateway: GatewayConfig,
    /// Handler map, keyed by the normalized domain (lowercased, trailing `.` removed)
    handlers: BTreeMap<String, HandlerKind>,
    /// Every handler field under the same keys (0.2.0: ssh_port, upstream and the rest)
    handler_specs: BTreeMap<String, DomainHandler>,
}

/// Reads the file. A missing file yields an empty configuration, matching Python's `load_config`.
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
            .filter(|(_, k)| **k == HandlerKind::Github)
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// 0.2.2: the domains using the `https-relay` handler, which pass only 443 through the relay's passthrough.
    pub fn https_relay_domains(&self) -> Vec<String> {
        self.handlers
            .iter()
            .filter(|(_, k)| **k == HandlerKind::HttpsRelay)
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// Whether the relay should start, that is whether there is at least one `git-relay` handler.
    /// 0.2.0: several git-relay domains are separated by port; a duplicate port and the like are invalid (`Err`).
    /// 0.2.2: `https-relay` without any git-relay is invalid too, since the 443 passthrough starts alongside git-relay.
    pub fn needs_relay(&self) -> Result<bool, ConfigError> {
        if self.git_relay_domains().is_empty() {
            if !self.https_relay_domains().is_empty() {
                return Err(ConfigError::Invalid(
                    "https-relay needs at least one git-relay domain in this version (the 443 passthrough is started with it)".into(),
                ));
            }
            return Ok(false);
        }
        let relay = self
            .gateway
            .relay
            .as_ref()
            .ok_or(ConfigError::NoRelaySection)?;
        self.resolve_https_targets(relay, &self.resolve_upstreams(relay)?)?;
        let relay = self
            .gateway
            .relay
            .as_ref()
            .ok_or(ConfigError::NoRelaySection)?;
        self.resolve_upstreams(relay)?;
        Ok(true)
    }

    /// Builds the upstream for each git-relay domain (0.2.0).
    ///
    /// - Default upstream: the handler with `default: true`, else the one without an `ssh_port`, else the
    ///   first in lexicographic order
    /// - The default upstream listens on `relay.ssh_listen` and uses `relay.upstream` / `api_base` /
    ///   `graphql_base` / `paths.upstream_token` / `paths.known_hosts`, exactly as in 0.1.x
    /// - Every other upstream needs an `ssh_port` and listens on the same IP as `relay.ssh_listen`,
    ///   with its state under `upstreams/<host>/`
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
            // 0.2.1: the handler's api_base / graphql_base take precedence; the default upstream also honours relay.api_base / graphql_base
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
            // 0.2.1: validate ssh_options - Key=Value, and nothing the relay enforces may be overridden
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
                max_upload: upload_cap(
                    h.max_upload_bytes.unwrap_or(relay.https_max_upload_bytes),
                    &format!("domain_handlers.{d}"),
                )?,
                is_default,
            });
        }
        // put the default upstream first
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

    /// Resolves everything the relay needs in order to run.
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        if self.git_relay_domains().is_empty() {
            return Err(ConfigError::NoGitRelayDomain);
        }
        let relay = self
            .gateway
            .relay
            .clone()
            .ok_or(ConfigError::NoRelaySection)?;
        for b in &relay.project.boards {
            b.validate().map_err(ConfigError::Invalid)?;
        }
        let upstreams = self.resolve_upstreams(&relay)?;
        let default_up = upstreams[0].clone();
        let domain = default_up.domain.clone();
        let upstream = default_up.host.clone();
        let api_base = default_up.api_base.clone();
        let graphql_base = default_up.graphql_base.clone();

        // project defaults; the old relay.allow_tags / allow_delete fold into them (moved under project in 0.1.9)
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
        // 0.2.1: the upstream layer, keyed by git-relay domain (an upstream hostname also works)
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
        // collect (repo config, owning upstream domain, upstream layer) from project.repos, with its host prefix, and upstreams.<d>.repos
        let mut entries: Vec<(&RepoConfig, String)> = Vec::new();
        for r in &pc.repos {
            // 0.2.0: `host/Org/Repo` names the upstream explicitly; a bare `Org/Repo` means the default upstream
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
            let l_dmb = layer.and_then(|l| l.delete_merged_branch);
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
            rp.delete_merged_branch = r
                .delete_merged_branch
                .or(l_dmb)
                .unwrap_or(pc.delete_merged_branch);
            // permissions: the upstream layer's delta, then the repo's; in both, allow adds and deny wins
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
        // when the same Org/Repo exists on several upstreams, point out that a bare `Org/Repo` in an API call resolves to the default upstream
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

        let https_targets = self.resolve_https_targets(&relay, &upstreams)?;
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
            https_targets,
        })
    }

    /// 0.2.2: the destinations of the 443 passthrough - the git-relay upstreams, with their caps, plus the https-relay domains.
    fn resolve_https_targets(
        &self,
        relay: &RelayConfig,
        upstreams: &[Upstream],
    ) -> Result<Vec<HttpsTarget>, ConfigError> {
        let mut out: Vec<HttpsTarget> = upstreams
            .iter()
            .map(|u| HttpsTarget {
                domain: u.domain.clone(),
                host: u.host.clone(),
                max_upload: u.max_upload,
                kind: HandlerKind::Github,
            })
            .collect();
        for d in self.https_relay_domains() {
            let h = self.handler_specs.get(&d).cloned().unwrap_or_default();
            let host = h
                .upstream
                .clone()
                .unwrap_or_else(|| d.clone())
                .trim()
                .to_ascii_lowercase();
            if host.is_empty() || host.contains('/') || host.contains(':') {
                return Err(ConfigError::Invalid(format!(
                    "domain_handlers.{d}.upstream {host:?} must be a bare hostname"
                )));
            }
            if h.ssh_port.is_some() || !h.ssh_options.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "domain_handlers.{d}: ssh_port / ssh_options only apply to git-relay (https-relay carries 443 only)"
                )));
            }
            out.push(HttpsTarget {
                domain: d.clone(),
                host,
                max_upload: upload_cap(
                    h.max_upload_bytes.unwrap_or(relay.https_max_upload_bytes),
                    &format!("domain_handlers.{d}"),
                )?,
                kind: HandlerKind::HttpsRelay,
            });
        }
        Ok(out)
    }
}

/// Turns `max_upload_bytes` into a cap: `-1` is unlimited (None) and a positive value is a byte count. `0` and anything else is an error.
pub fn upload_cap(v: i64, what: &str) -> Result<Option<u64>, ConfigError> {
    match v {
        -1 => Ok(None),
        n if n > 0 => Ok(Some(n as u64)),
        0 => Err(ConfigError::Invalid(format!(
            "{what}: max_upload_bytes 0 would block every HTTPS request (TLS itself sends bytes); use -1 for unlimited or a positive size"
        ))),
        n => Err(ConfigError::Invalid(format!(
            "{what}: max_upload_bytes {n} is invalid; use -1 for unlimited or a positive size"
        ))),
    }
}

/// Options the relay enforces on the upstream ssh. `ssh_options` may not override them - they are listed first
/// and would win anyway, but they are also rejected at configuration time.
pub const ENFORCED_SSH_OPTIONS: &[&str] = &[
    "batchmode",
    "stricthostkeychecking",
    "userknownhostsfile",
    "globalknownhostsfile",
    "updatehostkeys",
];

/// Requires the `Key=Value` form, on a single line, and not one of the enforced options.
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

/// `host/Org/Repo` becomes (Some(host), "Org/Repo") and `Org/Repo` becomes (None, "Org/Repo").
/// Only a three-part name whose first part contains a `.` is read as a host, since a GitHub org name cannot contain one.
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

/// The upstream proxy: `proxy.upstream_proxy` (host:port) from `config.yml`, plus credentials that environment variables may override.
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

/// The file layout under `state_dir`.
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

/// A single upstream, that is one git-relay domain. Since 0.2.0 there can be more than one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The domain DNS points at the relay: the name the agent writes in a URL, and the host prefix on a repo
    pub domain: String,
    /// The host of the upstream git / API
    pub host: String,
    /// The address on which the relay accepts SSH for this upstream
    pub listen: SocketAddr,
    pub upstream_ssh_port: u16,
    pub api_base: Url,
    pub graphql_base: Url,
    pub oauth_client_id: String,
    pub upstream_token: PathBuf,
    pub known_hosts: PathBuf,
    /// 0.2.1: `-o` options added to the upstream ssh (relay.ssh_options followed by handler.ssh_options)
    pub ssh_options: Vec<String>,
    /// 0.2.2: upload cap for the 443 passthrough (None = unlimited)
    pub max_upload: Option<u64>,
    pub is_default: bool,
}

/// 0.2.2: one destination of the 443 passthrough - a git-relay upstream or an https-relay domain. Selected by SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsTarget {
    pub domain: String,
    pub host: String,
    /// Upload cap (None = unlimited)
    pub max_upload: Option<u64>,
    pub kind: HandlerKind,
}

/// The resolved configuration the relay runs on.
///
/// `domain` / `upstream` / `api_base` / `graphql_base` / `paths` describe the **default upstream**, which keeps
/// them backward compatible with 0.1.x. Every upstream is in `upstreams`, the default one first.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The domain DNS points at the relay, for the default upstream
    pub domain: String,
    /// The host of the upstream git / API, for the default upstream
    pub upstream: String,
    pub api_base: Url,
    pub graphql_base: Url,
    pub paths: Paths,
    pub proxy: Option<ProxySpec>,
    pub project: Project,
    pub relay: RelayConfig,
    /// 0.2.0: every upstream, the default one first
    pub upstreams: Vec<Upstream>,
    /// 0.2.2: the destinations of the 443 passthrough - git-relay upstreams plus https-relay, selected by SNI
    pub https_targets: Vec<HttpsTarget>,
}

impl Resolved {
    pub fn default_upstream(&self) -> &Upstream {
        &self.upstreams[0]
    }
    /// Looks up an upstream by domain name or by upstream hostname.
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

    /// 0.2.7: a Projects v2 board is written the way its URL reads, because the node id the API
    /// wants appears nowhere a person can copy it from.
    #[test]
    fn project_boards_are_written_as_owner_and_number() {
        let body = |boards: &str| {
            format!(
                r#"
domain_handlers:
  github.com: {{ handler: github }}
relay:
  project:
    name: case-a
    permissions: [project:read]
    boards:
{boards}
    repos:
      - {{ name: Org/App, mode: read-write, bases: [main] }}
"#
            )
        };
        let ok = p(&body(
            "      - { org: acme, number: 3 }\n      - { user: someone, number: 1 }",
        ))
        .expect("org and user forms must parse")
        .resolve()
        .expect("and resolve");
        assert_eq!(ok.relay.project.boards.len(), 2);
        assert_eq!(ok.relay.project.boards[0].label(), "orgs/acme/projects/3");
        assert_eq!(
            ok.relay.project.boards[1].label(),
            "users/someone/projects/1"
        );

        // Both owners, or neither, is a mistake worth catching at startup rather than at use
        for bad in [
            "      - { org: acme, user: someone, number: 3 }",
            "      - { number: 3 }",
            "      - { org: acme, number: 0 }",
        ] {
            assert!(
                p(&body(bad)).and_then(|l| l.resolve()).is_err(),
                "should reject {bad}"
            );
        }

        // Omitting boards is allowed by the parser; the refusal happens at request time
        let none = p(&body("      []"))
            .expect("empty list parses")
            .resolve()
            .unwrap();
        assert!(none.relay.project.boards.is_empty());
    }

    /// 0.2.6 renamed the handler to `github`. A config written for 0.1.x keeps working, and the two
    /// spellings resolve identically, so nobody has to touch a running configuration.
    #[test]
    fn the_original_git_relay_handler_name_still_works() {
        let body = |handler: &str| {
            format!(
                r#"
domain_handlers:
  github.com: {{ handler: {handler} }}
relay:
  project:
    name: case-a
    permissions: [pr:create]
    repos:
      - {{ name: Org/App, mode: read-write, bases: [main] }}
"#
            )
        };
        let old = p(&body("git-relay")).expect("git-relay must still parse");
        let new = p(&body("github")).expect("github must parse");
        assert_eq!(old.needs_relay().unwrap(), new.needs_relay().unwrap());
        let (ro, rn) = (old.resolve().unwrap(), new.resolve().unwrap());
        assert_eq!(ro.upstreams.len(), 1);
        assert_eq!(ro.upstreams[0].domain, rn.upstreams[0].domain);
        assert_eq!(ro.upstreams[0].host, rn.upstreams[0].host);
        assert_eq!(ro.https_targets.len(), rn.https_targets.len());

        // The two spellings may be mixed across domains
        let mixed = p(r#"
domain_handlers:
  github.com: { handler: git-relay }
  ghe.example.com: { handler: github, ssh_port: 2222 }
relay:
  project:
    name: case-a
    permissions: [pr:create]
    repos:
      - { name: github.com/Org/App, mode: read-write, bases: [main] }
"#)
        .expect("a mix of both names must parse");
        assert_eq!(mixed.resolve().unwrap().upstreams.len(), 2);
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
        // the old relay.allow_tags: true folds into the defaults as ["*"] when project.tags is empty
        assert_eq!(lib.tags, vec!["*"]);
        assert!(lib.delete);
        assert_eq!(r.project.effective_keys(lib), vec!["pr:create", "pr:merge"]);
        let old = r.project.find_repo("Org/Old").unwrap();
        assert_eq!(
            r.project.effective_keys(old),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        // the default push glob is sekimore/*
        assert_eq!(old.push, vec!["sekimore/*"]);
        // permissions written as a plain list still work as before
        let text2 = "domain_handlers:\n  github.com: { handler: git-relay }\nrelay:\n  project: { name: x, permissions: [pr:create] }\n";
        assert_eq!(
            p(text2).unwrap().resolve().unwrap().project.granted(),
            vec!["pr:create"]
        );
        // a typo in a repo's permissions is a startup error
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
        assert_eq!(r.relay.https_max_upload_bytes, 1024 * 1024);
        assert_eq!(r.https_targets.len(), 1);
        assert_eq!(r.https_targets[0].max_upload, Some(1024 * 1024));
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
        // 0.2.0: a single upstream gives one entry in upstreams, matching the 0.1.x fields
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
        // spelling out the same port is rejected too
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
        // the third entry duplicates Org/App on github.com, so it is a startup error
        assert!(p(text).unwrap().resolve().is_err());
        let text = text.replace("      - { name: Org/App, mode: read-only }   # DUP\n", "");
        let l = p(&text).unwrap();
        assert!(l.needs_relay().unwrap());
        let r = l.resolve().unwrap();
        // the default upstream is github.com, the one without an ssh_port; the 0.1.x fields still point at it
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
        // the repo's host
        let app = r.project.find_repo("Org/App").unwrap();
        assert_eq!(app.host, "github.com");
        let internal = r
            .project
            .find_repo("ghe.example.com/Corp/Internal")
            .unwrap();
        assert_eq!(internal.host, "ghe.example.com");
        assert_eq!(internal.full_name, "Corp/Internal");
        // a unique name resolves without a host; on the SSH path, where the upstream is fixed, the other upstream is invisible
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
        // an unknown host is a startup error
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
        // a repo's deny beats the upstream layer's allow, and the repo's tags override
        let tool = pr.find_repo("Org/Tool").unwrap();
        assert_eq!(
            pr.effective_keys(tool),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        assert!(tool.tags.is_empty());
        // on the GHES side: merging is not allowed and delete comes from the upstream layer's default
        let internal = pr.find_repo("ghe.example.com/Corp/Internal").unwrap();
        assert_eq!(internal.host, "ghe.example.com");
        assert_eq!(
            pr.effective_keys(internal),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        assert!(internal.delete && internal.tags.is_empty());
        // the host-prefixed form under project.repos also picks up the upstream layer's defaults
        let legacy = pr.find_repo("Corp/Legacy").unwrap();
        assert_eq!(legacy.host, "ghe.example.com");
        assert!(legacy.delete);
        assert_eq!(
            pr.effective_keys(legacy),
            vec!["ci:read", "pr:create", "pr:read"]
        );
        // authorize answers differently per upstream
        assert!(pr.authorize("Org/App", Resource::Pr, Action::Merge).is_ok());
        assert!(pr
            .authorize("ghe.example.com/Corp/Internal", Resource::Pr, Action::Merge)
            .is_err());
        // an unknown upstream key, or a repo name pointing at another upstream, is a startup error
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
        // relay.ssh_options applies to every upstream and a handler's only to its own, in that order
        assert_eq!(gh.ssh_options, vec!["ConnectionAttempts=2"]);
        assert_eq!(
            ghe.ssh_options,
            vec![
                "ConnectionAttempts=2",
                "ProxyJump=bastion.example.com",
                "HostKeyAlias=ghe.example.com"
            ]
        );
        // the handler's api_base wins and is not derived from upstream
        assert_eq!(ghe.host, "host.docker.internal");
        assert_eq!(ghe.upstream_ssh_port, 2200);
        assert_eq!(ghe.api_base.as_str(), "https://ghe.example.com/api/v3");
        assert_eq!(
            ghe.graphql_base.as_str(),
            "https://ghe.example.com/api/graphql"
        );
        assert_eq!(gh.api_base.as_str(), "https://api.github.com/");
        // overriding an enforced option, or a malformed one, is a startup error
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
    fn https_relay_targets_and_upload_caps() {
        let text = r#"
domain_handlers:
  github.com: { handler: git-relay, max_upload_bytes: 262144 }
  ghcr.io: { handler: https-relay, max_upload_bytes: -1 }
  registry-1.docker.io: { handler: https-relay }
  telemetry.example.com: { handler: deny }
relay:
  https_max_upload_bytes: 4194304
  project: { name: x }
"#;
        let l = p(text).unwrap();
        assert!(l.needs_relay().unwrap());
        assert_eq!(
            l.https_relay_domains(),
            vec!["ghcr.io".to_string(), "registry-1.docker.io".to_string()]
        );
        let r = l.resolve().unwrap();
        // github.com is the only SSH upstream, but there are three 443 destinations
        assert_eq!(r.upstreams.len(), 1);
        let caps: Vec<(&str, Option<u64>, HandlerKind)> = r
            .https_targets
            .iter()
            .map(|t| (t.domain.as_str(), t.max_upload, t.kind))
            .collect();
        assert_eq!(
            caps,
            vec![
                ("github.com", Some(262144), HandlerKind::Github),
                ("ghcr.io", None, HandlerKind::HttpsRelay),
                (
                    "registry-1.docker.io",
                    Some(4194304),
                    HandlerKind::HttpsRelay
                ),
            ]
        );
        assert_eq!(r.default_upstream().max_upload, Some(262144));
        // 0 is a configuration error; -1 is what means unlimited
        let bad = text.replace("max_upload_bytes: -1", "max_upload_bytes: 0");
        let err = p(&bad).unwrap().resolve().unwrap_err().to_string();
        assert!(err.contains("max_upload_bytes 0"), "{err}");
        let bad = text.replace(
            "https_max_upload_bytes: 4194304",
            "https_max_upload_bytes: -5",
        );
        assert!(p(&bad).unwrap().resolve().is_err());
        // ssh_port cannot be written on an https-relay
        let bad = text.replace(
            "{ handler: https-relay }",
            "{ handler: https-relay, ssh_port: 2222 }",
        );
        assert!(p(&bad).unwrap().resolve().is_err());
        // https-relay on its own, with no git-relay, is invalid
        let only = "domain_handlers:\n  ghcr.io: { handler: https-relay }\nrelay:\n  project: { name: x }\n";
        assert!(p(only).unwrap().needs_relay().is_err());
    }

    #[test]
    fn default_upstream_can_be_chosen_explicitly() {
        // when every entry has an ssh_port, default: true picks the default upstream, and relay.upstream applies only to it
        let text = "domain_handlers:\n  a.example.com: { handler: git-relay, ssh_port: 2201 }\n  b.example.com: { handler: git-relay, ssh_port: 2202, default: true, upstream: b-internal.example.com }\nrelay:\n  ssh_listen: 0.0.0.0:22\n  project: { name: x }\n";
        let r = p(text).unwrap().resolve().unwrap();
        assert_eq!(r.domain, "b.example.com");
        assert_eq!(r.upstream, "b-internal.example.com");
        assert_eq!(r.default_upstream().listen.port(), 2202);
        assert_eq!(r.upstreams[1].domain, "a.example.com");
        // two defaults are not allowed
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
        // three parts without a `.` in the first are not a host, so this falls through to the Org/Repo check and fails there
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
        // real config.yml files keep an upstream_proxy placeholder around with enabled: false
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
