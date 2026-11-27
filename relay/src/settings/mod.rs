//! The gateway's settings: every key of `config.yml` that the Python side reads (`src/config.py`),
//! read the way it reads them, and the resolved [`Rules`](rules::Rules) built from them.
//!
//! This is the first step of moving the gateway off Python (Issue #498, under the 0.3.0 plan).
//! Nothing in a running gateway reads it yet: the Python orchestrator keeps its own `config.py`,
//! and the relay keeps [`crate::config`]. The Web UI (α4) and the core (α6) will read from here.
//!
//! # Why apart from `crate::config`
//!
//! `crate::config` is the relay's reading: strict under `relay:` and `domain_handlers`, lenient
//! at the top, YAML 1.2, and it decides whether `serve` and `needs-relay` start. This module is
//! the Python reading: YAML 1.1, pydantic's coercions, unknown keys ignored everywhere, and the
//! four relay keys Python looks at with Python's defaults. The two disagree on some files today
//! (a duplicate key, `max_upload_bytes: "100"`, a typo in a handler entry) and both readings are
//! in force, so folding one into the other would change what a running gateway accepts. They
//! share nothing but the file. [`rules::Rules`] takes the relay's resolved 443 targets when there
//! are any, so the one structure carries both.
//!
//! # The rule of this step
//!
//! Nothing is added: the same files are accepted and refused, with the same defaults, the same
//! environment overrides and the same derived lists. A quirk of the Python reading is kept and
//! listed in the plan's difference ledger. `relay/tests/equivalence.rs` compares this module with
//! `src/config.py` over the corpus in `relay/tests/fixtures/corpus/`.

pub mod ip;
pub mod lax;
pub mod py;
pub mod rules;
pub mod yaml11;

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

use lax::{at, field, Errors, FieldError, Loc};
use yaml11::{py_eq, PyValue, YamlError};

pub use rules::Rules;

/// `DEFAULT_DENY_CIDRS` (`src/resolved_ips.py`): what an allowlisted name may not resolve to.
pub const DEFAULT_DENY_CIDRS: &[&str] = &[
    "169.254.0.0/16",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "0.0.0.0/8",
    "100.64.0.0/10",
    "::1/128",
    "fe80::/10",
    "fc00::/7",
];

/// `PROXY_DENIED_HANDLERS`: the handler kinds Squid refuses to serve (#212).
pub const PROXY_DENIED_HANDLERS: &[Handler] =
    &[Handler::Github, Handler::HttpsRelay, Handler::Deny];

/// `NO_PROXY_ALWAYS`: never sent to the proxy, whatever the config says.
pub const NO_PROXY_ALWAYS: &[&str] = &["localhost", "127.0.0.1", "sekimore-gw"];

/// `SEKIMORE_UPSTREAM_PROXY_USERNAME` / `_PASSWORD`: override `config.yml` when set and non-empty.
pub const ENV_PROXY_USERNAME: &str = "SEKIMORE_UPSTREAM_PROXY_USERNAME";
pub const ENV_PROXY_PASSWORD: &str = "SEKIMORE_UPSTREAM_PROXY_PASSWORD";

/// Python's `int`, which has no bound. Values outside `i128` are refused as unsupported.
pub type PyInt = i128;

/// A credential. Its `Debug` does not show it, and nothing here serializes it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Splice,
    /// written `github`, or `git-relay` (the original spelling)
    Github,
    HttpsRelay,
    Deny,
}

impl Handler {
    pub fn as_str(self) -> &'static str {
        match self {
            Handler::Splice => "splice",
            Handler::Github => "github",
            Handler::HttpsRelay => "https-relay",
            Handler::Deny => "deny",
        }
    }
    /// The handlers DNS answers with the gateway's address for (`RELAY_HANDLERS`).
    pub fn is_relayed(self) -> bool {
        matches!(self, Handler::Github | Handler::HttpsRelay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectEgress {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsMode {
    Passthrough,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Auto,
    En,
    Ja,
}

/// `ProxyConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct Proxy {
    pub enabled: bool,
    pub port: PyInt,
    pub cache_enabled: bool,
    pub cache_size_mb: PyInt,
    pub upstream_proxy: Option<String>,
    pub upstream_proxy_tls: bool,
    pub upstream_proxy_username: Option<Secret>,
    pub upstream_proxy_password: Option<Secret>,
    pub direct_egress: DirectEgress,
    /// Blank entries dropped, the rest stripped; not yet normalized
    pub no_proxy: Vec<String>,
}

/// `NetworkConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    pub lan_subnets: Vec<String>,
    /// 1-65535, duplicates dropped, order kept
    pub allowed_ports: Vec<u16>,
    pub host_enforcement: bool,
}

/// `DomainHandlerConfig`: the four keys of a `domain_handlers` entry Python reads.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainHandler {
    pub handler: Handler,
    /// -1 or positive; None falls back to `relay.https_max_upload_bytes` (the relay's key)
    pub max_upload_bytes: Option<PyInt>,
    pub ssh_port: Option<u16>,
    pub upstream: Option<String>,
}

/// `RelayConfig`: the four `relay:` keys Python reads. The rest belong to the relay.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayListen {
    pub ssh_listen: String,
    pub api_listen: String,
    pub https_listen: String,
    pub https: HttpsMode,
}

/// `Config`, as `Config.from_yaml` leaves it.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub name: Option<String>,
    pub description: Option<String>,
    pub allow_domains: Vec<String>,
    pub block_domains: Vec<String>,
    pub ignore_domains: Vec<String>,
    pub allow_ips: Vec<String>,
    pub block_ips: Vec<String>,
    pub resolve_deny_cidrs: Vec<String>,
    pub resolve_allow_cidrs: Vec<String>,
    pub proxy: Proxy,
    pub network: Network,
    pub database_path: String,
    /// sha256 of the `relay` and `domain_handlers` subtrees as written
    pub relay_fingerprint: String,
    /// `auto`, `manual` or a duration, stripped and lowercased
    pub reload: String,
    /// In file order, keyed by the normalized domain (stripped, trailing dots removed, lowercased)
    pub domain_handlers: Vec<(String, DomainHandler)>,
    pub relay: RelayListen,
    pub ui: Language,
}

/// Which model validator refused the file. They run in this order, after every field is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRule {
    HttpsRelayNeedsGitRelay,
    DuplicateSshPort,
    RelayedNotAllowed,
    DirectEgressNeedsUpstream,
}

impl ModelRule {
    pub fn as_str(self) -> &'static str {
        match self {
            ModelRule::HttpsRelayNeedsGitRelay => "https_relay_needs_git_relay",
            ModelRule::DuplicateSshPort => "duplicate_ssh_port",
            ModelRule::RelayedNotAllowed => "relayed_not_allowed",
            ModelRule::DirectEgressNeedsUpstream => "direct_egress_needs_upstream",
        }
    }
}

/// Why `Config.from_yaml` raises, by the stage that raised.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// The file is not UTF-8 or cannot be read
    Unreadable(String),
    /// `yaml.safe_load` raised
    Yaml(String),
    /// PyYAML would load it and this reader cannot (difference ledger)
    Unsupported(String),
    /// The document is not a mapping (`data.pop` raises)
    NotAMapping,
    /// `json.dumps` of the relay subtrees raised (`relay_fingerprint`)
    Fingerprint(String),
    /// A top-level key is not a string (`Config(**data)` raises)
    NonStringKey(String),
    /// pydantic's field validation, every error
    Fields(Vec<FieldError>),
    /// A model validator
    Model(ModelRule, String),
}

impl Refusal {
    /// The stage, as the equivalence harness compares it.
    pub fn stage(&self) -> &'static str {
        match self {
            Refusal::Unreadable(_) | Refusal::Yaml(_) => "yaml",
            Refusal::Unsupported(_) => "unsupported",
            Refusal::NotAMapping => "not_a_mapping",
            Refusal::Fingerprint(_) => "fingerprint",
            Refusal::NonStringKey(_) => "non_string_key",
            Refusal::Fields(_) => "fields",
            Refusal::Model(..) => "model",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unreadable(m) | Refusal::Yaml(m) | Refusal::Fingerprint(m) => f.write_str(m),
            Refusal::Unsupported(m) => write!(f, "not supported by this reader: {m}"),
            Refusal::NotAMapping => f.write_str("config.yml must be a mapping at the top level"),
            Refusal::NonStringKey(k) => write!(f, "keywords must be strings (found the key {k})"),
            Refusal::Fields(errors) => {
                write!(f, "{} validation error(s) for Config", errors.len())?;
                for e in errors {
                    write!(f, "\n{}\n  {}", e.path(), e.message)?;
                }
                Ok(())
            }
            Refusal::Model(_, m) => write!(f, "Value error, {m}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// `load_config(path)`: a missing file is the defaults. The environment overrides are read from
/// the process environment.
pub fn load(path: &Path) -> Result<Settings, Refusal> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(defaults(&process_env)),
        Err(e) => return Err(Refusal::Unreadable(format!("{}: {e}", path.display()))),
    };
    let text = String::from_utf8(bytes)
        .map_err(|e| Refusal::Unreadable(format!("{}: {e}", path.display())))?;
    parse(&text, &process_env)
}

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// `Config()`, the settings of a gateway with no `config.yml`.
pub fn defaults(env: &dyn Fn(&str) -> Option<String>) -> Settings {
    parse("", env).unwrap_or_else(|_| unreachable!("an empty document is always accepted"))
}

/// `Config.from_yaml` on `text`, with `env` standing in for `os.getenv`.
pub fn parse(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Settings, Refusal> {
    let doc = yaml11::safe_load(text).map_err(|e| match e {
        YamlError::Refused(m) => Refusal::Yaml(m),
        YamlError::Unsupported(m) => Refusal::Unsupported(m),
    })?;
    let mut data = match doc {
        PyValue::None => Vec::new(),
        PyValue::Dict(pairs) => pairs,
        _ => return Err(Refusal::NotAMapping),
    };
    // derived, never read from the file
    data.retain(|(k, _)| !py_eq(k, &PyValue::Str("relay_fingerprint".into())));
    let fingerprint = relay_fingerprint(&data)?;
    if let Some((k, _)) = data.iter().find(|(k, _)| !matches!(k, PyValue::Str(_))) {
        return Err(Refusal::NonStringKey(py::str_of(k)));
    }
    validate(&data, fingerprint, env)
}

/// `relay_fingerprint(raw)`: sha256 of the `relay` and `domain_handlers` subtrees as parsed.
fn relay_fingerprint(data: &[(PyValue, PyValue)]) -> Result<String, Refusal> {
    let get = |name: &str| {
        data.iter()
            .find(|(k, _)| py_eq(k, &PyValue::Str(name.into())))
            .map(|(_, v)| v.clone())
            .unwrap_or(PyValue::None)
    };
    let subject = PyValue::Dict(vec![
        (PyValue::Str("relay".into()), get("relay")),
        (
            PyValue::Str("domain_handlers".into()),
            get("domain_handlers"),
        ),
    ]);
    let json = py::json_dumps(&subject).map_err(|e| Refusal::Fingerprint(e.0))?;
    Ok(hex::encode(Sha256::digest(json.as_bytes())))
}

fn strings(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<Vec<String>> {
    lax::list(v, loc, e, lax::string)
}

/// A field: its value converted, or the default when the key is absent.
fn get<T>(
    data: &[(PyValue, PyValue)],
    name: &str,
    loc: &[Loc],
    e: &mut Errors,
    default: impl FnOnce() -> T,
    convert: impl FnOnce(&PyValue, &[Loc], &mut Errors) -> Option<T>,
) -> Option<T> {
    match field(data, name) {
        Some(v) => convert(v, &at(loc, name), e),
        None => Some(default()),
    }
}

/// `validate_ip_entries`.
fn ip_entries(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<Vec<String>> {
    let entries = strings(v, loc, e)?;
    for entry in &entries {
        let bad = if let Some((start, end)) = entry.split_once('-') {
            (!ip::is_address(py::strip(start)) || !ip::is_address(py::strip(end)))
                .then(|| format!("Invalid IP range: {entry}"))
        } else if entry.contains('/') {
            (!ip::is_network(entry)).then(|| format!("Invalid CIDR notation: {entry}"))
        } else {
            (!ip::is_address(entry)).then(|| format!("Invalid IP address: {entry}"))
        };
        if let Some(msg) = bad {
            e.push(loc, format!("Value error, {msg}"));
            return None;
        }
    }
    Some(entries)
}

fn proxy(
    v: &PyValue,
    loc: &[Loc],
    e: &mut Errors,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<Proxy> {
    let d = lax::model(v, "ProxyConfig", loc, e)?;
    let enabled = get(d, "enabled", loc, e, || false, lax::boolean);
    let port = get(d, "port", loc, e, || 3128, lax::int);
    let cache_enabled = get(d, "cache_enabled", loc, e, || true, lax::boolean);
    let cache_size_mb = get(d, "cache_size_mb", loc, e, || 1000, lax::int);
    let upstream_proxy = get(d, "upstream_proxy", loc, e, || None, lax::opt_string);
    let upstream_proxy_tls = get(d, "upstream_proxy_tls", loc, e, || false, lax::boolean);
    let username = get(
        d,
        "upstream_proxy_username",
        loc,
        e,
        || None,
        lax::opt_string,
    );
    let password = get(
        d,
        "upstream_proxy_password",
        loc,
        e,
        || None,
        lax::opt_string,
    );
    let direct_egress = get(
        d,
        "direct_egress",
        loc,
        e,
        || DirectEgress::Allow,
        |v, l, e| {
            lax::literal(v, &["allow", "deny"], l, e).map(|s| {
                if s == "deny" {
                    DirectEgress::Deny
                } else {
                    DirectEgress::Allow
                }
            })
        },
    );
    let no_proxy = get(d, "no_proxy", loc, e, Vec::new, |v, l, e| {
        let entries = strings(v, l, e)?;
        // validate_no_proxy: drop blanks; one entry per item
        let mut out = Vec::new();
        for entry in &entries {
            let s = py::strip(entry);
            if s.is_empty() {
                continue;
            }
            if s.chars().any(py::is_space) || s.contains(',') {
                e.push(
                    l,
                    format!(
                        "Value error, proxy.no_proxy: {entry:?} must be a single entry (no spaces or commas); use one list item per host"
                    ),
                );
                return None;
            }
            out.push(s.to_string());
        }
        Some(out)
    });
    let (Some(enabled), Some(port), Some(cache_enabled), Some(cache_size_mb), Some(upstream_proxy)) =
        (enabled, port, cache_enabled, cache_size_mb, upstream_proxy)
    else {
        return None;
    };
    let (
        Some(upstream_proxy_tls),
        Some(username),
        Some(password),
        Some(direct_egress),
        Some(no_proxy),
    ) = (
        upstream_proxy_tls,
        username,
        password,
        direct_egress,
        no_proxy,
    )
    else {
        return None;
    };
    // model_post_init: the environment wins when set and non-empty
    let from_env = |name: &str| env(name).filter(|v| !v.is_empty());
    Some(Proxy {
        enabled,
        port,
        cache_enabled,
        cache_size_mb,
        upstream_proxy,
        upstream_proxy_tls,
        upstream_proxy_username: from_env(ENV_PROXY_USERNAME).or(username).map(Secret),
        upstream_proxy_password: from_env(ENV_PROXY_PASSWORD).or(password).map(Secret),
        direct_egress,
        no_proxy,
    })
}

fn network(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<Network> {
    let d = lax::model(v, "NetworkConfig", loc, e)?;
    let lan_subnets = get(
        d,
        "lan_subnets",
        loc,
        e,
        || vec!["10.100.0.0/16".to_string()],
        strings,
    );
    let allowed_ports = get(d, "allowed_ports", loc, e, Vec::new, |v, l, e| {
        let ports = lax::list(v, l, e, lax::int)?;
        // validate_allowed_ports. A bool has already become an int, so `true` is port 1.
        let mut out: Vec<u16> = Vec::new();
        for p in ports {
            if !(1..=65535).contains(&p) {
                e.push(
                    l,
                    format!("Value error, network.allowed_ports: {p} is not a TCP port (1-65535)"),
                );
                return None;
            }
            if !out.contains(&(p as u16)) {
                out.push(p as u16);
            }
        }
        Some(out)
    });
    let host_enforcement = get(d, "host_enforcement", loc, e, || true, lax::boolean);
    Some(Network {
        lan_subnets: lan_subnets?,
        allowed_ports: allowed_ports?,
        host_enforcement: host_enforcement?,
    })
}

fn relay_listen(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<RelayListen> {
    let d = lax::model(v, "RelayConfig", loc, e)?;
    let ssh_listen = get(d, "ssh_listen", loc, e, || "0.0.0.0:22".into(), lax::string);
    let api_listen = get(
        d,
        "api_listen",
        loc,
        e,
        || "0.0.0.0:8420".into(),
        lax::string,
    );
    let https_listen = get(
        d,
        "https_listen",
        loc,
        e,
        || "0.0.0.0:443".into(),
        lax::string,
    );
    let https = get(
        d,
        "https",
        loc,
        e,
        || HttpsMode::Passthrough,
        |v, l, e| {
            lax::literal(v, &["passthrough", "reject"], l, e).map(|s| {
                if s == "reject" {
                    HttpsMode::Reject
                } else {
                    HttpsMode::Passthrough
                }
            })
        },
    );
    Some(RelayListen {
        ssh_listen: ssh_listen?,
        api_listen: api_listen?,
        https_listen: https_listen?,
        https: https?,
    })
}

fn domain_handler(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<DomainHandler> {
    let d = lax::model(v, "DomainHandlerConfig", loc, e)?;
    let handler = get(
        d,
        "handler",
        loc,
        e,
        || Handler::Splice,
        |v, l, e| {
            // accept_the_original_handler_name, then the Literal
            let v = match v {
                PyValue::Str(s) if s == "git-relay" => PyValue::Str("github".into()),
                other => other.clone(),
            };
            lax::literal(&v, &["splice", "github", "https-relay", "deny"], l, e).map(|s| match s {
                "github" => Handler::Github,
                "https-relay" => Handler::HttpsRelay,
                "deny" => Handler::Deny,
                _ => Handler::Splice,
            })
        },
    );
    let max_upload_bytes = get(
        d,
        "max_upload_bytes",
        loc,
        e,
        || None,
        |v, l, e| {
            let n = lax::opt_int(v, l, e)?;
            if let Some(n) = n {
                if n == 0 || n < -1 {
                    e.push(
                    l,
                    "Value error, max_upload_bytes must be -1 (unlimited) or a positive number of bytes; 0 would block every HTTPS request",
                );
                    return None;
                }
            }
            Some(n)
        },
    );
    let ssh_port = get(
        d,
        "ssh_port",
        loc,
        e,
        || None,
        |v, l, e| {
            let n = lax::opt_int(v, l, e)?;
            match n {
                Some(p) if p < 1 => {
                    e.push(l, "Input should be greater than or equal to 1");
                    None
                }
                Some(p) if p > 65535 => {
                    e.push(l, "Input should be less than or equal to 65535");
                    None
                }
                Some(p) => Some(Some(p as u16)),
                None => Some(None),
            }
        },
    );
    let upstream = get(d, "upstream", loc, e, || None, lax::opt_string);
    Some(DomainHandler {
        handler: handler?,
        max_upload_bytes: max_upload_bytes?,
        ssh_port: ssh_port?,
        upstream: upstream?,
    })
}

/// `normalize_domain_handlers` (mode="before"), then `dict[str, DomainHandlerConfig]`.
fn domain_handlers(
    v: &PyValue,
    loc: &[Loc],
    e: &mut Errors,
) -> Option<Vec<(String, DomainHandler)>> {
    let pairs = match v {
        PyValue::None => return Some(Vec::new()),
        PyValue::Dict(p) => p,
        _ => {
            e.push(
                loc,
                "Value error, domain_handlers must be a mapping of domain -> {handler: ...}",
            );
            return None;
        }
    };
    let mut normalized: Vec<(String, PyValue)> = Vec::new();
    for (key, val) in pairs {
        let raw = py::str_of(key);
        let norm = py::lower(py::rstrip_dots(py::strip(&raw)));
        let fail = |e: &mut Errors, m: String| {
            e.push(loc, format!("Value error, {m}"));
        };
        if norm.is_empty() {
            fail(e, "domain_handlers: empty domain key".into());
            return None;
        }
        if norm.starts_with('.') || norm.contains('*') {
            fail(
                e,
                format!(
                    "domain_handlers: '{raw}' must be an exact FQDN (a wildcard would redirect every subdomain, e.g. api.github.com)"
                ),
            );
            return None;
        }
        if normalized.iter().any(|(k, _)| *k == norm) {
            fail(e, format!("domain_handlers: duplicate domain '{norm}'"));
            return None;
        }
        let val = match val {
            PyValue::None => PyValue::Dict(Vec::new()),
            other => other.clone(),
        };
        normalized.push((norm, val));
    }
    let mut out = Vec::new();
    let mut ok = true;
    for (k, val) in &normalized {
        match domain_handler(val, &at(loc, k), e) {
            Some(h) => out.push((k.clone(), h)),
            None => ok = false,
        }
    }
    ok.then_some(out)
}

/// `reload`: a string, then `_validate_reload`.
fn reload(v: &PyValue, loc: &[Loc], e: &mut Errors) -> Option<String> {
    let s = lax::string(v, loc, e)?;
    let v = py::lower(py::strip(&s));
    if v == "auto" || v == "manual" || parse_duration(&v).is_some() {
        return Some(v);
    }
    e.push(
        loc,
        format!(
            "Value error, reload: '{v}' is not valid. Use 'auto', 'manual', or a duration such as '30m', '2h'"
        ),
    );
    None
}

/// `parse_duration`: `30m` / `2h` / `90s` / `1d` in seconds, None when it is not a duration.
/// The number is read with Python's `int()`, so `" 3_0 m"` is 30 minutes.
pub fn parse_duration(text: &str) -> Option<PyInt> {
    let t = py::strip(text);
    let last = t.chars().last()?;
    if t.chars().count() < 2 {
        return None;
    }
    let unit = match last {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    let n = py::int(&t[..t.len() - last.len_utf8()])?;
    if n <= 0 {
        return None;
    }
    n.checked_mul(unit)
}

/// A field with no error has a value.
const SET: &str = "a field without an error has a value";

fn validate(
    data: &[(PyValue, PyValue)],
    relay_fingerprint: String,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Settings, Refusal> {
    let mut e = Errors::new();
    let root: &[Loc] = &[];
    let e_ = &mut e;
    let name = get(data, "name", root, e_, || None, lax::opt_string);
    let description = get(data, "description", root, e_, || None, lax::opt_string);
    let allow_domains = get(data, "allow_domains", root, e_, Vec::new, strings);
    let block_domains = get(data, "block_domains", root, e_, Vec::new, strings);
    let ignore_domains = get(data, "ignore_domains", root, e_, Vec::new, strings);
    let allow_ips = get(data, "allow_ips", root, e_, Vec::new, ip_entries);
    let block_ips = get(data, "block_ips", root, e_, Vec::new, ip_entries);
    let resolve_deny_cidrs = get(
        data,
        "resolve_deny_cidrs",
        root,
        e_,
        || DEFAULT_DENY_CIDRS.iter().map(|s| s.to_string()).collect(),
        strings,
    );
    let resolve_allow_cidrs = get(data, "resolve_allow_cidrs", root, e_, Vec::new, strings);
    // DNSConfig has no fields: any dict will do
    get(
        data,
        "dns",
        root,
        e_,
        || (),
        |v, l, e| lax::model(v, "DNSConfig", l, e).map(|_| ()),
    );
    let empty = PyValue::Dict(Vec::new());
    let proxy = proxy(
        field(data, "proxy").unwrap_or(&empty),
        &at(root, "proxy"),
        e_,
        env,
    );
    let network = network(
        field(data, "network").unwrap_or(&empty),
        &at(root, "network"),
        e_,
    );
    let database_path = get(
        data,
        "database_path",
        root,
        e_,
        || "/data/security_gateway.db".into(),
        lax::string,
    );
    let reload = get(data, "reload", root, e_, || "auto".into(), reload);
    let domain_handlers = get(data, "domain_handlers", root, e_, Vec::new, domain_handlers);
    let relay = relay_listen(
        field(data, "relay").unwrap_or(&empty),
        &at(root, "relay"),
        e_,
    );
    let ui = get(
        data,
        "ui",
        root,
        e_,
        || Language::Auto,
        |v, l, e| {
            let d = lax::model(v, "UIConfig", l, e)?;
            get(
                d,
                "language",
                l,
                e,
                || Language::Auto,
                |v, l, e| {
                    lax::literal(v, &["auto", "en", "ja"], l, e).map(|s| match s {
                        "en" => Language::En,
                        "ja" => Language::Ja,
                        _ => Language::Auto,
                    })
                },
            )
        },
    );
    if !e.list.is_empty() {
        return Err(Refusal::Fields(e.list));
    }
    let settings = Settings {
        name: name.expect(SET),
        description: description.expect(SET),
        allow_domains: allow_domains.expect(SET),
        block_domains: block_domains.expect(SET),
        ignore_domains: ignore_domains.expect(SET),
        allow_ips: allow_ips.expect(SET),
        block_ips: block_ips.expect(SET),
        resolve_deny_cidrs: resolve_deny_cidrs.expect(SET),
        resolve_allow_cidrs: resolve_allow_cidrs.expect(SET),
        proxy: proxy.expect(SET),
        network: network.expect(SET),
        database_path: database_path.expect(SET),
        relay_fingerprint,
        reload: reload.expect(SET),
        domain_handlers: domain_handlers.expect(SET),
        relay: relay.expect(SET),
        ui: ui.expect(SET),
    };
    settings.model_validators()?;
    Ok(settings)
}

/// `_port_of`: the port after the last `:`, read with Python's `int()`, or `default`.
fn port_of(listen: &str, default: PyInt) -> PyInt {
    let tail = listen.rsplit_once(':').map(|(_, p)| p).unwrap_or(listen);
    py::int(tail).unwrap_or(default)
}

/// `domain_matches` (`src/domains.py`): `domain` is covered by an entry of `patterns` — an exact
/// name, or `.example.com` / `*.example.com` for the name and everything under it, on label
/// boundaries.
pub fn domain_matches(domain: &str, patterns: &[String]) -> bool {
    let d = py::lower(domain);
    let d = py::rstrip_dots(&d);
    patterns
        .iter()
        .any(|entry| rules::Pattern::of(entry).matches_normalized(d))
}

/// `normalize_no_proxy_entry`: `*.x` is written `.x`, the rest is kept.
pub fn normalize_no_proxy_entry(entry: &str) -> String {
    let e = py::strip(entry);
    e.strip_prefix("*.")
        .map(|r| format!(".{r}"))
        .unwrap_or_else(|| e.to_string())
}

/// `merge_no_proxy`: normalize, concatenate, drop blanks and repeats (the first one stays).
pub fn merge_no_proxy<S: AsRef<str>>(groups: &[&[S]]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for group in groups {
        for entry in *group {
            let e = normalize_no_proxy_entry(entry.as_ref());
            if !e.is_empty() && !out.contains(&e) {
                out.push(e);
            }
        }
    }
    out
}

impl Settings {
    /// The model validators, in `Config`'s order.
    fn model_validators(&self) -> Result<(), Refusal> {
        // validate_git_relay_ports
        if !self.https_relay_domains().is_empty() && self.git_relay_domains().is_empty() {
            return Err(Refusal::Model(
                ModelRule::HttpsRelayNeedsGitRelay,
                "domain_handlers: https-relay needs at least one git-relay domain in this version (the relay's 443 passthrough is started with it)".into(),
            ));
        }
        let mut seen: Vec<(PyInt, &str)> = Vec::new();
        let ports = self.git_relay_ssh_ports();
        for (domain, port) in &ports {
            if let Some((_, first)) = seen.iter().find(|(p, _)| p == port) {
                return Err(Refusal::Model(
                    ModelRule::DuplicateSshPort,
                    format!(
                        "domain_handlers: git-relay domains '{first}' and '{domain}' would both listen on ssh port {port}; every git-relay domain but the default one needs its own ssh_port because the SSH exec request carries only the repository path"
                    ),
                ));
            }
            seen.push((*port, domain));
        }
        // validate_relayed_domains_are_allowed
        let missing: Vec<String> = self
            .relay_domains()
            .into_iter()
            .filter(|d| !domain_matches(d, &self.allow_domains))
            .collect();
        if !missing.is_empty() {
            return Err(Refusal::Model(
                ModelRule::RelayedNotAllowed,
                format!(
                    "domain_handlers: {} not covered by allow_domains. DNS answers with the gateway for a relayed domain, so the relay would try to reach itself. Add them to allow_domains (a wildcard such as '.github.com' counts)",
                    missing.join(", ")
                ),
            ));
        }
        // validate_direct_egress
        if self.proxy.direct_egress == DirectEgress::Deny && !self.proxy.uses_upstream() {
            return Err(Refusal::Model(
                ModelRule::DirectEgressNeedsUpstream,
                "proxy.direct_egress: 'deny' needs proxy.enabled: true and proxy.upstream_proxy set — it keeps allow_domains addresses out of the firewall so that the upstream proxy is the only way out, and without one dev would reach nothing at all. Set an upstream proxy, or leave direct_egress: allow".into(),
            ));
        }
        Ok(())
    }

    fn domains_with(&self, f: impl Fn(Handler) -> bool) -> Vec<String> {
        self.domain_handlers
            .iter()
            .filter(|(_, h)| f(h.handler))
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// Each git-relay domain and its relay SSH port (`relay.ssh_listen`'s when `ssh_port` is unset).
    pub fn git_relay_ssh_ports(&self) -> Vec<(String, PyInt)> {
        let default_port = port_of(&self.relay.ssh_listen, 22);
        self.domain_handlers
            .iter()
            .filter(|(_, h)| h.handler == Handler::Github)
            .map(|(d, h)| {
                (
                    d.clone(),
                    h.ssh_port.map(PyInt::from).unwrap_or(default_port),
                )
            })
            .collect()
    }

    pub fn git_relay_domains(&self) -> Vec<String> {
        self.domains_with(|h| h == Handler::Github)
    }

    pub fn https_relay_domains(&self) -> Vec<String> {
        self.domains_with(|h| h == Handler::HttpsRelay)
    }

    /// The domains DNS answers with the gateway's address for: git-relay, then https-relay.
    pub fn relay_domains(&self) -> Vec<String> {
        let mut out = self.git_relay_domains();
        out.extend(self.https_relay_domains());
        out
    }

    /// The domains Squid must not serve: github, https-relay and deny handlers, in file order.
    pub fn proxy_denied_domains(&self) -> Vec<String> {
        self.domains_with(|h| PROXY_DENIED_HANDLERS.contains(&h))
    }

    /// `allow_domains` minus the exact names in `proxy_denied_domains`; wildcards stay.
    pub fn proxy_allow_domains(&self) -> Vec<String> {
        let denied = self.proxy_denied_domains();
        self.allow_domains
            .iter()
            .filter(|d| {
                let n = py::lower(d);
                !denied.iter().any(|x| x == py::rstrip_dots(&n))
            })
            .cloned()
            .collect()
    }

    pub fn has_git_relay(&self) -> bool {
        !self.git_relay_domains().is_empty()
    }

    /// The ports opened in INPUT for the relay; empty without a git-relay domain. 443 is opened
    /// even with `https: reject`.
    pub fn relay_input_ports(&self) -> Vec<PyInt> {
        if !self.has_git_relay() {
            return Vec::new();
        }
        let mut ssh = vec![port_of(&self.relay.ssh_listen, 22)];
        for (_, p) in self.git_relay_ssh_ports() {
            if !ssh.contains(&p) {
                ssh.push(p);
            }
        }
        ssh.push(port_of(&self.relay.api_listen, 8420));
        ssh.push(port_of(&self.relay.https_listen, 443));
        ssh
    }

    pub fn reload_window_seconds(&self) -> Option<PyInt> {
        parse_duration(&self.reload)
    }

    pub fn reload_is_windowed(&self) -> bool {
        self.reload_window_seconds().is_some()
    }
}

impl Proxy {
    /// Whether dev's traffic has an upstream proxy to go through at all.
    pub fn uses_upstream(&self) -> bool {
        self.enabled
            && self
                .upstream_proxy
                .as_deref()
                .is_some_and(|s| !s.is_empty())
    }

    /// Whether `allow_domains` addresses are kept out of the firewall (#212).
    pub fn direct_egress_denied(&self) -> bool {
        self.direct_egress == DirectEgress::Deny && self.uses_upstream()
    }

    /// `no_proxy` as `NO_PROXY` wants it.
    pub fn normalized_no_proxy(&self) -> Vec<String> {
        merge_no_proxy(&[self.no_proxy.as_slice()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }
    fn ok(text: &str) -> Settings {
        parse(text, &no_env).unwrap_or_else(|e| panic!("{e}"))
    }
    fn refused(text: &str) -> Refusal {
        parse(text, &no_env).expect_err("should be refused")
    }
    fn paths(r: &Refusal) -> Vec<String> {
        match r {
            Refusal::Fields(f) => f.iter().map(FieldError::path).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn defaults_match_config() {
        let s = defaults(&no_env);
        assert_eq!(s.proxy.port, 3128);
        assert!(!s.proxy.enabled);
        assert!(s.proxy.cache_enabled);
        assert_eq!(s.proxy.cache_size_mb, 1000);
        assert_eq!(s.network.lan_subnets, ["10.100.0.0/16"]);
        assert!(s.network.host_enforcement);
        assert_eq!(s.reload, "auto");
        assert_eq!(s.relay.ssh_listen, "0.0.0.0:22");
        assert_eq!(s.relay.https, HttpsMode::Passthrough);
        assert_eq!(s.ui, Language::Auto);
        assert_eq!(s.resolve_deny_cidrs.len(), DEFAULT_DENY_CIDRS.len());
        assert_eq!(s.database_path, "/data/security_gateway.db");
        // json.dumps({"relay": None, "domain_handlers": None}, sort_keys=True)
        assert_eq!(
            s.relay_fingerprint,
            hex::encode(Sha256::digest(
                b"{\"domain_handlers\": null, \"relay\": null}"
            ))
        );
    }

    #[test]
    fn the_environment_overrides_the_credentials_when_non_empty() {
        let env = |n: &str| match n {
            ENV_PROXY_USERNAME => Some("alice".to_string()),
            ENV_PROXY_PASSWORD => Some(String::new()),
            _ => None,
        };
        let s = parse("proxy:\n  upstream_proxy_password: fromfile\n", &env).unwrap();
        assert_eq!(s.proxy.upstream_proxy_username.unwrap().expose(), "alice");
        assert_eq!(
            s.proxy.upstream_proxy_password.unwrap().expose(),
            "fromfile"
        );
    }

    #[test]
    fn handlers_are_normalized_and_derive_the_lists() {
        let s = ok("allow_domains: [github.com, .example.com]\ndomain_handlers:\n  GitHub.COM.:\n    handler: git-relay\n  api.example.com: {handler: https-relay}\n  t.example.com: {handler: deny}\n  s.example.com:\n");
        assert_eq!(s.git_relay_domains(), ["github.com"]);
        assert_eq!(s.relay_domains(), ["github.com", "api.example.com"]);
        assert_eq!(
            s.proxy_denied_domains(),
            ["github.com", "api.example.com", "t.example.com"]
        );
        assert_eq!(s.proxy_allow_domains(), [".example.com"]);
        assert_eq!(s.relay_input_ports(), [22, 8420, 443]);
        assert_eq!(s.domain_handlers[3].1.handler, Handler::Splice);
    }

    #[test]
    fn field_errors_are_all_reported() {
        let r = refused("proxy: {port: x}\nallow_domains: [1]\nreload: bad\n");
        let mut p = paths(&r);
        p.sort();
        assert_eq!(p, ["allow_domains.0", "proxy.port", "reload"]);
    }

    #[test]
    fn model_validators_run_in_order() {
        let r =
            refused("proxy: {direct_egress: deny}\ndomain_handlers: {a.com: {handler: github}}\n");
        assert!(
            matches!(r, Refusal::Model(ModelRule::RelayedNotAllowed, _)),
            "{r:?}"
        );
        let r = refused("domain_handlers: {a.com: {handler: https-relay}}\n");
        assert!(matches!(
            r,
            Refusal::Model(ModelRule::HttpsRelayNeedsGitRelay, _)
        ));
        let r = refused("allow_domains: [a.com, b.com]\ndomain_handlers: {a.com: {handler: github}, b.com: {handler: github}}\n");
        assert!(matches!(r, Refusal::Model(ModelRule::DuplicateSshPort, _)));
        let r = refused("proxy: {direct_egress: deny}\n");
        assert!(matches!(
            r,
            Refusal::Model(ModelRule::DirectEgressNeedsUpstream, _)
        ));
    }

    #[test]
    fn the_python_quirks_are_kept() {
        // pydantic turns `true` into 1 before the port check sees a bool
        assert_eq!(
            ok("network: {allowed_ports: [true, '80', 80.0]}\n")
                .network
                .allowed_ports,
            [1, 80]
        );
        // `int()` reads the duration
        assert_eq!(
            ok("reload: ' 3_0 M '\n").reload_window_seconds(),
            Some(1800)
        );
        // a non-string handler key becomes str(key)
        assert_eq!(ok("domain_handlers: {1: {}}\n").domain_handlers[0].0, "1");
        assert_eq!(
            ok("domain_handlers: {yes: {}}\n").domain_handlers[0].0,
            "true"
        );
        // `_port_of` reads a negative port and Python lists it
        let s = ok("allow_domains: [a.b]\ndomain_handlers: {a.b: {handler: github}}\nrelay: {ssh_listen: '0.0.0.0:-5'}\n");
        assert_eq!(s.relay_input_ports(), [-5, 8420, 443]);
    }

    #[test]
    fn top_level_shapes() {
        assert_eq!(refused("- a\n"), Refusal::NotAMapping);
        assert!(matches!(refused("1: x\n"), Refusal::NonStringKey(_)));
        assert!(matches!(
            refused("relay: {1: a, b: c}\n"),
            Refusal::Fingerprint(_)
        ));
        // the fingerprint is checked before the keys
        assert!(matches!(
            refused("yes: 1\nrelay: {1: a, b: c}\n"),
            Refusal::Fingerprint(_)
        ));
        assert!(matches!(refused("a: [\n"), Refusal::Yaml(_)));
        // a file's own relay_fingerprint is dropped
        assert_eq!(
            ok("relay_fingerprint: 5\n").relay_fingerprint,
            defaults(&no_env).relay_fingerprint
        );
    }
}
