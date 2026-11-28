//! The Relay tab: `/api/relay/config`, `/api/relay/stats`, `/api/relay/tokens` and
//! `/api/relay/audit`, ported from `src/web_ui/relay_view.py`.
//!
//! **Read only, and only what is shown.** `config.yml` is read through [`cfg::load`]'s projection;
//! `tokens.json` into [`TokenView`], which has no place for the hash every record is filed under;
//! the other state files only for whether they exist and how many lines they have. The relay's
//! own resolved configuration (`Resolved`) is not used: the Python UI rebuilt the relay's view
//! from the raw YAML, and so does this, so the answer for an odd file is the answer it was.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

use super::cfg::{self, int_or, py_get, py_str, truthy, Py, Raised};
use super::json::{obj, Json};
use super::UiView;
use crate::settings::py;
use crate::settings::yaml11::PyValue;

const DEFAULT_CAP: i128 = 1_048_576;
/// Passthrough uploads at least this large are flagged in the tab (0.2.2).
const LARGE_UPLOAD_BYTES: i128 = 1024 * 1024;

fn s(v: &str) -> PyValue {
    PyValue::Str(v.to_string())
}

/// `str(key).strip().rstrip(".").lower()`.
fn domain_key(v: &PyValue) -> String {
    py::lower(py::rstrip_dots(py::strip(&py_str(v))))
}

/// `[str(x) for x in (v or [])]`.
fn str_list(v: Option<&PyValue>) -> Py<Vec<String>> {
    match v {
        Some(x) if truthy(x) => Ok(cfg::iter_items(x)?.iter().map(py_str).collect()),
        _ => Ok(vec![]),
    }
}

/// `_port_of(listen, default)`.
fn port_of(listen: &PyValue, default: i128) -> i128 {
    let text = py_str(listen);
    let tail = text.rsplit_once(':').map_or(text.as_str(), |(_, p)| p);
    py::int(tail).unwrap_or(default)
}

/// `_perm_spec`: `[...]` is an allow list, `{allow, deny}` both.
fn perm_spec(v: Option<&PyValue>) -> Py<(Vec<String>, Vec<String>)> {
    match v {
        Some(PyValue::List(_)) => Ok((str_list(v)?, vec![])),
        Some(d @ PyValue::Dict(_)) => Ok((
            str_list(py_get(d, "allow")?)?,
            str_list(py_get(d, "deny")?)?,
        )),
        _ => Ok((vec![], vec![])),
    }
}

/// One git-relay upstream as `_git_relay_upstreams` builds it.
struct Upstream {
    domain: String,
    upstream: String,
    ssh_port: i128,
    default: bool,
    api_base: String,
    ssh_options: Vec<String>,
    max_upload_bytes: i128,
    token_path: PathBuf,
    known_hosts_path: PathBuf,
}

/// `v.get(key) or {}` that is also a dict, else an empty one.
fn dict_or_empty(config: &PyValue, key: &str) -> Py<PyValue> {
    let v = cfg::get_or_empty(config, key)?;
    Ok(if cfg::is_dict(&v) {
        v
    } else {
        PyValue::Dict(vec![])
    })
}

/// `_git_relay_upstreams`: default first (the same rule as the relay's `resolve_upstreams`).
fn git_relay_upstreams(config: &PyValue) -> Py<Vec<Upstream>> {
    let handlers = cfg::get_or_empty(config, "domain_handlers")?;
    let relay = cfg::get_or_empty(config, "relay")?;
    let PyValue::Dict(pairs) = &handlers else {
        return Ok(vec![]);
    };
    if !cfg::is_dict(&relay) {
        return Ok(vec![]);
    }
    let mut specs: Vec<(String, PyValue)> = Vec::new();
    for (domain, spec) in pairs {
        let spec = if cfg::is_dict(spec) {
            spec.clone()
        } else {
            PyValue::Dict(vec![])
        };
        if matches!(py_get(&spec, "handler")?, Some(PyValue::Str(h)) if h == "github" || h == "git-relay")
        {
            let key = domain_key(domain);
            match specs.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = spec,
                None => specs.push((key, spec)),
            }
        }
    }
    if specs.is_empty() {
        return Ok(vec![]);
    }
    specs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut explicit = None;
    let mut no_port = Vec::new();
    for (d, spec) in &specs {
        if explicit.is_none() && py_get(spec, "default")?.is_some_and(truthy) {
            explicit = Some(d.clone());
        }
        if matches!(py_get(spec, "ssh_port")?, None | Some(PyValue::None)) {
            no_port.push(d.clone());
        }
    }
    let default = match (explicit, no_port.as_slice()) {
        (Some(d), _) => d,
        (None, [only]) => only.clone(),
        _ => specs.first().map(|(d, _)| d.clone()).unwrap_or_default(),
    };
    let listen_port = port_of(&cfg::get_or(&relay, "ssh_listen", s("0.0.0.0:22"))?, 22);
    let state_dir = PathBuf::from(py_str(&cfg::get_or(&relay, "state_dir", s("/data/relay"))?));
    let relay_upstream = py_get(&relay, "upstream")?;
    let relay_api_base = py_get(&relay, "api_base")?;
    let relay_cap = int_or(py_get(&relay, "https_max_upload_bytes")?, DEFAULT_CAP)?;
    let relay_ssh_options = str_list(py_get(&relay, "ssh_options")?)?;

    let mut out = Vec::new();
    for (d, spec) in &specs {
        let is_default = *d == default;
        let host = [
            py_get(spec, "upstream")?,
            if is_default { relay_upstream } else { None },
        ]
        .into_iter()
        .flatten()
        .find(|v| truthy(v))
        .map_or_else(|| d.clone(), py_str);
        let host = py::lower(py::strip(&host));
        let ssh_port = match py_get(spec, "ssh_port")? {
            None | Some(PyValue::None) => listen_port,
            Some(p) => cfg::py_int(p)?.unwrap_or(listen_port),
        };
        let api_base = match (py_get(spec, "api_base")?, relay_api_base) {
            (Some(a), _) if truthy(a) => py_str(a),
            (_, Some(a)) if is_default && truthy(a) => py_str(a),
            _ if host == "github.com" => "https://api.github.com".to_string(),
            _ => format!("https://{host}/api/v3"),
        };
        let (token_path, known_hosts_path) = if is_default {
            (
                state_dir.join("upstream_token"),
                state_dir.join("known_hosts"),
            )
        } else {
            let dir = state_dir.join("upstreams").join(&host);
            (dir.join("upstream_token"), dir.join("known_hosts"))
        };
        let mut ssh_options = relay_ssh_options.clone();
        ssh_options.extend(str_list(py_get(spec, "ssh_options")?)?);
        let max_upload_bytes = int_or(py_get(spec, "max_upload_bytes")?, relay_cap)?;
        out.push(Upstream {
            domain: d.clone(),
            upstream: host,
            ssh_port,
            default: is_default,
            api_base,
            ssh_options,
            max_upload_bytes,
            token_path,
            known_hosts_path,
        });
    }
    out.sort_by_key(|u| !u.default);
    Ok(out)
}

/// Python's `<` between two dict keys, for `sorted(handlers.items())`.
fn key_order(a: &PyValue, b: &PyValue) -> Py<std::cmp::Ordering> {
    use PyValue::*;
    match (a, b) {
        (Str(x), Str(y)) => Ok(x.cmp(y)),
        (Int(_) | Bool(_) | Float(_), Int(_) | Bool(_) | Float(_)) => {
            let f = |v: &PyValue| match v {
                Int(i) => *i as f64,
                Bool(b) => f64::from(u8::from(*b)),
                Float(f) => *f,
                _ => 0.0,
            };
            Ok(f(a).partial_cmp(&f(b)).unwrap_or(std::cmp::Ordering::Equal))
        }
        _ => Err(Raised("'<' not supported between these keys")),
    }
}

/// `_https_relays`: the https-relay domains, by name.
fn https_relays(config: &PyValue) -> Py<Json> {
    let handlers = cfg::get_or_empty(config, "domain_handlers")?;
    let relay = cfg::get_or_empty(config, "relay")?;
    let PyValue::Dict(pairs) = &handlers else {
        return Ok(Json::Arr(vec![]));
    };
    if !cfg::is_dict(&relay) {
        return Ok(Json::Arr(vec![]));
    }
    let default_cap = int_or(py_get(&relay, "https_max_upload_bytes")?, DEFAULT_CAP)?;
    let mut sorted: Vec<&(PyValue, PyValue)> = pairs.iter().collect();
    let mut failed = None;
    sorted.sort_by(|x, y| {
        key_order(&x.0, &y.0).unwrap_or_else(|e| {
            failed = Some(e);
            std::cmp::Ordering::Equal
        })
    });
    if let Some(e) = failed {
        return Err(e);
    }
    let mut out = Vec::new();
    for (domain, spec) in sorted {
        let spec = if cfg::is_dict(spec) {
            spec.clone()
        } else {
            PyValue::Dict(vec![])
        };
        if !matches!(py_get(&spec, "handler")?, Some(PyValue::Str(h)) if h == "https-relay") {
            continue;
        }
        let d = domain_key(domain);
        let upstream = match py_get(&spec, "upstream")? {
            Some(u) if truthy(u) => py_str(u),
            _ => d.clone(),
        };
        out.push(obj([
            ("domain", Json::str(&d)),
            ("upstream", Json::Str(py::lower(py::strip(&upstream)))),
            (
                "max_upload_bytes",
                Json::Int(int_or(py_get(&spec, "max_upload_bytes")?, default_cap)?),
            ),
        ]));
    }
    Ok(Json::Arr(out))
}

/// `_count_lines`: the lines that are neither blank nor a comment; 0 when it cannot be read.
fn count_lines(path: &Path) -> i128 {
    let Ok(bytes) = std::fs::read(path) else {
        return 0;
    };
    let text = String::from_utf8_lossy(&bytes);
    // text mode reads with universal newlines: \r, \n and \r\n all end a line
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    text.split_inclusive('\n')
        .filter(|l| !py::strip(l).is_empty() && !l.starts_with('#'))
        .count() as i128
}

/// What `build_config` answers, with what `build_stats` needs from it.
struct RelayConfig {
    json: Json,
    enabled: bool,
    state_dir: String,
    authorized_keys: Option<i128>,
}

/// `build_config`.
fn build_config(config: &PyValue) -> Py<RelayConfig> {
    let upstreams = git_relay_upstreams(config)?;
    let first = upstreams.first();
    let domain = first.map(|u| u.domain.clone());
    let relay = dict_or_empty(config, "relay")?;
    let project = dict_or_empty(&relay, "project")?;

    let (p_allow, p_deny) = perm_spec(py_get(&project, "permissions")?)?;
    let default_push = match py_get(&project, "push")? {
        Some(v) if truthy(v) => str_list(Some(v))?,
        _ => vec!["sekimore/*".to_string()],
    };
    let mut default_tags = str_list(py_get(&project, "tags")?)?;
    if default_tags.is_empty() && truthy(&cfg::get_or(&relay, "allow_tags", PyValue::Bool(false))?)
    {
        default_tags = vec!["*".to_string()];
    }
    let default_delete = truthy(&cfg::get_or(&project, "delete", PyValue::Bool(false))?)
        || truthy(&cfg::get_or(&relay, "allow_delete", PyValue::Bool(false))?);
    let default_force_push = truthy(&cfg::get_or(&project, "force_push", PyValue::Bool(false))?);
    let default_signed_tags = truthy(&cfg::get_or(&project, "signed_tags", PyValue::Bool(true))?);
    let default_signing = match py_get(&project, "signing")? {
        Some(v) if truthy(v) => py_str(v),
        _ => "optional".to_string(),
    };

    // project.upstreams.<domain or host>: the upstream layer (0.2.1)
    let mut host_to_domain: Vec<(String, String)> = Vec::new();
    for u in &upstreams {
        match host_to_domain.iter_mut().find(|(h, _)| *h == u.upstream) {
            Some(slot) => slot.1 = u.domain.clone(),
            None => host_to_domain.push((u.upstream.clone(), u.domain.clone())),
        }
    }
    let to_domain = |k: &str| {
        host_to_domain
            .iter()
            .find(|(h, _)| h == k)
            .map_or_else(|| k.to_string(), |(_, d)| d.clone())
    };
    let mut layers: Vec<(String, PyValue)> = Vec::new();
    if let PyValue::Dict(raw) = cfg::get_or_empty(&project, "upstreams")? {
        for (key, layer) in raw {
            let d = to_domain(&domain_key(&key));
            let layer = if cfg::is_dict(&layer) {
                layer
            } else {
                PyValue::Dict(vec![])
            };
            match layers.iter_mut().find(|(x, _)| *x == d) {
                Some(slot) => slot.1 = layer,
                None => layers.push((d, layer)),
            }
        }
    }

    let repo_name = |r: &PyValue| -> Py<String> {
        let name = py_str(&py_get(r, "name")?.cloned().unwrap_or(PyValue::None));
        Ok(py::strip(&name).trim_start_matches('/').to_string())
    };
    let mut entries: Vec<(PyValue, String)> = Vec::new();
    let repos_v = cfg::get_or_empty(&project, "repos")?;
    let repos_items = if truthy(&repos_v) {
        cfg::iter_items(&repos_v)?
    } else {
        vec![]
    };
    for r in repos_items {
        if !cfg::is_dict(&r) || !py_get(&r, "name")?.is_some_and(truthy) {
            continue;
        }
        let name = repo_name(&r)?;
        let parts: Vec<&str> = name.split('/').collect();
        let mut host = domain.clone().unwrap_or_default();
        if let [first, _, _] = parts.as_slice() {
            if first.contains('.') {
                host = to_domain(&py::lower(first));
            }
        }
        entries.push((r, host));
    }
    for (d, layer) in &layers {
        let lr = cfg::get_or_empty(layer, "repos")?;
        let items = if truthy(&lr) {
            cfg::iter_items(&lr)?
        } else {
            vec![]
        };
        for r in items {
            if cfg::is_dict(&r) && py_get(&r, "name")?.is_some_and(truthy) {
                entries.push((r, d.clone()));
            }
        }
    }

    let empty = PyValue::Dict(vec![]);
    let mut repos = Vec::new();
    for (r, host) in &entries {
        let layer = layers
            .iter()
            .find(|(d, _)| d == host)
            .map_or(&empty, |(_, l)| l);
        let (l_allow, l_deny) = perm_spec(py_get(layer, "permissions")?)?;
        let (r_allow, r_deny) = perm_spec(py_get(r, "permissions")?)?;
        let allow: BTreeSet<&String> = p_allow.iter().chain(&l_allow).chain(&r_allow).collect();
        let deny: BTreeSet<&String> = p_deny.iter().chain(&l_deny).chain(&r_deny).collect();
        let effective: Vec<&String> = allow.difference(&deny).copied().collect();

        let mut name = repo_name(r)?;
        let parts: Vec<&str> = name.split('/').collect();
        if let [first, a, b] = parts.as_slice() {
            if first.contains('.') {
                name = format!("{a}/{b}");
            }
        }
        // the repo's own value, else the layer's
        let pick = |key: &str| -> Py<Option<PyValue>> {
            match py_get(r, key)? {
                Some(v) if *v != PyValue::None => Ok(Some(v.clone())),
                _ => Ok(py_get(layer, key)?
                    .filter(|v| **v != PyValue::None)
                    .cloned()),
            }
        };
        let push = match pick("push")? {
            Some(v) => cfg::iter_items(&v)?.iter().map(py_str).collect(),
            None => default_push.clone(),
        };
        let tags = match pick("tags")? {
            Some(v) => cfg::iter_items(&v)?.iter().map(py_str).collect(),
            None => default_tags.clone(),
        };
        let delete = pick("delete")?.map_or(default_delete, |v| truthy(&v));
        let force_push = pick("force_push")?.map_or(default_force_push, |v| truthy(&v));
        let signed_tags = pick("signed_tags")?.map_or(default_signed_tags, |v| truthy(&v));
        let signing = pick("signing")?.map_or_else(|| default_signing.clone(), |v| py_str(&v));
        repos.push(obj([
            ("name", Json::Str(name)),
            (
                "mode",
                Json::Str(py_str(&cfg::get_or(r, "mode", s("read-only"))?)),
            ),
            ("bases", Json::strs(&str_list(py_get(r, "bases")?)?)),
            ("push", Json::strs(&push)),
            ("tags", Json::strs(&tags)),
            ("delete", Json::Bool(delete)),
            ("force_push", Json::Bool(force_push)),
            ("signed_tags", Json::Bool(signed_tags)),
            ("signing", Json::Str(signing)),
            ("permissions", Json::strs(&effective)),
            ("host", Json::str(host)),
        ]));
    }

    let state_dir = py_str(&cfg::get_or(&relay, "state_dir", s("/data/relay"))?);
    let enabled = domain.is_some();
    let deny_set: BTreeSet<&String> = p_deny.iter().collect();
    let allow_set: BTreeSet<&String> = p_allow.iter().collect();
    let permissions: Vec<&String> = allow_set.difference(&deny_set).copied().collect();
    let project_name = match py_get(&project, "name")? {
        Some(n) if truthy(n) => Json::Str(py_str(n)),
        _ => Json::Null,
    };
    let field = |key: &str, default: &str| -> Py<Json> {
        Ok(Json::Str(py_str(&cfg::get_or(&relay, key, s(default))?)))
    };

    let mut fields: Vec<(String, Json)> = vec![
        ("enabled".into(), Json::Bool(enabled)),
        ("domain".into(), Json::opt_str(domain.clone())),
        (
            "upstream".into(),
            Json::opt_str(first.map(|u| u.upstream.clone())),
        ),
        ("project".into(), project_name),
        ("https".into(), field("https", "passthrough")?),
        ("bootstrap".into(), field("bootstrap", "auto")?),
        ("token_ttl".into(), field("token_ttl", "12h")?),
        ("allow_delete".into(), Json::Bool(default_delete)),
        ("allow_tags".into(), Json::Bool(!default_tags.is_empty())),
        ("tags".into(), Json::strs(&default_tags)),
        (
            "permissions_deny".into(),
            Json::strs(&deny_set.iter().collect::<Vec<_>>()),
        ),
        ("ssh_listen".into(), field("ssh_listen", "0.0.0.0:22")?),
        ("api_listen".into(), field("api_listen", "0.0.0.0:8420")?),
        ("state_dir".into(), Json::str(&state_dir)),
        ("permissions".into(), Json::strs(&permissions)),
        ("repos".into(), Json::Arr(repos)),
    ];

    let mut authorized_keys = None;
    if enabled {
        let sd = PathBuf::from(&state_dir);
        let mut names: Vec<String> = [
            "host_key",
            "authorized_keys",
            "known_hosts",
            "upstream_token",
            "tokens.json",
            "audit.jsonl",
        ]
        .iter()
        .map(|n| n.to_string())
        .collect();
        for u in upstreams.iter().filter(|u| !u.default) {
            names.push(format!("upstreams/{}/upstream_token", u.upstream));
            names.push(format!("upstreams/{}/known_hosts", u.upstream));
        }
        let mut files = Vec::new();
        for name in &names {
            let p = sd.join(name);
            let present = p.exists();
            let count = (present
                && (name.ends_with("authorized_keys") || name.ends_with("known_hosts")))
            .then(|| count_lines(&p));
            if name == "authorized_keys" && authorized_keys.is_none() {
                authorized_keys = Some(count.unwrap_or(0));
            }
            files.push(obj([
                ("name", Json::str(name)),
                ("present", Json::Bool(present)),
                ("count", Json::opt_int(count)),
            ]));
        }
        let ups: Vec<Json> = upstreams
            .iter()
            .map(|u| {
                obj([
                    ("domain", Json::str(&u.domain)),
                    ("upstream", Json::str(&u.upstream)),
                    ("ssh_port", Json::Int(u.ssh_port)),
                    ("default", Json::Bool(u.default)),
                    ("api_base", Json::str(&u.api_base)),
                    ("ssh_options", Json::strs(&u.ssh_options)),
                    ("max_upload_bytes", Json::Int(u.max_upload_bytes)),
                    ("token_present", Json::Bool(u.token_path.exists())),
                    (
                        "known_hosts_count",
                        Json::opt_int(
                            u.known_hosts_path
                                .exists()
                                .then(|| count_lines(&u.known_hosts_path)),
                        ),
                    ),
                ])
            })
            .collect();
        fields.push(("upstreams".into(), Json::Arr(ups)));
        fields.push(("https_relays".into(), https_relays(config)?));
        fields.push((
            "https_max_upload_bytes".into(),
            Json::Int(int_or(
                py_get(&relay, "https_max_upload_bytes")?,
                DEFAULT_CAP,
            )?),
        ));
        fields.push(("state_files".into(), Json::Arr(files)));
        fields.push((
            "bootstrap_disabled".into(),
            Json::Bool(sd.join("bootstrap.disabled").exists()),
        ));
    } else {
        fields.push(("upstreams".into(), Json::Arr(vec![])));
        fields.push(("https_relays".into(), Json::Arr(vec![])));
        fields.push(("https_max_upload_bytes".into(), Json::Int(DEFAULT_CAP)));
        fields.push(("state_files".into(), Json::Arr(vec![])));
        fields.push(("bootstrap_disabled".into(), Json::Bool(false)));
    }
    Ok(RelayConfig {
        json: Json::Obj(fields),
        enabled,
        state_dir,
        authorized_keys,
    })
}

// ---- timestamps --------------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// `parse_ts`: RFC 3339 in UTC (`…Z`, any number of fractional digits) to epoch seconds. Not a
/// string or not that shape is None; that shape with an impossible date raises, as `strptime` did.
pub fn parse_ts(v: Option<&Value>) -> Py<Option<f64>> {
    let Some(Value::String(text)) = v else {
        return Ok(None);
    };
    // `$` also matches before a final newline
    let t = text.strip_suffix('\n').unwrap_or(text);
    let Some(t) = t.strip_suffix('Z') else {
        return Ok(None);
    };
    let (main, frac) = match t.split_once('.') {
        Some((m, f)) => (m, Some(f)),
        None => (t, None),
    };
    let b = main.as_bytes();
    let shape = b.len() == 19
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        });
    if !shape || frac.is_some_and(|f| f.is_empty() || !f.bytes().all(|c| c.is_ascii_digit())) {
        return Ok(None);
    }
    let num = |a: usize, z: usize| -> i64 {
        main.get(a..z)
            .and_then(|x| x.parse::<i64>().ok())
            .unwrap_or(-1)
    };
    let (y, mo, d, h, mi, se) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    );
    if y < 1
        || !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
        || h > 23
        || mi > 59
        || se > 59
    {
        return Err(Raised("time data does not match a valid date"));
    }
    let mut ts = (days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se) as f64;
    if let Some(f) = frac {
        let mut nine: String = f.chars().take(9).collect();
        while nine.len() < 9 {
            nine.push('0');
        }
        ts += nine.parse::<f64>().unwrap_or(0.0) / 1_000_000_000.0;
    }
    Ok(Some(ts))
}

// ---- JSON values as Python sees them -------------------------------------------------------------

/// `str(v)` of a value `json.loads` made.
fn json_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => json_repr(other),
    }
}

fn json_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (None, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => py::float_repr(f),
            _ => n.to_string(),
        },
        Value::String(s) => cfg::repr_str(s),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(json_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}: {}", cfg::repr_str(k), json_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `int(v)` for `_int_or` and `use_count`: None where Python raises TypeError / ValueError.
fn json_int(v: &Value) -> Option<i128> {
    match v {
        Value::Bool(b) => Some(i128::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .or_else(|| n.as_f64().map(|f| f.trunc() as i128)),
        Value::String(s) => py::int(s),
        _ => None,
    }
}

/// `_field`: a non-empty string, `-` being the relay's own "unknown".
fn field(o: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match o.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() || s == "-" => None,
        Some(v) => Some(json_str(v)),
    }
}

/// A `str | None` model field: a string, or null; anything else fails the model.
fn opt_str_field(o: &serde_json::Map<String, Value>, key: &str) -> Py<Json> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(Json::Null),
        Some(Value::String(s)) => Ok(Json::str(s)),
        Some(_) => Err(Raised("Input should be a valid string")),
    }
}

// ---- tokens.json -------------------------------------------------------------------------------

/// One record of `tokens.json`, as much as the tab shows. The hash it is filed under is not here.
#[derive(Default)]
struct TokenView {
    label: Option<Value>,
    project: Option<Value>,
    issued_at: Option<Value>,
    expires_at: Option<Value>,
    last_used: Option<Value>,
    use_count: Option<Value>,
    revoked: Option<Value>,
}

/// A record that is a JSON object, or something else (skipped, as the Python skipped it).
enum Record {
    View(Box<TokenView>),
    NotADict,
}

impl<'de> serde::Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Record;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a token record")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Record, A::Error> {
                let mut t = TokenView::default();
                while let Some(k) = m.next_key::<String>()? {
                    let slot = match k.as_str() {
                        "label" => &mut t.label,
                        "project" => &mut t.project,
                        "issued_at" => &mut t.issued_at,
                        "expires_at" => &mut t.expires_at,
                        "last_used" => &mut t.last_used,
                        "use_count" => &mut t.use_count,
                        "revoked" => &mut t.revoked,
                        _ => {
                            m.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    *slot = Some(m.next_value::<Value>()?);
                }
                Ok(Record::View(Box::new(t)))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_str<E>(self, _: &str) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_unit<E>(self) -> Result<Record, E> {
                Ok(Record::NotADict)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Record, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Record::NotADict)
            }
        }
        d.deserialize_any(V)
    }
}

/// `data.get("records")` when it is a dict: its values in file order (a repeated key keeps its
/// first place and its last value, as a Python dict does). The keys are compared and dropped.
enum Records {
    Some(Vec<Record>),
    None,
}

struct RecordsSeed;

impl<'de> serde::de::DeserializeSeed<'de> for RecordsSeed {
    type Value = Records;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Records, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Records;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("the records")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Records, A::Error> {
                let mut keyed: Vec<(String, Record)> = Vec::new();
                while let Some(k) = m.next_key::<String>()? {
                    let rec = m.next_value::<Record>()?;
                    match keyed.iter_mut().find(|(x, _)| *x == k) {
                        Some(slot) => slot.1 = rec,
                        None => keyed.push((k, rec)),
                    }
                }
                Ok(Records::Some(keyed.into_iter().map(|(_, r)| r).collect()))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_str<E>(self, _: &str) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_unit<E>(self) -> Result<Records, E> {
                Ok(Records::None)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<Records, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Records::None)
            }
        }
        d.deserialize_any(V)
    }
}

struct TokensFile(Records);

impl<'de> serde::Deserialize<'de> for TokensFile {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TokensFile;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("tokens.json")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<TokensFile, A::Error> {
                let mut records = Records::None;
                while let Some(k) = m.next_key::<String>()? {
                    if k == "records" {
                        records = m.next_value_seed(RecordsSeed)?;
                    } else {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(TokensFile(records))
            }
            fn visit_bool<E>(self, _: bool) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_str<E>(self, _: &str) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_unit<E>(self) -> Result<TokensFile, E> {
                Ok(TokensFile(Records::None))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<TokensFile, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(TokensFile(Records::None))
            }
        }
        d.deserialize_any(V)
    }
}

struct TokenRow {
    issued_at: Option<f64>,
    state: &'static str,
    json: Json,
}

/// `read_tokens`: labels and metadata, newest first.
fn read_tokens(state_dir: &Path, now: f64) -> Py<Vec<TokenRow>> {
    let Ok(bytes) = std::fs::read(state_dir.join("tokens.json")) else {
        return Ok(vec![]);
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Err(Raised("tokens.json is not UTF-8"));
    };
    let Ok(TokensFile(Records::Some(records))) = serde_json::from_str::<TokensFile>(&text) else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for rec in records {
        let Record::View(t) = rec else {
            continue;
        };
        let expires = parse_ts(t.expires_at.as_ref())?;
        let revoked = t.revoked.as_ref().is_some_and(json_truthy);
        let state = if revoked {
            "revoked"
        } else if expires.is_some_and(|e| now > e) {
            "expired"
        } else {
            "active"
        };
        let issued = parse_ts(t.issued_at.as_ref())?;
        let use_count = match t.use_count.as_ref() {
            None => 0,
            Some(v) if !json_truthy(v) => 0,
            Some(v) => json_int(v).ok_or(Raised("int() of use_count failed"))?,
        };
        let label = t.label.as_ref().map_or_else(|| "?".to_string(), json_str);
        let project = t.project.as_ref().map_or_else(String::new, json_str);
        out.push(TokenRow {
            issued_at: issued,
            state,
            json: obj([
                ("label", Json::Str(label)),
                ("project", Json::Str(project)),
                ("issued_at", Json::opt_float(issued)),
                ("expires_at", Json::opt_float(expires)),
                (
                    "last_used",
                    Json::opt_float(parse_ts(t.last_used.as_ref())?),
                ),
                ("use_count", Json::Int(use_count)),
                ("state", Json::str(state)),
            ]),
        });
    }
    // `sort(key=issued_at or 0, reverse=True)`: stable, so equal keys keep their order
    out.sort_by(|a, b| {
        let k = |t: &TokenRow| t.issued_at.filter(|f| *f != 0.0).unwrap_or(0.0);
        k(b).partial_cmp(&k(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(out)
}

fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

// ---- audit.jsonl -------------------------------------------------------------------------------

const ALLOW_EVENTS: [(&str, &str); 5] = [
    ("relay_ok", "GIT"),
    ("api_ok", "API"),
    ("https_passthrough", "HTTPS"),
    ("ssh_auth_ok", "SSH"),
    ("bootstrap_ok", "BOOTSTRAP"),
];
const DENY_EVENTS: [(&str, &str); 22] = [
    ("repo_denied", "GIT"),
    ("push_denied", "GIT"),
    ("push_rejected", "GIT"),
    ("relay_failed", "GIT"),
    ("pr_failed", "API"),
    ("api_error", "API"),
    ("token_denied", "API"),
    ("access_denied", "API"),
    ("bootstrap_denied", "BOOTSTRAP"),
    ("bootstrap_disabled", "BOOTSTRAP"),
    ("cmd_rejected", "SSH"),
    ("ssh_auth_denied", "SSH"),
    ("ssh_channel_rejected", "SSH"),
    ("ssh_exec_rejected", "SSH"),
    ("ssh_request_rejected", "SSH"),
    ("ssh_rejected", "SSH"),
    ("ssh_failed", "SSH"),
    ("https_rejected", "HTTPS"),
    ("https_failed", "HTTPS"),
    ("upstream_preflight_failed", "GIT"),
    ("upstream_spawn_failed", "GIT"),
    ("https_upload_capped", "HTTPS"),
];
const SYSTEM_EVENTS: [(&str, &str); 2] = [
    ("serve_started", "SYSTEM"),
    ("bootstrap_enabled", "BOOTSTRAP"),
];

const DETAIL_KEYS: [&str; 11] = [
    "method",
    "bytes_in",
    "bytes_out",
    "cap",
    "ms",
    "status",
    "cmdline",
    "fingerprint",
    "kind",
    "client_label",
    "token_label",
];

struct AuditEntry {
    timestamp: f64,
    action: &'static str,
    event: String,
    large: bool,
    json: Json,
}

fn lookup(table: &[(&str, &'static str)], event: &str) -> Option<&'static str> {
    table.iter().find(|(e, _)| *e == event).map(|(_, c)| *c)
}

/// `to_entry`: one audit line shaped like the dashboard's LogEntry.
fn to_entry(o: &serde_json::Map<String, Value>) -> Py<Option<AuditEntry>> {
    let event = o.get("event").map_or_else(String::new, json_str);
    if event.is_empty() {
        return Ok(None);
    }
    let (component, action) = if let Some(c) = lookup(&ALLOW_EVENTS, &event) {
        (c, "ALLOWED")
    } else if let Some(c) = lookup(&DENY_EVENTS, &event) {
        (c, "BLOCKED")
    } else if let Some(c) = lookup(&SYSTEM_EVENTS, &event) {
        (c, "INFO")
    } else if ["denied", "rejected", "failed", "error"]
        .iter()
        .any(|w| event.contains(w))
    {
        ("RELAY", "BLOCKED")
    } else {
        ("RELAY", "INFO")
    };
    let Some(ts) = parse_ts(o.get("ts"))? else {
        return Ok(None);
    };
    let mut details: Vec<String> = Vec::new();
    for k in DETAIL_KEYS {
        match o.get(k) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.is_empty() => {}
            Some(v) => details.push(format!("{k}={}", json_str(v))),
        }
    }
    // the host the relay dialed, else what the client asked for; both only when they differ
    let upstream = field(o, "upstream");
    let sni = field(o, "sni");
    let destination = upstream.clone().or_else(|| sni.clone());
    for (name, value) in [("sni", &sni), ("upstream", &upstream)] {
        if let Some(v) = value {
            if Some(v) != destination.as_ref() {
                details.push(format!("{name}={v}"));
            }
        }
    }
    let reason = field(o, "reason");
    let detail = if details.is_empty() {
        reason.clone()
    } else {
        Some(details.join(" "))
    };
    let large = event == "https_passthrough"
        && o.get("bytes_in").and_then(json_int).unwrap_or(0) >= LARGE_UPLOAD_BYTES;
    let peer = match o.get("peer") {
        Some(p) if json_truthy(p) => Json::Str(json_str(p)),
        _ => Json::Null,
    };
    let repo = match o.get("repo") {
        None | Some(Value::Null) => Json::Null,
        Some(v) => {
            let s = json_str(v);
            if s.is_empty() {
                Json::Null
            } else {
                Json::Str(s)
            }
        }
    };
    let json = obj([
        ("timestamp", Json::Float(ts)),
        ("component", Json::str(component)),
        ("action", Json::str(action)),
        ("event", Json::str(&event)),
        ("actor", opt_str_field(o, "actor")?),
        ("peer", peer),
        ("destination", Json::opt_str(destination)),
        ("repo", repo),
        ("verb", opt_str_field(o, "verb")?),
        ("path", opt_str_field(o, "path")?),
        ("label", opt_str_field(o, "label")?),
        ("reason", Json::opt_str(reason)),
        ("detail", Json::opt_str(detail)),
        (
            "flag",
            if large {
                Json::str("large_upload")
            } else {
                Json::Null
            },
        ),
        ("edge", Json::opt_str(field(o, "edge"))),
    ]);
    Ok(Some(AuditEntry {
        timestamp: ts,
        action,
        event,
        large,
        json,
    }))
}

/// `str.splitlines()`: every line boundary Python knows.
fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        out.push(text.get(start..i).unwrap_or_default());
        let mut next = i + c.len_utf8();
        if c == '\r' {
            if let Some((j, '\n')) = chars.peek().copied() {
                chars.next();
                next = j + 1;
            }
        }
        start = next;
    }
    if start < text.len() {
        out.push(text.get(start..).unwrap_or_default());
    }
    out
}

/// `_tail_lines`: up to `max_lines` lines from the last 4 MiB, the first one dropped when the
/// read began mid-file.
fn tail_lines(path: &Path, max_lines: usize) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return vec![];
    };
    let Ok(size) = f.metadata().map(|m| m.len()) else {
        return vec![];
    };
    let start = size.saturating_sub(MAX_BYTES);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_err() || f.read_to_end(&mut buf).is_err() {
        return vec![];
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = splitlines(&text);
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(max_lines);
    lines
        .into_iter()
        .skip(if max_lines > 0 { skip } else { 0 })
        .map(String::from)
        .collect()
}

/// `read_audit`: newest first, `kind` = all | allowed | blocked.
fn read_audit(state_dir: &Path, limit: usize, kind: &str) -> Py<Vec<AuditEntry>> {
    let raw = tail_lines(
        &state_dir.join("audit.jsonl"),
        (limit.saturating_mul(8)).max(400),
    );
    let mut out = Vec::new();
    for line in raw.iter().rev() {
        let line = py::strip(line);
        if line.is_empty() {
            continue;
        }
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(entry) = to_entry(&o)? else {
            continue;
        };
        if (kind == "allowed" && entry.action != "ALLOWED")
            || (kind == "blocked" && entry.action != "BLOCKED")
        {
            continue;
        }
        out.push(entry);
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

// ---- the endpoints -----------------------------------------------------------------------------

/// `GET /api/relay/config`.
pub fn config(view: &UiView) -> Py<Json> {
    Ok(build_config(&cfg::load(&view.config_path))?.json)
}

fn state_dir_of(view: &UiView) -> Py<PathBuf> {
    Ok(PathBuf::from(
        build_config(&cfg::load(&view.config_path))?.state_dir,
    ))
}

/// `GET /api/relay/tokens`.
pub fn tokens(view: &UiView, now: f64) -> Py<Json> {
    let rows = read_tokens(&state_dir_of(view)?, now)?;
    Ok(Json::Arr(rows.into_iter().map(|t| t.json).collect()))
}

/// `GET /api/relay/audit?limit=&kind=`.
pub fn audit(view: &UiView, limit: i128, kind: Option<&str>) -> Py<Json> {
    let limit = limit.clamp(1, 1000) as usize;
    let kind = kind
        .filter(|k| matches!(*k, "allowed" | "blocked"))
        .unwrap_or("all");
    let entries = read_audit(&state_dir_of(view)?, limit, kind)?;
    Ok(Json::Arr(entries.into_iter().map(|e| e.json).collect()))
}

/// `GET /api/relay/stats`: the last 24 hours of the audit log, and the tokens and keys.
pub fn stats(view: &UiView, now: f64) -> Py<Json> {
    let cfgv = build_config(&cfg::load(&view.config_path))?;
    if !cfgv.enabled {
        return Ok(obj([
            ("enabled", Json::Bool(false)),
            ("allowed", Json::Int(0)),
            ("blocked", Json::Int(0)),
            ("tokens_active", Json::Int(0)),
            ("tokens_total", Json::Int(0)),
            ("keys", Json::Int(0)),
            ("large_uploads", Json::Int(0)),
            ("upload_capped", Json::Int(0)),
        ]));
    }
    let sd = PathBuf::from(&cfgv.state_dir);
    let cutoff = now - 24.0 * 3600.0;
    let (mut allowed, mut blocked, mut large, mut capped) = (0, 0, 0, 0);
    for e in read_audit(&sd, 5000, "all")? {
        if e.timestamp < cutoff {
            break;
        }
        match e.action {
            "ALLOWED" => allowed += 1,
            "BLOCKED" => blocked += 1,
            _ => {}
        }
        if e.large {
            large += 1;
        }
        if e.event == "https_upload_capped" {
            capped += 1;
        }
    }
    let tokens = read_tokens(&sd, now)?;
    Ok(obj([
        ("enabled", Json::Bool(true)),
        ("allowed", Json::Int(allowed)),
        ("blocked", Json::Int(blocked)),
        (
            "tokens_active",
            Json::Int(tokens.iter().filter(|t| t.state == "active").count() as i128),
        ),
        ("tokens_total", Json::Int(tokens.len() as i128)),
        ("keys", Json::Int(cfgv.authorized_keys.unwrap_or(0))),
        ("large_uploads", Json::Int(large)),
        ("upload_capped", Json::Int(capped)),
    ]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_ts_reads_rfc3339_with_and_without_a_fraction() {
        assert_eq!(
            parse_ts(Some(&json!("2026-01-02T03:04:05Z"))).unwrap(),
            Some(1_767_323_045.0)
        );
        let f = parse_ts(Some(&json!("2026-01-02T03:04:05.123456789123Z")))
            .unwrap()
            .unwrap();
        assert!((f - 1_767_323_045.123_456_7).abs() < 1e-6);
        assert_eq!(
            parse_ts(Some(&json!("2026-01-02T03:04:05Z\n"))).unwrap(),
            Some(1_767_323_045.0)
        );
    }

    #[test]
    fn parse_ts_rejects_garbage_and_raises_on_an_impossible_date() {
        for v in [
            json!(1),
            json!(null),
            json!("yesterday"),
            json!("2026-01-02 03:04:05Z"),
            json!("2026-01-02T03:04:05.Z"),
        ] {
            assert_eq!(parse_ts(Some(&v)).unwrap(), None, "{v}");
        }
        assert!(parse_ts(Some(&json!("2026-02-30T00:00:00Z"))).is_err());
        assert!(parse_ts(Some(&json!("2026-01-01T00:00:60Z"))).is_err());
    }

    #[test]
    fn a_token_record_has_no_place_for_its_hash() {
        let text = r#"{"version":1,"records":{"deadbeefhash":{"label":"deadbeef","project":"p","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","use_count":3,"fingerprint":"SHA256:x"},"x":5}}"#;
        let TokensFile(Records::Some(recs)) = serde_json::from_str::<TokensFile>(text).unwrap()
        else {
            panic!("no records");
        };
        assert_eq!(recs.len(), 2);
        assert!(matches!(recs.get(1), Some(Record::NotADict)));
    }

    #[test]
    fn splitlines_knows_every_boundary() {
        assert_eq!(splitlines("a\r\nb\rc\u{2028}d\n"), ["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n\nb"), ["a", "", "b"]);
    }
}
