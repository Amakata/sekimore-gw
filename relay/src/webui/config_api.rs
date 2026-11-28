//! `/api/config`, `/api/proxy-env`, `/api/gateway-info` and `/api/i18n`.
//!
//! `/api/config` is the endpoint that once leaked (Issue #217): the generated `squid.conf` carries
//! the upstream proxy's password in `cache_peer … login=user:password`, and the file was returned
//! whole. It goes out with the password blanked, as before, and the credential's *state* comes
//! from the `serve` side as a value with nothing in it (`CredentialState`).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::cfg::{self, py_get, Py, Raised};
use super::http::Req;
use super::i18n;
use super::json::{obj, Json};
use super::{CredentialState, UiView};
use crate::settings::py;
use crate::settings::yaml11::{DateTime, PyValue};
use crate::settings::{lax, merge_no_proxy, NO_PROXY_ALWAYS};

/// The three versions `/api/config` reports. `version_core` and `version_webui` were constants of
/// the Python packages (`src/__init__.py`, `src/web_ui/__init__.py`) and stay what they were.
pub const VERSION_CORE: &str = "0.1.3";
pub const VERSION_WEBUI: &str = "0.3.2";

/// `version_package`: the gateway's version, which the Python UI read from the installed package
/// and which is the relay's own (the two are released together, one number).
pub fn version_package() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The handlers whose names Squid refuses (`PROXY_DENIED_HANDLERS`).
const PROXY_DENIED: [&str; 3] = ["github", "https-relay", "deny"];

/// A raw value as FastAPI's encoder writes it: a date in ISO form, a mapping's keys as strings.
pub fn raw_json(v: &PyValue) -> Json {
    match v {
        PyValue::None => Json::Null,
        PyValue::Bool(b) => Json::Bool(*b),
        PyValue::Int(i) => Json::Int(*i),
        PyValue::Float(f) => Json::Float(*f),
        PyValue::Str(s) => Json::Str(s.clone()),
        PyValue::Date(d) => Json::Str(format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)),
        PyValue::DateTime(d) => Json::Str(isoformat(d)),
        PyValue::List(items) => Json::Arr(items.iter().map(raw_json).collect()),
        PyValue::Dict(pairs) => Json::Obj(
            pairs
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        PyValue::Bool(true) => "true".to_string(),
                        PyValue::Bool(false) => "false".to_string(),
                        PyValue::None => "null".to_string(),
                        PyValue::Date(_) | PyValue::DateTime(_) => match raw_json(k) {
                            Json::Str(s) => s,
                            _ => String::new(),
                        },
                        other => cfg::py_str(other),
                    };
                    (key, raw_json(v))
                })
                .collect(),
        ),
    }
}

/// `datetime.isoformat()`.
fn isoformat(d: &DateTime) -> String {
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        d.date.year, d.date.month, d.date.day, d.hour, d.minute, d.second
    );
    if d.microsecond != 0 {
        s.push_str(&format!(".{:06}", d.microsecond));
    }
    if let Some(m) = d.offset_minutes {
        let sign = if m < 0 { '-' } else { '+' };
        s.push_str(&format!("{sign}{:02}:{:02}", m.abs() / 60, m.abs() % 60));
    }
    s
}

/// `GET /api/gateway-info`.
pub fn gateway_info(view: &UiView) -> Py<Json> {
    let config = cfg::load(&view.config_path);
    let name = py_get(&config, "name")?.map_or(Json::Null, raw_json);
    let description = py_get(&config, "description")?.map_or(Json::Null, raw_json);
    Ok(obj([("name", name), ("description", description)]))
}

/// `GET /api/proxy-env`: what `agent-setup.sh` writes into dev's `HTTP_PROXY` / `NO_PROXY`.
pub fn proxy_env(view: &UiView) -> Py<Json> {
    let config = cfg::load(&view.config_path);
    let proxy = cfg::get_or_empty(&config, "proxy")?;
    let handlers = cfg::get_or_empty(&config, "domain_handlers")?;

    let mut denied: Vec<String> = Vec::new();
    if let PyValue::Dict(pairs) = &handlers {
        for (domain, spec) in pairs {
            let handler = match spec {
                PyValue::Dict(_) => cfg::get_or(spec, "handler", PyValue::Str("splice".into()))?,
                _ => PyValue::Str("splice".into()),
            };
            let handler = match &handler {
                PyValue::Str(h) if h == "git-relay" => "github",
                PyValue::Str(h) => h.as_str(),
                _ => "",
            };
            if PROXY_DENIED.contains(&handler) {
                denied.push(py::lower(py::rstrip_dots(py::strip(&cfg::py_str(domain)))));
            }
        }
    }

    // Written as one string rather than a list, `Config` would have refused the file at start-up;
    // the UI read it anyway
    let operator: Vec<String> = match cfg::py_get(&proxy, "no_proxy")? {
        Some(v) if cfg::truthy(v) => match v {
            PyValue::Str(s) => s
                .split(',')
                .filter(|e| !py::strip(e).is_empty())
                .map(String::from)
                .collect(),
            PyValue::List(items) => items.iter().map(cfg::py_str).collect(),
            _ => vec![],
        },
        _ => vec![],
    };

    let enabled = cfg::get_or(&proxy, "enabled", PyValue::Bool(false))?;
    let configured =
        cfg::truthy(&enabled) && cfg::py_get(&proxy, "upstream_proxy")?.is_some_and(cfg::truthy);
    let port = cfg::py_int(&cfg::get_or(&proxy, "port", PyValue::Int(3128))?)?
        .ok_or(Raised("int() of a value that is not a number"))?;
    let direct = cfg::py_str(&cfg::get_or(
        &proxy,
        "direct_egress",
        PyValue::Str("allow".into()),
    )?);
    let always: Vec<String> = NO_PROXY_ALWAYS.iter().map(|s| s.to_string()).collect();
    let no_proxy = merge_no_proxy(&[&denied[..], &operator[..], &always[..]]);
    Ok(obj([
        ("configured", Json::Bool(configured)),
        ("port", Json::Int(port)),
        ("no_proxy", Json::strs(&no_proxy)),
        ("direct_egress", Json::Str(direct)),
    ]))
}

/// `redact_squid_config`: `login=<user>:<password>` loses the password (#217). Squid's other
/// `login=` forms (PASS, PASSTHRU, NEGOTIATE, PROXYPASS) have no colon and are left alone. The
/// regular expression it replaces is `(login=[^:\s]+:)\S+`, applied left to right.
pub fn redact_squid_config(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if let Some(end_of_user) = login_at(&chars, i) {
            out.extend(chars.get(i..end_of_user).unwrap_or_default());
            out.push_str("***");
            i = end_of_user;
            while chars.get(i).is_some_and(|c| !py::is_space(*c)) {
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Where `login=<user>:` ends when it starts at `i` and a non-blank character follows it.
fn login_at(chars: &[char], i: usize) -> Option<usize> {
    const LOGIN: [char; 6] = ['l', 'o', 'g', 'i', 'n', '='];
    if chars.get(i..i + LOGIN.len())? != LOGIN {
        return None;
    }
    let mut j = i + LOGIN.len();
    let user_start = j;
    while chars.get(j).is_some_and(|c| *c != ':' && !py::is_space(*c)) {
        j += 1;
    }
    if j == user_start || chars.get(j) != Some(&':') {
        return None;
    }
    j += 1;
    chars.get(j).filter(|c| !py::is_space(**c))?;
    Some(j)
}

fn squid(path: &Path) -> Json {
    let text = path
        .exists()
        .then(|| std::fs::read(path).ok())
        .flatten()
        .and_then(|b| String::from_utf8(b).ok());
    match text {
        Some(t) => obj([
            ("available", Json::Bool(true)),
            ("config_text", Json::Str(redact_squid_config(&t))),
        ]),
        None => obj([
            ("available", Json::Bool(false)),
            ("config_text", Json::Null),
        ]),
    }
}

/// The outcome of one command run with a deadline.
enum Ran {
    Done {
        ok: bool,
        stdout: String,
        stderr: String,
    },
    NotFound,
    TimedOut,
    Failed(String),
}

fn run_with_deadline(program: &Path, args: &[&str], deadline: Duration) -> Ran {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ran::NotFound,
        Err(e) => return Ran::Failed(e.to_string()),
    };
    let drain = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Ran::Failed(e.to_string()),
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    match status {
        Some(s) => Ran::Done {
            ok: s.success(),
            stdout,
            stderr,
        },
        None => Ran::TimedOut,
    }
}

fn iptables_json(
    available: bool,
    filter: Option<String>,
    nat: Option<String>,
    error: Option<String>,
) -> Json {
    obj([
        ("available", Json::Bool(available)),
        ("filter_rules", Json::opt_str(filter)),
        ("nat_rules", Json::opt_str(nat)),
        ("error", Json::opt_str(error)),
    ])
}

/// `_run_iptables`: the filter and nat tables, five seconds each.
fn iptables(cmd: &Path) -> Json {
    const DEADLINE: Duration = Duration::from_secs(5);
    // the message names the command, not where it was looked for
    let name = cmd.file_name().map_or_else(
        || cmd.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let filter = match run_with_deadline(cmd, &["-L", "-n", "-v"], DEADLINE) {
        Ran::Done {
            ok: true, stdout, ..
        } => stdout,
        Ran::Done { stderr, .. } => {
            return iptables_json(false, None, None, Some(py::strip(&stderr).to_string()))
        }
        Ran::NotFound => {
            return iptables_json(false, None, None, Some(format!("{name} not found")))
        }
        Ran::TimedOut => return iptables_json(false, None, None, Some("Command timed out".into())),
        Ran::Failed(e) => return iptables_json(false, None, None, Some(e)),
    };
    let nat = match run_with_deadline(cmd, &["-t", "nat", "-L", "-n", "-v"], DEADLINE) {
        Ran::Done {
            ok: true, stdout, ..
        } => Some(stdout),
        Ran::Done { .. } => None,
        Ran::NotFound => {
            return iptables_json(false, None, None, Some(format!("{name} not found")))
        }
        Ran::TimedOut => return iptables_json(false, None, None, Some("Command timed out".into())),
        Ran::Failed(e) => return iptables_json(false, None, None, Some(e)),
    };
    iptables_json(true, Some(filter), nat, None)
}

/// `_upstream_auth_state`: which credential is in force, never the credential (#194).
fn upstream_auth(state: CredentialState, has_config_auth: bool) -> &'static str {
    let fallback = if has_config_auth { "config" } else { "none" };
    match state {
        // no relay, or not up yet: say what is in force instead
        CredentialState::Unreachable => {
            if has_config_auth {
                "config"
            } else {
                "unavailable"
            }
        }
        CredentialState::Set => "set",
        CredentialState::Locked => "locked",
        CredentialState::NotSet | CredentialState::Unusable => fallback,
    }
}

fn lax_or_raise<T>(r: Option<T>) -> Py<T> {
    r.ok_or(Raised("the response model refused a value"))
}

/// `GET /api/config`.
pub fn config(view: &UiView) -> Py<Json> {
    let config = cfg::load(&view.config_path);
    let proxy = cfg::get_or(&config, "proxy", PyValue::Dict(vec![]))?;
    let has_config_auth =
        cfg::is_literal(py_get(&proxy, "upstream_proxy_username")?) || view.env_proxy_username_set;
    let auth = upstream_auth(view.credential_state(), has_config_auth);
    let has_auth = matches!(auth, "set" | "config");

    let e = &mut lax::Errors::new();
    let enabled = lax_or_raise(lax::boolean(
        &cfg::get_or(&proxy, "enabled", PyValue::Bool(false))?,
        &[],
        e,
    ))?;
    let port = lax_or_raise(lax::int(
        &cfg::get_or(&proxy, "port", PyValue::Int(3128))?,
        &[],
        e,
    ))?;
    let cache_enabled = lax_or_raise(lax::boolean(
        &cfg::get_or(&proxy, "cache_enabled", PyValue::Bool(true))?,
        &[],
        e,
    ))?;
    let cache_size = lax_or_raise(lax::int(
        &cfg::get_or(&proxy, "cache_size_mb", PyValue::Int(1000))?,
        &[],
        e,
    ))?;
    let upstream = lax_or_raise(lax::opt_string(
        &cfg::get_or(&proxy, "upstream_proxy", PyValue::None)?,
        &[],
        e,
    ))?;
    let tls = lax_or_raise(lax::boolean(
        &cfg::get_or(&proxy, "upstream_proxy_tls", PyValue::Bool(false))?,
        &[],
        e,
    ))?;

    let proxy_json = obj([
        ("enabled", Json::Bool(enabled)),
        ("port", Json::Int(port)),
        ("cache_enabled", Json::Bool(cache_enabled)),
        ("cache_size_mb", Json::Int(cache_size)),
        ("upstream_proxy", Json::opt_str(upstream)),
        ("upstream_proxy_tls", Json::Bool(tls)),
        ("has_upstream_auth", Json::Bool(has_auth)),
        ("upstream_auth", Json::str(auth)),
    ]);
    Ok(obj([
        ("version_package", Json::str(version_package())),
        ("version_core", Json::str(VERSION_CORE)),
        ("version_webui", Json::str(VERSION_WEBUI)),
        ("proxy", proxy_json),
        ("squid", squid(&view.squid_config_path)),
        ("iptables", iptables(&view.iptables)),
    ]))
}

/// `GET /api/i18n?lang=`.
pub fn i18n(view: &UiView, req: &Req) -> Py<Json> {
    let config = cfg::load(&view.config_path);
    let configured = match &config {
        PyValue::Dict(_) => match py_get(&config, "ui")? {
            Some(ui @ PyValue::Dict(_)) => {
                cfg::py_str(&cfg::get_or(ui, "language", PyValue::Str("auto".into()))?)
            }
            _ => "auto".to_string(),
        },
        _ => "auto".to_string(),
    };
    let cookie = req.cookie_value(i18n::COOKIE_NAME);
    let lang = i18n::resolve_lang(
        req.param("lang"),
        cookie.as_deref(),
        req.accept_language.as_deref(),
        &configured,
    );
    Ok(obj([
        ("lang", Json::str(lang)),
        ("supported", Json::strs(&i18n::SUPPORTED)),
        (
            "strings",
            Json::Obj(
                i18n::strings(lang)
                    .into_iter()
                    .map(|(k, v)| (k, Json::Str(v)))
                    .collect(),
            ),
        ),
    ]))
}

/// The key the store is asked for the proxy username: the config's `{key}`, or `proxy_user`.
/// The `serve` side uses this to keep [`CredentialState`] current; the UI never asks the store.
pub fn proxy_user_key(config_path: &Path) -> String {
    let config = cfg::load(config_path);
    py_get(&config, "proxy")
        .ok()
        .flatten()
        .and_then(|p| py_get(p, "upstream_proxy_username").ok().flatten())
        .and_then(cfg::reference)
        .unwrap_or_else(|| "proxy_user".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn it_blanks_the_password_and_keeps_the_user() {
        let conf = "cache_peer proxy.example parent 3128 0 no-query login=alice:s3cret default\n";
        assert_eq!(
            redact_squid_config(conf),
            "cache_peer proxy.example parent 3128 0 no-query login=alice:*** default\n"
        );
    }

    #[test]
    fn it_leaves_squids_other_login_forms_alone() {
        for form in ["PASS", "PASSTHRU", "NEGOTIATE", "PROXYPASS"] {
            let line = format!("cache_peer p parent 3128 0 login={form}\n");
            assert_eq!(redact_squid_config(&line), line);
        }
    }

    #[test]
    fn it_handles_a_password_with_a_colon_in_it() {
        assert_eq!(
            redact_squid_config("login=alice:pa:ss:word x"),
            "login=alice:*** x"
        );
        assert_eq!(
            redact_squid_config("login=:x login=a: b"),
            "login=:x login=a: b"
        );
        assert_eq!(redact_squid_config("xlogin=a:b"), "xlogin=a:***");
        assert_eq!(
            redact_squid_config("login=a:b\u{3000}c"),
            "login=a:***\u{3000}c"
        );
    }

    #[test]
    fn it_maps_the_store_answer_as_python_did() {
        use CredentialState::*;
        assert_eq!(upstream_auth(Set, false), "set");
        assert_eq!(upstream_auth(Locked, true), "locked");
        assert_eq!(upstream_auth(NotSet, false), "none");
        assert_eq!(upstream_auth(NotSet, true), "config");
        assert_eq!(upstream_auth(Unusable, false), "none");
        assert_eq!(upstream_auth(Unreachable, false), "unavailable");
        assert_eq!(upstream_auth(Unreachable, true), "config");
    }

    #[test]
    fn iptables_failures_read_as_python_wrote_them() {
        let missing = Path::new("/nonexistent/iptables-legacy");
        let j = iptables(missing).to_text();
        assert!(j.contains("\"available\":false"), "{j}");
        assert!(j.contains("\"iptables-legacy not found\""), "{j}");
        let j = iptables(Path::new("false")).to_text();
        assert_eq!(
            j,
            "{\"available\":false,\"filter_rules\":null,\"nat_rules\":null,\"error\":\"\"}"
        );
    }
}
