//! `config.yml` as the Web UI reads it: `yaml.safe_load` on every request (`load_config()` in the
//! Python UI), so an edit shows on the next page load whatever the reload window says.
//!
//! The Python UI read the raw document, not the validated `Config`, and every endpoint picked the
//! keys it needed with `dict.get`. The answers depend on that — a missing key, a `null`, a list
//! where a mapping was expected each give their own answer, often a 500 — so the same raw value is
//! kept here, with Python's built-ins over it (`py_get`, `truthy`, `int_or`, `py_str`).
//!
//! **What is kept is only what an endpoint reads.** The document is projected through
//! [`KEEP`] as soon as it is parsed, and the parsed tree is dropped with the function that read
//! it: the upstream proxy password, the store's unlock setting, a sidecar's credentials and every
//! key no endpoint names never reach a handler. The one credential field an answer depends on,
//! `proxy.upstream_proxy_username`, is kept only as what `literal()` and `reference()` need: the
//! `{key}` text when it is a reference, and a stand-in when it is a literal.

use std::path::Path;

use crate::settings::py;
use crate::settings::yaml11::{self, PyValue};

/// A handler raised where Python would have, and FastAPI answered 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raised(pub &'static str);

pub type Py<T> = Result<T, Raised>;

/// Which part of a value to keep.
enum Keep {
    /// The whole value
    All,
    /// A mapping: only these keys, each projected. Anything that is not a mapping is kept as it
    /// is, so `dict.get` on it fails as it did.
    Keys(&'static [(&'static str, Keep)]),
    /// A mapping with keys of any name, each value projected
    Values(&'static Keep),
    /// A list, each item projected
    Items(&'static Keep),
    /// `proxy.upstream_proxy_username`
    Username,
}

const REPO: Keep = Keep::Keys(&[
    ("name", Keep::All),
    ("mode", Keep::All),
    ("bases", Keep::All),
    ("permissions", Keep::All),
    ("push", Keep::All),
    ("tags", Keep::All),
    ("delete", Keep::All),
    ("force_push", Keep::All),
    ("signed_tags", Keep::All),
    ("signing", Keep::All),
]);

const LAYER: Keep = Keep::Keys(&[
    ("repos", Keep::Items(&REPO)),
    ("permissions", Keep::All),
    ("push", Keep::All),
    ("tags", Keep::All),
    ("delete", Keep::All),
    ("force_push", Keep::All),
    ("signed_tags", Keep::All),
    ("signing", Keep::All),
]);

const PROJECT: Keep = Keep::Keys(&[
    ("name", Keep::All),
    ("repos", Keep::Items(&REPO)),
    ("upstreams", Keep::Values(&LAYER)),
    ("permissions", Keep::All),
    ("push", Keep::All),
    ("tags", Keep::All),
    ("delete", Keep::All),
    ("force_push", Keep::All),
    ("signed_tags", Keep::All),
    ("signing", Keep::All),
]);

const HANDLER: Keep = Keep::Keys(&[
    ("handler", Keep::All),
    ("upstream", Keep::All),
    ("ssh_port", Keep::All),
    ("default", Keep::All),
    ("api_base", Keep::All),
    ("ssh_options", Keep::All),
    ("max_upload_bytes", Keep::All),
]);

/// Every key an endpoint reads, and nothing else.
const KEEP: Keep = Keep::Keys(&[
    ("name", Keep::All),
    ("description", Keep::All),
    ("allow_domains", Keep::All),
    ("block_domains", Keep::All),
    ("ignore_domains", Keep::All),
    ("ui", Keep::Keys(&[("language", Keep::All)])),
    (
        "proxy",
        Keep::Keys(&[
            ("enabled", Keep::All),
            ("port", Keep::All),
            ("cache_enabled", Keep::All),
            ("cache_size_mb", Keep::All),
            ("upstream_proxy", Keep::All),
            ("upstream_proxy_tls", Keep::All),
            ("direct_egress", Keep::All),
            ("no_proxy", Keep::All),
            ("upstream_proxy_username", Keep::Username),
        ]),
    ),
    ("domain_handlers", Keep::Values(&HANDLER)),
    (
        "relay",
        Keep::Keys(&[
            ("project", PROJECT),
            ("https", Keep::All),
            ("bootstrap", Keep::All),
            ("token_ttl", Keep::All),
            ("allow_tags", Keep::All),
            ("allow_delete", Keep::All),
            ("ssh_listen", Keep::All),
            ("api_listen", Keep::All),
            ("state_dir", Keep::All),
            ("https_max_upload_bytes", Keep::All),
            ("ssh_options", Keep::All),
            ("upstream", Keep::All),
            ("api_base", Keep::All),
        ]),
    ),
]);

/// What a literal username is replaced with: a truthy string that is not a `{key}`, so
/// `literal()` says what it said about the real one.
const LITERAL_STANDIN: &str = "(literal)";

fn project(v: PyValue, keep: &Keep) -> PyValue {
    match (keep, v) {
        (Keep::All, v) => v,
        (Keep::Keys(keys), PyValue::Dict(pairs)) => PyValue::Dict(
            pairs
                .into_iter()
                .filter_map(|(k, v)| {
                    let PyValue::Str(name) = &k else {
                        return None;
                    };
                    let (_, sub) = keys.iter().find(|(n, _)| n == name)?;
                    Some((k, project(v, sub)))
                })
                .collect(),
        ),
        (Keep::Values(sub), PyValue::Dict(pairs)) => PyValue::Dict(
            pairs
                .into_iter()
                .map(|(k, v)| (k, project(v, sub)))
                .collect(),
        ),
        (Keep::Items(sub), PyValue::List(items)) => {
            PyValue::List(items.into_iter().map(|v| project(v, sub)).collect())
        }
        (Keep::Username, v) => {
            if !truthy(&v) || reference(&v).is_some() {
                v
            } else {
                PyValue::Str(LITERAL_STANDIN.into())
            }
        }
        (_, v) => v,
    }
}

/// `load_config()`: the document, or `{"allow_domains": [], "block_domains": []}` when it cannot
/// be read or parsed (a missing file, invalid YAML, not UTF-8).
pub fn load(path: &Path) -> PyValue {
    let parsed = std::fs::read(path)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|text| yaml11::safe_load(&text).ok());
    match parsed {
        Some(doc) => project(doc, &KEEP),
        None => {
            log::debug!("webui: cannot load {}", path.display());
            PyValue::Dict(vec![
                (PyValue::Str("allow_domains".into()), PyValue::List(vec![])),
                (PyValue::Str("block_domains".into()), PyValue::List(vec![])),
            ])
        }
    }
}

// ---- Python's built-ins over a raw value -------------------------------------------------------

/// `bool(v)`.
pub fn truthy(v: &PyValue) -> bool {
    match v {
        PyValue::None => false,
        PyValue::Bool(b) => *b,
        PyValue::Int(i) => *i != 0,
        PyValue::Float(f) => *f != 0.0,
        PyValue::Str(s) => !s.is_empty(),
        PyValue::List(l) => !l.is_empty(),
        PyValue::Dict(d) => !d.is_empty(),
        PyValue::Date(_) | PyValue::DateTime(_) => true,
    }
}

/// `v.get(key)`: a dict's value for a string key; `AttributeError` on anything that is not a dict.
pub fn py_get<'a>(v: &'a PyValue, key: &str) -> Py<Option<&'a PyValue>> {
    match v {
        PyValue::Dict(pairs) => Ok(pairs
            .iter()
            .find(|(k, _)| matches!(k, PyValue::Str(s) if s == key))
            .map(|(_, v)| v)),
        _ => Err(Raised("'.get' on a value that is not a dict")),
    }
}

/// `v.get(key, default)` with the default owned.
pub fn get_or(v: &PyValue, key: &str, default: PyValue) -> Py<PyValue> {
    Ok(py_get(v, key)?.cloned().unwrap_or(default))
}

/// `v.get(key) or {}`: the value when truthy, else an empty dict.
pub fn get_or_empty(v: &PyValue, key: &str) -> Py<PyValue> {
    Ok(match py_get(v, key)? {
        Some(x) if truthy(x) => x.clone(),
        _ => PyValue::Dict(vec![]),
    })
}

/// `isinstance(v, dict)`.
pub fn is_dict(v: &PyValue) -> bool {
    matches!(v, PyValue::Dict(_))
}

/// `str(v)`, with Python's `repr` for the items of a list or a dict.
pub fn py_str(v: &PyValue) -> String {
    match v {
        PyValue::List(_) | PyValue::Dict(_) => py_repr(v),
        _ => py::str_of(v),
    }
}

/// `repr(v)`.
pub fn py_repr(v: &PyValue) -> String {
    match v {
        PyValue::Str(s) => repr_str(s),
        PyValue::Date(d) => format!("datetime.date({}, {}, {})", d.year, d.month, d.day),
        PyValue::DateTime(_) => format!("datetime.datetime({})", py::str_of(v)),
        PyValue::List(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        PyValue::Dict(pairs) => {
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
        _ => py::str_of(v),
    }
}

/// `repr(str)`: single quotes unless the text has one and no double quote.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `int(v)`: `None` where Python raises `TypeError` / `ValueError`, `Err` where it raises
/// something no caller catches (`OverflowError` for an infinite float).
pub fn py_int(v: &PyValue) -> Py<Option<i128>> {
    Ok(match v {
        PyValue::Bool(b) => Some(*b as i128),
        PyValue::Int(i) => Some(*i),
        PyValue::Float(f) if f.is_infinite() => {
            return Err(Raised("cannot convert float infinity to integer"))
        }
        PyValue::Float(f) if f.is_nan() => None,
        PyValue::Float(f) => {
            let t = f.trunc();
            if t.abs() >= 1.7e38 {
                return Err(Raised("an integer beyond what this reader holds"));
            }
            Some(t as i128)
        }
        PyValue::Str(s) => py::int(s),
        _ => None,
    })
}

/// `_int_or(value, default)`: `int(value)` unless it is None or does not convert.
pub fn int_or(v: Option<&PyValue>, default: i128) -> Py<i128> {
    match v {
        None | Some(PyValue::None) => Ok(default),
        Some(x) => Ok(py_int(x)?.unwrap_or(default)),
    }
}

/// `reference(field)`: the key a whole `{key}` field names.
pub fn reference(v: &PyValue) -> Option<String> {
    let PyValue::Str(field) = v else {
        return None;
    };
    let f = py::strip(field);
    let key = f.strip_prefix('{')?.strip_suffix('}')?;
    let valid = !key.is_empty()
        && key.chars().count() <= 128
        && key.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        });
    valid.then(|| key.to_string())
}

/// `literal(field)`: truthy and not a `{key}`.
pub fn is_literal(v: Option<&PyValue>) -> bool {
    v.is_some_and(|v| truthy(v) && reference(v).is_none())
}

/// Iterating a value as Python's `for x in v` would: a list's items, a dict's keys, a string's
/// characters; anything else raises `TypeError`.
pub fn iter_items(v: &PyValue) -> Py<Vec<PyValue>> {
    match v {
        PyValue::List(items) => Ok(items.clone()),
        PyValue::Dict(pairs) => Ok(pairs.iter().map(|(k, _)| k.clone()).collect()),
        PyValue::Str(s) => Ok(s.chars().map(|c| PyValue::Str(c.to_string())).collect()),
        _ => Err(Raised("not iterable")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn load_text(text: &str) -> PyValue {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.yml");
        std::fs::write(&p, text).unwrap();
        load(&p)
    }

    #[test]
    fn it_keeps_no_credential_and_no_key_it_does_not_read() {
        let v = load_text(
            "proxy:\n  upstream_proxy: p:3128\n  upstream_proxy_username: alice-secret\n  upstream_proxy_password: hunter2\n\
             relay:\n  store: {unlock: {env: PASS}}\n  sidecars: {notes: {credentials: {k: v}}}\n  https: reject\n\
             other: x\n",
        );
        let text = format!("{v:?}");
        for gone in [
            "alice-secret",
            "hunter2",
            "PASS",
            "sidecars",
            "credentials",
            "other",
        ] {
            assert!(!text.contains(gone), "{gone} survived: {text}");
        }
        let proxy = py_get(&v, "proxy").unwrap().unwrap();
        assert!(is_literal(
            py_get(proxy, "upstream_proxy_username").unwrap()
        ));
        let relay = py_get(&v, "relay").unwrap().unwrap();
        assert_eq!(
            py_get(relay, "https").unwrap(),
            Some(&PyValue::Str("reject".into()))
        );
    }

    #[test]
    fn a_reference_username_stays_a_reference() {
        let v = load_text("proxy:\n  upstream_proxy_username: '{team/user}'\n");
        let proxy = py_get(&v, "proxy").unwrap().unwrap();
        let u = py_get(proxy, "upstream_proxy_username").unwrap().unwrap();
        assert_eq!(reference(u).as_deref(), Some("team/user"));
        assert!(!is_literal(Some(u)));
    }

    #[test]
    fn an_unreadable_file_is_the_python_default() {
        let v = load(Path::new("/nonexistent/config.yml"));
        assert_eq!(
            py_get(&v, "allow_domains").unwrap(),
            Some(&PyValue::List(vec![]))
        );
        assert_eq!(py_get(&v, "name").unwrap(), None);
    }

    #[test]
    fn a_shape_python_could_not_get_from_raises() {
        let v = load_text("- a\n- b\n");
        assert!(py_get(&v, "name").is_err());
        let v = load_text("");
        assert!(py_get(&v, "name").is_err());
    }

    #[test]
    fn int_matches_python() {
        assert_eq!(py_int(&PyValue::Str(" 1_0 ".into())).unwrap(), Some(10));
        assert_eq!(py_int(&PyValue::Float(2.9)).unwrap(), Some(2));
        assert_eq!(py_int(&PyValue::Str("x".into())).unwrap(), None);
        assert!(py_int(&PyValue::Float(f64::INFINITY)).is_err());
        assert_eq!(py_int(&PyValue::List(vec![])).unwrap(), None);
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr_str("a'b"), "\"a'b\"");
        assert_eq!(repr_str("a'b\""), "'a\\'b\"'");
        assert_eq!(
            py_str(&PyValue::List(vec![
                PyValue::Str("x".into()),
                PyValue::Int(1),
                PyValue::None
            ])),
            "['x', 1, None]"
        );
    }
}
