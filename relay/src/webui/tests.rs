//! The boundary between the Web UI and the rest of `serve` (0.3.0 plan, "`serve` の中での分離"
//! 1–3). The sentinel test (5) is `relay/tests/webui.rs`, against a running `serve`.

use std::path::{Path, PathBuf};

use super::http::Req;
use super::*;

/// `UiView`, field by field with its type. Adding a field makes this fail to compile: write down
/// here, next to the new line, why the field cannot reach the store, a token or a credential.
#[test]
fn ui_view_is_exactly_these_fields() {
    let (_tx, rx) = watch::channel(CredentialState::Unreachable);
    let view = UiView::from_env(PathBuf::from("/nonexistent/config.yml"), rx);
    let UiView {
        // paths: the UI opens them itself, read only
        config_path,
        db_path,
        squid_config_path,
        iptables,
        // a boolean: whether a variable is set, not its value
        env_proxy_username_set,
        // a receiver of a value with nothing secret in it
        credential,
    } = view;
    let _: PathBuf = config_path;
    let _: PathBuf = db_path;
    let _: PathBuf = squid_config_path;
    let _: PathBuf = iptables;
    let _: bool = env_proxy_username_set;
    let _: watch::Receiver<CredentialState> = credential;
    // and the value carries no data: every variant is a bare name
    let all = [
        CredentialState::Unreachable,
        CredentialState::Locked,
        CredentialState::NotSet,
        CredentialState::Unusable,
        CredentialState::Set,
    ];
    assert_eq!(std::mem::size_of::<CredentialState>(), 1, "{all:?}");
}

/// The modules of the crate a Web UI file may name, and what in them.
const ALLOWED: &[&str] = &[
    // YAML as PyYAML reads it, Python's built-ins, pydantic's lax conversions: parsers with no
    // state, and nothing in them holds a secret
    "settings::yaml11",
    "settings::py",
    "settings::lax",
    // two plain functions and a list of three names from the Python reading of the config
    "settings::merge_no_proxy",
    "settings::NO_PROXY_ALWAYS",
];

/// What no file of the Web UI may name, whatever the list above says.
const FORBIDDEN: &[&str] = &[
    "store",
    "proxy_credential",
    "tokens",
    "vars",
    "github",
    "ssh",
    "git",
    "forge",
    "api",
    "config",
    "cli",
    "audit",
    "agent_setup",
    "passthrough",
    "netutil",
];

fn webui_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            out.push((
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            ));
        }
    }
    assert!(out.len() >= 10, "found {} files", out.len());
    out
}

/// Every path into the crate a source names: `crate::a::b`, with a `{…}` group expanded.
fn crate_paths(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("crate::") {
        let after = &rest[i + "crate::".len()..];
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(after.len());
        let path = &after[..end];
        if path.ends_with("::") && after[end..].starts_with('{') {
            let close = after[end..].find('}').map_or(after.len(), |c| end + c);
            for item in after[end + 1..close].split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    out.push(format!("{}{item}", path));
                }
            }
            rest = &after[close..];
        } else {
            out.push(path.trim_end_matches(':').to_string());
            rest = &after[end..];
        }
    }
    out
}

#[test]
fn webui_imports_only_what_it_may() {
    for (file, src) in webui_sources() {
        // a test file may name what it checks
        if file == "tests.rs" {
            continue;
        }
        assert!(
            !src.contains("super::super"),
            "{file}: reaches out of webui through super::super"
        );
        assert!(
            !src.contains("sekimore_relay::"),
            "{file}: names the crate by its name"
        );
        for path in crate_paths(&src) {
            let first = path.split("::").next().unwrap_or_default();
            assert!(
                !FORBIDDEN.contains(&first),
                "{file}: uses crate::{path}, which the Web UI may not reach"
            );
            let path = path.trim_end_matches("::self").to_string();
            let allowed = ALLOWED
                .iter()
                .any(|a| path == *a || path.starts_with(&format!("{a}::")));
            assert!(
                allowed,
                "{file}: uses crate::{path}, which is not on the list in webui/tests.rs"
            );
        }
    }
}

#[test]
fn the_import_check_reads_paths_as_written() {
    let src = "use crate::settings::{lax, merge_no_proxy};\nuse crate::store::SecretStore;\nlet x = crate::settings::py::strip(s);";
    assert_eq!(
        crate_paths(src),
        [
            "settings::lax",
            "settings::merge_no_proxy",
            "store::SecretStore",
            "settings::py::strip",
        ]
    );
}

/// Static assertion that a type does not implement `Serialize` (the `static_assertions` trick:
/// two blanket impls that become ambiguous when the bound holds).
trait AmbiguousIfSerialize<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
#[allow(dead_code)]
struct Invalid;
impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<Invalid> for T {}

/// The relay's configuration types are not serializable: nobody can take the shortcut of turning
/// one into JSON whole. Adding `Serialize` to any of them stops this from compiling.
#[test]
fn the_config_types_are_not_serializable() {
    let _ = <crate::config::RelayConfig as AmbiguousIfSerialize<_>>::some_item;
    let _ = <crate::config::ProxyConfig as AmbiguousIfSerialize<_>>::some_item;
    let _ = <crate::config::ProxySpec as AmbiguousIfSerialize<_>>::some_item;
    let _ = <crate::config::Resolved as AmbiguousIfSerialize<_>>::some_item;
    let _ = <crate::settings::Settings as AmbiguousIfSerialize<_>>::some_item;
    let _ = <crate::settings::Secret as AmbiguousIfSerialize<_>>::some_item;
}

fn view() -> UiView {
    let (_tx, rx) = watch::channel(CredentialState::Unreachable);
    UiView::from_env(PathBuf::from("/nonexistent/config.yml"), rx)
}

/// Every path string literal in the API's sources.
fn api_paths() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let src = std::fs::read_to_string(e.unwrap().path()).unwrap();
        for piece in src.split('"').skip(1).step_by(2) {
            if piece.starts_with('/')
                && piece.len() > 1
                && piece
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '/' || c == '-' || c == '_')
            {
                out.push(piece.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    assert!(out.len() > 30, "found only {out:?}");
    out
}

/// The UI's router shares no route with the API's: every path the API serves is a 404 here, for
/// any method. The mirror (every UI path refused by the API) is in `relay/tests/webui.rs`.
#[test]
fn every_api_path_is_a_404_here() {
    let v = view();
    for p in api_paths() {
        assert!(
            !ROUTES.contains(&p.as_str()) && p != WS_ROUTE,
            "{p} is in both"
        );
        for m in ["GET", "POST"] {
            let r = dispatch(&v, m, &Req::new(&p, None, None, None, None), 0.0, "x");
            assert_eq!(r.status, 404, "{m} {p}");
        }
    }
}

/// Inputs built to break a handler answer, and never panic (a panic aborts `serve`).
#[test]
fn hostile_requests_get_an_answer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.yml"),
        "relay: {state_dir: /nonexistent}\n",
    )
    .unwrap();
    let (_tx, rx) = watch::channel(CredentialState::Unreachable);
    let mut v = UiView::from_env(dir.path().join("config.yml"), rx);
    v.db_path = dir.path().join("none.db");
    let long = "x".repeat(1 << 20);
    let queries = [
        format!("limit={long}"),
        format!("limit=9{long}"),
        "limit=-99999999999999999999999999999999999999999999".to_string(),
        "limit=%ff%fe".to_string(),
        "limit=%".to_string(),
        "kind=%00&limit=1e9999".to_string(),
        format!("lang={long}"),
        "&&&==&=".to_string(),
    ];
    for route in ROUTES {
        for q in &queries {
            let r = dispatch(
                &v,
                "GET",
                &Req::new(route, Some(q), Some(&long), Some(&long), Some(&long)),
                0.0,
                "x",
            );
            assert!(
                [200, 422, 500].contains(&r.status),
                "{route}?{}: {}",
                &q[..q.len().min(40)],
                r.status
            );
        }
    }
    for path in [
        format!("/{long}"),
        "/%".into(),
        "/%ff".into(),
        "/api/%00".into(),
        format!("/api/stats{}", "/".repeat(1000)),
    ] {
        let r = dispatch(
            &v,
            "GET",
            &Req::new(&path, None, None, None, None),
            0.0,
            "x",
        );
        assert!([404, 307].contains(&r.status), "{}", r.status);
    }
}

/// A config written to break the reading: deep nesting, huge numbers, every YAML type where a
/// mapping or a list was expected.
#[test]
fn hostile_configs_get_an_answer() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.yml");
    let (_tx, rx) = watch::channel(CredentialState::Unreachable);
    let v = UiView::from_env(cfg.clone(), rx);
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    let texts = [
        format!("name: {deep}\n"),
        "proxy: {port: 99999999999999999999999999999999999999999999999999}\n".to_string(),
        "proxy: {port: -1e400}\nrelay: {https_max_upload_bytes: .nan}\n".to_string(),
        "domain_handlers: {a: {handler: github, ssh_port: 1e308, max_upload_bytes: .inf}}\nrelay: {}\n".to_string(),
        "relay: {project: {repos: 5, permissions: {allow: 7}}}\ndomain_handlers: {a: {handler: github}}\n".to_string(),
        "relay: {state_dir: \"\\0\"}\ndomain_handlers: {a: {handler: github}}\n".to_string(),
        "allow_domains: !!binary aGVsbG8=\n".to_string(),
        "? [a, b]\n: c\n".to_string(),
        "&a [*a]\n".to_string(),
        "ui: {language: !!set {a, b}}\n".to_string(),
    ];
    for t in &texts {
        std::fs::write(&cfg, t).unwrap();
        for route in ROUTES {
            let r = dispatch(
                &v,
                "GET",
                &Req::new(route, None, None, None, None),
                0.0,
                "x",
            );
            assert!(
                [200, 500].contains(&r.status),
                "{t:?} {route}: {}",
                r.status
            );
        }
    }
}

// ---- the dashboard -------------------------------------------------------------------------------

/// The Relay tab offers a fixed list of permission keys (`allPerms`); it has to be the relay's own
/// set, rebuilt here from `valid_actions()` in `policy.rs`.
#[test]
fn the_dashboard_offers_every_permission_the_relay_defines() {
    let html = DASHBOARD;
    let start = html.find("const allPerms = [").expect("allPerms") + "const allPerms = [".len();
    let end = start + html[start..].find("];").expect("the end of allPerms");
    let shown: std::collections::BTreeSet<String> = html[start..end]
        .split('\'')
        .skip(1)
        .step_by(2)
        .filter(|k| k.contains(':'))
        .map(String::from)
        .collect();

    let policy =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/policy.rs"))
            .unwrap();
    let snake = |camel: &str| {
        let mut out = String::new();
        for (i, c) in camel.chars().enumerate() {
            if c.is_ascii_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        }
        out
    };
    let mut defined = std::collections::BTreeSet::new();
    let mut rest = policy.as_str();
    while let Some(i) = rest.find("Resource::") {
        let after = &rest[i + "Resource::".len()..];
        let name_end = after
            .find(|c: char| !c.is_alphanumeric())
            .unwrap_or(after.len());
        let (res, tail) = after.split_at(name_end);
        if let Some(body) = tail.strip_prefix(" => &[") {
            let close = body.find(']').unwrap();
            for action in body[..close]
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
            {
                defined.insert(format!("{}:{}", res.to_ascii_lowercase(), snake(action)));
            }
        }
        rest = tail;
    }
    assert!(defined.len() > 20, "{defined:?}");
    assert_eq!(
        defined, shown,
        "the dashboard is out of step with policy.rs"
    );
}

#[test]
fn the_dashboard_has_the_relay_tab_with_destination_and_edge() {
    for needle in [
        "id=\"tab-relay\"",
        "switchTab('relay')",
        "/api/relay/audit",
        "e.destination",
        "relay.to_destination",
        "e.edge",
        "new WebSocket(",
        "/api/i18n",
    ] {
        assert!(DASHBOARD.contains(needle), "{needle}");
    }
}

/// A credential state the dashboard cannot name shows a raw key to the operator (#194).
#[test]
fn every_credential_state_has_a_name_in_both_locales() {
    for lang in ["en", "ja"] {
        let strings = super::i18n::strings(lang);
        for state in ["none", "locked", "set", "config", "unavailable"] {
            let key = format!("config.upstream_auth_{state}");
            assert!(strings.iter().any(|(k, _)| *k == key), "{lang}: {key}");
        }
    }
}
