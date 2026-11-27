//! The `config` comparison: how a config file is read.
//!
//! For each case both sides answer: what `yaml.safe_load` makes of the file (`raw`), whether
//! `Config.from_yaml` accepts it, and then either the stage that refused it (with the pydantic
//! locations, or the model validator) or the resolved settings, every derived list of `Config`,
//! and what `Rules` answers — DNS's decision for a set of names derived from the config, the
//! names seeded at start-up, and Squid's allow and deny ACLs.

use serde_json::{json, Value};

use sekimore_relay::settings::rules::{Decision, Rules};
use sekimore_relay::settings::yaml11::{self, PyValue};
use sekimore_relay::settings::{
    self, py, DirectEgress, HttpsMode, Language, PyInt, Refusal, Settings,
};

use crate::harness::{Case, Comparison};

pub struct ConfigReading;

impl Comparison for ConfigReading {
    fn kind(&self) -> &'static str {
        "config"
    }

    fn request(&self, case: &Case) -> Value {
        let probes = read(case)
            .ok()
            .and_then(|text| settings::parse(&text, &env_of(case)).ok())
            .map(|s| probes(&s))
            .unwrap_or_default();
        json!({
            "id": case.id,
            "path": case.path,
            "env": case.env,
            "probes": probes,
        })
    }

    fn rust(&self, case: &Case, request: &Value) -> Value {
        let probes: Vec<String> = request["probes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let text = match read(case) {
            Ok(t) => t,
            Err(_) => {
                return json!({"id": case.id, "raw": {"error": null}, "refused": {"stage": "yaml"}})
            }
        };
        let raw = match yaml11::safe_load(&text) {
            Ok(v) => typed(&v),
            Err(_) => json!({"error": null}),
        };
        match settings::parse(&text, &env_of(case)) {
            Err(r) => json!({"id": case.id, "raw": raw, "refused": refused(&r)}),
            Ok(s) => json!({
                "id": case.id,
                "raw": raw,
                "accepted": {
                    "settings": settings_json(&s),
                    "derived": derived(&s),
                    "rules": rules(&s, &probes),
                }
            }),
        }
    }
}

fn read(case: &Case) -> Result<String, ()> {
    String::from_utf8(std::fs::read(&case.path).map_err(|_| ())?).map_err(|_| ())
}

fn env_of(case: &Case) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| case.env.get(name).cloned()
}

/// `oracle.py`'s `typed`.
pub fn typed(v: &PyValue) -> Value {
    match v {
        PyValue::None => json!({"none": null}),
        PyValue::Bool(b) => json!({"bool": b}),
        PyValue::Int(i) => json!({"int": i.to_string()}),
        PyValue::Float(f) => json!({"float": py::float_repr(*f)}),
        PyValue::Str(s) => json!({"str": s}),
        PyValue::Date(_) => json!({"date": py::str_of(v)}),
        PyValue::DateTime(_) => json!({"datetime": py::str_of(v)}),
        PyValue::List(items) => json!({"list": items.iter().map(typed).collect::<Vec<_>>()}),
        PyValue::Dict(pairs) => json!({
            "dict": pairs.iter().map(|(k, v)| json!([typed(k), typed(v)])).collect::<Vec<_>>()
        }),
    }
}

fn refused(r: &Refusal) -> Value {
    match r {
        Refusal::Fields(errors) => {
            let mut locs: Vec<String> = errors.iter().map(|e| e.path()).collect();
            locs.sort();
            json!({"stage": "fields", "locs": locs})
        }
        Refusal::Model(rule, _) => json!({"stage": "model", "rule": rule.as_str()}),
        other => json!({"stage": other.stage()}),
    }
}

/// Python's int as JSON: a number while it fits.
fn int(n: PyInt) -> Value {
    i64::try_from(n)
        .map(Value::from)
        .unwrap_or_else(|_| Value::from(n.to_string()))
}

fn settings_json(s: &Settings) -> Value {
    let p = &s.proxy;
    json!({
        "name": s.name,
        "description": s.description,
        "allow_domains": s.allow_domains,
        "block_domains": s.block_domains,
        "ignore_domains": s.ignore_domains,
        "allow_ips": s.allow_ips,
        "block_ips": s.block_ips,
        "resolve_deny_cidrs": s.resolve_deny_cidrs,
        "resolve_allow_cidrs": s.resolve_allow_cidrs,
        "proxy": {
            "enabled": p.enabled,
            "port": int(p.port),
            "cache_enabled": p.cache_enabled,
            "cache_size_mb": int(p.cache_size_mb),
            "upstream_proxy": p.upstream_proxy,
            "upstream_proxy_tls": p.upstream_proxy_tls,
            "upstream_proxy_username": p.upstream_proxy_username.as_ref().map(|x| x.expose()),
            "upstream_proxy_password": p.upstream_proxy_password.as_ref().map(|x| x.expose()),
            "direct_egress": match p.direct_egress { DirectEgress::Allow => "allow", DirectEgress::Deny => "deny" },
            "no_proxy": p.no_proxy,
        },
        "network": {
            "lan_subnets": s.network.lan_subnets,
            "allowed_ports": s.network.allowed_ports,
            "host_enforcement": s.network.host_enforcement,
        },
        "database_path": s.database_path,
        "relay_fingerprint": s.relay_fingerprint,
        "reload": s.reload,
        "domain_handlers": s.domain_handlers.iter().map(|(d, h)| json!([d, {
            "handler": h.handler.as_str(),
            "max_upload_bytes": h.max_upload_bytes.map(int),
            "ssh_port": h.ssh_port,
            "upstream": h.upstream,
        }])).collect::<Vec<_>>(),
        "relay": {
            "ssh_listen": s.relay.ssh_listen,
            "api_listen": s.relay.api_listen,
            "https_listen": s.relay.https_listen,
            "https": match s.relay.https { HttpsMode::Passthrough => "passthrough", HttpsMode::Reject => "reject" },
        },
        "ui": {"language": match s.ui { Language::Auto => "auto", Language::En => "en", Language::Ja => "ja" }},
    })
}

fn derived(s: &Settings) -> Value {
    json!({
        "git_relay_ssh_ports": s.git_relay_ssh_ports().into_iter().map(|(d, p)| json!([d, int(p)])).collect::<Vec<_>>(),
        "git_relay_domains": s.git_relay_domains(),
        "https_relay_domains": s.https_relay_domains(),
        "relay_domains": s.relay_domains(),
        "proxy_denied_domains": s.proxy_denied_domains(),
        "proxy_allow_domains": s.proxy_allow_domains(),
        "has_git_relay": s.has_git_relay(),
        "relay_input_ports": s.relay_input_ports().into_iter().map(int).collect::<Vec<_>>(),
        "reload_window_seconds": s.reload_window_seconds().map(int),
        "reload_is_windowed": s.reload_is_windowed(),
        "normalized_no_proxy": s.proxy.normalized_no_proxy(),
        "uses_upstream": s.proxy.uses_upstream(),
        "direct_egress_denied": s.proxy.direct_egress_denied(),
    })
}

/// `oracle.py`'s DNS_BRANCHES words.
pub fn decision(d: Decision) -> &'static str {
    match d {
        Decision::Block => "block",
        Decision::Ignore => "ignore",
        Decision::Deny => "deny",
        Decision::AnswerGateway => "gateway",
        Decision::Resolve { admit: true } => "resolve+admit",
        Decision::Resolve { admit: false } => "resolve",
        Decision::NotAllowed => "not_allowed",
    }
}

fn rules(s: &Settings, probes: &[String]) -> Value {
    let r = Rules::build(s, None);
    let decide: serde_json::Map<String, Value> = probes
        .iter()
        .map(|p| {
            (
                p.clone(),
                json!([decision(r.decide(p, false)), decision(r.decide(p, true))]),
            )
        })
        .collect();
    json!({
        "decide": decide,
        "seed_candidates": r.seed_candidates(),
        "squid_allow": r.squid_allow(),
        "squid_deny": r.squid_deny(),
    })
}

/// The names DNS is asked about for a config: every name the config mentions, and its
/// neighbours — a name under it, the name in capitals, with a trailing dot, with a letter in
/// front (`evilgithub.com` for `github.com`) and with its last letter changed. Only names a DNS
/// query can carry.
pub fn probes(s: &Settings) -> Vec<String> {
    let entries = s
        .allow_domains
        .iter()
        .chain(&s.block_domains)
        .chain(&s.ignore_domains)
        .chain(s.domain_handlers.iter().map(|(d, _)| d));
    let mut out: Vec<String> = vec!["unlisted.invalid".into()];
    for e in entries {
        let base = e
            .trim()
            .trim_start_matches('*')
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let ok = !base.is_empty()
            && base
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && base.split('.').all(|l| !l.is_empty() && l.len() <= 60)
            && base.len() <= 200;
        if !ok {
            continue;
        }
        let mut changed = base.clone();
        let last = changed.pop().unwrap_or('a');
        changed.push(if last == 'a' { 'b' } else { 'a' });
        out.extend([
            base.clone(),
            format!("sub.{base}"),
            base.to_ascii_uppercase(),
            format!("{base}."),
            format!("x{base}"),
            changed,
        ]);
    }
    out.sort();
    out.dedup();
    out
}
