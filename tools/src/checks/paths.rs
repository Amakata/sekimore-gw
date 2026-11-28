//! The path ledger (docs/paths.yml) checked as a graph (#223).
//!
//! The rules are the bugs of 2026-09-25, written so they cannot come back unnoticed:
//! - #220: every SSH hop is verified against a known_hosts the relay owns
//! - #212 / #186 / #190: nothing leaves dev without passing a policy node, unless the edge is the
//!   one direct-egress edge and it is flagged as warned; every edge that must not work names
//!   what blocks it
//! - #217: no secret can be read through an edge that starts in dev
//! - #205: two implementations of TLS towards the same peer need an interop reference
//! - every edge names files that exist and at least one test; the ids in the code
//!   (src/paths.py, relay/src/paths.rs) are exactly the ids in the ledger

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_yaml_ng::Value;

use crate::ledger::{self, get, get_list, get_str, get_truthy, Graph, MEDIATING_KINDS};
use crate::pyfmt::py_str;

pub const REQUIRED: [&str; 10] = [
    "id",
    "from",
    "to",
    "proto",
    "resolves",
    "verifies_peer",
    "presents",
    "audit",
    "impl",
    "tests",
];

fn re(s: &str) -> Regex {
    Regex::new(s).expect("regex")
}

static RELAY_OWNED_KNOWN_HOSTS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)known_hosts"));
static RUST_CONST: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?m)^pub const ([A-Z_]+): &str = "([a-z_.]+)";"#));
static RUST_DECLARED: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^pub const ([A-Z_]+): &str"));
static RUST_LISTED: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^\s+([A-Z_]+),$"));
static AUDIT_PAIR: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^\s+\(([A-Z_]+), "([a-z_]+)"\),"#));
static PLAIN_AUDIT: LazyLock<Regex> =
    LazyLock::new(|| re(r#"audit\.(?:log|deny)\(\s*"([a-z_]+)""#));
static VERIFY_BLOCK: LazyLock<Regex> = LazyLock::new(|| re(r"edges: &\[([^\]]*)\]"));
static PATHS_REF: LazyLock<Regex> = LazyLock::new(|| re(r"paths::([A-Z_]+)"));
static ID_LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r#""([a-z_.]+)""#));
static PY_CONST: LazyLock<Regex> = LazyLock::new(|| re(r#"(?m)^([A-Z_]+) = "([a-z_.]+)""#));
static PY_EDGES: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^EDGES\b[^=\n]*="));
static PY_NAME: LazyLock<Regex> = LazyLock::new(|| re(r"\b([A-Z][A-Z_]*)\b"));

/// The source files the ledger is held to.
#[derive(Clone, Debug, Default)]
pub struct Code {
    /// relay/src/paths.rs
    pub rust_paths: String,
    /// src/paths.py, while the gateway is Python
    pub python_paths: Option<String>,
    /// relay/src/host/verify.rs
    pub verify: String,
    /// every relay/src/**/*.rs, concatenated
    pub relay_sources: String,
}

impl Code {
    pub fn read(root: &Path) -> Result<Code, String> {
        let read = |p: &str| std::fs::read_to_string(root.join(p)).map_err(|e| format!("{p}: {e}"));
        let mut sources = Vec::new();
        collect_rs(&root.join("relay/src"), &mut sources)?;
        sources.sort();
        let mut relay_sources = String::new();
        for p in sources {
            relay_sources.push_str(&std::fs::read_to_string(&p).map_err(|e| e.to_string())?);
            relay_sources.push('\n');
        }
        Ok(Code {
            rust_paths: read("relay/src/paths.rs")?,
            python_paths: read("src/paths.py").ok(),
            verify: read("relay/src/host/verify.rs")?,
            relay_sources,
        })
    }

    /// The `pub const NAME: &str = "id";` of relay/src/paths.rs.
    fn rust_consts(&self) -> BTreeMap<String, String> {
        RUST_CONST
            .captures_iter(&self.rust_paths)
            .map(|m| (m[1].to_string(), m[2].to_string()))
            .collect()
    }
}

fn collect_rs(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.is_dir() {
            collect_rs(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    Ok(())
}

/// The edges by id; the ledger's edge list in order.
pub fn edges_by_id(l: &Value) -> Result<BTreeMap<String, &Value>, String> {
    ledger::edges(l)?
        .iter()
        .map(|e| Ok((get_str(e, "id")?, e)))
        .collect()
}

/// `(id, attribute)` for every required attribute an edge lacks.
pub fn missing_attributes(l: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for e in ledger::edges(l)? {
        for k in REQUIRED {
            if get(e, k).is_none() {
                let id = get(e, "id").map_or("None".into(), py_str);
                out.push(format!("({id}, {k})"));
            }
        }
    }
    Ok(out)
}

/// Nodes an edge names that the ledger does not list.
pub fn unknown_nodes(l: &Value) -> Result<Vec<String>, String> {
    let nodes: BTreeSet<String> = ledger::nodes(l)?.keys().map(py_str).collect();
    let mut out = Vec::new();
    for (id, e) in edges_by_id(l)? {
        let mut named = ledger::hops(e)?;
        if let Some(b) = get_truthy(e, "blocked_by") {
            named.push(py_str(b));
        }
        for n in named {
            if !nodes.contains(&n) {
                out.push(format!("({id}, {n})"));
            }
        }
    }
    Ok(out)
}

/// Ids that appear more than once.
pub fn duplicate_ids(l: &Value) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for e in ledger::edges(l)? {
        let id = get_str(e, "id")?;
        if !seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

/// `impl` and `tests` paths that do not exist under `root`.
pub fn missing_files(l: &Value, root: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (id, e) in edges_by_id(l)? {
        for f in get_list(e, "impl").into_iter().chain(get_list(e, "tests")) {
            if !root.join(&f).exists() {
                out.push(format!("({id}, {f})"));
            }
        }
    }
    Ok(out)
}

/// Edges with no test.
pub fn untested_edges(l: &Value) -> Result<Vec<String>, String> {
    Ok(edges_by_id(l)?
        .into_iter()
        .filter(|(_, e)| get_truthy(e, "tests").is_none())
        .map(|(id, _)| id)
        .collect())
}

/// The ids relay/src/paths.rs declares (all but `EDGE_FIELD`).
pub fn rust_ids(code: &Code) -> BTreeSet<String> {
    code.rust_consts()
        .into_iter()
        .filter(|(name, _)| name != "EDGE_FIELD")
        .map(|(_, v)| v)
        .collect()
}

/// The ids in src/paths.py's `EDGES`: its constants by name, and literals. Empty once the file is
/// gone.
pub fn python_ids(code: &Code) -> Result<BTreeSet<String>, String> {
    let Some(text) = &code.python_paths else {
        return Ok(BTreeSet::new());
    };
    let consts: BTreeMap<&str, &str> = PY_CONST
        .captures_iter(text)
        .map(|m| {
            let (_, [name, value]) = m.extract();
            (name, value)
        })
        .collect();
    let block = PY_EDGES
        .find(text)
        .map(|m| &text[m.end()..])
        .and_then(|rest| rest.split_once("\n)").map(|(b, _)| b))
        .ok_or("src/paths.py: no `EDGES = frozenset(…)`")?;
    let block: String = block
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out: BTreeSet<String> = ID_LITERAL
        .captures_iter(&block)
        .map(|m| m[1].to_string())
        .collect();
    for m in PY_NAME.captures_iter(&block) {
        let name = &m[1];
        match consts.get(name) {
            Some(v) => {
                out.insert(v.to_string());
            }
            None => {
                return Err(format!(
                    "src/paths.py: EDGES names {name}, which it does not define"
                ))
            }
        }
    }
    Ok(out)
}

/// Ids named by the code and not in the ledger, and the reverse.
pub fn ids_disagree(l: &Value, code: &Code) -> Result<Vec<String>, String> {
    let in_code: BTreeSet<String> = python_ids(code)?
        .into_iter()
        .chain(rust_ids(code))
        .collect();
    let in_ledger: BTreeSet<String> = edges_by_id(l)?.into_keys().collect();
    let mut out = Vec::new();
    let only_code: Vec<_> = in_code.difference(&in_ledger).collect();
    if !only_code.is_empty() {
        out.push(format!(
            "named in the code, not in the ledger: {only_code:?}"
        ));
    }
    let only_ledger: Vec<_> = in_ledger.difference(&in_code).collect();
    if !only_ledger.is_empty() {
        out.push(format!("in the ledger, named by no code: {only_ledger:?}"));
    }
    Ok(out)
}

/// Constants relay/src/paths.rs declares and does not list in `EDGES`, and the reverse.
pub fn rust_table_disagrees(code: &Code) -> Vec<String> {
    let text = &code.rust_paths;
    let declared: BTreeSet<String> = RUST_DECLARED
        .captures_iter(text)
        .map(|m| m[1].to_string())
        .filter(|n| n != "EDGES" && n != "EDGE_FIELD")
        .collect();
    let table = text
        .split_once("pub const EDGES")
        .map_or("", |(_, rest)| rest.split("];").next().unwrap_or(""));
    let listed: BTreeSet<String> = RUST_LISTED
        .captures_iter(table)
        .map(|m| m[1].to_string())
        .collect();
    let mut out = Vec::new();
    let a: Vec<_> = declared.difference(&listed).collect();
    let b: Vec<_> = listed.difference(&declared).collect();
    if !a.is_empty() || !b.is_empty() {
        out.push(format!(
            "declared but not in EDGES: {a:?}; listed but not declared: {b:?}"
        ));
    }
    out
}

/// `(edge, event)` pairs of `paths::AUDIT_EVENTS`.
pub fn audit_registry(code: &Code) -> Result<BTreeSet<(String, String)>, String> {
    let consts = code.rust_consts();
    let table = code
        .rust_paths
        .split_once("pub const AUDIT_EVENTS")
        .map(|(_, rest)| rest.split("];").next().unwrap_or(""))
        .ok_or("relay/src/paths.rs has no AUDIT_EVENTS")?;
    AUDIT_PAIR
        .captures_iter(table)
        .map(|m| {
            let id = consts
                .get(&m[1])
                .ok_or_else(|| format!("AUDIT_EVENTS names {}, which is not a constant", &m[1]))?;
            Ok((id.clone(), m[2].to_string()))
        })
        .collect()
}

/// `(edge, event)` pairs the ledger's `audit` attributes name: `audit.jsonl a / b (…); …`.
pub fn audit_in_ledger(l: &Value) -> Result<BTreeSet<(String, String)>, String> {
    let mut pairs = BTreeSet::new();
    for (id, e) in edges_by_id(l)? {
        let audit = get(e, "audit").map(py_str).unwrap_or_default();
        let Some(rest) = audit.strip_prefix("audit.jsonl") else {
            continue;
        };
        let events = rest.split(';').next().unwrap_or("");
        let events = events.split('(').next().unwrap_or("");
        for ev in events.split('/') {
            let ev = ev.trim();
            if !ev.is_empty() {
                pairs.insert((id.clone(), ev.to_string()));
            }
        }
    }
    Ok(pairs)
}

/// The relay writes pairs the ledger does not name, or the ledger names pairs nothing writes.
pub fn audit_disagrees(l: &Value, code: &Code) -> Result<Vec<String>, String> {
    let (in_code, in_ledger) = (audit_registry(code)?, audit_in_ledger(l)?);
    let mut out = Vec::new();
    let a: Vec<_> = in_code.difference(&in_ledger).collect();
    if !a.is_empty() {
        out.push(format!(
            "written by the relay, missing from the ledger: {a:?}"
        ));
    }
    let b: Vec<_> = in_ledger.difference(&in_code).collect();
    if !b.is_empty() {
        out.push(format!("in the ledger, written by no code: {b:?}"));
    }
    Ok(out)
}

/// Registered events written through the plain `log` / `deny`, which carry no edge.
pub fn events_written_without_an_edge(code: &Code) -> Result<Vec<String>, String> {
    let registered: BTreeSet<String> = audit_registry(code)?
        .into_iter()
        .map(|(_, ev)| ev)
        .collect();
    let plain: BTreeSet<String> = PLAIN_AUDIT
        .captures_iter(&code.relay_sources)
        .map(|m| m[1].to_string())
        .collect();
    Ok(plain.intersection(&registered).cloned().collect())
}

/// The edges `sgw verify`'s items name (`edges: &[paths::X, "id"]`).
pub fn verify_edges(code: &Code) -> Result<BTreeSet<String>, String> {
    let consts = code.rust_consts();
    let mut out = BTreeSet::new();
    for block in VERIFY_BLOCK.captures_iter(&code.verify) {
        for m in PATHS_REF.captures_iter(&block[1]) {
            let id = consts.get(&m[1]).ok_or_else(|| {
                format!("verify.rs names paths::{}, which is not a constant", &m[1])
            })?;
            out.insert(id.clone());
        }
        for m in ID_LITERAL.captures_iter(&block[1]) {
            out.insert(m[1].to_string());
        }
    }
    Ok(out)
}

/// `sgw verify` and the ledger's `verify` attributes disagree on what a real machine probes.
pub fn verify_disagrees(l: &Value, code: &Code) -> Result<Vec<String>, String> {
    let in_ledger: BTreeSet<String> = edges_by_id(l)?
        .into_iter()
        .filter(|(_, e)| get_truthy(e, "verify").is_some())
        .map(|(id, _)| id)
        .collect();
    let in_sgw = verify_edges(code)?;
    let mut out = Vec::new();
    let a: Vec<_> = in_sgw.difference(&in_ledger).collect();
    if !a.is_empty() {
        out.push(format!(
            "sgw verify names edges the ledger does not mark as verified: {a:?}"
        ));
    }
    let b: Vec<_> = in_ledger.difference(&in_sgw).collect();
    if !b.is_empty() {
        out.push(format!(
            "the ledger says these are probed on a real machine, but no verify item names them: {b:?}"
        ));
    }
    Ok(out)
}

/// #220: SSH edges of the relay verified by something other than a known_hosts it owns.
pub fn ssh_not_verified_by_the_relay(l: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (id, e) in edges_by_id(l)? {
        if get_str(e, "from")? != "gateway.relay.ssh" {
            continue;
        }
        let peer = get_str(e, "verifies_peer")?;
        if !RELAY_OWNED_KNOWN_HOSTS.is_match(&peer) {
            out.push(format!("{id}: {peer}"));
        }
        if peer.contains("~/.ssh") {
            out.push(format!("{id} is verified by a file the relay does not own"));
        }
    }
    Ok(out)
}

/// #220: the bastion hop of a multi-hop edge is not marked as a hop or not verified the same way.
pub fn hops_not_verified(l: &Value) -> Result<Vec<String>, String> {
    let all = ledger::edges(l)?;
    let mut out = Vec::new();
    for (id, e) in edges_by_id(l)? {
        let from = get_str(e, "from")?;
        for hop in get_list(e, "via").into_iter().filter(|h| h == "bastion") {
            let Some(hop_edge) = all.iter().find(|x| {
                get_str(x, "from").ok() == Some(from.clone())
                    && get_str(x, "to").ok() == Some(hop.clone())
            }) else {
                out.push(format!(
                    "{id} goes through {hop} but no edge goes from {from} to it"
                ));
                continue;
            };
            let hop_id = get_str(hop_edge, "id")?;
            if get_truthy(hop_edge, "hops").is_none() {
                out.push(format!(
                    "{id} goes through {hop} but {hop_id} is not marked as a hop"
                ));
            }
            if !RELAY_OWNED_KNOWN_HOSTS.is_match(&get_str(hop_edge, "verifies_peer")?) {
                out.push(hop_id);
            }
        }
    }
    Ok(out)
}

/// #212 #186 #190: external nodes reachable from dev through no policy, proxy, relay or service
/// node. (A simple path that skips every mediating node exists exactly when the target is
/// reachable through non-mediating nodes alone.)
pub fn unmediated_from_dev(l: &Value) -> Result<Vec<String>, String> {
    let g = Graph::from_ledger(l, false)?;
    if !g.contains("dev") {
        return Ok(Vec::new());
    }
    let reached = g.reachable("dev", |n| {
        !g.kind(n).is_some_and(|k| MEDIATING_KINDS.contains(&k))
    });
    Ok(g.nodes()
        .iter()
        .filter(|n| g.kind(n) == Some("external") && reached.contains(*n))
        .map(|n| format!("dev reaches {n} with no policy on the way"))
        .collect())
}

/// Not exactly one direct-egress edge, or that edge not flagged `warned`.
pub fn direct_egress_problems(l: &Value) -> Result<Vec<String>, String> {
    let direct: Vec<&Value> = ledger::edges(l)?
        .iter()
        .filter(|e| {
            get(e, "switches")
                .and_then(|s| get(s, "direct_egress"))
                .is_some_and(|v| v.as_str() == Some("allow"))
        })
        .collect();
    if direct.len() != 1 {
        return Ok(vec![format!(
            "exactly one edge is the direct-egress one; found {}",
            direct.len()
        )]);
    }
    if get(direct[0], "warned") != Some(&Value::Bool(true)) {
        return Ok(vec![
            "the gateway must warn when it is open beside an upstream proxy".into(),
        ]);
    }
    Ok(Vec::new())
}

/// Edges from dev to the internet or the host, other than the direct-egress one, that name no
/// `blocked_by` or no `verify` item.
pub fn unblocked_edges(l: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (id, e) in edges_by_id(l)? {
        let to = get_str(e, "to")?;
        if get_str(e, "from")? != "dev"
            || !(to == "internet" || to == "host")
            || id == "dev.egress.direct"
        {
            continue;
        }
        if get_truthy(e, "blocked_by").is_none() {
            out.push(format!(
                "{id} reaches {to} from dev and nothing is named as blocking it"
            ));
        }
        if get_truthy(e, "verify").is_none() {
            out.push(format!(
                "{id}: a blocked edge is probed on the real machine, so it needs a verify item"
            ));
        }
    }
    Ok(out)
}

/// #217: secrets the gateway holds that are readable over an edge starting in dev.
pub fn secrets_readable_from_dev(l: &Value) -> Result<Vec<String>, String> {
    let edges = edges_by_id(l)?;
    let mut out = Vec::new();
    for (name, s) in ledger::secrets(l)? {
        if get_str(s, "held_by")? == "dev" {
            continue; // dev's own credentials are meant to be in dev
        }
        for id in get_list(s, "exposed_via") {
            if let Some(e) = edges.get(&id) {
                if get_str(e, "from")? == "dev" {
                    out.push(format!(
                        "secret {} is readable over {id}, which starts in dev",
                        py_str(name)
                    ));
                }
            }
        }
    }
    Ok(out)
}

/// Secrets used on, or exposed through, an edge the ledger does not have.
pub fn secrets_on_unknown_edges(l: &Value) -> Result<Vec<String>, String> {
    let edges = edges_by_id(l)?;
    let mut out = Vec::new();
    for (name, s) in ledger::secrets(l)? {
        for id in get_list(s, "used_by")
            .into_iter()
            .chain(get_list(s, "exposed_via"))
        {
            if !edges.contains_key(&id) {
                out.push(format!(
                    "secret {} names an unknown edge {id}",
                    py_str(name)
                ));
            }
        }
    }
    Ok(out)
}

/// Secrets the gateway holds that no test and no verify item checks.
pub fn unchecked_secrets(l: &Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (name, s) in ledger::secrets(l)? {
        if get_str(s, "held_by")? == "dev" {
            continue;
        }
        if get_truthy(s, "tests").is_none() && get_truthy(s, "verify").is_none() {
            out.push(format!(
                "secret {}: nothing checks that it stays where it is",
                py_str(name)
            ));
        }
    }
    Ok(out)
}

/// #205: a peer reached with two TLS implementations, by an edge without a valid `interop`.
pub fn interop_missing(l: &Value) -> Result<Vec<String>, String> {
    let edges = edges_by_id(l)?;
    let mut by_peer: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (id, e) in &edges {
        if let Some(t) = get_truthy(e, "tls_impl") {
            by_peer
                .entry(get_str(e, "to")?)
                .or_default()
                .entry(py_str(t))
                .or_default()
                .push(id.clone());
        }
    }
    let mut out = Vec::new();
    for (peer, impls) in by_peer {
        if impls.len() < 2 {
            continue;
        }
        for id in impls.values().flatten() {
            match get_truthy(edges[id], "interop") {
                None => out.push(format!(
                    "{id}: {peer} is reached with more than one TLS implementation; name the \
                     interop test or the detour"
                )),
                Some(i) if !edges.contains_key(&py_str(i)) => {
                    out.push(format!("{id}: interop names an unknown edge"))
                }
                Some(_) => {}
            }
        }
    }
    Ok(out)
}
