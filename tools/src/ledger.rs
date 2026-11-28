//! The path ledger (`docs/paths.yml`, #223): loading it, its graph, and the questions the `paths`
//! binary answers. What the binary prints is byte for byte what `scripts/paths.py` printed
//! (NetworkX's `MultiDiGraph` and `all_simple_paths`, reproduced in `Graph`).

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use serde_yaml_ng::{Mapping, Value};

use crate::pyfmt::{py_str, truthy};

pub type Error = String;

/// The ledger as PyYAML read it: insertion-ordered mappings.
pub fn load(path: &Path) -> Result<Value, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_yaml_ng::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `d.get(key)` on a mapping; `None` for anything else.
pub fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Mapping(m) => m.get(key),
        _ => None,
    }
}

/// `d.get(key)` that is also true.
pub fn get_truthy<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    get(v, key).filter(|x| truthy(x))
}

/// `d[key]` as a string (`str()` of whatever is there).
pub fn get_str(v: &Value, key: &str) -> Result<String, Error> {
    get(v, key)
        .map(py_str)
        .ok_or_else(|| format!("KeyError: {key:?}"))
}

/// A list of strings under `key`; `[]` when absent.
pub fn get_list(v: &Value, key: &str) -> Vec<String> {
    match get(v, key) {
        Some(Value::Sequence(s)) => s.iter().map(py_str).collect(),
        _ => Vec::new(),
    }
}

pub fn nodes(ledger: &Value) -> Result<&Mapping, Error> {
    match get(ledger, "nodes") {
        Some(Value::Mapping(m)) => Ok(m),
        _ => Err("the ledger has no `nodes` mapping".into()),
    }
}

pub fn edges(ledger: &Value) -> Result<&Vec<Value>, Error> {
    match get(ledger, "edges") {
        Some(Value::Sequence(s)) => Ok(s),
        _ => Err("the ledger has no `edges` list".into()),
    }
}

pub fn secrets(ledger: &Value) -> Result<&Mapping, Error> {
    match get(ledger, "secrets") {
        Some(Value::Mapping(m)) => Ok(m),
        _ => Err("the ledger has no `secrets` mapping".into()),
    }
}

/// `[from, *via, to]` of an edge.
pub fn hops(e: &Value) -> Result<Vec<String>, Error> {
    let mut h = vec![get_str(e, "from")?];
    h.extend(get_list(e, "via"));
    h.push(get_str(e, "to")?);
    Ok(h)
}

/// A directed multigraph, iterated the way NetworkX iterates one: nodes in the order they were
/// added, each node's successors in the order they were first added, parallel edges together.
#[derive(Default, Debug)]
pub struct Graph {
    order: Vec<String>,
    kind: HashMap<String, Option<String>>,
    succ: HashMap<String, Vec<(String, usize)>>,
}

impl Graph {
    fn add_node(&mut self, name: &str, kind: Option<String>) {
        if !self.kind.contains_key(name) {
            self.order.push(name.to_string());
            self.kind.insert(name.to_string(), kind);
            self.succ.insert(name.to_string(), Vec::new());
        }
    }

    fn add_edge(&mut self, a: &str, b: &str) {
        self.add_node(a, None);
        self.add_node(b, None);
        let s = self.succ.get_mut(a).expect("added above");
        match s.iter_mut().find(|(n, _)| n == b) {
            Some((_, count)) => *count += 1,
            None => s.push((b.to_string(), 1)),
        }
    }

    /// The ledger's graph. `blocked` keeps the edges that must not work (scripts/paths.py's
    /// `--blocked`); the rules leave them out, since a blocked edge is not a way through.
    pub fn from_ledger(ledger: &Value, blocked: bool) -> Result<Graph, Error> {
        let mut g = Graph::default();
        for (name, attrs) in nodes(ledger)? {
            g.add_node(&py_str(name), get(attrs, "kind").map(py_str));
        }
        for e in edges(ledger)? {
            if get_truthy(e, "blocked_by").is_some() && !blocked {
                continue;
            }
            let h = hops(e)?;
            for w in h.windows(2) {
                g.add_edge(&w[0], &w[1]);
            }
        }
        Ok(g)
    }

    pub fn contains(&self, n: &str) -> bool {
        self.kind.contains_key(n)
    }

    /// `g.nodes[n].get("kind")`.
    pub fn kind(&self, n: &str) -> Option<&str> {
        self.kind.get(n).and_then(|k| k.as_deref())
    }

    /// The nodes in insertion order.
    pub fn nodes(&self) -> &[String] {
        &self.order
    }

    /// Each outgoing edge of `n` as its far end, parallel edges repeated.
    fn out_edges(&self, n: &str) -> Vec<String> {
        self.succ
            .get(n)
            .map(|s| {
                s.iter()
                    .flat_map(|(v, c)| std::iter::repeat_n(v.clone(), *c))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The nodes reachable from `start` by edges only, with `start` itself.
    pub fn reachable(&self, start: &str, through: impl Fn(&str) -> bool) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut todo = vec![start.to_string()];
        while let Some(n) = todo.pop() {
            if !seen.insert(n.clone()) {
                continue;
            }
            if n != start && !through(&n) {
                continue;
            }
            for (v, _) in self.succ.get(&n).into_iter().flatten() {
                todo.push(v.clone());
            }
        }
        seen
    }

    /// `nx.all_simple_paths(g, source, target)` in NetworkX 3.x's order, including its quirks: a
    /// path is listed once per combination of parallel edges, `source == target` gives the
    /// one-node path, and a target that is not a node is read as the set of its characters.
    pub fn all_simple_paths(&self, source: &str, target: &str) -> Result<Vec<Vec<String>>, Error> {
        if !self.contains(source) {
            return Err(format!("NodeNotFound: source node {source} not in graph"));
        }
        let targets: BTreeSet<String> = if self.contains(target) {
            [target.to_string()].into()
        } else {
            target.chars().map(String::from).collect()
        };
        let cutoff = self.order.len() as i64 - 1;
        let mut found = Vec::new();
        if cutoff < 0 || targets.is_empty() {
            return Ok(found);
        }
        // the path so far; NetworkX's dict also holds a dummy `None` at the front
        let mut path: Vec<String> = Vec::new();
        let mut stack: Vec<(Vec<String>, usize)> = vec![(vec![source.to_string()], 0)];
        while let Some((edges, cursor)) = stack.last_mut() {
            let next = edges[*cursor..].iter().position(|v| !path.contains(v));
            let Some(offset) = next else {
                stack.pop();
                path.pop();
                continue;
            };
            let v = edges[*cursor + offset].clone();
            *cursor += offset + 1;
            if targets.contains(&v) {
                let mut p = path.clone();
                p.push(v.clone());
                found.push(p);
            }
            let depth_ok = (path.len() as i64) < cutoff;
            let targets_left = targets.iter().any(|t| *t != v && !path.contains(t));
            if depth_ok && targets_left {
                let out = self.out_edges(&v);
                path.push(v);
                stack.push((out, 0));
            }
        }
        Ok(found)
    }
}

const COLORS: &[(&str, &str)] = &[
    ("agent", "#f2c9c9"),
    ("policy", "#c9e2f2"),
    ("proxy", "#f2e6c9"),
    ("relay", "#d5f2c9"),
    ("service", "#e6d5f2"),
    ("store", "#e6d5f2"),
    ("host", "#dddddd"),
    ("person", "#ffffff"),
    ("external", "#f2f2f2"),
];

/// The node kinds that mediate: a path through one of them is governed.
pub const MEDIATING_KINDS: [&str; 4] = ["policy", "proxy", "relay", "service"];

/// `value in container` for a container read from YAML: a key of a mapping, an item of a list,
/// a substring of a string.
fn py_in(needle: &str, container: &Value) -> Result<bool, Error> {
    match container {
        Value::Mapping(m) => Ok(m.contains_key(needle)),
        Value::Sequence(s) => Ok(s
            .iter()
            .any(|x| matches!(x, Value::String(v) if v == needle))),
        Value::String(s) => Ok(s.contains(needle)),
        Value::Tagged(t) => py_in(needle, &t.value),
        other => Err(format!(
            "TypeError: argument of type {} is not iterable",
            crate::pyfmt::py_repr(other)
        )),
    }
}

/// `f"{s:<width}"`.
fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    format!("{s}{}", " ".repeat(width.saturating_sub(n)))
}

/// `paths.py edges [--switch S] [--without K] [-v]`.
pub fn cmd_edges(
    ledger: &Value,
    switch: Option<&str>,
    without: Option<&str>,
    verbose: bool,
) -> Result<String, Error> {
    let mut out = String::new();
    for e in edges(ledger)? {
        if let Some(sw) = switch.filter(|s| !s.is_empty()) {
            let switches = get_truthy(e, "switches")
                .cloned()
                .unwrap_or(Value::Mapping(Mapping::new()));
            if !py_in(sw, &switches)? {
                continue;
            }
        }
        if let Some(k) = without.filter(|s| !s.is_empty()) {
            if get_truthy(e, k).is_some() {
                continue;
            }
        }
        let flag = match get_truthy(e, "blocked_by") {
            Some(b) => format!(" [blocked by {}]", py_str(b)),
            None => String::new(),
        };
        let via = if get_truthy(e, "via").is_some() {
            format!(" via {}", get_list(e, "via").join(","))
        } else {
            String::new()
        };
        writeln!(
            out,
            "{} {} → {}{via}{flag}",
            pad(&get_str(e, "id")?, 34),
            get_str(e, "from")?,
            get_str(e, "to")?
        )
        .expect("writing to a String");
        if verbose {
            for k in [
                "proto",
                "resolves",
                "verifies_peer",
                "presents",
                "audit",
                "switches",
                "verify",
                "check",
            ] {
                if let Some(v) = get_truthy(e, k) {
                    writeln!(out, "    {} {}", pad(k, 14), py_str(v)).expect("writing to a String");
                }
            }
        }
    }
    Ok(out)
}

/// `paths.py paths SRC DST [--blocked]`.
pub fn cmd_paths(ledger: &Value, src: &str, dst: &str, blocked: bool) -> Result<String, Error> {
    let g = Graph::from_ledger(ledger, blocked)?;
    let mut out = String::new();
    for path in g.all_simple_paths(src, dst)? {
        let inner = if path.len() > 2 {
            &path[1..path.len() - 1]
        } else {
            &[][..]
        };
        let mediating: Vec<&str> = inner
            .iter()
            .filter(|n| g.kind(n).is_some_and(|k| MEDIATING_KINDS.contains(&k)))
            .map(String::as_str)
            .collect();
        let by = if mediating.is_empty() {
            "NOTHING".to_string()
        } else {
            mediating.join(", ")
        };
        writeln!(out, "{}    (mediated by: {by})", path.join(" → ")).expect("writing to a String");
    }
    Ok(out)
}

/// `paths.py secret NAME`.
pub fn cmd_secret(ledger: &Value, name: &str) -> Result<String, Error> {
    let s = secrets(ledger)?
        .get(name)
        .ok_or_else(|| format!("KeyError: {name:?}"))?;
    let or = |list: Vec<String>, empty: &str| {
        let j = list.join(", ");
        if j.is_empty() {
            empty.to_string()
        } else {
            j
        }
    };
    let mut out = String::new();
    writeln!(out, "{name}: held by {}", get_str(s, "held_by")?).expect("writing to a String");
    writeln!(out, "  used on   {}", or(get_list(s, "used_by"), "-")).expect("writing to a String");
    writeln!(
        out,
        "  readable  {}",
        or(get_list(s, "exposed_via"), "nowhere")
    )
    .expect("writing to a String");
    if let Some(v) = get_truthy(s, "verify") {
        writeln!(out, "  verify    {}", py_str(v)).expect("writing to a String");
    }
    Ok(out)
}

/// `paths.py dot`: Graphviz.
pub fn cmd_dot(ledger: &Value) -> Result<String, Error> {
    let mut out = String::from(
        "digraph paths {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fontname=\"sans-serif\", fontsize=10];\n  edge [fontname=\"sans-serif\", fontsize=8];\n",
    );
    for (name, a) in nodes(ledger)? {
        let kind = get(a, "kind").map(py_str);
        let color = COLORS
            .iter()
            .find(|(k, _)| Some(*k) == kind.as_deref())
            .map_or("#ffffff", |(_, c)| c);
        writeln!(out, "  \"{}\" [fillcolor=\"{color}\"];", py_str(name))
            .expect("writing to a String");
    }
    for e in edges(ledger)? {
        let h = hops(e)?;
        let id = get_str(e, "id")?;
        let (style, label) = match get_truthy(e, "blocked_by") {
            Some(b) => (
                " style=dashed color=red",
                format!("{id}\\n(blocked by {})", py_str(b)),
            ),
            None => ("", id),
        };
        for (n, w) in h.windows(2).enumerate() {
            let lab = if n == 0 { label.as_str() } else { "" };
            writeln!(
                out,
                "  \"{}\" -> \"{}\" [label=\"{lab}\"{style}];",
                w[0], w[1]
            )
            .expect("writing to a String");
        }
    }
    out.push_str("}\n");
    Ok(out)
}
