//! The harness: the corpus, the two oracles (the recorded answers and the live Python gateway),
//! and the comparison.
//!
//! A [`Comparison`] is one thing both implementations are asked about: given a case, the request
//! the oracle receives and the answer the Rust side gives, in the same JSON shape. This step has
//! one, `config` (`config.rs`). The later steps add theirs the same way — a `Comparison` here and
//! a kind in `oracle.py`'s `KINDS`:
//!
//! | step | kind | request | answer |
//! |---|---|---|---|
//! | α4 | `config` | a config file, its environment, names to decide | accepted / refused, the settings, the derived lists, `Rules` |
//! | α4 | `webui` | a config, a database, an HTTP request | the response JSON |
//! | α6 | `dns` | a config, a list of queries | the response bytes (ID aside) |
//! | α6 | `firewall` | a config, a list of queries | the `iptables-legacy` / `ipset` command lines, recorded by fakes on PATH |
//! | α6 | `squid` | a config, the credential state | `squid.conf` |
//!
//! Every comparison is checked against two oracles:
//!
//! - **the record**, `relay/tests/fixtures/oracle/<kind>.json`: Python's answers, written by
//!   `SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_config` (only that test: the
//!   others read the record while it is written). Always checked, so the harness needs no
//!   Python — and it keeps working after the Python is gone (0.3.0-alpha.7)
//! - **the live gateway**, `oracle.py` run with `uv` (`UV` names another binary): checked when
//!   `uv` is there, and required when `SEKIMORE_E2E_REQUIRED` is set, as CI sets it. The live
//!   answers are also checked against the record, so a record Python no longer agrees with fails
//!
//! A case whose header says `# ledger: <why>` is a known difference (the 0.3.0 plan's difference
//! ledger): it is expected to differ, and fails if it stops differing.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Map, Value};

/// One input of the corpus.
#[derive(Debug, Clone)]
pub struct Case {
    /// The path from the repository root
    pub id: String,
    pub path: PathBuf,
    /// `# env: NAME=value` header lines
    pub env: BTreeMap<String, String>,
    /// `# ledger: …` — a known difference
    pub ledger: Option<String>,
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("relay/ has a parent")
        .to_path_buf()
}

/// Config files from elsewhere in the repository that are part of the corpus as they are.
const CORPUS_ELSEWHERE: &[&str] = &[
    "config/config.yml",
    "config/config.sample.yml",
    "relay/templates/devcontainer/.devcontainer/config/config.sample.yml",
];

/// Every case: the shared fixtures, `relay/tests/fixtures/corpus/`, and the samples above.
pub fn corpus() -> Vec<Case> {
    let root = repo_root();
    let mut paths: Vec<PathBuf> = Vec::new();
    for dir in ["relay/tests/fixtures", "relay/tests/fixtures/corpus"] {
        let mut found: Vec<PathBuf> = std::fs::read_dir(root.join(dir))
            .unwrap_or_else(|e| panic!("{dir}: {e}"))
            .map(|e| e.expect("dir entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml"))
            .collect();
        found.sort();
        paths.extend(found);
    }
    paths.extend(CORPUS_ELSEWHERE.iter().map(|p| root.join(p)));
    paths
        .into_iter()
        .map(|path| {
            let id = path
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .into_owned();
            let (env, ledger) = header(&path);
            Case {
                id,
                path,
                env,
                ledger,
            }
        })
        .collect()
}

/// The leading comment lines: `# env: NAME=value` and `# ledger: …`.
fn header(path: &Path) -> (BTreeMap<String, String>, Option<String>) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let text = String::from_utf8_lossy(&bytes);
    let mut env = BTreeMap::new();
    let mut ledger = None;
    for line in text.lines().take_while(|l| l.starts_with('#')) {
        if let Some(kv) = line.strip_prefix("# env: ") {
            let (k, v) = kv.split_once('=').expect("# env: NAME=value");
            env.insert(k.to_string(), v.to_string());
        } else if let Some(why) = line.strip_prefix("# ledger: ") {
            ledger = Some(why.to_string());
        }
    }
    (env, ledger)
}

/// One thing both implementations are asked about.
pub trait Comparison {
    /// The oracle's kind (`oracle.py` `KINDS`) and the record's file name
    fn kind(&self) -> &'static str;
    /// What the oracle is asked for `case`. Holds at least `id`
    fn request(&self, case: &Case) -> Value;
    /// The Rust side's answer to `request`, in the oracle's shape (with `id`)
    fn rust(&self, case: &Case, request: &Value) -> Value;
}

/// The differences between two JSON values, as `path: left != right` lines.
pub fn diff(left: &Value, right: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(left, right, "", &mut out);
    out
}

fn walk(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                let p = format!("{path}/{k}");
                match (x.get(k), y.get(k)) {
                    (Some(l), Some(r)) => walk(l, r, &p, out),
                    (l, r) => out.push(format!("{p}: {} != {}", show(l), show(r))),
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (l, r)) in x.iter().zip(y).enumerate() {
                walk(l, r, &format!("{path}/{i}"), out);
            }
        }
        _ if a == b => {}
        _ => out.push(format!("{path}: {} != {}", show(Some(a)), show(Some(b)))),
    }
}

fn show(v: Option<&Value>) -> String {
    match v {
        None => "(absent)".into(),
        Some(v) => {
            let s = v.to_string();
            if s.len() > 300 {
                format!("{}…", &s[..s.floor_char_boundary_compat(300)])
            } else {
                s
            }
        }
    }
}

trait FloorCharBoundary {
    fn floor_char_boundary_compat(&self, i: usize) -> usize;
}

impl FloorCharBoundary for str {
    fn floor_char_boundary_compat(&self, mut i: usize) -> usize {
        while !self.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
}

fn record_path(kind: &str) -> PathBuf {
    repo_root().join(format!("relay/tests/fixtures/oracle/{kind}.json"))
}

/// The recorded answers, by case id.
pub fn recorded(kind: &str) -> BTreeMap<String, Value> {
    let path = record_path(kind);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    let v: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    v["answers"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn write_record(kind: &str, python: &Value, answers: &[Value]) {
    let mut by_id = Map::new();
    for a in answers {
        by_id.insert(
            a["id"].as_str().expect("an answer has an id").to_string(),
            a.clone(),
        );
    }
    let doc = json!({
        "comment": "Python's answers, recorded by SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_config. Do not edit by hand.",
        "kind": kind,
        "python": python,
        "answers": by_id,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("serializable");
    text.push('\n');
    std::fs::write(record_path(kind), text).expect("write the record");
}

pub fn required() -> bool {
    std::env::var("SEKIMORE_E2E_REQUIRED").is_ok()
}

fn recording() -> bool {
    std::env::var("SEKIMORE_ORACLE_RECORD").is_ok()
}

fn uv() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("UV") {
        return Some(PathBuf::from(p));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("uv"))
        .find(|p| p.is_file())
}

/// The live Python answers, or why there are none.
pub fn live(kind: &str, requests: &[Value]) -> Result<(Value, Vec<Value>), String> {
    let uv = uv().ok_or("uv is not on PATH (set UV to name it)")?;
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let req = dir.path().join("request.json");
    let ans = dir.path().join("answer.json");
    std::fs::write(&req, json!({"kind": kind, "cases": requests}).to_string())
        .map_err(|e| e.to_string())?;
    let out = Command::new(&uv)
        .args(["run", "--frozen", "--no-dev", "--quiet", "python"])
        .arg("relay/tests/equivalence/oracle.py")
        .arg(&req)
        .arg(&ans)
        .current_dir(repo_root())
        .output()
        .map_err(|e| format!("{}: {e}", uv.display()))?;
    if !out.status.success() {
        return Err(format!(
            "the oracle failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let v: Value = serde_json::from_slice(&std::fs::read(&ans).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let answers = v["answers"].as_array().cloned().unwrap_or_default();
    Ok((v["python"].clone(), answers))
}

/// How one case came out against one oracle.
#[derive(Debug)]
pub struct Outcome {
    pub id: String,
    pub ledger: Option<String>,
    pub differences: Vec<String>,
}

impl Outcome {
    /// A failure: an unexpected difference, or a ledger case that no longer differs.
    pub fn failed(&self) -> bool {
        self.differences.is_empty() == self.ledger.is_some()
    }
}

/// Compares `rust` with `oracle` case by case. A case the oracle has no answer for is a
/// difference ("re-record").
pub fn compare(
    cases: &[Case],
    rust: &[Value],
    oracle: &BTreeMap<String, Value>,
    oracle_name: &str,
) -> Vec<Outcome> {
    cases
        .iter()
        .zip(rust)
        .map(|(case, r)| {
            let differences = match oracle.get(&case.id) {
                Some(o) => diff(r, o),
                None => vec![format!(
                    "{oracle_name} has no answer (SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_config)"
                )],
            };
            Outcome {
                id: case.id.clone(),
                ledger: case.ledger.clone(),
                differences,
            }
        })
        .collect()
}

/// A readable account of the failures, or None when there are none.
pub fn report(title: &str, outcomes: &[Outcome]) -> Option<String> {
    let failed: Vec<&Outcome> = outcomes.iter().filter(|o| o.failed()).collect();
    if failed.is_empty() {
        return None;
    }
    let mut s = format!("{title}: {} of {} cases\n", failed.len(), outcomes.len());
    for o in failed {
        if o.differences.is_empty() {
            s.push_str(&format!(
                "\n{}: marked `# ledger: {}` but no longer differs; drop the mark\n",
                o.id,
                o.ledger.as_deref().unwrap_or("")
            ));
            continue;
        }
        s.push_str(&format!("\n{} (left: Rust, right: Python)\n", o.id));
        for d in o.differences.iter().take(25) {
            s.push_str(&format!("  {d}\n"));
        }
        if o.differences.len() > 25 {
            s.push_str(&format!("  … {} more\n", o.differences.len() - 25));
        }
    }
    Some(s)
}

fn by_id(answers: &[Value]) -> BTreeMap<String, Value> {
    answers
        .iter()
        .map(|a| (a["id"].as_str().unwrap_or_default().to_string(), a.clone()))
        .collect()
}

/// Runs a comparison over the whole corpus against both oracles; panics with the report on any
/// failure. With `SEKIMORE_ORACLE_RECORD` set, writes the record from the live answers first.
pub fn run(cmp: &dyn Comparison) {
    let cases = corpus();
    let requests: Vec<Value> = cases.iter().map(|c| cmp.request(c)).collect();
    let rust: Vec<Value> = cases
        .iter()
        .zip(&requests)
        .map(|(c, r)| cmp.rust(c, r))
        .collect();

    let live = match live(cmp.kind(), &requests) {
        Ok(l) => Some(l),
        Err(why) if required() || recording() => panic!("the Python oracle is required: {why}"),
        Err(why) => {
            eprintln!("skipping the live Python comparison: {why}");
            None
        }
    };
    if recording() {
        let (python, answers) = live.as_ref().expect("checked above");
        write_record(cmp.kind(), python, answers);
    }

    let mut failures = Vec::new();
    let record = recorded(cmp.kind());
    failures.extend(report(
        "Rust vs the record",
        &compare(&cases, &rust, &record, "the record"),
    ));
    if let Some((_, answers)) = &live {
        let live = by_id(answers);
        failures.extend(report(
            "Rust vs live Python",
            &compare(&cases, &rust, &live, "Python"),
        ));
        // the record has to be what Python says today
        let live_values: Vec<Value> = cases
            .iter()
            .map(|c| live.get(&c.id).cloned().unwrap_or(Value::Null))
            .collect();
        let plain: Vec<Case> = cases
            .iter()
            .map(|c| Case {
                ledger: None,
                ..c.clone()
            })
            .collect();
        failures.extend(report(
            "live Python vs the record (re-record with SEKIMORE_ORACLE_RECORD=1 … the_config)",
            &compare(&plain, &live_values, &record, "the record"),
        ));
    }
    for o in compare(&cases, &rust, &record, "the record") {
        if let (Some(why), false) = (&o.ledger, o.differences.is_empty()) {
            eprintln!("known difference, {}: {why}", o.id);
            for d in o.differences.iter().take(5) {
                eprintln!("  {d}");
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
