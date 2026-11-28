//! Which language images to build (#376).
//!
//! lang/versions.yml lists each language's versions with a revision, the way a Debian package has
//! one: `8.3.33: 1` is published as `sgw-lang-php:8.3.33-1-bookworm`, and `8.3.33-bookworm` moves
//! to the newest revision. A published revision never changes; rebuilding means raising the
//! revision. So nothing already published is built again:
//!
//! - publish: every version whose `<version>-<revision>-bookworm` is not on the registry yet. A
//!   revision 1 whose image was published before revisions existed (`8.3.26-bookworm` alone) is
//!   adopted — tagged, not rebuilt.
//! - pr: the versions the pull request adds or re-revisions, and — when a recipe changed — the
//!   newest version of each language that recipe builds, to check it still builds.
//!
//! `track` (#378) names minor lines (`php: ["8.3"]`) whose newest patch, asked of the base image's
//! mise, is published as revision 1 without being written into the file: the registry's tags are
//! the record. A daily run picks each new patch up; on most days it finds nothing to build.
//!
//! The binary `lang-plan` prints a JSON object: `build` (each `{lang, version, revision}`) and
//! `adopt` (the same shape), byte for byte what `lang/plan.py` printed before it.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use serde_yaml_ng::Value;

use crate::pyfmt::{json_str, last_line, py_repr_str, py_str, truthy};

/// The Debian the images are built on: lang/Dockerfile's `ARG BASE` is a plain base tag, which is
/// Debian 12. The base is on Debian 13 too (`<version>-trixie`, #507), but these images are not:
/// their binaries and runtime package names are Debian 12's (docs/languages.md).
pub const SUFFIX: &str = "bookworm";
/// A change here is a change to every language's build.
pub const COMMON: [&str; 2] = ["lang/Dockerfile", "lang/runtime-packages.sh"];

pub type Error = String;

/// One image: a language at a version and revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub lang: String,
    pub version: String,
    pub revision: u64,
}

impl Entry {
    pub fn new(lang: &str, version: &str, revision: u64) -> Entry {
        Entry {
            lang: lang.into(),
            version: version.into(),
            revision,
        }
    }

    /// `8.3.33-2-bookworm`.
    pub fn tag(&self) -> String {
        format!("{}-{}-{SUFFIX}", self.version, self.revision)
    }

    pub fn repo(&self) -> String {
        format!("ghcr.io/amakata/sgw-lang-{}", self.lang)
    }

    fn json(&self) -> String {
        format!(
            "{{\"lang\": {}, \"version\": {}, \"revision\": {}}}",
            json_str(&self.lang),
            json_str(&self.version),
            self.revision
        )
    }
}

/// What a run decides: images to build and images only to tag.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Plan {
    pub build: Vec<Entry>,
    pub adopt: Vec<Entry>,
}

impl Plan {
    /// `json.dumps({"build": …, "adopt": …})`.
    pub fn to_json(&self) -> String {
        let list = |v: &[Entry]| {
            let items: Vec<String> = v.iter().map(Entry::json).collect();
            format!("[{}]", items.join(", "))
        };
        format!(
            "{{\"build\": {}, \"adopt\": {}}}",
            list(&self.build),
            list(&self.adopt)
        )
    }
}

/// `x.y`, `x.y.z` or `x.y.z.w`: ASCII digits only.
fn is_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    (2..=4).contains(&parts.len()) && parts.iter().all(|p| is_number(p))
}

/// A tracked minor line: `x.y`.
fn is_line(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 2 && parts.iter().all(|p| is_number(p))
}

fn is_number(p: &str) -> bool {
    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
}

/// Compares two versions part by part as whole numbers, however long.
fn version_cmp(a: &str, b: &str) -> Ordering {
    let num = |p: &str| p.trim_start_matches('0').to_string();
    let (a, b): (Vec<String>, Vec<String>) = (
        a.split('.').map(num).collect(),
        b.split('.').map(num).collect(),
    );
    for (x, y) in a.iter().zip(&b) {
        let o = x.len().cmp(&y.len()).then_with(|| x.cmp(y));
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

/// The top-level mapping of the file, `{}` when it is empty.
fn top(text: &str) -> Result<serde_yaml_ng::Mapping, Error> {
    let data: Value = serde_yaml_ng::from_str(text).map_err(|e| format!("versions.yml: {e}"))?;
    if !truthy(&data) {
        return Ok(Default::default());
    }
    match data {
        Value::Mapping(m) => Ok(m),
        _ => Err("versions.yml: the file is a mapping".into()),
    }
}

/// The mapping under `key`, `{}` when absent or empty.
fn section(text: &str, key: &str) -> Result<serde_yaml_ng::Mapping, Error> {
    let top = top(text)?;
    match top.get(key) {
        None => Ok(Default::default()),
        Some(v) if !truthy(v) => Ok(Default::default()),
        Some(Value::Mapping(m)) => Ok(m.clone()),
        Some(_) => Err(format!("versions.yml: `{key}` is a mapping")),
    }
}

/// `pin: {lang: {version: revision}}` as a list, checked. `before_revisions` also reads the list
/// form the file had before (`php: ["8.3.26"]`), each as revision 1: a pull request's base branch
/// may still have it.
pub fn entries(text: &str, before_revisions: bool) -> Result<Vec<Entry>, Error> {
    let mut out = Vec::new();
    for (lang, versions) in section(text, "pin")? {
        let lang = py_str(&lang);
        let versions: Vec<(String, Value)> = match versions {
            Value::Sequence(list) if before_revisions => {
                // `{str(v): 1 for v in versions}`: a version listed twice is one entry
                let mut seen: Vec<(String, Value)> = Vec::new();
                for v in &list {
                    let v = py_str(v);
                    if !seen.iter().any(|(s, _)| *s == v) {
                        seen.push((v, Value::Number(1u64.into())));
                    }
                }
                seen
            }
            Value::Mapping(m) => m.iter().map(|(k, v)| (py_str(k), v.clone())).collect(),
            _ => {
                return Err(format!(
                    "{lang}: write each version with its revision, `\"8.3.33\": 1`"
                ))
            }
        };
        for (version, revision) in versions {
            if !is_version(&version) {
                return Err(format!("{lang} {version}: a version is x.y.z"));
            }
            let revision = match &revision {
                Value::Number(n) => n.as_u64().filter(|r| *r >= 1),
                _ => None,
            }
            .ok_or_else(|| format!("{lang} {version}: the revision is a whole number from 1"))?;
            out.push(Entry {
                lang: lang.clone(),
                version,
                revision,
            });
        }
    }
    Ok(out)
}

/// `track: {lang: [line, …]}` (#378): the minor lines whose newest patch is built.
pub fn tracks(text: &str) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for (lang, lines) in section(text, "track")? {
        let lang = py_str(&lang);
        let Value::Sequence(lines) = lines else {
            return Err(format!("{lang}: track lists minor lines, `[\"8.3\"]`"));
        };
        for line in &lines {
            let line = py_str(line);
            if !is_line(&line) {
                return Err(format!("{lang} {line}: a tracked line is x.y"));
            }
            out.push((lang.clone(), line));
        }
    }
    Ok(out)
}

/// Each tracked line's newest patch, as revision 1 — unless a pin already names that version (a
/// pin can raise its revision; the track never does).
pub fn resolve(
    pinned: &[Entry],
    lines: &[(String, String)],
    mut latest: impl FnMut(&str, &str) -> Result<String, Error>,
) -> Result<Vec<Entry>, Error> {
    let mut out: Vec<Entry> = Vec::new();
    for (lang, line) in lines {
        let version = latest(lang, line)?;
        if !version.starts_with(&format!("{line}.")) || !is_version(&version) {
            return Err(format!(
                "{lang} {line}: the newest patch came back as {}",
                py_repr_str(&version)
            ));
        }
        let have = pinned
            .iter()
            .any(|e| &e.lang == lang && e.version == version);
        let e = Entry::new(lang, &version, 1);
        if !have && !out.contains(&e) {
            out.push(e);
        }
    }
    Ok(out)
}

/// The base the images are built on, from `ARG BASE=` in the Dockerfile.
pub fn base_image(dockerfile: &Path) -> Result<String, Error> {
    let text = std::fs::read_to_string(dockerfile)
        .map_err(|e| format!("{}: {e}", dockerfile.display()))?;
    text.lines()
        .find_map(|l| l.strip_prefix("ARG BASE="))
        .map(|b| b.trim().to_string())
        .ok_or_else(|| format!("{} has no ARG BASE=", dockerfile.display()))
}

/// Asks the base image's mise, the one that will build it, for the line's newest patch.
pub fn latest_from_mise(base: &str, lang: &str, line: &str) -> Result<String, Error> {
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            base,
            "mise",
            "latest",
            &format!("{lang}@{line}"),
        ])
        .output()
        .map_err(|e| format!("docker: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker run {base} mise latest {lang}@{line}: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    last_line(&stdout)
        .map(str::to_string)
        .ok_or_else(|| format!("mise latest {lang}@{line} printed nothing"))
}

/// Whether the registry has the image.
pub fn on_registry(reference: &str) -> Result<bool, Error> {
    let status = Command::new("docker")
        .args(["buildx", "imagetools", "inspect", reference])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("docker: {e}"))?;
    Ok(status.success())
}

/// What a pull request has to check.
pub fn plan_pr(head: &[Entry], base: &[Entry], changed: &[String]) -> Vec<Entry> {
    let mut out: Vec<Entry> = head.iter().filter(|e| !base.contains(e)).cloned().collect();
    let langs: BTreeSet<&str> = head.iter().map(|e| e.lang.as_str()).collect();
    let touched: BTreeSet<&str> = if changed.iter().any(|f| COMMON.contains(&f.as_str())) {
        langs.clone()
    } else {
        changed
            .iter()
            .filter(|f| f.starts_with("lang/") && f.matches('/').count() >= 2)
            .filter_map(|f| f.split('/').nth(1))
            .collect()
    };
    for lang in touched.intersection(&langs) {
        // the first of the newest, as Python's max() picks
        let mut newest: Option<&Entry> = None;
        for e in head.iter().filter(|e| e.lang == *lang) {
            if newest.is_none_or(|n| version_cmp(&e.version, &n.version) == Ordering::Greater) {
                newest = Some(e);
            }
        }
        if let Some(n) = newest {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
    }
    out
}

/// What a publish has to build, and what it only has to tag.
pub fn plan_publish(
    head: &[Entry],
    mut exists: impl FnMut(&str) -> Result<bool, Error>,
) -> Result<Plan, Error> {
    let mut plan = Plan::default();
    for e in head {
        let repo = e.repo();
        if exists(&format!("{repo}:{}", e.tag()))? {
            continue;
        }
        if e.revision == 1 && exists(&format!("{repo}:{}-{SUFFIX}", e.version))? {
            plan.adopt.push(e.clone());
        } else {
            plan.build.push(e.clone());
        }
    }
    Ok(plan)
}

/// The command line of `lang-plan`, as `lang/plan.py` took it.
#[derive(Debug, Default)]
pub struct Args {
    pub publish: bool,
    pub versions: String,
    pub base: Option<String>,
    pub changed: Option<String>,
    pub lang: String,
    pub version: String,
}

pub const USAGE: &str = "usage: lang-plan [-h] [--versions VERSIONS] [--base BASE] [--changed CHANGED] [--lang LANG] [--version VERSION] {publish,pr}";

pub fn parse_args(argv: &[String]) -> Result<Args, Error> {
    let mut a = Args {
        versions: "lang/versions.yml".into(),
        ..Args::default()
    };
    let mut mode: Option<String> = None;
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = |name: &str| -> Result<String, Error> {
            match inline.clone() {
                Some(v) => Ok(v),
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("argument {name}: expected one argument")),
            }
        };
        match flag {
            "--versions" => a.versions = value(flag)?,
            "--base" => a.base = Some(value(flag)?),
            "--changed" => a.changed = Some(value(flag)?),
            "--lang" => a.lang = value(flag)?,
            "--version" => a.version = value(flag)?,
            "-h" | "--help" => return Err(String::new()),
            m if !m.starts_with('-') && mode.is_none() => mode = Some(m.to_string()),
            other => return Err(format!("unrecognized arguments: {other}")),
        }
    }
    match mode.as_deref() {
        Some("publish") => a.publish = true,
        Some("pr") => {}
        Some(other) => {
            return Err(format!(
                "argument mode: invalid choice: '{other}' (choose from 'publish', 'pr')"
            ))
        }
        None => return Err("the following arguments are required: mode".into()),
    }
    Ok(a)
}

fn read(path: &str) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// The whole run: reads the files, asks docker what it has to, and returns the plan. `Ok(None)`
/// is a publish asked for a language or version the file does not list.
pub fn run(a: &Args) -> Result<Result<Plan, Error>, Error> {
    let text = read(&a.versions)?;
    let head = entries(&text, false)?;
    let lines = tracks(&text)?;
    let latest = |lang: &str, line: &str| {
        let base = base_image(Path::new("lang/Dockerfile"))?;
        latest_from_mise(&base, lang, line)
    };
    if !a.publish {
        let base_text = match a.base.as_deref() {
            Some(p) if !p.is_empty() => read(p)?,
            _ => String::new(),
        };
        let base = entries(&base_text, true)?;
        let changed: Vec<String> = match a.changed.as_deref() {
            Some(p) if !p.is_empty() => read(p)?.split_whitespace().map(String::from).collect(),
            _ => Vec::new(),
        };
        let mut build = plan_pr(&head, &base, &changed);
        // a line the pull request starts tracking: check its newest patch builds
        let before = tracks(&base_text)?;
        let new_lines: Vec<(String, String)> =
            lines.into_iter().filter(|t| !before.contains(t)).collect();
        for e in resolve(&head, &new_lines, latest)? {
            if !build.contains(&e) {
                build.push(e);
            }
        }
        return Ok(Ok(Plan {
            build,
            adopt: Vec::new(),
        }));
    }
    let mut all = head.clone();
    all.extend(resolve(&head, &lines, latest)?);
    let chosen: Vec<Entry> = all
        .into_iter()
        .filter(|e| {
            (a.lang.is_empty() || e.lang == a.lang)
                && (a.version.is_empty() || e.version == a.version)
        })
        .collect();
    if (!a.lang.is_empty() || !a.version.is_empty()) && chosen.is_empty() {
        return Ok(Err(format!(
            "{} {} is not in {}",
            a.lang, a.version, a.versions
        )));
    }
    plan_publish(&chosen, on_registry).map(Ok)
}
