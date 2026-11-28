//! Actions and base images are pinned by digest, and a digest is easy to drop back to a tag.
//!
//! `cargo audit` reads `relay/Cargo.lock` and nothing else, so for a long time nothing in CI
//! looked at the workflows or the Dockerfiles at all (#75). Pinning them by digest closes that,
//! but only while the pins stay: one `uses: foo/bar@v1` added later and that step is floating
//! again, silently, because a floating tag is not an error anywhere. These rules are the check.
//!
//! The trailing `# v1.2.3` comment is not decoration. It is the only place the human-readable
//! version survives once the ref is a digest, and it is what Dependabot reads to know what to bump
//! the pin to. A pin without one is a number nobody can update.
//!
//! Which is the other half, and checked here too: a pin is only maintained while something reads
//! it. From #87 until #103 the comments and the digests had no consumer at all, because
//! `.github/dependabot.yml` did not exist. Pinning a new ecosystem and forgetting to configure it
//! is the same failure in slow motion, so the config is held to what this repository pins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_yaml_ng::Value;

use crate::pyfmt::py_str;

/// Every file that names an image pulled from a registry at build or test time, relative to the
/// repository root.
pub const IMAGE_FILES: [&str; 5] = [
    "Dockerfile",
    "Dockerfile.agent",
    // the sidecar template's build stage (#499); its final stage is `FROM scratch`
    "examples/sidecar-template/Dockerfile",
    "tests/docker-compose.test.yml",
    // No `image:` of its own today — both services build. Listed so that one added later is
    // covered from the start rather than whenever someone remembers this file exists.
    "docker-compose.yml",
];

/// The updater the pins are written for.
pub const DEPENDABOT: &str = ".github/dependabot.yml";

/// What each ecosystem reads, as globs under its `directory`. A directory that exists is not
/// enough on its own: move relay/Cargo.toml one level down and `/relay` is still there while the
/// cargo updater reads nothing, silently, which is the shape of the bug this whole file is about.
/// One match is enough — Dependabot needs the manifest, and a lockfile beside it is optional.
pub const ECOSYSTEM_MANIFESTS: [(&str, &[&str]); 5] = [
    (
        "github-actions",
        &[".github/workflows/*.yml", ".github/workflows/*.yaml"],
    ),
    ("cargo", &["Cargo.toml"]),
    ("uv", &["pyproject.toml"]),
    ("docker", &["[Dd]ockerfile*", "[Cc]ontainerfile*"]),
    ("docker-compose", &["*compose*.yml", "*compose*.yaml"]),
];

/// The set the derived checks should be finding. Not the rule — the rule is read off the tree —
/// but the tripwire under it: a detector that goes blind would otherwise look exactly like a
/// repository with nothing to fix.
pub const PINNED_ECOSYSTEMS: [&str; 5] =
    ["cargo", "docker", "docker-compose", "github-actions", "uv"];

/// How long the image may go without a security update before CI says so. Short enough that a
/// forgotten pin is caught in the same quarter, long enough not to fire on every release.
pub const MAX_SNAPSHOT_AGE_DAYS: i64 = 90;

/// Written by `apt-get install` and read by nothing. Each one differed between 0.2.21 and 0.2.22
/// and nothing else in the 160 MB layer did.
pub const BUILD_RESIDUE: [&str; 7] = [
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/var/log/alternatives.log",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/apt/term.log",
    "/var/cache/ldconfig/aux-cache",
];

fn re(s: &str) -> Regex {
    Regex::new(s).expect("regex")
}

/// `uses: owner/repo@<40 hex> # v1.2.3`. The version after the `#` is free-form because the
/// actions do not agree on a shape: most tag `v6.1.0`, dtolnay/rust-toolchain names branches.
static PINNED_USES: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40} # \S+"));
static USES: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*(?:- )?uses:\s+(.+?)\s*$"));
static BARE_PIN: LazyLock<Regex> = LazyLock::new(|| re(r"\A[\w./-]+@[0-9a-f]{40}\z"));
/// `python:3.13-slim@sha256:…`, with the tag kept so the digest is readable.
static DIGEST: LazyLock<Regex> = LazyLock::new(|| re(r"@sha256:[0-9a-f]{64}(?:\s|$)"));
static FROM: LazyLock<Regex> = LazyLock::new(|| re(r"^FROM\s+(?:--\S+\s+)*(\S+)"));
static SYNTAX: LazyLock<Regex> = LazyLock::new(|| re(r"^#\s*syntax=(\S+)"));
static COMPOSE_IMAGE: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*image:\s*(\S+)"));
/// The sources point at the snapshot archive — literally, or through the ARG that carries the
/// timestamp so bumping it is one line.
static SNAPSHOT_URI: LazyLock<Regex> =
    LazyLock::new(|| re(r"https://snapshot\.debian\.org/archive/debian/(\S+)"));
/// `ARG DEBIAN_SNAPSHOT=20260920T000000Z`, or the timestamp written straight into the URI.
static SNAPSHOT_STAMP: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?:ARG\s+DEBIAN_SNAPSHOT=|/debian/)(\d{8}T\d{6}Z)"));
/// `\` line continuations mean one `apt-get install` spans many lines; a package is a bare token
/// on one of them. `-y`, `--no-install-recommends` and the `&&` that ends the run are not.
static APT_INSTALL: LazyLock<Regex> = LazyLock::new(|| re(r"apt-get\s+install\b"));
static APT_PACKAGE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s*([A-Za-z0-9][A-Za-z0-9.+-]*(?:=\S+)?)\s*\\?\s*$"));

/// The workflows, sorted by name.
pub fn workflows(root: &Path) -> Vec<PathBuf> {
    glob(root, ".github/workflows/*.yml")
}

pub fn is_dockerfile(rel: &str) -> bool {
    file_name(rel).starts_with("Dockerfile")
}

pub fn is_compose(rel: &str) -> bool {
    file_name(rel).contains("compose")
}

fn file_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

/// Every package named by an `apt-get install`, with its line number.
pub fn apt_packages(body: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for (n, line) in body.lines().enumerate() {
        if APT_INSTALL.is_match(line) {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // The run ends at the first line that is not a bare package: `&& rm -rf …`, or no `\`
        match APT_PACKAGE.captures(line) {
            Some(m) => out.push((n + 1, m[1].to_string())),
            None => inside = line.trim_end().ends_with('\\') && line.trim().starts_with('-'),
        }
    }
    out
}

pub fn uses_lines(body: &str) -> Vec<(usize, String)> {
    body.lines()
        .enumerate()
        .filter_map(|(n, l)| USES.captures(l).map(|m| (n + 1, m[1].to_string())))
        .collect()
}

/// Every registry reference in the file: FROM, the syntax directive, and compose images.
pub fn image_refs(body: &str) -> Vec<(usize, String)> {
    body.lines()
        .enumerate()
        .filter_map(|(n, l)| {
            [&*FROM, &*SYNTAX, &*COMPOSE_IMAGE]
                .iter()
                .find_map(|p| p.captures(l))
                .map(|m| (n + 1, m[1].to_string()))
        })
        .collect()
}

/// `uses:` refs that are not on a commit with a version comment.
pub fn floating_actions(name: &str, body: &str) -> Vec<String> {
    uses_lines(body)
        .into_iter()
        // `./…` is an action from this repository; there is no third party to pin
        .filter(|(_, r)| !r.starts_with("./") && !PINNED_USES.is_match(r))
        .map(|(n, r)| format!("{name}:{n} {r}"))
        .collect()
}

/// Registry images without a digest.
pub fn floating_images(name: &str, body: &str) -> Vec<String> {
    image_refs(body)
        .into_iter()
        // A later stage building on an earlier one by name, e.g. `FROM relay-builder`
        .filter(|(_, r)| (r.contains('/') || r.contains(':')) && !DIGEST.is_match(r))
        .map(|(n, r)| format!("{name}:{n} {r}"))
        .collect()
}

/// Actions pinned to a commit with no `# <version>` comment.
pub fn pins_without_a_version(name: &str, body: &str) -> Vec<String> {
    uses_lines(body)
        .into_iter()
        .filter(|(_, r)| BARE_PIN.is_match(r))
        .map(|(n, r)| format!("{name}:{n} {r}"))
        .collect()
}

pub fn installs_debian_packages(body: &str) -> bool {
    body.contains("apt-get install")
}

/// Whether the Debian sources are the snapshot archive.
pub fn pins_snapshot(body: &str) -> bool {
    SNAPSHOT_URI.is_match(body)
}

/// Packages installed without `=version`.
pub fn unpinned_packages(name: &str, body: &str) -> Vec<String> {
    apt_packages(body)
        .into_iter()
        .filter(|(_, p)| !p.contains('='))
        .map(|(n, p)| format!("{name}:{n} {p}"))
        .collect()
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYYMMDDTHHMMSSZ` as seconds since the epoch; `None` for a date that does not exist.
pub fn parse_stamp(stamp: &str) -> Option<i64> {
    let b = stamp.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| stamp.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (h, mi, s) = (n(9..11)?, n(11..13)?, n(13..15)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo) || d < 1 || d > month_days[(mo - 1) as usize] {
        return None;
    }
    if h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// Seconds since the epoch, now.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The snapshot is missing its timestamp or is older than `MAX_SNAPSHOT_AGE_DAYS` at `now`.
/// Nothing to say for a file that pins no snapshot.
pub fn stale_snapshot(name: &str, body: &str, now: i64) -> Option<String> {
    if !pins_snapshot(body) {
        return None;
    }
    let Some(stamp) = SNAPSHOT_STAMP.captures(body) else {
        return Some(format!(
            "{name}: the snapshot URI is there but no timestamp is — write it as \
             `ARG DEBIAN_SNAPSHOT=YYYYMMDDTHHMMSSZ`, so bumping it is one line"
        ));
    };
    let Some(stamped) = parse_stamp(&stamp[1]) else {
        return Some(format!("{name}: {} is not a date", &stamp[1]));
    };
    let age = (now - stamped).div_euclid(86_400);
    (age > MAX_SNAPSHOT_AGE_DAYS).then(|| {
        format!(
            "{name}: the Debian snapshot is {age} days old, and nothing has reached this image \
             since. Bump DEBIAN_SNAPSHOT and re-read the package versions out of the new one \
             (limit {MAX_SNAPSHOT_AGE_DAYS} days)."
        )
    })
}

/// Build residue the Dockerfile does not clear.
pub fn residue_left(body: &str) -> Vec<&'static str> {
    if !installs_debian_packages(body) {
        return Vec::new();
    }
    BUILD_RESIDUE
        .iter()
        .copied()
        .filter(|f| !body.contains(f))
        .collect()
}

/// A Dockerfile that installs Python packages and lets bytecode be written or compiles it.
pub fn bytecode_problems(name: &str, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !body.contains("pip install") {
        return out;
    }
    if !body.contains("PYTHONDONTWRITEBYTECODE=1") {
        out.push(format!(
            "{name}: `ENV PYTHONDONTWRITEBYTECODE=1`, or the first import writes a timestamped \
             .pyc into the running container"
        ));
    }
    if body.contains("compileall") {
        out.push(format!(
            "{name}: nothing should compile bytecode into the image; it is the layer digest's \
             only source of non-determinism left"
        ));
    }
    out
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// `uv pip install` lines without `--no-cache`.
pub fn cached_installs(body: &str) -> Vec<String> {
    body.lines()
        // A comment mentioning the command is not the command
        .filter(|l| !is_comment(l) && l.contains("uv pip install") && !l.contains("--no-cache"))
        .map(|l| l.trim().to_string())
        .collect()
}

/// The project installed into the dependency layer.
pub fn project_install_problems(name: &str, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !body.contains("uv pip install") {
        return out;
    }
    if !body.contains("uv export --frozen --no-dev --no-emit-project") {
        out.push(format!(
            "{name}: dependencies are installed from `uv export --no-emit-project`, not from `uv \
             pip install .`, so the layer holds no trace of the project's version"
        ));
    }
    for l in body.lines() {
        if !is_comment(l)
            && l.contains("uv pip install")
            && l.trim_end_matches([' ', '\\']).ends_with(" .")
            && !l.contains("--no-deps")
        {
            out.push(format!(
                "{name}: `uv pip install .` without --no-deps installs the project into the \
                 dependency layer: {}",
                l.trim()
            ));
        }
    }
    out
}

/// The workflows triggered by `pull_request` that run `tool`.
pub fn audited_on_pull_request<'a>(workflows: &'a [(String, String)], tool: &str) -> Vec<&'a str> {
    workflows
        .iter()
        .filter(|(_, body)| body.contains("pull_request") && body.contains(tool))
        .map(|(n, _)| n.as_str())
        .collect()
}

/// Every `updates:` entry of the Dependabot config, in file order (an ecosystem may appear twice,
/// for two directories). Empty when the config is absent or has none.
pub fn dependabot_updates(config: &Value) -> Vec<&Value> {
    match config.get("updates") {
        Some(Value::Sequence(s)) => s.iter().filter(|u| u.is_mapping()).collect(),
        _ => Vec::new(),
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).filter(|x| !x.is_null()).map(py_str)
}

/// Which Dependabot ecosystem each pinned thing needs, read off the tree rather than listed.
pub fn ecosystems_with_pins(root: &Path) -> BTreeMap<&'static str, &'static str> {
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let mut required = BTreeMap::new();
    if workflows(root)
        .iter()
        .any(|p| !uses_lines(&read(p)).is_empty())
    {
        required.insert("github-actions", "the `uses:` shas in .github/workflows/");
    }
    let any_refs = |pick: fn(&str) -> bool| {
        IMAGE_FILES
            .iter()
            .filter(|f| pick(f))
            .any(|f| !image_refs(&read(&root.join(f))).is_empty())
    };
    if any_refs(is_dockerfile) {
        required.insert("docker", "the FROM digests in the Dockerfiles");
    }
    if any_refs(is_compose) {
        required.insert("docker-compose", "the image digests in the compose files");
    }
    if root.join("relay/Cargo.lock").exists() {
        required.insert("cargo", "relay/Cargo.lock");
    }
    if root.join("uv.lock").exists() {
        required.insert("uv", "pyproject.toml and uv.lock");
    }
    required
}

/// What is wrong with one `updates:` entry: no ecosystem, an ecosystem nothing here knows the
/// manifests of, or a directory with nothing in it for the updater to read.
pub fn updater_problems(root: &Path, index: usize, block: &Value) -> Vec<String> {
    let Some(ecosystem) = str_field(block, "package-ecosystem").filter(|e| !e.is_empty()) else {
        return vec![format!("updates[{index}] has no `package-ecosystem`")];
    };
    let Some((_, patterns)) = ECOSYSTEM_MANIFESTS.iter().find(|(e, _)| *e == ecosystem) else {
        return vec![format!(
            "updates[{index}]: `{ecosystem}` is configured but ECOSYSTEM_MANIFESTS does not say \
             what it reads, so nothing here can tell whether it reads anything. Add it."
        )];
    };
    let directories: Vec<String> = match block.get("directories") {
        Some(Value::Sequence(d)) if !d.is_empty() => d.iter().map(py_str).collect(),
        _ => vec![str_field(block, "directory").unwrap_or_else(|| "/".into())],
    };
    let mut out = Vec::new();
    for directory in directories {
        if directory.contains('*') {
            // A glob directory (`/apps/*`) is Dependabot's to expand, not this check's.
            continue;
        }
        let dir = root.join(directory.trim_start_matches('/'));
        if !dir.is_dir() {
            out.push(format!(
                "{ecosystem}: no such directory in the repository: {directory}"
            ));
            continue;
        }
        if patterns.iter().all(|p| glob(&dir, p).is_empty()) {
            out.push(format!(
                "{ecosystem} at {directory}: the directory is there and has nothing in it for the \
                 updater to read. Expected one of {patterns:?}. A manifest that moved leaves the \
                 entry configured and silently reading nothing."
            ));
        }
    }
    out
}

/// `Path.glob` for patterns of `*`, `?` and `[…]` per path component, sorted.
pub fn glob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut found = vec![root.to_path_buf()];
    for part in pattern.split('/') {
        let mut next = Vec::new();
        for dir in &found {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in rd.flatten() {
                if wildcard(part, &entry.file_name().to_string_lossy()) {
                    next.push(entry.path());
                }
            }
        }
        found = next;
    }
    found.sort();
    found
}

/// fnmatch: `*`, `?`, `[abc]`, `[!abc]`, `[a-z]`.
pub fn wildcard(pattern: &str, name: &str) -> bool {
    fn class(p: &[char], c: char) -> Option<(bool, usize)> {
        // returns (matched, length of the class in the pattern)
        let mut i = 1;
        let negate = p.get(1) == Some(&'!');
        if negate {
            i += 1;
        }
        let start = i;
        let mut hit = false;
        while i < p.len() && (p[i] != ']' || i == start) {
            if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
                hit |= p[i] <= c && c <= p[i + 2];
                i += 3;
            } else {
                hit |= p[i] == c;
                i += 1;
            }
        }
        (i < p.len()).then_some((hit != negate, i + 1))
    }
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|k| go(&p[1..], &n[k..])),
            Some('?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some('[') => match (n.first(), class(p, n.first().copied().unwrap_or('\0'))) {
                (Some(_), Some((true, len))) => go(&p[len..], &n[1..]),
                (Some(_), Some((false, _))) | (None, _) => false,
                // an unclosed `[` is a literal
                (Some(c), None) => *c == '[' && go(&p[1..], &n[1..]),
            },
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    go(&p, &n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_as_fnmatch_does() {
        assert!(wildcard("[Dd]ockerfile*", "Dockerfile.agent"));
        assert!(wildcard("[Dd]ockerfile*", "dockerfile"));
        assert!(!wildcard("[Dd]ockerfile*", "Xockerfile"));
        assert!(wildcard("*compose*.yml", "docker-compose.test.yml"));
        assert!(!wildcard("*compose*.yml", "compose.yaml"));
        assert!(wildcard("Cargo.toml", "Cargo.toml"));
        assert!(wildcard("[!a]x", "bx") && !wildcard("[!a]x", "ax"));
        assert!(wildcard("?.yml", "a.yml") && !wildcard("?.yml", ".yml"));
    }

    #[test]
    fn stamps_are_read_as_utc() {
        assert_eq!(parse_stamp("19700101T000000Z"), Some(0));
        assert_eq!(parse_stamp("20000301T000000Z"), Some(951_868_800));
        assert_eq!(parse_stamp("20240229T120000Z"), Some(1_709_208_000));
        assert_eq!(parse_stamp("20230229T000000Z"), None);
        assert_eq!(parse_stamp("20261301T000000Z"), None);
    }
}
