//! The changelogs are written to a shape, and that shape is easy to drift out of.
//!
//! An entry is meant to say what changed, not to argue the case for it. Three releases in a row
//! grew to 450-720 character bullets before anyone noticed, because nothing checked. These rules
//! are the check: they enforce the shape the 0.1.x entries already had, and keep the two languages
//! aligned.
//!
//! The shape, since 0.2.18:
//!
//! ```text
//! ## 0.2.17 (2026-09-21)
//!
//! ### Security
//!
//! - sealed the set of records with a MAC, checked at unlock (#77)
//! ```
//!
//! A release groups its bullets under `### Security`, `### Fix`, `### Enhancement` — heaviest
//! first, each one optional — and every bullet ends with the pull request that changed it. The
//! reader who wants the reasoning follows the number; the entry itself stays one scannable line.

use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

/// A bullet longer than this is a paragraph wearing a bullet's clothes. Entries sit between 60
/// and 210; the cap leaves room for one that genuinely needs a clause about scope.
pub const MAX_BULLET: usize = 250;
/// A release with more bullets than this is usually several releases, or one entry split too
/// fine.
pub const MAX_BULLETS_PER_RELEASE: usize = 12;
/// Heaviest first. A release uses the ones it needs and keeps them in this order.
pub const CATEGORIES: [&str; 3] = ["Security", "Fix", "Enhancement"];

/// `(#77)` at the end of the line. One pull request per entry; an entry spanning two is two.
static REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r" \(#\d+\)$").expect("regex"));
static RELEASE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^## (\S+?)[ （(]").expect("regex"));
/// `## 0.2.8 (2026-09-17)`, or the Japanese `## 0.2.8（2026-09-17）` with no space before the
/// bracket. A range like `## 0.1.0 – 0.1.2 (2026-09-08 – 13)` covers the entries written in one
/// go; a prerelease (0.3.0-alpha.1, #325) is a version too.
pub static HEADING: LazyLock<Regex> = LazyLock::new(|| {
    let v = r"\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?";
    let ver = format!(r"{v}(?: [–〜] {v})?");
    // a date, or a range whose second half may be shortened: `2026-09-08 – 13`
    let date = r"\d{4}-\d{2}-\d{2}(?: [–〜] [\d-]+)?";
    Regex::new(&format!(r"\A## {ver}(?: \({date}\)|（{date}）)\z")).expect("regex")
});
static SEMVER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z").expect("regex"));

/// SemVer order: a prerelease (0.3.0-alpha.1, #325) sorts below its release, and its identifiers
/// compare numerically when numeric and below any alphanumeric one.
pub fn semver_cmp(a: &str, b: &str) -> Ordering {
    fn num_cmp(x: &str, y: &str) -> Ordering {
        let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
        x.len().cmp(&y.len()).then_with(|| x.cmp(y))
    }
    let (core_a, pre_a) = a.split_once('-').unwrap_or((a, ""));
    let (core_b, pre_b) = b.split_once('-').unwrap_or((b, ""));
    let (na, nb): (Vec<&str>, Vec<&str>) =
        (core_a.split('.').collect(), core_b.split('.').collect());
    for (x, y) in na.iter().zip(&nb) {
        let o = num_cmp(x, y);
        if o != Ordering::Equal {
            return o;
        }
    }
    let o = na.len().cmp(&nb.len());
    if o != Ordering::Equal {
        return o;
    }
    match (pre_a.is_empty(), pre_b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    let numeric = |p: &str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit());
    let (ia, ib): (Vec<&str>, Vec<&str>) = (pre_a.split('.').collect(), pre_b.split('.').collect());
    for (x, y) in ia.iter().zip(&ib) {
        let o = match (numeric(x), numeric(y)) {
            (true, true) => num_cmp(x, y),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    ia.len().cmp(&ib.len())
}

/// An insertion-ordered map in which a repeated key keeps its first place and takes the new
/// value, as a Python dict does.
fn upsert(list: &mut Vec<(String, Vec<String>)>, key: &str) -> usize {
    match list.iter().position(|(k, _)| k == key) {
        Some(i) => {
            list[i].1.clear();
            i
        }
        None => {
            list.push((key.to_string(), Vec::new()));
            list.len() - 1
        }
    }
}

/// One changelog file, read the way the rules need it.
#[derive(Debug, Default)]
pub struct Changelog {
    /// Each release heading's bullets, in file order.
    pub releases: Vec<(String, Vec<String>)>,
    /// Each release heading's `### ` categories, in file order.
    pub categories: Vec<(String, Vec<String>)>,
    /// Bullets under a release but under no category of it.
    pub orphans: Vec<String>,
    /// Every `## ` line.
    pub headings: Vec<String>,
}

impl Changelog {
    pub fn parse(text: &str) -> Changelog {
        let mut c = Changelog::default();
        let (mut rel, mut cat): (Option<usize>, Option<usize>) = (None, None);
        let (mut in_release, mut in_category) = (false, false);
        for line in text.lines() {
            if line.starts_with("## ") {
                c.headings.push(line.to_string());
            }
            if let Some(m) = RELEASE.captures(line) {
                rel = Some(upsert(&mut c.releases, &m[1]));
                cat = Some(upsert(&mut c.categories, &m[1]));
                in_release = true;
                in_category = false;
            } else if let Some(name) = line.strip_prefix("### ") {
                in_category = true;
                if let Some(i) = cat {
                    c.categories[i].1.push(name.trim().to_string());
                }
            } else if line.starts_with("- ") {
                if let Some(i) = rel {
                    c.releases[i].1.push(line.to_string());
                }
                if in_release && !in_category {
                    c.orphans.push(line.to_string());
                }
            }
        }
        c
    }

    fn bullets(&self) -> impl Iterator<Item = (&str, &str)> {
        self.releases
            .iter()
            .flat_map(|(r, bs)| bs.iter().map(move |b| (r.as_str(), b.as_str())))
    }
}

/// Bullets over `MAX_BULLET` characters: `(release, length, the first 80 characters)`.
pub fn long_bullets(c: &Changelog) -> Vec<String> {
    c.bullets()
        .filter(|(_, b)| b.chars().count() > MAX_BULLET)
        .map(|(r, b)| {
            let head: String = b.chars().take(80).collect();
            format!("({r}, {}, {head:?})", b.chars().count())
        })
        .collect()
}

/// Bullets that do not end with ` (#77)`.
pub fn bullets_without_a_pull_request(c: &Changelog) -> Vec<String> {
    c.bullets()
        .filter(|(_, b)| !REF.is_match(b))
        .map(|(r, b)| format!("({r}, {b:?})"))
        .collect()
}

/// Releases whose categories are unknown, out of order or repeated.
pub fn misordered_categories(c: &Changelog) -> Vec<String> {
    let rank = |n: &str| CATEGORIES.iter().position(|c| *c == n);
    c.categories
        .iter()
        .filter(|(_, cats)| {
            let ranks: Vec<Option<usize>> = cats.iter().map(|n| rank(n)).collect();
            let unknown = ranks.iter().any(Option::is_none);
            let mut sorted = ranks.clone();
            sorted.sort();
            let mut unique = cats.clone();
            unique.sort();
            unique.dedup();
            unknown || ranks != sorted || unique.len() != cats.len()
        })
        .map(|(r, cats)| format!("{r}: {cats:?}"))
        .collect()
}

/// Releases categorised differently in the two languages.
pub fn categories_differ(en: &Changelog, ja: &Changelog) -> Vec<String> {
    en.categories
        .iter()
        .filter_map(|(r, a)| {
            let b = ja.categories.iter().find(|(k, _)| k == r).map(|(_, v)| v);
            (Some(a) != b).then(|| format!("{r}: ({a:?}, {b:?})"))
        })
        .collect()
}

/// Releases with more than `MAX_BULLETS_PER_RELEASE` entries.
pub fn crowded_releases(c: &Changelog) -> Vec<String> {
    c.releases
        .iter()
        .filter(|(_, b)| b.len() > MAX_BULLETS_PER_RELEASE)
        .map(|(r, b)| format!("{r}: {}", b.len()))
        .collect()
}

/// `## ` lines that are not `## X.Y.Z (YYYY-MM-DD)` (or `## Unreleased…`).
pub fn bad_headings(c: &Changelog) -> Vec<String> {
    c.headings
        .iter()
        .filter(|h| !HEADING.is_match(h) && !h.starts_with("## Unreleased"))
        .cloned()
        .collect()
}

/// The two languages list different releases, or a different number of entries in one.
pub fn releases_differ(en: &Changelog, ja: &Changelog) -> Vec<String> {
    let a: Vec<&String> = en.releases.iter().map(|(r, _)| r).collect();
    let b: Vec<&String> = ja.releases.iter().map(|(r, _)| r).collect();
    if a != b {
        let only_en: Vec<_> = a.iter().filter(|r| !b.contains(r)).collect();
        let only_ja: Vec<_> = b.iter().filter(|r| !a.contains(r)).collect();
        return vec![format!(
            "the releases differ: en-only {only_en:?}, ja-only {only_ja:?}"
        )];
    }
    en.releases
        .iter()
        .zip(&ja.releases)
        .filter(|((_, x), (_, y))| x.len() != y.len())
        .map(|((r, x), (_, y))| format!("{r}: ({}, {})", x.len(), y.len()))
        .collect()
}

/// The releases (those that are a plain or prerelease version) are not newest first.
pub fn not_newest_first(c: &Changelog) -> Vec<String> {
    let versions: Vec<&str> = c
        .releases
        .iter()
        .map(|(r, _)| r.as_str())
        .filter(|r| SEMVER.is_match(r))
        .collect();
    let mut sorted = versions.clone();
    sorted.sort_by(|a, b| semver_cmp(b, a));
    if versions
        .iter()
        .zip(&sorted)
        .all(|(a, b)| semver_cmp(a, b) == Ordering::Equal)
    {
        Vec::new()
    } else {
        vec![format!("{versions:?}")]
    }
}

/// The newest release, when it is not `version`.
pub fn newest_is_not(c: &Changelog, version: &str) -> Option<String> {
    match c.releases.first() {
        Some((r, _)) if r == version => None,
        Some((r, _)) => Some(r.clone()),
        None => Some("nothing".into()),
    }
}

/// `version = "…"` of a Cargo.toml.
pub fn cargo_version(cargo_toml: &str) -> Option<String> {
    static V: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?m)^version = "([^"]+)""#).expect("regex"));
    V.captures(cargo_toml).map(|m| m[1].to_string())
}
