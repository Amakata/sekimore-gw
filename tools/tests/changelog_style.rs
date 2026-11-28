//! The changelogs' shape (rules in `sekimore_tools::checks::changelog`), on CHANGELOG.md and
//! CHANGELOG.ja.md, and on changelogs broken on purpose to show each rule still catches what it
//! is for.
//!
//! One changelog, two languages. The relay's and the base's were folded into it once one version
//! number covered them all; base/CHANGELOG.md keeps the base's own numbering up to 0.2.45 and is
//! not written to.

use std::cmp::Ordering;

use sekimore_tools::checks::changelog::*;
use sekimore_tools::repo_root;

const EN: &str = "CHANGELOG.md";
const JA: &str = "CHANGELOG.ja.md";

fn read(name: &str) -> Changelog {
    let path = repo_root().join(name);
    Changelog::parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}")))
}

fn both() -> [(&'static str, Changelog); 2] {
    [(EN, read(EN)), (JA, read(JA))]
}

#[test]
fn it_has_both_changelogs_to_check() {
    // A rename would otherwise turn every test below green by having nothing to read
    for name in [EN, JA] {
        assert!(repo_root().join(name).exists(), "changelog missing: {name}");
        assert!(!read(name).releases.is_empty(), "{name} has no release");
    }
}

#[test]
fn it_keeps_bullets_short_enough_to_scan() {
    for (name, c) in both() {
        let long = long_bullets(&c);
        assert!(
            long.is_empty(),
            "{name}: a changelog entry states what changed; the reasoning belongs in the commit or \
             the pull request. Split or shorten these (limit {MAX_BULLET}): {long:?}"
        );
    }
}

#[test]
fn it_names_the_pull_request_that_changed_it() {
    // The number is how a reader gets from "what" to "why" without the entry carrying the why.
    for (name, c) in both() {
        let missing = bullets_without_a_pull_request(&c);
        assert!(
            missing.is_empty(),
            "{name}: every entry ends with the pull request that changed it, as ` (#77)`. \
             Missing: {missing:?}"
        );
    }
}

#[test]
fn it_files_every_entry_under_a_category() {
    for (name, c) in both() {
        assert!(
            c.orphans.is_empty(),
            "{name}: an entry belongs under one of {CATEGORIES:?}, not directly under the release \
             heading: {:?}",
            c.orphans
        );
    }
}

#[test]
fn it_orders_the_categories_heaviest_first() {
    for (name, c) in both() {
        let wrong = misordered_categories(&c);
        assert!(
            wrong.is_empty(),
            "{name}: categories are {CATEGORIES:?}, heaviest first, at most one of each: {wrong:?}"
        );
    }
}

#[test]
fn it_files_an_entry_under_the_same_category_in_both_languages() {
    let uneven = categories_differ(&read(EN), &read(JA));
    assert!(
        uneven.is_empty(),
        "{EN} and {JA} categorise differently (en, ja): {uneven:?}"
    );
}

#[test]
fn it_keeps_a_release_to_a_readable_number_of_entries() {
    for (name, c) in both() {
        let crowded = crowded_releases(&c);
        assert!(
            crowded.is_empty(),
            "{name}: too many entries in one release: {crowded:?}"
        );
    }
}

#[test]
fn it_takes_a_prerelease_of_the_03_line_as_a_version() {
    // #325: `next` ships v0.3.0-alpha.N while `main` ships 0.2.x
    assert!(HEADING.is_match("## 0.3.0-alpha.1 (2026-10-01)"));
    assert!(HEADING.is_match("## 0.3.0-alpha.1（2026-10-01）"));
    assert!(!HEADING.is_match("## 0.3.0-alpha.1 first alpha (2026-10-01)"));
    let order = [
        "0.2.61",
        "0.3.0-alpha.1",
        "0.3.0-alpha.2",
        "0.3.0-alpha.10",
        "0.3.0-beta",
        "0.3.0",
    ];
    let mut scrambled: Vec<&str> = [5, 3, 0, 4, 1, 2].iter().map(|i| order[*i]).collect();
    scrambled.sort_by(|a, b| semver_cmp(a, b));
    assert_eq!(scrambled, order);
    assert_eq!(semver_cmp("0.2.10", "0.2.9"), Ordering::Greater);
}

#[test]
fn it_heads_a_release_with_a_version_and_a_date_only() {
    // `## 0.2.8 (2026-09-17)` — a heading that also summarises the release duplicates the
    // entries below it and goes stale on its own.
    for (name, c) in both() {
        let bad = bad_headings(&c);
        assert!(
            bad.is_empty(),
            "{name}: heading should be `## X.Y.Z (YYYY-MM-DD)`: {bad:?}"
        );
    }
}

#[test]
fn it_describes_the_same_releases_in_both_languages() {
    // Not a translation check — just that neither side quietly lost an entry
    let drift = releases_differ(&read(EN), &read(JA));
    assert!(
        drift.is_empty(),
        "{EN} and {JA} have drifted apart: {drift:?}"
    );
}

#[test]
fn it_leads_with_the_newest_release() {
    for (name, c) in both() {
        let wrong = not_newest_first(&c);
        assert!(
            wrong.is_empty(),
            "{name}: releases should be newest first: {wrong:?}"
        );
    }
}

#[test]
fn it_matches_the_version_the_code_declares() {
    // One image carries the gateway and the relay, so one version number covers both and both
    // changelogs lead with it.
    let cargo = std::fs::read_to_string(repo_root().join("relay/Cargo.toml")).unwrap();
    let version = cargo_version(&cargo).expect("relay/Cargo.toml has a version");
    for (name, c) in both() {
        if let Some(newest) = newest_is_not(&c, &version) {
            panic!(
                "{name} leads with {newest} but relay/Cargo.toml says {version}; the release \
                 entry and the version bump belong in the same change"
            );
        }
    }
}

// ---- each rule, on a changelog broken on purpose ----

const GOOD: &str = "# changelog

## 0.3.0-alpha.2 (2026-11-02)

### Security

- bumped a crate for an advisory (#12)

### Enhancement

- added a thing (#11)

## 0.3.0-alpha.1 (2026-11-01)

### Fix

- fixed a thing (#10)
";

const GOOD_JA: &str = "# 変更履歴

## 0.3.0-alpha.2（2026-11-02）

### Security

- 勧告のためにクレートを上げた (#12)

### Enhancement

- 機能を足した (#11)

## 0.3.0-alpha.1（2026-11-01）

### Fix

- 直した (#10)
";

#[test]
fn the_good_example_passes_every_rule() {
    let (en, ja) = (Changelog::parse(GOOD), Changelog::parse(GOOD_JA));
    for c in [&en, &ja] {
        assert!(long_bullets(c).is_empty());
        assert!(bullets_without_a_pull_request(c).is_empty());
        assert!(c.orphans.is_empty());
        assert!(misordered_categories(c).is_empty());
        assert!(crowded_releases(c).is_empty());
        assert!(bad_headings(c).is_empty(), "{:?}", bad_headings(c));
        assert!(not_newest_first(c).is_empty());
        assert_eq!(newest_is_not(c, "0.3.0-alpha.2"), None);
    }
    assert!(categories_differ(&en, &ja).is_empty());
    assert!(releases_differ(&en, &ja).is_empty());
}

#[test]
fn it_catches_a_251_character_bullet() {
    let body = "x".repeat(MAX_BULLET - 2 - " (#11)".len());
    let at_limit = format!("- {body} (#11)");
    assert_eq!(at_limit.chars().count(), MAX_BULLET);
    let c = Changelog::parse(&GOOD.replace("- added a thing (#11)", &at_limit));
    assert!(long_bullets(&c).is_empty(), "250 is allowed");
    let over = format!("- {body}y (#11)");
    let c = Changelog::parse(&GOOD.replace("- added a thing (#11)", &over));
    assert_eq!(long_bullets(&c).len(), 1, "251 is not");
    // characters, not bytes: 250 Japanese characters are within the limit
    let ja = format!("- {} (#11)", "あ".repeat(MAX_BULLET - 2 - " (#11)".len()));
    assert!(long_bullets(&Changelog::parse(
        &GOOD_JA.replace("- 機能を足した (#11)", &ja)
    ))
    .is_empty());
}

#[test]
fn it_catches_a_bullet_without_its_pull_request() {
    for bad in [
        "- added a thing",
        "- added a thing (#11) ",
        "- added a thing #11",
        "- added (#11) a thing",
    ] {
        let c = Changelog::parse(&GOOD.replace("- added a thing (#11)", bad));
        assert_eq!(bullets_without_a_pull_request(&c).len(), 1, "{bad:?}");
    }
}

#[test]
fn it_catches_a_bullet_under_no_category() {
    let c = Changelog::parse(&GOOD.replace(
        "## 0.3.0-alpha.1 (2026-11-01)\n",
        "## 0.3.0-alpha.1 (2026-11-01)\n\n- loose (#9)\n",
    ));
    assert_eq!(c.orphans, vec!["- loose (#9)"]);
}

#[test]
fn it_catches_categories_out_of_order_unknown_or_repeated() {
    let swapped = GOOD
        .replace("### Security", "### TMP")
        .replace("### Enhancement", "### Security")
        .replace("### TMP", "### Enhancement");
    assert_eq!(misordered_categories(&Changelog::parse(&swapped)).len(), 1);
    let unknown = GOOD.replace("### Fix", "### Fixes");
    assert_eq!(misordered_categories(&Changelog::parse(&unknown)).len(), 1);
    let repeated = GOOD.replace("### Enhancement", "### Security");
    assert_eq!(misordered_categories(&Changelog::parse(&repeated)).len(), 1);
}

#[test]
fn it_catches_the_languages_categorising_differently() {
    let ja = Changelog::parse(&GOOD_JA.replace("### Fix", "### Enhancement"));
    assert_eq!(categories_differ(&Changelog::parse(GOOD), &ja).len(), 1);
}

#[test]
fn it_catches_a_crowded_release() {
    let many: String = (0..=MAX_BULLETS_PER_RELEASE)
        .map(|i| format!("- entry {i} (#{i})\n"))
        .collect();
    let c = Changelog::parse(&GOOD.replace("- fixed a thing (#10)\n", &many));
    assert_eq!(crowded_releases(&c), vec!["0.3.0-alpha.1: 13"]);
}

#[test]
fn it_catches_a_heading_that_is_more_than_a_version_and_a_date() {
    for bad in [
        "## 0.3.0-alpha.1 first alpha (2026-11-01)",
        "## 0.3.0-alpha.1",
        "## 0.3.0-alpha.1 (2026-11)",
        "## Release 0.3.0 (2026-11-01)",
    ] {
        let c = Changelog::parse(&GOOD.replace("## 0.3.0-alpha.1 (2026-11-01)", bad));
        assert_eq!(bad_headings(&c), vec![bad.to_string()], "{bad}");
    }
    for ok in [
        "## Unreleased",
        "## 0.1.0 – 0.1.2 (2026-09-08 – 13)",
        "## 0.1.0 〜 0.1.2（2026-09-08 〜 13）",
    ] {
        let c = Changelog::parse(&GOOD.replace("## 0.3.0-alpha.1 (2026-11-01)", ok));
        assert!(bad_headings(&c).is_empty(), "{ok}");
    }
}

#[test]
fn it_catches_the_languages_drifting_apart() {
    let lost_release = GOOD_JA.split("## 0.3.0-alpha.1").next().unwrap();
    assert_eq!(
        releases_differ(&Changelog::parse(GOOD), &Changelog::parse(lost_release)).len(),
        1
    );
    let lost_entry = GOOD_JA.replace("- 機能を足した (#11)\n", "");
    assert_eq!(
        releases_differ(&Changelog::parse(GOOD), &Changelog::parse(&lost_entry)),
        vec!["0.3.0-alpha.2: (2, 1)"]
    );
}

#[test]
fn it_catches_an_older_release_first() {
    let swapped = GOOD
        .replace("0.3.0-alpha.2", "TMP")
        .replace("0.3.0-alpha.1", "0.3.0-alpha.2")
        .replace("TMP", "0.3.0-alpha.1");
    assert_eq!(not_newest_first(&Changelog::parse(&swapped)).len(), 1);
    // alpha.10 is newer than alpha.9
    let c = Changelog::parse(
        &GOOD
            .replace("0.3.0-alpha.2", "0.3.0-alpha.10")
            .replace("0.3.0-alpha.1", "0.3.0-alpha.9"),
    );
    assert!(not_newest_first(&c).is_empty());
}

#[test]
fn it_catches_a_version_bump_without_its_entry() {
    let c = Changelog::parse(GOOD);
    assert_eq!(
        newest_is_not(&c, "0.3.0-alpha.3"),
        Some("0.3.0-alpha.2".into())
    );
    assert_eq!(
        cargo_version("[package]\nname = \"x\"\nversion = \"0.3.0-alpha.3\"\n"),
        Some("0.3.0-alpha.3".into())
    );
}
