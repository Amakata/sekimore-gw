//! The plan's rules (#376, #378), case by case: the cases of tests/unit/test_lang_plan.py.

use sekimore_tools::plan::{entries, plan_pr, plan_publish, resolve, tracks, Entry, Plan};

const HEAD: &str = r#"
pin:
  php:
    "8.3.26": 1
    "8.3.33": 1
  python:
    "2.7.18": 1
"#;

fn e(lang: &str, version: &str) -> Entry {
    Entry::new(lang, version, 1)
}

fn changed(files: &[&str]) -> Vec<String> {
    files.iter().map(|f| f.to_string()).collect()
}

/// `exists` answering from a fixed set of references.
fn on<'a>(refs: &'a [&'a str]) -> impl FnMut(&str) -> Result<bool, String> + 'a {
    move |r| Ok(refs.contains(&r))
}

fn head() -> Vec<Entry> {
    entries(HEAD, false).unwrap()
}

// ---- versions.yml ----

#[test]
fn it_reads_each_version_with_its_revision() {
    assert_eq!(
        head(),
        vec![
            e("php", "8.3.26"),
            e("php", "8.3.33"),
            e("python", "2.7.18")
        ]
    );
}

#[test]
fn it_refuses_what_is_not_a_version_and_a_revision() {
    for text in [
        "pin:\n  php: [\"8.3.26\"]\n", // the old list form: no revision
        "pin:\n  php:\n    \"8.3.26\": 0\n",
        "pin:\n  php:\n    \"8.3.26\": true\n",
        "pin:\n  php:\n    \"latest\": 1\n",
    ] {
        assert!(entries(text, false).is_err(), "{text}");
    }
}

#[test]
fn it_tags_with_the_revision() {
    assert_eq!(Entry::new("php", "8.3.33", 2).tag(), "8.3.33-2-bookworm");
}

// ---- a pull request ----

fn base() -> Vec<Entry> {
    vec![e("php", "8.3.26"), e("python", "2.7.18")]
}

#[test]
fn it_checks_only_the_version_it_adds() {
    assert_eq!(
        plan_pr(&head(), &base(), &changed(&["lang/versions.yml"])),
        vec![e("php", "8.3.33")]
    );
}

#[test]
fn it_checks_a_raised_revision() {
    let raised = vec![
        Entry::new("php", "8.3.26", 2),
        e("php", "8.3.33"),
        e("python", "2.7.18"),
    ];
    assert_eq!(
        plan_pr(&raised, &head(), &changed(&["lang/versions.yml"])),
        vec![Entry::new("php", "8.3.26", 2)]
    );
}

#[test]
fn it_checks_the_newest_version_of_a_language_whose_recipe_changed() {
    assert_eq!(
        plan_pr(&head(), &head(), &changed(&["lang/php/deps"])),
        vec![e("php", "8.3.33")]
    );
}

#[test]
fn it_checks_every_language_when_the_common_recipe_changed() {
    assert_eq!(
        plan_pr(&head(), &head(), &changed(&["lang/Dockerfile"])),
        vec![e("php", "8.3.33"), e("python", "2.7.18")]
    );
}

#[test]
fn it_checks_nothing_for_a_change_that_builds_nothing() {
    assert_eq!(
        plan_pr(
            &head(),
            &head(),
            &changed(&["lang/README.md", "docs/languages.md"])
        ),
        vec![]
    );
}

#[test]
fn it_compares_versions_as_numbers() {
    // 8.3.9 < 8.3.10, which a string comparison gets wrong
    let h = vec![e("php", "8.3.10"), e("php", "8.3.9")];
    assert_eq!(
        plan_pr(&h, &h, &changed(&["lang/php/deps"])),
        vec![e("php", "8.3.10")]
    );
}

// ---- a publish ----

#[test]
fn it_builds_only_what_the_registry_lacks() {
    let refs = [
        "ghcr.io/amakata/sgw-lang-php:8.3.26-1-bookworm",
        "ghcr.io/amakata/sgw-lang-python:2.7.18-1-bookworm",
    ];
    assert_eq!(
        plan_publish(&head(), on(&refs)).unwrap(),
        Plan {
            build: vec![e("php", "8.3.33")],
            adopt: vec![],
        }
    );
}

#[test]
fn it_adopts_an_image_published_before_revisions_rather_than_rebuilding_it() {
    let refs = [
        "ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm",
        "ghcr.io/amakata/sgw-lang-python:2.7.18-bookworm",
    ];
    assert_eq!(
        plan_publish(&head(), on(&refs)).unwrap(),
        Plan {
            build: vec![e("php", "8.3.33")],
            adopt: vec![e("php", "8.3.26"), e("python", "2.7.18")],
        }
    );
}

#[test]
fn it_rebuilds_a_raised_revision_even_where_the_moving_tag_exists() {
    let refs = [
        "ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm",
        "ghcr.io/amakata/sgw-lang-php:8.3.26-1-bookworm",
    ];
    let raised = vec![Entry::new("php", "8.3.26", 2)];
    assert_eq!(
        plan_publish(&raised, on(&refs)).unwrap(),
        Plan {
            build: raised.clone(),
            adopt: vec![],
        }
    );
}

// ---- a base branch from before revisions ----

#[test]
fn it_reads_the_old_list_form_as_revision_1() {
    let old = "pin:\n  php: [\"8.3.26\"]\n  python: [\"2.7.18\"]\n";
    let base = entries(old, true).unwrap();
    assert_eq!(base, vec![e("php", "8.3.26"), e("python", "2.7.18")]);
    assert_eq!(
        plan_pr(&head(), &base, &changed(&["lang/versions.yml"])),
        vec![e("php", "8.3.33")]
    );
}

// ---- tracked lines ----

fn tracked() -> String {
    format!("{HEAD}track:\n  php: [\"8.3\"]\n")
}

#[test]
fn it_reads_the_lines() {
    assert_eq!(
        tracks(&tracked()).unwrap(),
        vec![("php".to_string(), "8.3".to_string())]
    );
}

#[test]
fn it_refuses_what_is_not_a_list_of_minor_lines() {
    for text in ["track:\n  php: \"8.3\"\n", "track:\n  php: [\"8\"]\n"] {
        assert!(tracks(text).is_err(), "{text}");
    }
}

fn php_83() -> Vec<(String, String)> {
    vec![("php".into(), "8.3".into())]
}

#[test]
fn it_adds_the_newest_patch_as_revision_1() {
    let pinned = entries(&tracked(), false).unwrap();
    let lines = tracks(&tracked()).unwrap();
    let got = resolve(&pinned, &lines, |_, _| Ok("8.3.35".into())).unwrap();
    assert_eq!(got, vec![e("php", "8.3.35")]);
}

#[test]
fn it_leaves_a_patch_a_pin_already_names_to_the_pin() {
    let pinned = entries(&tracked(), false).unwrap();
    assert_eq!(
        resolve(&pinned, &php_83(), |_, _| Ok("8.3.33".into())).unwrap(),
        vec![]
    );
}

#[test]
fn it_refuses_an_answer_outside_the_line() {
    assert!(resolve(&[], &php_83(), |_, _| Ok("8.4.1".into())).is_err());
}

#[test]
fn it_publishes_the_newest_patch_only_once() {
    let pinned = entries(&tracked(), false).unwrap();
    let mut all = pinned.clone();
    all.extend(resolve(&pinned, &php_83(), |_, _| Ok("8.3.35".into())).unwrap());
    let mut refs: Vec<String> = pinned
        .iter()
        .map(|x| format!("ghcr.io/amakata/sgw-lang-{}:{}", x.lang, x.tag()))
        .collect();
    refs.push("ghcr.io/amakata/sgw-lang-php:8.3.35-1-bookworm".into());
    let got = plan_publish(&all, |r| Ok(refs.iter().any(|x| x == r))).unwrap();
    assert_eq!(got, Plan::default());
}
