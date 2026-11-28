//! The equivalence harness: the Rust gateway against the Python gateway, through ends that do
//! not depend on either language (0.3.0 plan, "挙動が変わっていないことの確かめ方").
//!
//! It compares the two readings of `config.yml` (Issue #498), the two Web UIs (Issue #493), and the
//! periphery (Issue #505): the log followers, `maint`, and the reload window's state file.
//! `harness.rs` says how the later steps plug in, how the Python side is reached, and when it is
//! required.

mod config;
mod gateway;
mod harness;
mod webui;

use serde_json::{json, Value};

use sekimore_relay::settings;
use sekimore_relay::settings::rules::Rules;

use config::ConfigReading;
use harness::{compare, corpus, diff, recorded, report, Case, Comparison};

#[test]
fn the_config_is_read_as_python_reads_it() {
    harness::run(&ConfigReading);
}

#[test]
fn the_followers_record_what_python_recorded() {
    harness::run_cases(&gateway::Followers, &gateway::followers_cases());
}

#[test]
fn maint_answers_as_python_did() {
    harness::run_cases(&gateway::Maint, &gateway::maint_cases());
}

#[test]
fn the_orchestrator_reads_the_window_maint_writes() {
    harness::run_cases(&gateway::ReloadState, &gateway::reload_state_cases());
}

#[test]
fn the_web_ui_answers_as_python_did() {
    harness::run_cases(&webui::WebUi::new(), &webui::cases());
}

/// A reader that gets one case wrong, the way a port would: it lets a relayed name into the
/// ipset.
struct Divergent;

const DIVERGENT_CASE: &str = "relay/tests/fixtures/config_with_relay.yml";

impl Comparison for Divergent {
    fn kind(&self) -> &'static str {
        "config"
    }
    fn request(&self, case: &Case) -> Value {
        ConfigReading.request(case)
    }
    fn rust(&self, case: &Case, request: &Value) -> Value {
        let mut answer = ConfigReading.rust(case, request);
        if case.id == DIVERGENT_CASE {
            answer["accepted"]["rules"]["decide"]["github.com"][1] = json!("resolve+admit");
        }
        answer
    }
}

#[test]
fn the_harness_catches_a_divergent_reading() {
    let cases = corpus();
    let rust: Vec<Value> = cases
        .iter()
        .map(|c| Divergent.rust(c, &Divergent.request(c)))
        .collect();
    let outcomes = compare(&cases, &rust, &recorded("config"), "the record");
    let failed: Vec<_> = outcomes.iter().filter(|o| o.failed()).collect();
    assert_eq!(
        failed.len(),
        1,
        "{}",
        report("divergent", &outcomes).unwrap_or_default()
    );
    assert_eq!(failed[0].id, DIVERGENT_CASE);
    assert_eq!(
        failed[0].differences,
        ["/accepted/rules/decide/github.com/1: \"resolve+admit\" != \"resolve\""]
    );
}

#[test]
fn diff_names_every_difference() {
    let a = json!({"x": 1, "l": [1, 2], "o": {"k": "v"}, "only": true});
    let b = json!({"x": 2, "l": [1, 2, 3], "o": {"k": "v"}});
    assert_eq!(
        diff(&a, &b),
        [
            "/l: [1,2] != [1,2,3]",
            "/only: true != (absent)",
            "/x: 1 != 2"
        ]
    );
    assert!(diff(&a, &a).is_empty());
}

#[test]
fn a_ledger_case_that_stops_differing_fails() {
    let case = Case {
        id: "x".into(),
        path: "x".into(),
        env: Default::default(),
        ledger: Some("a known difference".into()),
    };
    let record = [("x".to_string(), json!({"a": 1}))].into_iter().collect();
    let same = compare(
        std::slice::from_ref(&case),
        &[json!({"a": 1})],
        &record,
        "r",
    );
    assert!(same[0].failed());
    let differs = compare(
        std::slice::from_ref(&case),
        &[json!({"a": 2})],
        &record,
        "r",
    );
    assert!(!differs[0].failed());
}

/// Rust against Rust: wherever the relay's own reading resolves, its 443 targets are exactly the
/// names the Python reading says the relay answers for.
#[test]
fn rules_carry_the_relays_https_targets() {
    let mut checked = 0;
    for case in corpus() {
        let Ok(text) = std::fs::read_to_string(&case.path) else {
            continue;
        };
        let env = |n: &str| case.env.get(n).cloned();
        let Ok(s) = settings::parse(&text, &env) else {
            continue;
        };
        let Ok(loaded) = sekimore_relay::config::parse(&case.path, &text) else {
            continue;
        };
        let Ok(resolved) = loaded.resolve() else {
            continue;
        };
        let rules = Rules::build(&s, Some(&resolved));
        let mut targets: Vec<&str> = rules
            .https_targets()
            .iter()
            .map(|t| t.domain.as_str())
            .collect();
        let mut relayed = s.relay_domains();
        targets.sort();
        relayed.sort();
        assert_eq!(targets, relayed, "{}", case.id);
        checked += 1;
    }
    assert!(
        checked >= 3,
        "only {checked} cases resolved on the relay side"
    );
}

/// The Web UI's record can only be made at the commit that still had the Python UI; that commit is
/// named where someone will look for it.
#[test]
fn the_web_ui_record_names_where_it_was_made() {
    let contributing =
        std::fs::read_to_string(harness::repo_root().join("CONTRIBUTING.md")).unwrap();
    assert!(contributing.contains(&format!(
        "git worktree add ../webui-oracle {}",
        webui::RECORDED_AT
    )));
    let why = harness::Comparison::live_gone(&webui::WebUi::new()).unwrap();
    assert!(why.contains(webui::RECORDED_AT), "{why}");
}

/// The periphery's records, too, can only be made at the commit that still had the Python code.
#[test]
fn the_periphery_records_name_where_they_were_made() {
    let contributing =
        std::fs::read_to_string(harness::repo_root().join("CONTRIBUTING.md")).unwrap();
    assert!(contributing.contains(&format!(
        "git worktree add ../periphery-oracle {}",
        gateway::RECORDED_AT
    )));
    for c in [
        harness::Comparison::live_gone(&gateway::Followers),
        harness::Comparison::live_gone(&gateway::Maint),
    ] {
        assert!(c.unwrap().contains(gateway::RECORDED_AT));
    }
    assert!(harness::Comparison::live_gone(&gateway::ReloadState).is_none());
}
