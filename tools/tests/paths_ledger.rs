//! The path ledger (docs/paths.yml) against itself, the code and the rules of #223 (rules in
//! `sekimore_tools::checks::paths`); then each rule on a ledger or code broken on purpose.
//!
//! The relay's ids are read from relay/src/paths.rs and relay/src/host/verify.rs as text, as
//! before: that keeps this crate from building the relay, and rustfmt keeps the lines the
//! patterns read in one shape. A constant written another way is caught by
//! `it_lists_in_rust_every_constant_it_declares` and `it_matches_the_ledger_exactly`.

use std::path::Path;

use sekimore_tools::checks::paths::*;
use sekimore_tools::ledger;
use sekimore_tools::repo_root;
use serde_yaml_ng::Value;

fn the_ledger() -> Value {
    ledger::load(&repo_root().join("docs/paths.yml")).unwrap()
}

fn the_code() -> Code {
    Code::read(&repo_root()).unwrap()
}

fn none(what: &str, found: Result<Vec<String>, String>) {
    let found = found.unwrap();
    assert!(found.is_empty(), "{what}: {found:?}");
}

// ---- the ledger itself ----

#[test]
fn it_has_every_required_attribute_on_every_edge() {
    none(
        "edges missing attributes",
        missing_attributes(&the_ledger()),
    );
}

#[test]
fn it_names_only_nodes_that_exist() {
    none("unknown nodes", unknown_nodes(&the_ledger()));
}

#[test]
fn it_has_unique_ids() {
    none("ids used twice", duplicate_ids(&the_ledger()));
}

#[test]
fn it_points_at_files_that_exist() {
    none(
        "paths that do not exist",
        missing_files(&the_ledger(), &repo_root()),
    );
}

#[test]
fn it_covers_every_edge_with_at_least_one_test() {
    none("edges without a test", untested_edges(&the_ledger()));
}

#[test]
fn it_has_edges_to_check() {
    // a move of the ledger would otherwise turn every rule green by having nothing to read
    let l = the_ledger();
    assert!(ledger::edges(&l).unwrap().len() >= 20);
    assert!(rust_ids(&the_code()).len() >= 15);
}

// ---- the ids in the code: a connection the code opens without a row, or a row nothing
// implements, both fail here ----

#[test]
fn it_matches_the_ledger_exactly() {
    none("ids", ids_disagree(&the_ledger(), &the_code()));
}

#[test]
fn it_lists_in_rust_every_constant_it_declares() {
    let wrong = rust_table_disagrees(&the_code());
    assert!(wrong.is_empty(), "{wrong:?}");
}

// ---- #228: the relay writes `edge=<id>` on every audit entry that records a connection, and
// refuses a pair `paths::AUDIT_EVENTS` does not list. The ledger's `audit` attribute names the
// same events, so a row can be read from an entry and an entry found from a row. ----

#[test]
fn it_names_in_the_ledger_exactly_the_events_the_relay_writes_on_each_edge() {
    none("audit events", audit_disagrees(&the_ledger(), &the_code()));
}

#[test]
fn it_writes_every_registered_pair_with_log_edge_or_deny_edge() {
    // An event in the table but reached through the plain `log` would carry no edge.
    none(
        "registered events written without an edge",
        events_written_without_an_edge(&the_code()),
    );
}

// ---- `sgw verify` (relay/src/host/verify.rs) names the rows each item probes ----

#[test]
fn it_probes_exactly_the_edges_the_ledger_says_a_real_machine_checks() {
    none("verify", verify_disagrees(&the_ledger(), &the_code()));
}

// ---- #220: the bastion hop was checked against ~/.ssh/known_hosts with
// StrictHostKeyChecking=ask ----

#[test]
fn it_verifies_every_ssh_edge_against_a_relay_owned_known_hosts() {
    none("ssh", ssh_not_verified_by_the_relay(&the_ledger()));
}

#[test]
fn it_verifies_the_hops_of_a_multi_hop_edge_the_same_way() {
    none("hops", hops_not_verified(&the_ledger()));
}

// ---- #212 #186 #190: every path from dev to an external node crosses a policy, proxy or relay
// node ----

#[test]
fn it_finds_no_path_from_dev_to_the_outside_that_skips_every_mediating_node() {
    none(
        "paths with no policy on them",
        unmediated_from_dev(&the_ledger()),
    );
}

#[test]
fn it_flags_the_one_direct_egress_edge_as_warned() {
    none("direct egress", direct_egress_problems(&the_ledger()));
}

#[test]
fn it_names_what_blocks_every_edge_that_must_not_work() {
    none("blocked edges", unblocked_edges(&the_ledger()));
}

// ---- #217: the upstream proxy password rode out in squid.config_text over dev.webui ----

#[test]
fn it_exposes_no_secret_through_an_edge_that_starts_in_dev() {
    none("secrets", secrets_readable_from_dev(&the_ledger()));
}

#[test]
fn it_uses_secrets_only_on_edges_that_exist() {
    none("secrets", secrets_on_unknown_edges(&the_ledger()));
}

#[test]
fn it_covers_every_non_dev_secret_with_a_test_or_a_verify_item() {
    none("secrets", unchecked_secrets(&the_ledger()));
}

// ---- #205: rustls in the relay, OpenSSL in Squid, one upstream proxy that only one of them
// could reach ----

#[test]
fn it_requires_an_interop_reference_where_implementations_differ() {
    none("interop", interop_missing(&the_ledger()));
}

// ---- each rule, on a ledger or code broken on purpose ----

/// A small ledger that passes every rule; the cases below break one thing each.
const LEDGER: &str = r#"
version: 1
nodes:
  dev: {kind: agent}
  gateway.firewall: {kind: policy}
  gateway.squid: {kind: proxy}
  gateway.relay.ssh: {kind: relay}
  gateway.webui: {kind: service}
  host: {kind: host}
  bastion: {kind: external}
  upstream.git: {kind: external}
  upstream_proxy: {kind: external}
  internet: {kind: external}
secrets:
  upstream_proxy_password:
    held_by: gateway.squid
    used_by: [squid.upstream_proxy]
    exposed_via: []
    tests: [tools/Cargo.toml]
  disposable_ssh_key:
    held_by: dev
    used_by: [dev.relay.ssh]
edges:
  - &base
    id: dev.relay.ssh
    from: dev
    to: gateway.relay.ssh
    proto: ssh
    resolves: dev
    verifies_peer: "the relay's host key in dev's known_hosts"
    presents: disposable key
    audit: "audit.jsonl ssh_auth_ok / ssh_auth_denied (each session)"
    impl: [tools/src/lib.rs]
    tests: [tools/Cargo.toml]
  - <<: *base
    id: relay.ssh.bastion
    from: gateway.relay.ssh
    to: bastion
    hops: true
    verify: bastion
    verifies_peer: "relay-owned known_hosts"
    audit: "audit.jsonl ssh_bastion"
  - <<: *base
    id: relay.ssh.upstream
    from: gateway.relay.ssh
    via: [bastion]
    to: upstream.git
    verifies_peer: "relay-owned known_hosts"
    audit: "-"
    tls_impl: rustls
    interop: squid.upstream_proxy
  - <<: *base
    id: dev.squid
    from: dev
    to: gateway.squid
    audit: "squid access.log"
  - <<: *base
    id: squid.upstream_proxy
    from: gateway.squid
    to: upstream_proxy
    audit: "squid access.log"
  - <<: *base
    id: dev.egress.direct
    from: dev
    via: [gateway.firewall]
    to: internet
    audit: "-"
    switches: {direct_egress: allow}
    warned: true
  - <<: *base
    id: dev.host_input
    from: dev
    to: host
    audit: "-"
    blocked_by: gateway.firewall
    verify: blocked
    verifies_peer: none
"#;

const PATHS_RS: &str = r#"//! ids
pub const DEV_RELAY_SSH: &str = "dev.relay.ssh";
pub const RELAY_SSH_BASTION: &str = "relay.ssh.bastion";
pub const RELAY_SSH_UPSTREAM: &str = "relay.ssh.upstream";

pub const EDGES: &[&str] = &[
    DEV_RELAY_SSH,
    RELAY_SSH_BASTION,
    RELAY_SSH_UPSTREAM,
];

pub const EDGE_FIELD: &str = "edge";

pub const AUDIT_EVENTS: &[(&str, &str)] = &[
    (DEV_RELAY_SSH, "ssh_auth_ok"),
    (DEV_RELAY_SSH, "ssh_auth_denied"),
    (RELAY_SSH_BASTION, "ssh_bastion"),
];
"#;

const PATHS_PY: &str = r#""""ids"""
DEV_SQUID = "dev.squid"
DEV_EGRESS_DIRECT = "dev.egress.direct"

EDGES: frozenset[str] = frozenset(
    {
        DEV_SQUID,
        DEV_EGRESS_DIRECT,
        # Squid's side (a comment naming NOT_A_CONSTANT is ignored)
        "squid.upstream_proxy",
        "dev.host_input",
    }
)
"#;

const VERIFY_RS: &str = r#"
Item { name: "bastion", edges: &[paths::RELAY_SSH_BASTION] },
Item { name: "host", edges: &["dev.host_input"] },
"#;

fn ledger_of(text: &str) -> Value {
    let mut v: Value = serde_yaml_ng::from_str(text).unwrap();
    v.apply_merge().unwrap();
    v
}

fn code() -> Code {
    Code {
        rust_paths: PATHS_RS.into(),
        python_paths: Some(PATHS_PY.into()),
        verify: VERIFY_RS.into(),
        relay_sources: "audit.log_edge(paths::DEV_RELAY_SSH, \"ssh_auth_ok\");\naudit.log(\"serve_started\");\n".into(),
    }
}

fn root() -> &'static Path {
    Box::leak(repo_root().into_boxed_path())
}

/// Every rule on the small ledger: all of them say nothing.
fn every_rule(l: &Value, c: &Code) -> Vec<String> {
    let mut all = Vec::new();
    for found in [
        missing_attributes(l),
        unknown_nodes(l),
        duplicate_ids(l),
        missing_files(l, root()),
        untested_edges(l),
        ids_disagree(l, c),
        Ok(rust_table_disagrees(c)),
        audit_disagrees(l, c),
        events_written_without_an_edge(c),
        verify_disagrees(l, c),
        ssh_not_verified_by_the_relay(l),
        hops_not_verified(l),
        unmediated_from_dev(l),
        direct_egress_problems(l),
        unblocked_edges(l),
        secrets_readable_from_dev(l),
        secrets_on_unknown_edges(l),
        unchecked_secrets(l),
        interop_missing(l),
    ] {
        all.extend(found.unwrap());
    }
    all
}

#[test]
fn the_small_ledger_passes_every_rule() {
    assert_eq!(
        every_rule(&ledger_of(LEDGER), &code()),
        Vec::<String>::new()
    );
}

fn broken(from: &str, to: &str) -> Value {
    assert!(LEDGER.contains(from), "{from}");
    ledger_of(&LEDGER.replacen(from, to, 1))
}

#[test]
fn it_catches_a_ledger_entry_missing_from_the_constants() {
    let l = broken(
        "  - <<: *base\n    id: dev.squid\n",
        "  - <<: *base\n    id: dev.new_path\n    from: dev\n    to: gateway.squid\n  - <<: *base\n    id: dev.squid\n",
    );
    let found = ids_disagree(&l, &code()).unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("named by no code") && found[0].contains("dev.new_path"));
}

#[test]
fn it_catches_a_constant_missing_from_the_ledger() {
    let mut c = code();
    c.rust_paths = c.rust_paths.replace(
        "pub const EDGES",
        "pub const RELAY_NEW: &str = \"relay.new\";\n\npub const EDGES",
    );
    let found = ids_disagree(&ledger_of(LEDGER), &c).unwrap();
    assert!(found[0].contains("not in the ledger") && found[0].contains("relay.new"));
    // ... and from the EDGES table
    assert_eq!(rust_table_disagrees(&c).len(), 1);
    // a Python constant counts as well, while src/paths.py exists
    let mut c = code();
    c.python_paths = Some(PATHS_PY.replace("\"dev.host_input\",", ""));
    assert_eq!(ids_disagree(&ledger_of(LEDGER), &c).unwrap().len(), 1);
    let mut c = code();
    c.python_paths = Some(PATHS_PY.replace(
        "        DEV_SQUID,\n",
        "        DEV_SQUID,\n        UNDEFINED,\n",
    ));
    assert!(ids_disagree(&ledger_of(LEDGER), &c).is_err());
}

#[test]
fn it_catches_a_listed_constant_that_is_not_declared() {
    let mut c = code();
    c.rust_paths = c.rust_paths.replace(
        "    RELAY_SSH_UPSTREAM,\n];",
        "    RELAY_SSH_UPSTREAM,\n    GONE,\n];",
    );
    assert_eq!(rust_table_disagrees(&c).len(), 1);
}

#[test]
fn it_catches_a_missing_attribute_an_unknown_node_a_duplicate_id_and_a_missing_file() {
    let l = broken("    proto: ssh\n", "");
    assert!(!missing_attributes(&l).unwrap().is_empty());
    let l = broken(
        "    to: gateway.squid\n    audit",
        "    to: gateway.sqiud\n    audit",
    );
    assert_eq!(
        unknown_nodes(&l).unwrap(),
        vec!["(dev.squid, gateway.sqiud)"]
    );
    let l = broken("blocked_by: gateway.firewall", "blocked_by: nowhere");
    assert_eq!(
        unknown_nodes(&l).unwrap(),
        vec!["(dev.host_input, nowhere)"]
    );
    let l = broken("id: dev.squid", "id: dev.relay.ssh");
    assert_eq!(duplicate_ids(&l).unwrap(), vec!["dev.relay.ssh"]);
    let l = broken("impl: [tools/src/lib.rs]", "impl: [tools/src/gone.rs]");
    assert!(!missing_files(&l, root()).unwrap().is_empty());
    let l = broken("    id: dev.squid\n", "    id: dev.squid\n    tests: []\n");
    assert_eq!(untested_edges(&l).unwrap(), vec!["dev.squid"]);
}

#[test]
fn it_catches_audit_events_the_ledger_and_the_relay_disagree_on() {
    let l = broken("ssh_auth_ok / ssh_auth_denied", "ssh_auth_ok");
    assert_eq!(audit_disagrees(&l, &code()).unwrap().len(), 1);
    let l = broken(
        "ssh_auth_ok / ssh_auth_denied",
        "ssh_auth_ok / ssh_auth_denied / ssh_extra",
    );
    assert_eq!(audit_disagrees(&l, &code()).unwrap().len(), 1);
    let mut c = code();
    c.relay_sources
        .push_str("self.audit.deny(\n    \"ssh_auth_denied\",\n);\n");
    assert_eq!(
        events_written_without_an_edge(&c).unwrap(),
        vec!["ssh_auth_denied"]
    );
}

#[test]
fn it_catches_sgw_verify_and_the_ledger_disagreeing() {
    let l = broken("    verify: blocked\n", "");
    // the blocked edge now has no verify item either
    assert_eq!(verify_disagrees(&l, &code()).unwrap().len(), 1);
    let mut c = code();
    c.verify = c.verify.replace(
        "paths::RELAY_SSH_BASTION",
        "paths::RELAY_SSH_BASTION, paths::DEV_RELAY_SSH",
    );
    assert_eq!(verify_disagrees(&ledger_of(LEDGER), &c).unwrap().len(), 1);
}

#[test]
fn it_catches_an_ssh_hop_not_verified_by_the_relay() {
    let l = broken(
        "verifies_peer: \"relay-owned known_hosts\"\n    audit: \"audit.jsonl ssh_bastion\"",
        "verifies_peer: \"StrictHostKeyChecking=ask\"\n    audit: \"audit.jsonl ssh_bastion\"",
    );
    assert_eq!(ssh_not_verified_by_the_relay(&l).unwrap().len(), 1);
    assert_eq!(hops_not_verified(&l).unwrap(), vec!["relay.ssh.bastion"]);
    let l = broken(
        "verifies_peer: \"relay-owned known_hosts\"\n    audit: \"-\"",
        "verifies_peer: \"~/.ssh/known_hosts\"\n    audit: \"-\"",
    );
    assert_eq!(ssh_not_verified_by_the_relay(&l).unwrap().len(), 1);
    let l = broken("    hops: true\n", "");
    assert_eq!(hops_not_verified(&l).unwrap().len(), 1);
}

#[test]
fn it_catches_a_path_out_of_dev_that_no_policy_mediates() {
    let l = broken("    via: [gateway.firewall]\n", "");
    assert_eq!(
        unmediated_from_dev(&l).unwrap(),
        vec!["dev reaches internet with no policy on the way"]
    );
    // through another unmediated node: dev → host → internet
    let l = broken(
        "    blocked_by: gateway.firewall\n",
        "    blocked_by: \"\"\n  - <<: *base\n    id: host.out\n    from: host\n    to: internet\n",
    );
    assert!(!unmediated_from_dev(&l).unwrap().is_empty());
    // a blocked edge is not a way through
    assert!(unmediated_from_dev(&ledger_of(LEDGER)).unwrap().is_empty());
}

#[test]
fn it_catches_direct_egress_that_is_not_one_warned_edge() {
    let l = broken("    warned: true\n", "");
    assert_eq!(direct_egress_problems(&l).unwrap().len(), 1);
    let l = broken("    warned: true\n", "    warned: \"yes\"\n");
    assert_eq!(direct_egress_problems(&l).unwrap().len(), 1);
    let l = broken(
        "switches: {direct_egress: allow}",
        "switches: {direct_egress: deny}",
    );
    assert_eq!(direct_egress_problems(&l).unwrap().len(), 1);
}

#[test]
fn it_catches_an_edge_that_must_not_work_without_what_blocks_it() {
    let l = broken("    blocked_by: gateway.firewall\n", "");
    assert_eq!(unblocked_edges(&l).unwrap().len(), 1);
    let l = broken("    verify: blocked\n", "");
    assert_eq!(unblocked_edges(&l).unwrap().len(), 1);
}

#[test]
fn it_catches_a_secret_readable_from_dev_unknown_or_unchecked() {
    let l = broken("    exposed_via: []\n", "    exposed_via: [dev.squid]\n");
    assert_eq!(secrets_readable_from_dev(&l).unwrap().len(), 1);
    let l = broken("used_by: [squid.upstream_proxy]", "used_by: [squid.gone]");
    assert_eq!(secrets_on_unknown_edges(&l).unwrap().len(), 1);
    let l = broken(
        "    tests: [tools/Cargo.toml]\n  disposable",
        "  disposable",
    );
    assert_eq!(unchecked_secrets(&l).unwrap().len(), 1);
    // dev's own credentials are meant to be in dev
    let l = broken(
        "used_by: [dev.relay.ssh]",
        "used_by: [dev.relay.ssh]\n    exposed_via: [dev.squid]",
    );
    assert!(secrets_readable_from_dev(&l).unwrap().is_empty());
}

#[test]
fn it_catches_two_tls_implementations_without_interop() {
    let two = |interop: &str| {
        broken(
            "    to: upstream_proxy\n",
            &format!("    to: upstream.git\n    tls_impl: openssl\n{interop}"),
        )
    };
    assert!(interop_missing(&two("    interop: relay.ssh.upstream\n"))
        .unwrap()
        .is_empty());
    assert_eq!(interop_missing(&two("")).unwrap().len(), 1);
    assert_eq!(
        interop_missing(&two("    interop: nowhere\n"))
            .unwrap()
            .len(),
        1
    );
}
