//! The edge ids of the path ledger (docs/paths.yml), as the relay names them (#223).
//!
//! Every place in the relay that opens a connection names its edge with one of these, and
//! the Python test `tests/unit/test_paths.py` refuses an id that is here and not in the
//! ledger, or in the ledger and not here or in `src/paths.py`. Audit entries carry the id as
//! `edge`, so a record can be traced to the row that describes the connection it came from.

/// dev → the relay's SSH front.
pub const DEV_RELAY_SSH: &str = "dev.relay.ssh";
/// The relay → a ProxyJump bastion (an OpenSSH hop run for us).
pub const RELAY_SSH_BASTION: &str = "relay.ssh.bastion";
/// The relay → the upstream git server over SSH.
pub const RELAY_SSH_UPSTREAM: &str = "relay.ssh.upstream";
/// dev → the relay's agent API.
pub const DEV_RELAY_API: &str = "dev.relay.api";
/// The relay's GitHub client → the upstream API.
pub const RELAY_GITHUB_API: &str = "relay.github.api";
/// The relay's GitHub client → the upstream proxy itself (plain, or TLS with Squid disabled).
pub const RELAY_GITHUB_VIA_PROXY: &str = "relay.github.via_proxy";
/// The relay's GitHub client → the local Squid, which speaks TLS to the upstream proxy.
pub const RELAY_GITHUB_VIA_SQUID: &str = "relay.github.via_squid";
/// dev → the relay's 443 passthrough.
pub const DEV_PASSTHROUGH: &str = "dev.passthrough";
/// The passthrough → the upstream, directly.
pub const PASSTHROUGH_UPSTREAM: &str = "passthrough.upstream";
/// The passthrough → the upstream proxy itself.
pub const PASSTHROUGH_VIA_PROXY: &str = "passthrough.via_proxy";
/// The passthrough → the local Squid.
pub const PASSTHROUGH_VIA_SQUID: &str = "passthrough.via_squid";
/// dev → the filtered signing agent socket.
pub const DEV_SIGNING: &str = "dev.signing";
/// The operator → the secret store's control socket.
pub const OPERATOR_STORE: &str = "operator.store";

/// Every edge the relay implements. The test compares this with the ledger.
pub const EDGES: &[&str] = &[
    DEV_RELAY_SSH,
    RELAY_SSH_BASTION,
    RELAY_SSH_UPSTREAM,
    DEV_RELAY_API,
    RELAY_GITHUB_API,
    RELAY_GITHUB_VIA_PROXY,
    RELAY_GITHUB_VIA_SQUID,
    DEV_PASSTHROUGH,
    PASSTHROUGH_UPSTREAM,
    PASSTHROUGH_VIA_PROXY,
    PASSTHROUGH_VIA_SQUID,
    DEV_SIGNING,
    OPERATOR_STORE,
];

/// The audit field that carries the edge id.
pub const EDGE_FIELD: &str = "edge";

/// Every (edge, event) pair the relay writes to audit.jsonl (#228).
///
/// `Audit::log_edge` and `Audit::deny_edge` refuse, in a debug build, a pair that is not here,
/// so a new event cannot be written on an edge without a row in this table; and
/// `tests/unit/test_paths.py` checks that the ledger's `audit` attribute names exactly these
/// events for each edge. Events that describe no connection (tokens issued, the store,
/// `serve_started`) go through `Audit::log` and carry no edge.
pub const AUDIT_EVENTS: &[(&str, &str)] = &[
    // the agent's SSH session with the relay: who may connect, and what the session asked for
    (DEV_RELAY_SSH, "ssh_rejected"),
    (DEV_RELAY_SSH, "ssh_auth_ok"),
    (DEV_RELAY_SSH, "ssh_auth_denied"),
    (DEV_RELAY_SSH, "ssh_channel_rejected"),
    (DEV_RELAY_SSH, "ssh_exec_rejected"),
    (DEV_RELAY_SSH, "ssh_request_rejected"),
    (DEV_RELAY_SSH, "cmd_rejected"),
    (DEV_RELAY_SSH, "repo_denied"),
    (DEV_RELAY_SSH, "push_rejected"),
    (DEV_RELAY_SSH, "refs_for_rewritten"),
    // the relay's own connection to the upstream git server (through a bastion or not)
    (RELAY_SSH_UPSTREAM, "upstream_preflight_failed"),
    (RELAY_SSH_UPSTREAM, "upstream_spawn_failed"),
    (RELAY_SSH_UPSTREAM, "relay_ok"),
    (RELAY_SSH_UPSTREAM, "relay_failed"),
    (RELAY_SSH_UPSTREAM, "known_hosts_added"),
    (RELAY_SSH_BASTION, "known_hosts_added"),
    // the agent's calls to the relay's API
    (DEV_RELAY_API, "token_denied"),
    (DEV_RELAY_API, "token_wrong_project"),
    (DEV_RELAY_API, "repo_denied"),
    (DEV_RELAY_API, "api_ok"),
    (DEV_RELAY_API, "api_error"),
    (DEV_RELAY_API, "security_alert_dismissed"),
    (DEV_RELAY_API, "security_alert_reopened"),
    (DEV_RELAY_API, "bootstrap_ok"),
    (DEV_RELAY_API, "bootstrap_denied"),
    // the relay's calls to the upstream API, on whichever hop the proxy config selects
    (RELAY_GITHUB_API, "api_call"),
    (RELAY_GITHUB_VIA_PROXY, "api_call"),
    (RELAY_GITHUB_VIA_SQUID, "api_call"),
    // what a push made of the API, on the logical edge: the hop is on the api_call entries
    (RELAY_GITHUB_API, "pr_created"),
    (RELAY_GITHUB_API, "pr_exists"),
    (RELAY_GITHUB_API, "pr_failed"),
    // the 443 passthrough: what dev asked for, and the hop the relay took
    (DEV_PASSTHROUGH, "https_rejected"),
    (DEV_PASSTHROUGH, "https_upload_capped"),
    (PASSTHROUGH_UPSTREAM, "https_passthrough"),
    (PASSTHROUGH_UPSTREAM, "https_failed"),
    // #178's refusal happens where the relay resolves the name itself: the direct hop only
    (PASSTHROUGH_UPSTREAM, "resolved_address_refused"),
    (PASSTHROUGH_VIA_PROXY, "https_passthrough"),
    (PASSTHROUGH_VIA_PROXY, "https_failed"),
    (PASSTHROUGH_VIA_SQUID, "https_passthrough"),
    (PASSTHROUGH_VIA_SQUID, "https_failed"),
    // the filtered signing socket
    (DEV_SIGNING, "signing_agent_started"),
    (DEV_SIGNING, "signing_agent_signed"),
    (DEV_SIGNING, "signing_agent_refused"),
];

/// Whether `event` is registered on `edge`.
pub fn is_audited(edge: &str, event: &str) -> bool {
    AUDIT_EVENTS
        .iter()
        .any(|(e, ev)| *e == edge && *ev == event)
}

/// The edge the relay's GitHub client takes: the proxy config decides the hop (#205).
pub fn github_route(proxy: Option<&crate::config::ProxySpec>) -> &'static str {
    match proxy {
        None => RELAY_GITHUB_API,
        Some(px) if px.via_squid.is_some() => RELAY_GITHUB_VIA_SQUID,
        Some(_) => RELAY_GITHUB_VIA_PROXY,
    }
}

/// The edge the 443 passthrough takes towards the upstream, by the same rule.
pub fn passthrough_route(proxy: Option<&crate::config::ProxySpec>) -> &'static str {
    match proxy {
        None => PASSTHROUGH_UPSTREAM,
        Some(px) if px.via_squid.is_some() => PASSTHROUGH_VIA_SQUID,
        Some(_) => PASSTHROUGH_VIA_PROXY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxySpec;

    fn proxy(via_squid: Option<u16>) -> ProxySpec {
        ProxySpec {
            url: "https://proxy.example.com:3129".into(),
            username: None,
            password: None,
            stored: Default::default(),
            via_squid,
            direct_egress: crate::config::DirectEgress::Allow,
        }
    }

    #[test]
    fn every_audited_edge_is_a_declared_edge() {
        for (edge, event) in AUDIT_EVENTS {
            assert!(
                EDGES.contains(edge),
                "{event} is registered on {edge}, which EDGES does not list"
            );
        }
    }

    #[test]
    fn the_registry_answers_pairs_not_events() {
        assert!(is_audited(DEV_RELAY_SSH, "ssh_auth_ok"));
        assert!(!is_audited(DEV_RELAY_API, "ssh_auth_ok"));
        assert!(
            is_audited(DEV_RELAY_API, "repo_denied"),
            "the same event on two edges"
        );
        assert!(is_audited(DEV_RELAY_SSH, "repo_denied"));
        assert!(
            !is_audited(DEV_RELAY_SSH, "token_issued"),
            "no edge for an operator event"
        );
    }

    #[test]
    fn the_route_follows_the_proxy_config() {
        assert_eq!(github_route(None), RELAY_GITHUB_API);
        assert_eq!(github_route(Some(&proxy(None))), RELAY_GITHUB_VIA_PROXY);
        assert_eq!(
            github_route(Some(&proxy(Some(3128)))),
            RELAY_GITHUB_VIA_SQUID
        );
        assert_eq!(passthrough_route(None), PASSTHROUGH_UPSTREAM);
        assert_eq!(passthrough_route(Some(&proxy(None))), PASSTHROUGH_VIA_PROXY);
        assert_eq!(
            passthrough_route(Some(&proxy(Some(3128)))),
            PASSTHROUGH_VIA_SQUID
        );
    }
}
