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
