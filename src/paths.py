"""The edge ids of the path ledger (docs/paths.yml), as the Python side names them (#223).

Every place in this package that opens or governs a connection names its edge with one of
these, and tests/unit/test_paths.py refuses an id that is here and not in the ledger, or in
the ledger and not here or in relay/src/paths.rs. That is what keeps the ledger honest: a
new kind of connection cannot be added without a row, and a row cannot go stale unnoticed.
"""

# dev's ordinary traffic
DEV_DNS = "dev.dns"
DEV_EGRESS_DIRECT = "dev.egress.direct"
DEV_EGRESS_ROUTE_PAST_GATEWAY = "dev.egress.route_past_gateway"
DEV_HOST_INPUT = "dev.host_input"
DEV_SQUID = "dev.squid"
SQUID_UPSTREAM_PROXY = "squid.upstream_proxy"
SQUID_INTERNET = "squid.internet"
# the gateway's own services
DEV_WEBUI = "dev.webui"
OPERATOR_WEBUI = "operator.webui"

# The edges this side implements or governs. The relay's own are in relay/src/paths.rs; the
# two lists together must equal the ledger.
EDGES: frozenset[str] = frozenset(
    {
        DEV_DNS,
        DEV_EGRESS_DIRECT,
        DEV_EGRESS_ROUTE_PAST_GATEWAY,
        DEV_HOST_INPUT,
        DEV_SQUID,
        SQUID_UPSTREAM_PROXY,
        SQUID_INTERNET,
        DEV_WEBUI,
        OPERATOR_WEBUI,
        # shared with the relay: Squid's side of the relay's detour (#205)
        "relay.github.via_squid",
        "passthrough.via_squid",
    }
)
