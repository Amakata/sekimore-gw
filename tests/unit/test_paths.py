"""The path ledger (docs/paths.yml) is checked here, as a graph (#223).

The rules are the bugs of 2026-09-25, written so they cannot come back unnoticed:
- #220: every SSH hop is verified against a known_hosts the relay owns
- #212 / #186 / #190: nothing leaves dev without passing a policy node, unless the edge is the
  one direct-egress edge and it is flagged as warned; every edge that must not work names what
  blocks it
- #217: no secret can be read through an edge that starts in dev
- #205: two implementations of TLS towards the same peer need an interop reference
- every edge names files that exist and at least one test; the ids in the code (src/paths.py,
  relay/src/paths.rs) are exactly the ids in the ledger
"""

from __future__ import annotations

import re
from pathlib import Path

import networkx as nx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs" / "paths.yml"

REQUIRED = (
    "id",
    "from",
    "to",
    "proto",
    "resolves",
    "verifies_peer",
    "presents",
    "audit",
    "impl",
    "tests",
)
MEDIATING_KINDS = {"policy", "proxy", "relay", "service"}
RELAY_OWNED_KNOWN_HOSTS = re.compile(r"known_hosts", re.I)


def load() -> dict:
    return yaml.safe_load(LEDGER.read_text(encoding="utf-8"))


def graph(ledger: dict) -> nx.MultiDiGraph:
    """Edges that work; a blocked edge is not a way through."""
    g = nx.MultiDiGraph()
    for name, attrs in ledger["nodes"].items():
        g.add_node(name, **attrs)
    for e in ledger["edges"]:
        if e.get("blocked_by"):
            continue
        hops = [e["from"], *e.get("via", []), e["to"]]
        for a, b in zip(hops, hops[1:], strict=False):
            g.add_edge(a, b, **{k: v for k, v in e.items() if k not in ("from", "to")})
    return g


@pytest.fixture(scope="module")
def ledger() -> dict:
    return load()


@pytest.fixture(scope="module")
def edges(ledger: dict) -> dict[str, dict]:
    return {e["id"]: e for e in ledger["edges"]}


def describe_the_ledger_itself():
    def it_has_every_required_attribute_on_every_edge(ledger):
        missing = [(e.get("id"), k) for e in ledger["edges"] for k in REQUIRED if k not in e]
        assert missing == [], f"edges missing attributes: {missing}"

    def it_names_only_nodes_that_exist(ledger, edges):
        nodes = set(ledger["nodes"])
        bad = [
            (i, n)
            for i, e in edges.items()
            for n in (
                e["from"],
                e["to"],
                *e.get("via", []),
                *([e["blocked_by"]] if e.get("blocked_by") else []),
            )
            if n not in nodes
        ]
        assert bad == [], f"unknown nodes: {bad}"

    def it_has_unique_ids(ledger):
        ids = [e["id"] for e in ledger["edges"]]
        assert len(ids) == len(set(ids))

    def it_points_at_files_that_exist(edges):
        gone = [
            (i, f)
            for i, e in edges.items()
            for f in (*e["impl"], *e["tests"])
            if not (ROOT / f).exists()
        ]
        assert gone == [], f"paths that do not exist: {gone}"

    def it_covers_every_edge_with_at_least_one_test(edges):
        untested = [i for i, e in edges.items() if not e["tests"]]
        assert untested == [], f"edges without a test: {untested}"


def describe_the_ids_in_the_code():
    """A connection the code opens without a row, or a row nothing implements, both fail here."""

    def _python_ids() -> set[str]:
        from src import paths

        return set(paths.EDGES)

    def _rust_ids() -> set[str]:
        text = (ROOT / "relay" / "src" / "paths.rs").read_text(encoding="utf-8")
        ids = re.findall(r'^pub const ([A-Z_]+): &str = "([a-z_.]+)";', text, re.M)
        return {value for name, value in ids if name != "EDGE_FIELD"}

    def it_matches_the_ledger_exactly(edges):
        in_code = _python_ids() | _rust_ids()
        in_ledger = set(edges)
        assert in_code - in_ledger == set(), (
            f"named in the code, not in the ledger: {in_code - in_ledger}"
        )
        assert in_ledger - in_code == set(), (
            f"in the ledger, named by no code: {in_ledger - in_code}"
        )

    def it_lists_in_rust_every_constant_it_declares():
        text = (ROOT / "relay" / "src" / "paths.rs").read_text(encoding="utf-8")
        declared = set(re.findall(r"^pub const ([A-Z_]+): &str", text, re.M)) - {
            "EDGES",
            "EDGE_FIELD",
        }
        table = text.split("pub const EDGES")[1].split("];")[0]
        listed = set(re.findall(r"^\s+([A-Z_]+),$", table, re.M))
        assert declared == listed, (
            f"declared but not in EDGES: {declared - listed}; listed but not declared: {listed - declared}"
        )


def describe_the_audit_events_on_each_edge():
    """#228: the relay writes `edge=<id>` on every audit entry that records a connection, and
    refuses a pair `paths::AUDIT_EVENTS` does not list. The ledger's `audit` attribute names
    the same events, so a row can be read from an entry and an entry found from a row."""

    audit_pair = re.compile(r"^\s+\(([A-Z_]+), \"([a-z_]+)\"\),", re.M)
    const_re = re.compile(r'^pub const ([A-Z_]+): &str = "([a-z_.]+)";', re.M)

    def _registry() -> set[tuple[str, str]]:
        text = (ROOT / "relay" / "src" / "paths.rs").read_text(encoding="utf-8")
        consts = dict(const_re.findall(text))
        table = text.split("pub const AUDIT_EVENTS")[1].split("];")[0]
        return {(consts[c], ev) for c, ev in audit_pair.findall(table)}

    def _ledger(edges: dict[str, dict]) -> set[tuple[str, str]]:
        pairs = set()
        for i, e in edges.items():
            audit = str(e["audit"])
            if not audit.startswith("audit.jsonl"):
                continue
            events = audit[len("audit.jsonl") :].split(";")[0].split("(")[0]
            pairs |= {(i, ev.strip()) for ev in events.split("/") if ev.strip()}
        return pairs

    def it_names_in_the_ledger_exactly_the_events_the_relay_writes_on_each_edge(edges):
        code, ledger = _registry(), _ledger(edges)
        assert code - ledger == set(), (
            f"written by the relay, missing from the ledger: {sorted(code - ledger)}"
        )
        assert ledger - code == set(), f"in the ledger, written by no code: {sorted(ledger - code)}"

    def it_writes_every_registered_pair_with_log_edge_or_deny_edge():
        """An event in the table but reached through the plain `log` would carry no edge."""
        src = ROOT / "relay" / "src"
        text = "\n".join(p.read_text(encoding="utf-8") for p in src.rglob("*.rs"))
        plain = re.findall(r'audit\.(?:log|deny)\(\s*"([a-z_]+)"', text)
        registered = {ev for _, ev in _registry()}
        leaked = sorted(set(plain) & registered)
        assert leaked == [], f"registered events written without an edge: {leaked}"


def describe_the_verify_items_of_sgw():
    """`sgw verify` (relay/src/host/verify.rs) names the ledger rows each item probes; the
    ledger's `verify` attribute says which rows a real machine checks. The two must agree."""

    def _verify_edges() -> set[str]:
        text = (ROOT / "relay" / "src" / "host" / "verify.rs").read_text(encoding="utf-8")
        consts = dict(
            re.findall(
                r'^pub const ([A-Z_]+): &str = "([a-z_.]+)";',
                (ROOT / "relay" / "src" / "paths.rs").read_text(encoding="utf-8"),
                re.M,
            )
        )
        out: set[str] = set()
        for block in re.findall(r"edges: &\[([^\]]*)\]", text):
            for name in re.findall(r"paths::([A-Z_]+)", block):
                out.add(consts[name])
            for lit in re.findall(r'"([a-z_.]+)"', block):
                out.add(lit)
        return out

    def it_probes_exactly_the_edges_the_ledger_says_a_real_machine_checks(edges):
        in_ledger = {i for i, e in edges.items() if e.get("verify")}
        in_sgw = _verify_edges()
        assert in_sgw - in_ledger == set(), (
            f"sgw verify names edges the ledger does not mark as verified: {in_sgw - in_ledger}"
        )
        assert in_ledger - in_sgw == set(), (
            f"the ledger says these are probed on a real machine, but no verify item names them: {in_ledger - in_sgw}"
        )


def describe_rule_ssh_hops_are_verified_by_the_relay():
    """#220: the bastion hop was checked against ~/.ssh/known_hosts with StrictHostKeyChecking=ask."""

    def it_verifies_every_ssh_edge_against_a_relay_owned_known_hosts(edges):
        for i, e in edges.items():
            if e["from"] != "gateway.relay.ssh":
                continue
            assert RELAY_OWNED_KNOWN_HOSTS.search(e["verifies_peer"]), f"{i}: {e['verifies_peer']}"
            assert "~/.ssh" not in e["verifies_peer"], (
                f"{i} is verified by a file the relay does not own"
            )

    def it_verifies_the_hops_of_a_multi_hop_edge_the_same_way(edges):
        for i, e in edges.items():
            for hop in e.get("via", []):
                if hop != "bastion":
                    continue
                hop_edge = next(
                    x for x in edges.values() if x["from"] == e["from"] and x["to"] == hop
                )
                assert hop_edge.get("hops"), (
                    f"{i} goes through {hop} but {hop_edge['id']} is not marked as a hop"
                )
                assert RELAY_OWNED_KNOWN_HOSTS.search(hop_edge["verifies_peer"]), (
                    f"{hop_edge['id']}"
                )


def describe_rule_nothing_leaves_dev_unmediated():
    """#212 #186 #190: every path from dev to an external node crosses a policy, proxy or relay node."""

    def it_finds_no_path_from_dev_to_the_outside_that_skips_every_mediating_node(ledger):
        g = graph(ledger)
        externals = [n for n, a in g.nodes(data=True) if a.get("kind") == "external"]
        unmediated = []
        for target in externals:
            for path in nx.all_simple_paths(g, "dev", target):
                kinds = {g.nodes[n].get("kind") for n in path[1:-1]}
                if not kinds & MEDIATING_KINDS:
                    unmediated.append(path)
        assert unmediated == [], f"paths with no policy on them: {unmediated}"

    def it_flags_the_one_direct_egress_edge_as_warned(edges):
        direct = [
            e for e in edges.values() if e.get("switches", {}).get("direct_egress") == "allow"
        ]
        assert len(direct) == 1, "exactly one edge is the direct-egress one"
        assert direct[0].get("warned") is True, (
            "the gateway must warn when it is open beside an upstream proxy"
        )

    def it_names_what_blocks_every_edge_that_must_not_work(edges):
        for i, e in edges.items():
            if (
                e["from"] == "dev"
                and e["to"] in ("internet", "host")
                and e["id"] != "dev.egress.direct"
            ):
                assert e.get("blocked_by"), (
                    f"{i} reaches {e['to']} from dev and nothing is named as blocking it"
                )
                assert e.get("verify"), (
                    f"{i}: a blocked edge is probed on the real machine, so it needs a verify item"
                )


def describe_rule_no_secret_is_readable_from_dev():
    """#217: the upstream proxy password rode out in squid.config_text over dev.webui."""

    def it_exposes_no_secret_through_an_edge_that_starts_in_dev(ledger, edges):
        for name, s in ledger["secrets"].items():
            if s["held_by"] == "dev":
                continue  # dev's own credentials are meant to be in dev
            for edge_id in s.get("exposed_via", []):
                assert edges[edge_id]["from"] != "dev", (
                    f"secret {name} is readable over {edge_id}, which starts in dev"
                )

    def it_uses_secrets_only_on_edges_that_exist(ledger, edges):
        for name, s in ledger["secrets"].items():
            for edge_id in (*s.get("used_by", []), *s.get("exposed_via", [])):
                assert edge_id in edges, f"secret {name} names an unknown edge {edge_id}"

    def it_covers_every_non_dev_secret_with_a_test_or_a_verify_item(ledger):
        for name, s in ledger["secrets"].items():
            if s["held_by"] == "dev":
                continue
            assert s.get("tests") or s.get("verify"), (
                f"secret {name}: nothing checks that it stays where it is"
            )


def describe_rule_two_tls_implementations_towards_one_peer_need_interop():
    """#205: rustls in the relay, OpenSSL in Squid, one upstream proxy that only one of them could reach."""

    def it_requires_an_interop_reference_where_implementations_differ(edges):
        by_peer: dict[str, dict[str, list[str]]] = {}
        for i, e in edges.items():
            if e.get("tls_impl"):
                by_peer.setdefault(e["to"], {}).setdefault(e["tls_impl"], []).append(i)
        for peer, impls in by_peer.items():
            if len(impls) < 2:
                continue
            for ids in impls.values():
                for i in ids:
                    assert edges[i].get("interop"), (
                        f"{i}: {peer} is reached with more than one TLS implementation; name the interop test or the detour"
                    )
                    assert edges[i]["interop"] in edges, f"{i}: interop names an unknown edge"
