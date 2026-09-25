#!/usr/bin/env python3
"""Ask the path ledger (docs/paths.yml) questions, or draw it (#223).

    uv run scripts/paths.py edges                       every edge, one line each
    uv run scripts/paths.py edges --switch direct_egress
    uv run scripts/paths.py edges --without verify      edges no relay:verify item probes
    uv run scripts/paths.py paths dev internet          every simple path, with the mediating nodes
    uv run scripts/paths.py secret upstream_proxy_password
    uv run scripts/paths.py dot | dot -Tsvg > paths.svg  Graphviz

The rules live in tests/unit/test_paths.py; this is for looking.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import networkx as nx
import yaml

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "paths.yml"

COLORS = {
    "agent": "#f2c9c9",
    "policy": "#c9e2f2",
    "proxy": "#f2e6c9",
    "relay": "#d5f2c9",
    "service": "#e6d5f2",
    "store": "#e6d5f2",
    "host": "#dddddd",
    "person": "#ffffff",
    "external": "#f2f2f2",
}


def load() -> dict:
    return yaml.safe_load(LEDGER.read_text(encoding="utf-8"))


def graph(ledger: dict, blocked: bool = False) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for name, attrs in ledger["nodes"].items():
        g.add_node(name, **attrs)
    for e in ledger["edges"]:
        if e.get("blocked_by") and not blocked:
            continue
        hops = [e["from"], *e.get("via", []), e["to"]]
        for a, b in zip(hops, hops[1:], strict=False):
            g.add_edge(a, b, **e)
    return g


def cmd_edges(ledger: dict, args: argparse.Namespace) -> None:
    for e in ledger["edges"]:
        if args.switch and args.switch not in (e.get("switches") or {}):
            continue
        if args.without and e.get(args.without):
            continue
        flag = f" [blocked by {e['blocked_by']}]" if e.get("blocked_by") else ""
        via = " via " + ",".join(e["via"]) if e.get("via") else ""
        print(f"{e['id']:<34} {e['from']} → {e['to']}{via}{flag}")
        if args.verbose:
            for k in (
                "proto",
                "resolves",
                "verifies_peer",
                "presents",
                "audit",
                "switches",
                "verify",
                "check",
            ):
                if e.get(k):
                    print(f"    {k:<14} {e[k]}")


def cmd_paths(ledger: dict, args: argparse.Namespace) -> None:
    g = graph(ledger, blocked=args.blocked)
    for path in nx.all_simple_paths(g, args.src, args.dst):
        mediating = [
            n
            for n in path[1:-1]
            if g.nodes[n].get("kind") in ("policy", "proxy", "relay", "service")
        ]
        print(" → ".join(path), f"   (mediated by: {', '.join(mediating) or 'NOTHING'})")


def cmd_secret(ledger: dict, args: argparse.Namespace) -> None:
    s = ledger["secrets"][args.name]
    print(f"{args.name}: held by {s['held_by']}")
    print(f"  used on   {', '.join(s.get('used_by', [])) or '-'}")
    print(f"  readable  {', '.join(s.get('exposed_via', [])) or 'nowhere'}")
    if s.get("verify"):
        print(f"  verify    {s['verify']}")


def cmd_dot(ledger: dict, _args: argparse.Namespace) -> None:
    print(
        'digraph paths {\n  rankdir=LR;\n  node [shape=box, style="rounded,filled", fontname="sans-serif", fontsize=10];\n  edge [fontname="sans-serif", fontsize=8];'
    )
    for name, a in ledger["nodes"].items():
        print(f'  "{name}" [fillcolor="{COLORS.get(a.get("kind"), "#ffffff")}"];')
    for e in ledger["edges"]:
        hops = [e["from"], *e.get("via", []), e["to"]]
        style = " style=dashed color=red" if e.get("blocked_by") else ""
        label = (
            e["id"] if not e.get("blocked_by") else f"{e['id']}\\n(blocked by {e['blocked_by']})"
        )
        for n, (a, b) in enumerate(zip(hops, hops[1:], strict=False)):
            lab = label if n == 0 else ""
            print(f'  "{a}" -> "{b}" [label="{lab}"{style}];')
    print("}")


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("edges")
    e.add_argument("--switch")
    e.add_argument("--without", choices=["verify", "check", "tests", "audit"])
    e.add_argument("-v", "--verbose", action="store_true")
    q = sub.add_parser("paths")
    q.add_argument("src")
    q.add_argument("dst")
    q.add_argument("--blocked", action="store_true", help="include the edges that must not work")
    s = sub.add_parser("secret")
    s.add_argument("name")
    sub.add_parser("dot")
    args = p.parse_args()
    ledger = load()
    {"edges": cmd_edges, "paths": cmd_paths, "secret": cmd_secret, "dot": cmd_dot}[args.cmd](
        ledger, args
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
