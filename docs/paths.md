# The path ledger

*[日本語版](paths.ja.md)*

`docs/paths.yml` lists every connection the gateway opens or governs, as a graph: one row per
edge. `tests/unit/test_paths.py` loads it with NetworkX and checks rules over the whole graph.
The bugs of 2026-09-25 (#186, #190, #205, #212, #217, #220) were each a missing row or a missing
attribute; the ledger makes that a test failure.

## What a row says

| Attribute | Question it answers |
|---|---|
| `from`, `to`, `via` | Who connects to whom, through which hops |
| `proto` | What goes over the wire |
| `resolves` | Who turns the name into an address |
| `verifies_peer` | Who checks the far end's identity, and with what |
| `presents` | Which credential goes on the wire, and from where |
| `audit` | Where a record lands |
| `switches` | The config keys that change the edge's shape |
| `impl`, `tests` | Where it lives, what covers it (files must exist) |
| `verify`, `check` | The `relay:verify` item or `check` line that probes it on a real machine |
| `blocked_by` | For an edge that must **not** work: the node that closes it |
| `hops`, `tls_impl`, `interop` | Multi-hop SSH, the TLS stack used, the edge that proves interop |

`secrets` lists each credential: who holds it, which edges use it, which edges could read it.

## Rules the test enforces

- Every edge has the required attributes, names nodes that exist, files that exist, and at
  least one test
- The ids in `src/paths.py` and `relay/src/paths.rs` are exactly the ids in the ledger
- Every SSH hop from the relay is verified against a known_hosts the relay owns (#220)
- No path from `dev` to an external node skips every policy, proxy and relay node; the one
  direct-egress edge is flagged `warned`; every blocked edge names `blocked_by` and a `verify`
  item (#186, #190, #212)
- No secret the gateway holds is readable over an edge that starts in `dev` (#217)
- Two TLS implementations towards one peer need an `interop` reference (#205)

## Audit entries name their edge

Every audit.jsonl entry that records a connection carries `edge=<id>`, written through
`Audit::log_edge` / `deny_edge`. The pairs the relay may write are listed in
`relay/src/paths.rs` (`AUDIT_EVENTS`); a pair not listed there fails a debug build, and the
test checks that each edge's `audit` attribute names exactly those events. The relay tab of
the Web UI shows the id on each row. Entries that record no connection (a token issued, the
store unlocked) carry no edge.

## Asking it questions

```
uv run scripts/paths.py edges                        every edge
uv run scripts/paths.py edges -v --switch direct_egress
uv run scripts/paths.py edges --without verify       edges no relay:verify item probes
uv run scripts/paths.py paths dev internet           every path, with the mediating nodes
uv run scripts/paths.py secret upstream_proxy_password
uv run scripts/paths.py dot | dot -Tsvg > paths.svg  draw it (Graphviz)
```

## Adding an edge

1. Add the row to `docs/paths.yml`
2. Add its id to `src/paths.py` or `relay/src/paths.rs`, and use the constant where the
   connection is opened
3. Name the tests that cover it; add a `relay:verify` item in `base/share/sgw/tasks.mise.*.toml` when a real
   machine has to probe it
4. Run `uv run pytest tests/unit/test_paths.py`
