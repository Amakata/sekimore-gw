"""The Python gateway as the oracle of the equivalence harness (relay/tests/equivalence/).

Run by the harness, from the repository root:

    uv run --frozen python relay/tests/equivalence/oracle.py REQUEST.json ANSWER.json

The request is {"kind": ..., "cases": [...]}; the answer is {"kind": ..., "python": {...},
"answers": [{"id": ..., ...}]}, one per case, in the shape the Rust side builds in
relay/tests/equivalence/<kind>.rs. Every answer comes from the gateway's own code (src/), called
the way the gateway calls it; nothing here re-decides anything.

The answer is written to a file rather than stdout because the gateway logs to stdout.

Lives with the tests and goes with the rest of the Python in 0.3.0-alpha.7. Not in the image
(the Dockerfile copies relay/src only).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import pydantic  # noqa: E402
import yaml  # noqa: E402
from dnslib import DNSRecord  # noqa: E402

import src.dns_server as dns_server  # noqa: E402
import src.orchestrator as orchestrator  # noqa: E402
import src.proxy_manager as proxy_manager  # noqa: E402
from src.config import Config, relay_fingerprint  # noqa: E402

ENV_KEYS = ("SEKIMORE_UPSTREAM_PROXY_USERNAME", "SEKIMORE_UPSTREAM_PROXY_PASSWORD")


def _quiet(*_args: Any, **_kwargs: Any) -> None:
    pass


# The gateway's log lines are not the subject, and they go to stdout
orchestrator.log_system_event = _quiet  # type: ignore[assignment]
proxy_manager.log_system_event = _quiet  # type: ignore[assignment]


def typed(v: Any) -> Any:
    """A value from yaml.safe_load, with its Python type kept (an int is not a float or a str)."""
    import datetime

    if v is None:
        return {"none": None}
    if isinstance(v, bool):
        return {"bool": v}
    if isinstance(v, int):
        return {"int": str(v)}
    if isinstance(v, float):
        return {"float": repr(v)}
    if isinstance(v, str):
        return {"str": v}
    if isinstance(v, datetime.datetime):
        return {"datetime": str(v)}
    if isinstance(v, datetime.date):
        return {"date": str(v)}
    if isinstance(v, list):
        return {"list": [typed(x) for x in v]}
    if isinstance(v, dict):
        return {"dict": [[typed(k), typed(x)] for k, x in v.items()]}
    return {"other": type(v).__name__}


def json_safe(v: Any) -> Any:
    """An int beyond i64 as a string, as the Rust side writes it (JSON numbers lose them)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and not -(2**63) <= v < 2**63:
        return str(v)
    if isinstance(v, list):
        return [json_safe(x) for x in v]
    if isinstance(v, dict):
        return {k: json_safe(x) for k, x in v.items()}
    return v


MODEL_RULES = (
    ("https-relay needs at least one git-relay", "https_relay_needs_git_relay"),
    ("would both listen on ssh port", "duplicate_ssh_port"),
    ("not covered by allow_domains", "relayed_not_allowed"),
    ("proxy.direct_egress", "direct_egress_needs_upstream"),
)


def refusal(e: pydantic.ValidationError) -> dict[str, Any]:
    errors = e.errors()
    if any(err["loc"] == () for err in errors):
        msg = str(e)
        rule = next((r for text, r in MODEL_RULES if text in msg), "unknown")
        return {"stage": "model", "rule": rule}
    locs = sorted(".".join(str(p) for p in err["loc"]) for err in errors)
    return {"stage": "fields", "locs": locs}


def load_staged(path: Path) -> tuple[Config | None, dict[str, Any] | None]:
    """`Config.from_yaml`, one stage at a time, so a refusal can say which stage refused.

    The stages are the lines of `from_yaml` (src/config.py), calling the same functions. The
    caller checks the outcome against `from_yaml` itself, so this cannot drift from it unnoticed.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)
    except (yaml.YAMLError, UnicodeDecodeError, ValueError):
        return None, {"stage": "yaml"}
    if data is None:
        data = {}
    try:
        data.pop("relay_fingerprint", None)
    except (AttributeError, TypeError):
        return None, {"stage": "not_a_mapping"}
    try:
        fingerprint = relay_fingerprint(data)
    except (TypeError, ValueError):
        return None, {"stage": "fingerprint"}
    try:
        return Config(**data, relay_fingerprint=fingerprint), None
    except pydantic.ValidationError as e:
        return None, refusal(e)
    except TypeError:
        return None, {"stage": "non_string_key"}


def settings_of(cfg: Config) -> dict[str, Any]:
    p, n, r = cfg.proxy, cfg.network, cfg.relay
    return {
        "name": cfg.name,
        "description": cfg.description,
        "allow_domains": cfg.allow_domains,
        "block_domains": cfg.block_domains,
        "ignore_domains": cfg.ignore_domains,
        "allow_ips": cfg.allow_ips,
        "block_ips": cfg.block_ips,
        "resolve_deny_cidrs": cfg.resolve_deny_cidrs,
        "resolve_allow_cidrs": cfg.resolve_allow_cidrs,
        "proxy": {
            "enabled": p.enabled,
            "port": p.port,
            "cache_enabled": p.cache_enabled,
            "cache_size_mb": p.cache_size_mb,
            "upstream_proxy": p.upstream_proxy,
            "upstream_proxy_tls": p.upstream_proxy_tls,
            "upstream_proxy_username": p.upstream_proxy_username,
            "upstream_proxy_password": p.upstream_proxy_password,
            "direct_egress": p.direct_egress,
            "no_proxy": p.no_proxy,
        },
        "network": {
            "lan_subnets": n.lan_subnets,
            "allowed_ports": n.allowed_ports,
            "host_enforcement": n.host_enforcement,
        },
        "database_path": cfg.database_path,
        "relay_fingerprint": cfg.relay_fingerprint,
        "reload": cfg.reload,
        "domain_handlers": [
            [
                d,
                {
                    "handler": h.handler,
                    "max_upload_bytes": h.max_upload_bytes,
                    "ssh_port": h.ssh_port,
                    "upstream": h.upstream,
                },
            ]
            for d, h in cfg.domain_handlers.items()
        ],
        "relay": {
            "ssh_listen": r.ssh_listen,
            "api_listen": r.api_listen,
            "https_listen": r.https_listen,
            "https": r.https,
        },
        "ui": {"language": cfg.ui.language},
    }


def derived_of(cfg: Config) -> dict[str, Any]:
    return {
        "git_relay_ssh_ports": [[d, p] for d, p in cfg.git_relay_ssh_ports().items()],
        "git_relay_domains": cfg.git_relay_domains(),
        "https_relay_domains": cfg.https_relay_domains(),
        "relay_domains": cfg.relay_domains(),
        "proxy_denied_domains": cfg.proxy_denied_domains(),
        "proxy_allow_domains": cfg.proxy_allow_domains(),
        "has_git_relay": cfg.has_git_relay(),
        "relay_input_ports": cfg.relay_input_ports(),
        "reload_window_seconds": cfg.reload_window_seconds(),
        "reload_is_windowed": cfg.reload_is_windowed(),
        "normalized_no_proxy": cfg.proxy.normalized_no_proxy(),
        "uses_upstream": cfg.proxy.uses_upstream(),
        "direct_egress_denied": cfg.proxy.direct_egress_denied(),
    }


class _Firewall:
    """Stands in for FirewallManager: records what DNS asks it to admit."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def setup_domain(self, domain: str, _ips: list[str]) -> None:
        self.calls.append(domain)


# The log line each branch of DNSServer.handle_query writes, and the decision it stands for
DNS_BRANCHES = {
    "DNS query blocked (blocklist)": "block",
    "DNS query ignored": "ignore",
    "DNS query denied (domain_handlers: deny)": "deny",
    "DNS query redirected to git-relay (returning gateway IP)": "gateway",
    "DNS query blocked (not in allowlist)": "not_allowed",
    "Firewall rule dynamically added": "resolve+admit",
    "Firewall rule skipped (the relay answers for it)": "resolve",
    "Firewall rule skipped (direct egress denied)": "resolve",
}


def decisions_of(cfg: Config, probes: list[str]) -> dict[str, list[str]]:
    """Each probe through the real `DNSServer.handle_query`, built as the orchestrator builds it
    (src/orchestrator.py:809-822), from a client in dev and from the gateway itself.

    Only the upstream lookup and the query log are stubbed; the branch taken is read from the
    log line it writes.
    """
    events: list[str] = []
    dns_server.log_system_event = lambda msg, **_kw: events.append(msg)  # type: ignore[assignment]
    firewall = _Firewall()
    server = dns_server.DNSServer(
        upstream_dns="127.0.0.11",
        port=53,
        blocked_domains=set(cfg.block_domains),
        allowed_domains=cfg.allow_domains,
        db_path=":memory:",
        firewall_manager=firewall,  # type: ignore[arg-type]
        lan_subnets=["10.100.0.0/16"],
        ignored_domains=cfg.ignore_domains,
        domain_handlers=orchestrator._domain_handlers_of(cfg),
        resolve_deny_cidrs=cfg.resolve_deny_cidrs,
        resolve_allow_cidrs=cfg.resolve_allow_cidrs,
        direct_egress_denied=cfg.proxy.direct_egress_denied(),
        cache_enabled=False,
    )
    server.gateway_hostname = None
    server.gateway_ip = "10.100.0.2"

    async def record_query(**_kw: Any) -> None:
        pass

    async def resolve(_domain: str, _qtype: str, **_kw: Any) -> tuple[list[str], int]:
        return (["93.184.216.34"], 300)

    server.mapping.record_query = record_query  # type: ignore[method-assign]
    server._resolve_domain = resolve  # type: ignore[method-assign]

    loop = asyncio.new_event_loop()
    out: dict[str, list[str]] = {}
    try:
        for name in probes:
            row = []
            for client in ("10.100.0.5", "127.0.0.1"):
                events.clear()
                firewall.calls.clear()
                packet = DNSRecord.question(name, "A").pack()
                loop.run_until_complete(server.handle_query(packet, (client, 5353)))
                found = [DNS_BRANCHES[e] for e in events if e in DNS_BRANCHES]
                row.append(found[0] if len(found) == 1 else f"unclassified: {events}")
            out[name] = row
    finally:
        loop.close()
    return out


def rules_of(cfg: Config, probes: list[str]) -> dict[str, Any]:
    stub = types.SimpleNamespace(config=cfg)
    stub._is_relayed = types.MethodType(orchestrator.SecurityGatewayOrchestrator._is_relayed, stub)
    # _seed_allow_list resolves nothing with direct egress denied (src/orchestrator.py)
    seeds = (
        []
        if cfg.proxy.direct_egress_denied()
        else orchestrator.SecurityGatewayOrchestrator._domains_to_seed(stub)  # type: ignore[arg-type]
    )
    pm = proxy_manager.ProxyManager
    allow_acl = pm._generate_domain_acls(None, cfg.proxy_allow_domains())  # type: ignore[arg-type]
    deny_acl, _ = pm._generate_relayed_denial(None, cfg.proxy_denied_domains())  # type: ignore[arg-type]
    return {
        "decide": decisions_of(cfg, probes),
        "seed_candidates": seeds,
        "squid_allow": [
            line.removeprefix("acl allowed_domains dstdomain ")
            for line in allow_acl.split("\n")
            if line
        ],
        "squid_deny": [
            line.removeprefix("acl relayed_domains dstdomain ")
            for line in deny_acl.split("\n")
            if line
        ],
    }


def config_case(case: dict[str, Any]) -> dict[str, Any]:
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(case.get("env", {}))
    path = Path(case["path"])

    try:
        with open(path, encoding="utf-8") as f:
            raw: Any = typed(yaml.safe_load(f))
    except Exception:  # noqa: BLE001 - any failure is "PyYAML did not load it"
        raw = {"error": None}

    cfg, refused = load_staged(path)
    # the staged load and from_yaml must agree
    try:
        real: Config | None = Config.from_yaml(path)
    except Exception:  # noqa: BLE001
        real = None
    if (real is None) != (cfg is None) or (
        real is not None and cfg is not None and real.model_dump() != cfg.model_dump()
    ):
        raise SystemExit(f"{case['id']}: the staged load disagrees with Config.from_yaml")

    answer: dict[str, Any] = {"id": case["id"], "raw": raw}
    if cfg is None:
        answer["refused"] = refused
    else:
        answer["accepted"] = json_safe(
            {
                "settings": settings_of(cfg),
                "derived": derived_of(cfg),
                "rules": rules_of(cfg, case.get("probes", [])),
            }
        )
    return answer


# ---- webui: the Python Web UI (src/web_ui/), driven over ASGI ------------------------------------
#
# The app is called the way uvicorn calls it, with nothing between: a request is one ASGI `http`
# scope, a `/ws` session one `websocket` scope fed from a queue. No HTTP client library is needed
# (the harness runs `uv run --no-dev`).


def _body_of(content_type: str | None, body: bytes) -> Any:
    import hashlib

    if content_type and content_type.startswith("application/json"):
        try:
            return json.loads(body)
        except ValueError:
            return {"unparsable": body.decode("utf-8", "replace")}
    if content_type and content_type.startswith("text/html"):
        return {"sha256": hashlib.sha256(body).hexdigest()}
    return body.decode("utf-8", "replace")


async def _http(app: Any, req: dict[str, Any]) -> dict[str, Any]:
    import urllib.parse

    headers = {k.lower(): v for k, v in req["headers"].items()}
    headers.setdefault("host", "testserver")
    raw_path = req["path"]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": req["method"],
        "scheme": "http",
        "path": urllib.parse.unquote(raw_path),
        "raw_path": raw_path.encode("latin-1"),
        "query_string": req["query"].encode("latin-1"),
        "root_path": "",
        "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
        "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 8080),
        "state": {},
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    # Starlette has already sent its 500 when the handler raised
    with contextlib.suppress(Exception):
        await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    if req["method"] == "HEAD":
        body = b""  # uvicorn sends no body for HEAD, whatever the app wrote
    h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in start["headers"]}
    ct = h.get("content-type")
    return {
        "status": start["status"],
        "content_type": ct,
        "location": h.get("location"),
        "allow": h.get("allow"),
        "body": _body_of(ct, body),
    }


async def _ws(app: Any, steps: list[dict[str, Any]], db_path: str) -> Any:
    import sqlite3

    if not steps:
        return None
    inbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": "/ws",
        "raw_path": b"/ws",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 40001),
        "server": ("127.0.0.1", 8080),
        "subprotocols": [],
        "state": {},
    }
    await inbox.put({"type": "websocket.connect"})
    task = asyncio.create_task(app(scope, inbox.get, outbox.put))

    async def nxt(wait: float) -> Any:
        getter = asyncio.ensure_future(outbox.get())
        done, _ = await asyncio.wait(
            {getter, task}, timeout=wait, return_when=asyncio.FIRST_COMPLETED
        )
        if getter in done:
            m = getter.result()
            if m["type"] == "websocket.send":
                return json.loads(m["text"]) if m.get("text") is not None else "binary"
            if m["type"] == "websocket.close":
                return "closed"
            return f"unexpected {m['type']}"
        getter.cancel()
        if task in done:
            return "closed"
        return "nothing"

    accept = await outbox.get()
    assert accept["type"] == "websocket.accept", accept
    out = [await nxt(5.0)]
    for step in steps:
        if "send" in step:
            await inbox.put({"type": "websocket.receive", "text": step["send"]})
            out.append(await nxt(step.get("wait", 5.0)))
        elif "binary" in step:
            await inbox.put({"type": "websocket.receive", "bytes": b"\x01\x02\x03"})
            out.append(await nxt(5.0))
        elif "sql" in step:
            con = sqlite3.connect(db_path)
            for q in step["sql"]:
                con.executescript(q)
            con.commit()
            con.close()
        elif "expect" in step:
            out.append(await nxt(step["expect"]))
    await inbox.put({"type": "websocket.disconnect", "code": 1000})
    try:
        await asyncio.wait_for(task, 5)
    except Exception:  # noqa: BLE001
        task.cancel()
    return out


def webui_case(case: dict[str, Any]) -> dict[str, Any]:
    import src.web_ui.app as app_module
    from src import constants
    from src.secret_store import SecretStoreError

    app_module.CONFIG_PATH = case["config_path"]
    app_module.DB_PATH = case["db_path"]
    constants.SQUID_CONFIG_PATH = case["squid_path"]
    os.environ["PATH"] = case["bin"]
    if case["env_username"]:
        os.environ["SEKIMORE_UPSTREAM_PROXY_USERNAME"] = "someone"
    else:
        os.environ.pop("SEKIMORE_UPSTREAM_PROXY_USERNAME", None)

    state = case["credential"]

    def read_proxy_credential(*_a: Any, **_k: Any) -> tuple[str, None]:
        if state == "unreachable":
            raise SecretStoreError("no relay")
        return state, None

    app_module.read_proxy_credential = read_proxy_credential  # type: ignore[assignment]
    app_module.log_error = _quiet  # type: ignore[assignment]
    app_module.log_system_event = _quiet  # type: ignore[assignment]
    app_module._streamer = None
    app_module.manager.active_connections.clear()

    async def run() -> dict[str, Any]:
        responses = [await _http(app_module.app, r) for r in case["requests"]]
        ws = await _ws(app_module.app, case["ws"], case["db_path"])
        return {"id": case["id"], "dir": case["dir"], "responses": responses, "ws": ws}

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(run())
    finally:
        loop.close()


# One entry per kind of comparison. Later steps add theirs here ("dns", "firewall", "squid"),
# each answering in the shape its relay/tests/equivalence/<kind>.rs builds.
KINDS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "config": config_case,
    "webui": webui_case,
}


def _webui_versions(kind: str) -> dict[str, str]:
    if kind != "webui":
        return {}
    import fastapi
    import starlette

    return {"fastapi": fastapi.__version__, "starlette": starlette.__version__}


def main() -> None:
    request_path, answer_path = sys.argv[1], sys.argv[2]
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    handler = KINDS[request["kind"]]
    answer = {
        "kind": request["kind"],
        "python": {
            "version": sys.version.split()[0],
            "pydantic": pydantic.VERSION,
            "pyyaml": yaml.__version__,
            **_webui_versions(request["kind"]),
        },
        "answers": [handler(case) for case in request["cases"]],
    }
    Path(answer_path).write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
