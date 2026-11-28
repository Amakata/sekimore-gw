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
import json
import os
import sys
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

import pydantic  # noqa: E402
import yaml  # noqa: E402
from dnslib import DNSRecord  # noqa: E402

import src.constants as constants  # noqa: E402
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


def _sqlite_rows(db: Path, sql: str) -> list[list[Any]]:
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        return [list(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def _opened_by_me(path: Path) -> bool:
    """Whether this process holds `path` open (the follower has opened and gone to its end)."""
    fds = Path("/proc/self/fd")
    for fd in fds.iterdir():
        try:
            if os.readlink(fd) == str(path):
                return True
        except OSError:
            continue
    return False


FIREWALL_SENTINEL = b"[FIREWALL-BLOCK] SRC=255.255.255.255 DST=255.255.255.255 PROTO=SENTINEL"
PROXY_SENTINEL = b"9999999999.5 0 sentinel TCP_MISS/200 0 GET sentinel"


async def _firewall(d: Path, data: bytes) -> dict[str, Any]:
    """FirewallMonitor's own loop, with a `tail` on PATH that prints the case and waits."""
    from src.firewall_monitor import FirewallMonitor

    bin_dir = d / "bin"
    bin_dir.mkdir()
    (d / "feed").write_bytes(data + b"\n" + FIREWALL_SENTINEL + b"\n")
    tail = bin_dir / "tail"
    tail.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{d}/argv"\n'
        f'echo $$ > "{d}/pid"\n'
        f'cat "{d}/feed"\n'
        "exec sleep 60\n"
    )
    tail.chmod(0o755)
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bin_dir}:{old_path}"
    log = d / "firewall.log"
    constants.ULOG_FILE_PATH = str(log)
    db = d / "gw.db"
    monitor = FirewallMonitor(str(db))
    try:
        await monitor.init_db()
        task = asyncio.create_task(monitor.monitor_ulog_file())
        for _ in range(600):
            await asyncio.sleep(0.05)
            if _sqlite_rows(db, "SELECT 1 FROM firewall_blocks WHERE src_ip = '255.255.255.255'"):
                break
        else:
            raise SystemExit("the firewall follower never reached the sentinel")
        monitor.running = False
        os.kill(int((d / "pid").read_text()), 15)
        await asyncio.wait_for(task, 10)
    finally:
        os.environ["PATH"] = old_path
        if monitor.db:
            await monitor.db.close()
    rows = _sqlite_rows(
        db,
        "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, action FROM firewall_blocks "
        "WHERE src_ip != '255.255.255.255' ORDER BY rowid",
    )
    argv = (d / "argv").read_text().splitlines()
    return {
        "rows": [["now" if abs(r[0] - time.time()) < 300 else r[0], *r[1:]] for r in rows],
        "argv": [a.replace(str(log), "{log}") for a in argv],
    }


async def _proxy(d: Path, data: bytes) -> dict[str, Any]:
    """ProxyMonitor's own loop on a file that the case is appended to once it is open."""
    from src.proxy_monitor import ProxyMonitor

    log = d / "access.log"
    log.write_bytes(b"")
    db = d / "gw.db"
    monitor = ProxyMonitor(str(db), log_path=str(log))
    await monitor.init_db()
    monitor.running = True
    task = asyncio.create_task(monitor._follow_log())
    for _ in range(200):
        await asyncio.sleep(0.02)
        if _opened_by_me(log):
            break
    else:
        raise SystemExit("the proxy follower never opened its log")
    with open(log, "ab") as f:
        f.write(data + b"\n" + PROXY_SENTINEL + b"\n")
    reached = False
    for _ in range(600):
        await asyncio.sleep(0.05)
        if _sqlite_rows(db, "SELECT 1 FROM proxy_logs WHERE client_ip = 'sentinel'"):
            reached = True
            break
        if task.done():
            break
    monitor.running = False
    await asyncio.wait_for(task, 10)
    if monitor.db:
        await monitor.db.close()
    rows = _sqlite_rows(
        db,
        "SELECT timestamp, client_ip, method, url, status_code, squid_result, action "
        "FROM proxy_logs WHERE client_ip != 'sentinel' ORDER BY rowid",
    )
    return {"rows": [[repr(r[0]), *r[1:]] for r in rows], "stopped": not reached}


def followers_case(case: dict[str, Any]) -> dict[str, Any]:
    import base64
    import tempfile

    data = base64.b64decode(case["data_b64"])
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        if case["follower"] == "firewall":
            out = asyncio.run(_firewall(d, data))
        else:
            out = asyncio.run(_proxy(d, data))
    return {"id": case["id"], **out}


def _materialize(d: Path, case: dict[str, Any]) -> None:
    import base64

    for name, b64 in case.get("files", {}).items():
        path = d / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = base64.b64decode(b64)
        if name != "gw.db":
            # {dir} in a text file is the case's directory (config.yml's database_path)
            data = data.replace(b"{dir}", str(d).encode())
        path.write_bytes(data)


def _after(d: Path) -> dict[str, Any]:
    """What a maint command left: the state file, the database's row counts, the files."""
    state = d / "state" / "reload-window.json"
    out: dict[str, Any] = {
        "state": state.read_text() if state.is_file() else None,
        "files": sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()),
    }
    db = d / "gw.db"
    if db.is_file():
        tables = [
            r[0]
            for r in _sqlite_rows(
                db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        out["rows"] = {t: _sqlite_rows(db, f"SELECT COUNT(*) FROM {t}")[0][0] for t in tables}
    return out


def maint_case(case: dict[str, Any]) -> dict[str, Any]:
    """`python -m src.maint` as `sgw` and the operator run it, in a directory of the case's files."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _materialize(d, case)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("LC_", "SEKIMORE_"))}
        env.pop("LANG", None)
        env["SEKIMORE_LANG"] = case.get("lang", "en")
        env["SEKIMORE_RELOAD_STATE"] = str(d / "state" / "reload-window.json")
        args = [a.replace("{dir}", str(d)) for a in case["args"]]
        r = subprocess.run(
            [sys.executable, "-m", "src.maint", *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        answer = {
            "id": case["id"],
            "code": r.returncode,
            "stdout": r.stdout.replace(str(d), "{dir}"),
            "stderr": r.stderr.replace(str(d), "{dir}"),
            **_after(d),
            "now": time.time(),
        }
    return answer


def reload_state_case(case: dict[str, Any]) -> dict[str, Any]:
    """The orchestrator's ReloadWindow reading a state file: what the running gateway would do."""
    import base64
    import tempfile

    logged: list[str] = []

    def capture(_component: Any, msg: str, **_kw: Any) -> None:
        logged.append(msg)

    saved = orchestrator.log_error
    orchestrator.log_error = capture  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reload-window.json"
            if case.get("state_b64") is not None:
                path.write_bytes(base64.b64decode(case["state_b64"]))
            try:
                w = orchestrator.ReloadWindow(case["mode"], case["window"], path)
                answer: dict[str, Any] = {
                    "is_open": w.is_open(),
                    "describe": w.describe(),
                    "seconds_left": None if w.seconds_left() is None else str(w.seconds_left()),
                }
            except Exception:  # noqa: BLE001
                answer = {"raised": True}
    finally:
        orchestrator.log_error = saved  # type: ignore[assignment]
    return {
        "id": case["id"],
        **answer,
        "logged": [m.split(": ")[0] for m in logged],
        "now": time.time(),
    }


# One entry per kind of comparison. Later steps add theirs here ("dns", "firewall", "squid"),
# each answering in the shape its relay/tests/equivalence/<kind>.rs builds.
#
# "webui" was here until the Python Web UI was removed (0.3.0-alpha.4): its record,
# relay/tests/fixtures/oracle/webui.json, was made at the commit named in CONTRIBUTING.md and is
# the only oracle of that comparison now.
KINDS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "config": config_case,
    "followers": followers_case,
    "maint": maint_case,
    "reload_state": reload_state_case,
}


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
        },
        "answers": [handler(case) for case in request["cases"]],
    }
    Path(answer_path).write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
