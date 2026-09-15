"""Relay（中継関所）タブのデータ読み出し.

relay の状態は Rust 側が /data/relay に書く（tokens.json / audit.jsonl / authorized_keys / …）。
ここではそれを **読むだけ** で、Web UI の他タブと同じ形（設定 / 履歴 / ブロック履歴）に整える。
秘密（トークン平文・上流トークン・ホスト鍵）はファイルにも無いか、あっても読まない。
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

# 監査イベントの分類（relay/src の Audit が書く event 名）
ALLOW_EVENTS = {
    "relay_ok": "GIT",
    "api_ok": "API",
    "https_passthrough": "HTTPS",
    "ssh_auth_ok": "SSH",
    "bootstrap_ok": "BOOTSTRAP",
}
DENY_EVENTS = {
    "repo_denied": "GIT",
    "push_denied": "GIT",
    "push_rejected": "GIT",
    "relay_failed": "GIT",
    "pr_failed": "API",
    "api_error": "API",
    "token_denied": "API",
    "access_denied": "API",
    "bootstrap_denied": "BOOTSTRAP",
    "bootstrap_disabled": "BOOTSTRAP",
    "cmd_rejected": "SSH",
    "ssh_auth_denied": "SSH",
    "ssh_channel_rejected": "SSH",
    "ssh_exec_rejected": "SSH",
    "ssh_request_rejected": "SSH",
    "ssh_rejected": "SSH",
    "ssh_failed": "SSH",
    "https_rejected": "HTTPS",
    "https_failed": "HTTPS",
    "upstream_preflight_failed": "GIT",
    "upstream_spawn_failed": "GIT",
}
SYSTEM_EVENTS = {"serve_started": "SYSTEM", "bootstrap_enabled": "BOOTSTRAP"}

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")


class RelayRepo(BaseModel):
    name: str
    mode: str
    bases: list[str] = []
    push: list[str] = []


class RelayStateFile(BaseModel):
    """/data/relay 内のファイルの有無だけ（中身は出さない）."""

    name: str
    present: bool
    count: int | None = None  # authorized_keys の鍵数 / known_hosts の行数


class RelayConfigResponse(BaseModel):
    enabled: bool
    domain: str | None = None
    upstream: str | None = None
    project: str | None = None
    https: str = "passthrough"
    bootstrap: str = "auto"
    token_ttl: str = "12h"
    allow_delete: bool = False
    ssh_listen: str = "0.0.0.0:22"
    api_listen: str = "0.0.0.0:8420"
    state_dir: str = "/data/relay"
    permissions: list[str] = []
    repos: list[RelayRepo] = []
    state_files: list[RelayStateFile] = []
    bootstrap_disabled: bool = False


class RelayTokenInfo(BaseModel):
    label: str
    project: str
    issued_at: float | None = None
    expires_at: float | None = None
    last_used: float | None = None
    use_count: int = 0
    state: str  # active / expired / revoked


class RelayAuditEntry(BaseModel):
    """監査ログ 1 行。Dashboard の LogEntry と同じ見せ方にするための形."""

    timestamp: float
    component: str  # GIT / API / SSH / HTTPS / BOOTSTRAP / SYSTEM
    action: str  # ALLOWED / BLOCKED / INFO
    event: str
    actor: str | None = None
    peer: str | None = None
    repo: str | None = None
    verb: str | None = None
    path: str | None = None
    label: str | None = None
    reason: str | None = None
    detail: str | None = None  # bytes / ms / cmdline など補足


class RelayStatsResponse(BaseModel):
    enabled: bool
    allowed: int = 0
    blocked: int = 0
    tokens_active: int = 0
    tokens_total: int = 0
    keys: int = 0


def parse_ts(value: Any) -> float | None:
    """RFC3339（humantime 形式、小数秒は任意桁）→ epoch 秒."""
    if not isinstance(value, str):
        return None
    m = _TS_RE.match(value)
    if not m:
        return None
    dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    frac = m.group(2)
    ts = dt.timestamp()
    if frac:
        ts += int(frac[:9].ljust(9, "0")) / 1_000_000_000
    return ts


def _git_relay_domain(config: dict) -> str | None:
    handlers = config.get("domain_handlers") or {}
    if not isinstance(handlers, dict):
        return None
    for domain, spec in handlers.items():
        handler = (spec or {}).get("handler") if isinstance(spec, dict) else None
        if handler == "git-relay":
            return str(domain).strip().rstrip(".").lower()
    return None


def _count_lines(path: Path) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip() and not line.startswith("#"))
    except OSError:
        return 0


def build_config(config: dict) -> RelayConfigResponse:
    """config.yml の relay 部分を表示用に整える（Rust が所有するキーもそのまま読む）."""
    domain = _git_relay_domain(config)
    relay = config.get("relay") or {}
    if not isinstance(relay, dict):
        relay = {}
    project = relay.get("project") or {}
    if not isinstance(project, dict):
        project = {}
    repos: list[RelayRepo] = []
    for r in project.get("repos") or []:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        repos.append(
            RelayRepo(
                name=str(r["name"]),
                mode=str(r.get("mode", "read-only")),
                bases=[str(b) for b in (r.get("bases") or [])],
                push=[str(p) for p in (r.get("push") or ["sekimore/*"])],
            )
        )
    state_dir = str(relay.get("state_dir", "/data/relay"))
    resp = RelayConfigResponse(
        enabled=domain is not None,
        domain=domain,
        upstream=str(relay.get("upstream") or domain) if domain else None,
        project=str(project.get("name")) if project.get("name") else None,
        https=str(relay.get("https", "passthrough")),
        bootstrap=str(relay.get("bootstrap", "auto")),
        token_ttl=str(relay.get("token_ttl", "12h")),
        allow_delete=bool(relay.get("allow_delete", False)),
        ssh_listen=str(relay.get("ssh_listen", "0.0.0.0:22")),
        api_listen=str(relay.get("api_listen", "0.0.0.0:8420")),
        state_dir=state_dir,
        permissions=sorted(str(p) for p in (project.get("permissions") or [])),
        repos=repos,
    )
    if resp.enabled:
        sd = Path(state_dir)
        files = []
        for name in (
            "host_key",
            "authorized_keys",
            "known_hosts",
            "upstream_token",
            "tokens.json",
            "audit.jsonl",
        ):
            p = sd / name
            count = None
            if name in ("authorized_keys", "known_hosts") and p.exists():
                count = _count_lines(p)
            files.append(RelayStateFile(name=name, present=p.exists(), count=count))
        resp.state_files = files
        resp.bootstrap_disabled = (sd / "bootstrap.disabled").exists()
    return resp


def read_tokens(state_dir: Path, now: float | None = None) -> list[RelayTokenInfo]:
    """tokens.json（ハッシュとメタデータのみ）を一覧にする。ハッシュ（キー）は出さない."""
    path = state_dir / "tokens.json"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    records = data.get("records") if isinstance(data, dict) else None
    if not isinstance(records, dict):
        return []
    now = now if now is not None else datetime.now(UTC).timestamp()
    out: list[RelayTokenInfo] = []
    for rec in records.values():
        if not isinstance(rec, dict):
            continue
        expires = parse_ts(rec.get("expires_at"))
        if rec.get("revoked"):
            state = "revoked"
        elif expires is not None and now > expires:
            state = "expired"
        else:
            state = "active"
        out.append(
            RelayTokenInfo(
                label=str(rec.get("label", "?")),
                project=str(rec.get("project", "")),
                issued_at=parse_ts(rec.get("issued_at")),
                expires_at=expires,
                last_used=parse_ts(rec.get("last_used")),
                use_count=int(rec.get("use_count", 0) or 0),
                state=state,
            )
        )
    out.sort(key=lambda t: t.issued_at or 0, reverse=True)
    return out


def _tail_lines(path: Path, max_lines: int, max_bytes: int = 4 * 1024 * 1024) -> list[str]:
    """ファイル末尾から最大 max_lines 行（大きな監査ログを全部読まない）."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            start = max(0, size - max_bytes)
            f.seek(start)
            chunk = f.read()
    except OSError:
        return []
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]  # 途中から読んだ最初の行は欠けている
    return lines[-max_lines:] if max_lines > 0 else lines


def to_entry(obj: dict) -> RelayAuditEntry | None:
    event = str(obj.get("event", ""))
    if not event:
        return None
    if event in ALLOW_EVENTS:
        component, action = ALLOW_EVENTS[event], "ALLOWED"
    elif event in DENY_EVENTS:
        component, action = DENY_EVENTS[event], "BLOCKED"
    elif event in SYSTEM_EVENTS:
        component, action = SYSTEM_EVENTS[event], "INFO"
    else:
        component = "RELAY"
        action = "BLOCKED" if re.search(r"denied|rejected|failed|error", event) else "INFO"
    ts = parse_ts(obj.get("ts"))
    if ts is None:
        return None
    details = []
    for k in (
        "bytes_in",
        "bytes_out",
        "ms",
        "status",
        "cmdline",
        "fingerprint",
        "kind",
        "client_label",
        "token_label",
    ):
        if obj.get(k) not in (None, ""):
            details.append(f"{k}={obj[k]}")
    peer = obj.get("peer")
    return RelayAuditEntry(
        timestamp=ts,
        component=component,
        action=action,
        event=event,
        actor=obj.get("actor"),
        peer=str(peer) if peer else None,
        repo=(str(obj["repo"]) or None) if obj.get("repo") is not None else None,
        verb=obj.get("verb"),
        path=obj.get("path"),
        label=obj.get("label"),
        reason=obj.get("reason"),
        detail=" ".join(details) if details else None,
    )


def read_audit(state_dir: Path, limit: int = 100, kind: str = "all") -> list[RelayAuditEntry]:
    """audit.jsonl の末尾を新しい順に。kind = all | allowed | blocked."""
    path = state_dir / "audit.jsonl"
    # 絞り込むときは余裕を持って読む
    raw = _tail_lines(path, max(limit * 8, 400))
    out: list[RelayAuditEntry] = []
    for line in reversed(raw):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        entry = to_entry(obj)
        if entry is None:
            continue
        if kind == "allowed" and entry.action != "ALLOWED":
            continue
        if kind == "blocked" and entry.action != "BLOCKED":
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def build_stats(config: dict, since_hours: int = 24) -> RelayStatsResponse:
    cfg = build_config(config)
    if not cfg.enabled:
        return RelayStatsResponse(enabled=False)
    sd = Path(cfg.state_dir)
    now = datetime.now(UTC).timestamp()
    cutoff = now - since_hours * 3600
    allowed = blocked = 0
    for entry in read_audit(sd, limit=5000):
        if entry.timestamp < cutoff:
            break  # 新しい順なので、ここから先は古い
        if entry.action == "ALLOWED":
            allowed += 1
        elif entry.action == "BLOCKED":
            blocked += 1
    tokens = read_tokens(sd, now)
    keys = next((f.count or 0 for f in cfg.state_files if f.name == "authorized_keys"), 0)
    return RelayStatsResponse(
        enabled=True,
        allowed=allowed,
        blocked=blocked,
        tokens_active=sum(1 for t in tokens if t.state == "active"),
        tokens_total=len(tokens),
        keys=keys,
    )
