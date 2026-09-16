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
    tags: list[str] = []  # push を許すタグ glob（空 = 拒否）
    delete: bool = False
    permissions: list[str] = []  # 実効権限 = (案件 allow ∪ repo allow) − (案件 deny ∪ repo deny)
    host: str = ""  # 0.2.0: 上流ドメイン（`host/Org/Repo` の host。省略時は既定上流）


class RelayUpstream(BaseModel):
    """0.2.0: git-relay ドメイン 1 つ分（上流）。一覧の先頭が既定上流."""

    domain: str
    upstream: str
    ssh_port: int
    default: bool = False
    api_base: str = ""
    token_present: bool = False
    known_hosts_count: int | None = None


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
    allow_delete: bool = False  # 0.1.9〜: project.delete の既定（旧 relay.allow_delete も畳み込む）
    allow_tags: bool = False  # 0.1.9〜: project.tags が非空か（旧 relay.allow_tags も畳み込む）
    tags: list[str] = []  # 案件既定のタグ glob
    permissions_deny: list[str] = []  # 案件既定の deny
    ssh_listen: str = "0.0.0.0:22"
    api_listen: str = "0.0.0.0:8420"
    state_dir: str = "/data/relay"
    permissions: list[str] = []
    repos: list[RelayRepo] = []
    upstreams: list[RelayUpstream] = []  # 0.2.0: 先頭が既定上流
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


def _port_of(listen: Any, default: int) -> int:
    try:
        return int(str(listen).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return default


def _git_relay_upstreams(config: dict) -> list[dict[str, Any]]:
    """git-relay の上流一覧（relay/src/config.rs の resolve_upstreams と同じ規則。先頭が既定）.

    既定上流 = `default: true` → 無ければ `ssh_port` を省いたもの → 無ければ辞書順の先頭。
    既定上流は relay.ssh_listen / relay.upstream / <state_dir>/{upstream_token,known_hosts} を使い、
    他は `ssh_port` で listen し、state は <state_dir>/upstreams/<host>/ に置く。
    """
    handlers = config.get("domain_handlers") or {}
    relay = config.get("relay") or {}
    if not isinstance(handlers, dict) or not isinstance(relay, dict):
        return []
    specs: dict[str, dict] = {}
    for domain, spec in handlers.items():
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("handler") == "git-relay":
            specs[str(domain).strip().rstrip(".").lower()] = spec
    if not specs:
        return []
    domains = sorted(specs)
    explicit = [d for d in domains if specs[d].get("default")]
    no_port = [d for d in domains if specs[d].get("ssh_port") is None]
    if explicit:
        default = explicit[0]
    elif len(no_port) == 1:
        default = no_port[0]
    else:
        default = domains[0]
    listen_port = _port_of(relay.get("ssh_listen", "0.0.0.0:22"), 22)
    state_dir = Path(str(relay.get("state_dir", "/data/relay")))
    out: list[dict[str, Any]] = []
    for d in domains:
        spec = specs[d]
        is_default = d == default
        host = spec.get("upstream") or (relay.get("upstream") if is_default else None) or d
        host = str(host).strip().lower()
        port = spec.get("ssh_port")
        try:
            port = int(port) if port is not None else listen_port
        except (TypeError, ValueError):
            port = listen_port
        if is_default and relay.get("api_base"):
            api_base = str(relay["api_base"])
        elif host == "github.com":
            api_base = "https://api.github.com"
        else:
            api_base = f"https://{host}/api/v3"
        if is_default:
            token_path, kh_path = state_dir / "upstream_token", state_dir / "known_hosts"
        else:
            token_path = state_dir / "upstreams" / host / "upstream_token"
            kh_path = state_dir / "upstreams" / host / "known_hosts"
        out.append(
            {
                "domain": d,
                "upstream": host,
                "ssh_port": port,
                "default": is_default,
                "api_base": api_base,
                "token_path": token_path,
                "known_hosts_path": kh_path,
            }
        )
    out.sort(key=lambda u: not u["default"])
    return out


def _git_relay_domain(config: dict) -> str | None:
    """既定上流のドメイン（git-relay が無ければ None）."""
    ups = _git_relay_upstreams(config)
    return ups[0]["domain"] if ups else None


def _perm_spec(v: Any) -> tuple[list[str], list[str]]:
    """permissions の `[…]`（allow）か `{allow, deny}` を (allow, deny) にする."""
    if isinstance(v, list):
        return [str(x) for x in v], []
    if isinstance(v, dict):
        return [str(x) for x in (v.get("allow") or [])], [str(x) for x in (v.get("deny") or [])]
    return [], []


def _count_lines(path: Path) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip() and not line.startswith("#"))
    except OSError:
        return 0


def build_config(config: dict) -> RelayConfigResponse:
    """config.yml の relay 部分を表示用に整える（Rust が所有するキーもそのまま読む）."""
    upstreams = _git_relay_upstreams(config)
    domain = upstreams[0]["domain"] if upstreams else None
    relay = config.get("relay") or {}
    if not isinstance(relay, dict):
        relay = {}
    project = relay.get("project") or {}
    if not isinstance(project, dict):
        project = {}
    # 案件の既定（旧 relay.allow_tags / allow_delete は既定へ畳み込む）
    p_allow, p_deny = _perm_spec(project.get("permissions"))
    default_push = [str(p) for p in (project.get("push") or ["sekimore/*"])]
    default_tags = [str(t) for t in (project.get("tags") or [])]
    if not default_tags and bool(relay.get("allow_tags", False)):
        default_tags = ["*"]
    default_delete = bool(project.get("delete", False)) or bool(relay.get("allow_delete", False))
    repos: list[RelayRepo] = []
    for r in project.get("repos") or []:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        r_allow, r_deny = _perm_spec(r.get("permissions"))
        effective = sorted((set(p_allow) | set(r_allow)) - (set(p_deny) | set(r_deny)))
        # 0.2.0: `host/Org/Repo` は上流を明示。`Org/Repo` は既定上流
        name = str(r["name"]).strip().lstrip("/")
        host = domain or ""
        parts = name.split("/")
        if len(parts) == 3 and "." in parts[0]:
            host, name = parts[0].lower(), "/".join(parts[1:])
        repos.append(
            RelayRepo(
                name=name,
                host=host,
                mode=str(r.get("mode", "read-only")),
                bases=[str(b) for b in (r.get("bases") or [])],
                push=[str(p) for p in r["push"]] if r.get("push") is not None else default_push,
                tags=[str(t) for t in r["tags"]] if r.get("tags") is not None else default_tags,
                delete=bool(r["delete"]) if r.get("delete") is not None else default_delete,
                permissions=effective,
            )
        )
    state_dir = str(relay.get("state_dir", "/data/relay"))
    resp = RelayConfigResponse(
        enabled=domain is not None,
        domain=domain,
        upstream=upstreams[0]["upstream"] if upstreams else None,
        project=str(project.get("name")) if project.get("name") else None,
        https=str(relay.get("https", "passthrough")),
        bootstrap=str(relay.get("bootstrap", "auto")),
        token_ttl=str(relay.get("token_ttl", "12h")),
        allow_delete=default_delete,
        allow_tags=bool(default_tags),
        tags=default_tags,
        permissions_deny=sorted(set(p_deny)),
        ssh_listen=str(relay.get("ssh_listen", "0.0.0.0:22")),
        api_listen=str(relay.get("api_listen", "0.0.0.0:8420")),
        state_dir=state_dir,
        permissions=sorted(set(p_allow) - set(p_deny)),
        repos=repos,
    )
    if resp.enabled:
        sd = Path(state_dir)
        files = []
        names = [
            "host_key",
            "authorized_keys",
            "known_hosts",
            "upstream_token",
            "tokens.json",
            "audit.jsonl",
        ]
        # 0.2.0: 既定以外の上流の state は upstreams/<host>/ にある
        for u in upstreams:
            if not u["default"]:
                names.append(f"upstreams/{u['upstream']}/upstream_token")
                names.append(f"upstreams/{u['upstream']}/known_hosts")
        for name in names:
            p = sd / name
            count = None
            if name.endswith(("authorized_keys", "known_hosts")) and p.exists():
                count = _count_lines(p)
            files.append(RelayStateFile(name=name, present=p.exists(), count=count))
        resp.state_files = files
        resp.upstreams = [
            RelayUpstream(
                domain=u["domain"],
                upstream=u["upstream"],
                ssh_port=u["ssh_port"],
                default=u["default"],
                api_base=u["api_base"],
                token_present=u["token_path"].exists(),
                known_hosts_count=_count_lines(u["known_hosts_path"])
                if u["known_hosts_path"].exists()
                else None,
            )
            for u in upstreams
        ]
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
