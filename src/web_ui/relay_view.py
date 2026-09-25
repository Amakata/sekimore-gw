"""Data sources for the Relay tab.

The relay state is written by the Rust side under /data/relay (tokens.json /
audit.jsonl / authorized_keys / ...). This module only **reads** it and reshapes it into
the same form as the other Web UI tabs (settings / history / block history). Secrets
(plaintext tokens, the upstream token, host keys) are either not in those files at all
or are never read.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

# Audit event categories (the event names written by Audit in relay/src)
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
    "https_upload_capped": "HTTPS",
}
SYSTEM_EVENTS = {"serve_started": "SYSTEM", "bootstrap_enabled": "BOOTSTRAP"}

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")


class RelayRepo(BaseModel):
    name: str
    mode: str
    bases: list[str] = []
    push: list[str] = []
    tags: list[str] = []  # tag globs allowed for push (empty = denied)
    delete: bool = False
    # 0.2.27 (#89): a pushed tag has to be an annotated tag object with a signature block
    signed_tags: bool = True
    # 0.2.29 (#59): required | optional | off — whether a push to a branch may carry an
    # unsigned commit
    signing: str = "optional"
    # effective = (project allow | repo allow) - (project deny | repo deny)
    permissions: list[str] = []
    # 0.2.0: upstream domain (the host in `host/Org/Repo`; default upstream if omitted)
    host: str = ""


class RelayUpstream(BaseModel):
    """0.2.0: one git-relay domain (an upstream). The first in the list is the default."""

    domain: str
    upstream: str
    ssh_port: int
    default: bool = False
    api_base: str = ""
    ssh_options: list[str] = []  # 0.2.1: extra -o options for the upstream ssh (ProxyJump etc.)
    max_upload_bytes: int = 1048576  # 0.2.2: upload cap on 443 (-1 = unlimited)
    token_present: bool = False
    known_hosts_count: int | None = None


class RelayHttpsTarget(BaseModel):
    """0.2.2: an https-relay domain (only 443 goes through the relay passthrough)."""

    domain: str
    upstream: str
    max_upload_bytes: int = 1048576


class RelayStateFile(BaseModel):
    """Only whether a file under /data/relay exists; its contents are never exposed."""

    name: str
    present: bool
    count: int | None = None  # keys in authorized_keys / lines in known_hosts


class RelayConfigResponse(BaseModel):
    enabled: bool
    domain: str | None = None
    upstream: str | None = None
    project: str | None = None
    https: str = "passthrough"
    bootstrap: str = "auto"
    token_ttl: str = "12h"
    # 0.1.9+: default for project.delete (folds in the old relay.allow_delete)
    allow_delete: bool = False
    # 0.1.9+: whether project.tags is non-empty (folds in the old relay.allow_tags)
    allow_tags: bool = False
    tags: list[str] = []  # project default tag globs
    permissions_deny: list[str] = []  # project default deny list
    ssh_listen: str = "0.0.0.0:22"
    api_listen: str = "0.0.0.0:8420"
    state_dir: str = "/data/relay"
    permissions: list[str] = []
    repos: list[RelayRepo] = []
    upstreams: list[RelayUpstream] = []  # 0.2.0: the first entry is the default upstream
    https_relays: list[RelayHttpsTarget] = []  # 0.2.2
    https_max_upload_bytes: int = 1048576  # 0.2.2: default upload cap (-1 = unlimited)
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
    """One audit log line, shaped like the dashboard LogEntry so it renders the same way."""

    timestamp: float
    component: str  # GIT / API / SSH / HTTPS / BOOTSTRAP / SYSTEM
    action: str  # ALLOWED / BLOCKED / INFO
    event: str
    actor: str | None = None
    peer: str | None = None
    # #195: the destination of an HTTPS row (the host the relay dialed, else the SNI the
    # client asked for), because peer is only dev's ephemeral port
    destination: str | None = None
    repo: str | None = None
    verb: str | None = None
    path: str | None = None
    label: str | None = None
    reason: str | None = None
    detail: str | None = None  # extras such as bytes / ms / cmdline
    # 0.2.2: "large_upload" = passthrough upload of at least LARGE_UPLOAD_BYTES
    flag: str | None = None
    # #228: the path-ledger edge (docs/paths.yml) the relay wrote the entry on, e.g.
    # relay.ssh.upstream; rows the relay writes on no connection (tokens, the store) have none
    edge: str | None = None


class RelayStatsResponse(BaseModel):
    enabled: bool
    allowed: int = 0
    blocked: int = 0
    tokens_active: int = 0
    tokens_total: int = 0
    keys: int = 0
    large_uploads: int = 0  # 0.2.2: large passthrough uploads in the last 24h
    upload_capped: int = 0  # 0.2.2: connections cut in the last 24h for exceeding the cap


# 0.2.2: passthrough connections uploading at least this much (dev -> upstream) are
# highlighted in the Relay tab
LARGE_UPLOAD_BYTES = 1024 * 1024


def parse_ts(value: Any) -> float | None:
    """Convert RFC3339 (humantime style, any number of fractional digits) to epoch seconds."""
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
    """The git-relay upstreams, default first (same rules as resolve_upstreams in relay/src/config.rs).

    The default upstream is the one with `default: true`; failing that, the one without
    `ssh_port`; failing that, the first in lexical order. The default uses
    relay.ssh_listen / relay.upstream / <state_dir>/{upstream_token,known_hosts}; the
    others listen on their `ssh_port` and keep state in <state_dir>/upstreams/<host>/.
    """
    handlers = config.get("domain_handlers") or {}
    relay = config.get("relay") or {}
    if not isinstance(handlers, dict) or not isinstance(relay, dict):
        return []
    specs: dict[str, dict] = {}
    for domain, spec in handlers.items():
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("handler") in ("github", "git-relay"):
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
        if spec.get("api_base"):  # 0.2.1: an override on the handler wins
            api_base = str(spec["api_base"])
        elif is_default and relay.get("api_base"):
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
        ssh_options = [str(o) for o in (relay.get("ssh_options") or [])] + [
            str(o) for o in (spec.get("ssh_options") or [])
        ]
        max_upload = _int_or(
            spec.get("max_upload_bytes"), _int_or(relay.get("https_max_upload_bytes"), 1048576)
        )
        out.append(
            {
                "domain": d,
                "upstream": host,
                "ssh_port": port,
                "default": is_default,
                "api_base": api_base,
                "ssh_options": ssh_options,
                "max_upload_bytes": max_upload,
                "token_path": token_path,
                "known_hosts_path": kh_path,
            }
        )
    out.sort(key=lambda u: not u["default"])
    return out


def _git_relay_domain(config: dict) -> str | None:
    """The default upstream domain, or None when there is no git-relay."""
    ups = _git_relay_upstreams(config)
    return ups[0]["domain"] if ups else None


def _int_or(value: Any, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _https_relays(config: dict) -> list[RelayHttpsTarget]:
    """The https-relay domains (0.2.2). The cap comes from the handler, then the relay default."""
    handlers = config.get("domain_handlers") or {}
    relay = config.get("relay") or {}
    if not isinstance(handlers, dict) or not isinstance(relay, dict):
        return []
    default_cap = _int_or(relay.get("https_max_upload_bytes"), 1048576)
    out = []
    for domain, spec in sorted(handlers.items()):
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("handler") != "https-relay":
            continue
        d = str(domain).strip().rstrip(".").lower()
        out.append(
            RelayHttpsTarget(
                domain=d,
                upstream=str(spec.get("upstream") or d).strip().lower(),
                max_upload_bytes=_int_or(spec.get("max_upload_bytes"), default_cap),
            )
        )
    return out


def _perm_spec(v: Any) -> tuple[list[str], list[str]]:
    """Turn a permissions `[...]` (allow) or `{allow, deny}` into an (allow, deny) pair."""
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
    """Shape the relay section of config.yml for display, including keys owned by Rust."""
    upstreams = _git_relay_upstreams(config)
    domain = upstreams[0]["domain"] if upstreams else None
    relay = config.get("relay") or {}
    if not isinstance(relay, dict):
        relay = {}
    project = relay.get("project") or {}
    if not isinstance(project, dict):
        project = {}
    # Project defaults (the old relay.allow_tags / allow_delete fold into them)
    p_allow, p_deny = _perm_spec(project.get("permissions"))
    default_push = [str(p) for p in (project.get("push") or ["sekimore/*"])]
    default_tags = [str(t) for t in (project.get("tags") or [])]
    if not default_tags and bool(relay.get("allow_tags", False)):
        default_tags = ["*"]
    default_delete = bool(project.get("delete", False)) or bool(relay.get("allow_delete", False))
    default_signed_tags = bool(project.get("signed_tags", True))
    default_signing = str(project.get("signing") or "optional")
    # 0.2.1: the upstream layer project.upstreams.<domain> (permission deltas, the
    # push / tags / delete defaults, and repos). Keys may be either a domain or an
    # upstream host name, so normalize them to domains.
    host_to_domain = {u["upstream"]: u["domain"] for u in upstreams}
    layers: dict[str, dict] = {}
    raw_layers = project.get("upstreams") or {}
    if isinstance(raw_layers, dict):
        for key, layer in raw_layers.items():
            k = str(key).strip().rstrip(".").lower()
            layers[host_to_domain.get(k, k)] = layer if isinstance(layer, dict) else {}
    # Collect (repo config, upstream domain) from project.repos (host prefix) and
    # upstreams.<d>.repos
    entries: list[tuple[dict, str]] = []
    for r in project.get("repos") or []:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        name = str(r["name"]).strip().lstrip("/")
        parts = name.split("/")
        host = domain or ""
        if len(parts) == 3 and "." in parts[0]:
            host = host_to_domain.get(parts[0].lower(), parts[0].lower())
        entries.append((r, host))
    for d, layer in layers.items():
        for r in layer.get("repos") or []:
            if isinstance(r, dict) and r.get("name"):
                entries.append((r, d))
    repos: list[RelayRepo] = []
    for r, host in entries:
        layer = layers.get(host, {})
        l_allow, l_deny = _perm_spec(layer.get("permissions"))
        r_allow, r_deny = _perm_spec(r.get("permissions"))
        effective = sorted(
            (set(p_allow) | set(l_allow) | set(r_allow)) - (set(p_deny) | set(l_deny) | set(r_deny))
        )
        # 0.2.0: `host/Org/Repo` names the upstream explicitly; `Org/Repo` means the
        # default upstream (or, inside an upstream layer's repos, that upstream)
        name = str(r["name"]).strip().lstrip("/")
        parts = name.split("/")
        if len(parts) == 3 and "." in parts[0]:
            name = "/".join(parts[1:])
        l_push, l_tags, l_delete = layer.get("push"), layer.get("tags"), layer.get("delete")
        push_v = r.get("push") if r.get("push") is not None else l_push
        tags_v = r.get("tags") if r.get("tags") is not None else l_tags
        delete_v = r.get("delete") if r.get("delete") is not None else l_delete
        signed_v = (
            r.get("signed_tags") if r.get("signed_tags") is not None else layer.get("signed_tags")
        )
        signing_v = r.get("signing") if r.get("signing") is not None else layer.get("signing")
        repos.append(
            RelayRepo(
                name=name,
                host=host,
                mode=str(r.get("mode", "read-only")),
                bases=[str(b) for b in (r.get("bases") or [])],
                push=[str(p) for p in push_v] if push_v is not None else default_push,
                tags=[str(t) for t in tags_v] if tags_v is not None else default_tags,
                delete=bool(delete_v) if delete_v is not None else default_delete,
                signed_tags=bool(signed_v) if signed_v is not None else default_signed_tags,
                signing=str(signing_v) if signing_v is not None else default_signing,
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
        resp.https_relays = _https_relays(config)
        resp.https_max_upload_bytes = _int_or(relay.get("https_max_upload_bytes"), 1048576)
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
        # 0.2.0: state for non-default upstreams lives under upstreams/<host>/
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
                ssh_options=u["ssh_options"],
                max_upload_bytes=u["max_upload_bytes"],
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
    """List tokens.json (hashes and metadata only); the hashes, which are the keys, are not exposed."""
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
    """Up to max_lines lines from the end of the file, so a large audit log is not read whole."""
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
        lines = lines[1:]  # reading from mid-file leaves the first line truncated
    return lines[-max_lines:] if max_lines > 0 else lines


def _field(obj: dict, key: str) -> str | None:
    """One audit field as a non-empty string. "-" is the relay's own placeholder for "unknown"."""
    value = obj.get(key)
    if value in (None, "", "-"):
        return None
    return str(value)


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
        "method",
        "bytes_in",
        "bytes_out",
        "cap",
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
    # The relay writes both the host it dialed (upstream) and what the client asked for
    # (sni). They differ only when a handler sends a domain to another upstream, so show
    # the pair only then; otherwise one destination says it all.
    upstream = _field(obj, "upstream")
    sni = _field(obj, "sni")
    destination = upstream or sni
    for name, value in (("sni", sni), ("upstream", upstream)):
        if value is not None and value != destination:
            details.append(f"{name}={value}")
    peer = obj.get("peer")
    reason = _field(obj, "reason")
    detail = " ".join(details) if details else None
    # A denied row carries its explanation in reason; mirror it so no BLOCKED row reads
    # detail=null next to an allowed row that has one
    if detail is None:
        detail = reason
    flag = None
    if event == "https_passthrough" and _int_or(obj.get("bytes_in"), 0) >= LARGE_UPLOAD_BYTES:
        flag = "large_upload"
    return RelayAuditEntry(
        timestamp=ts,
        component=component,
        action=action,
        event=event,
        actor=obj.get("actor"),
        peer=str(peer) if peer else None,
        destination=destination,
        repo=(str(obj["repo"]) or None) if obj.get("repo") is not None else None,
        verb=obj.get("verb"),
        path=obj.get("path"),
        label=obj.get("label"),
        reason=reason,
        detail=detail,
        flag=flag,
        edge=_field(obj, "edge"),
    )


def read_audit(state_dir: Path, limit: int = 100, kind: str = "all") -> list[RelayAuditEntry]:
    """The tail of audit.jsonl, newest first. kind = all | allowed | blocked."""
    path = state_dir / "audit.jsonl"
    # Read generously, since filtering discards some of it
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
    allowed = blocked = large_uploads = upload_capped = 0
    for entry in read_audit(sd, limit=5000):
        if entry.timestamp < cutoff:
            break  # newest first, so everything past here is older
        if entry.action == "ALLOWED":
            allowed += 1
        elif entry.action == "BLOCKED":
            blocked += 1
        if entry.flag == "large_upload":
            large_uploads += 1
        if entry.event == "https_upload_capped":
            upload_capped += 1
    tokens = read_tokens(sd, now)
    keys = next((f.count or 0 for f in cfg.state_files if f.name == "authorized_keys"), 0)
    return RelayStatsResponse(
        enabled=True,
        allowed=allowed,
        blocked=blocked,
        tokens_active=sum(1 for t in tokens if t.state == "active"),
        tokens_total=len(tokens),
        keys=keys,
        large_uploads=large_uploads,
        upload_capped=upload_capped,
    )
