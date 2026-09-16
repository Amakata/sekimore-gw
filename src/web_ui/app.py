"""FastAPI web application - the real-time monitoring dashboard."""

# NOTE: the proxy_blocks table has been merged into proxy_logs (ProxyMonitor.init_db
# migrates automatically)

import contextlib
import os
import subprocess
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path

import aiosqlite
import yaml
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .. import __version__ as core_version
from .. import constants, i18n
from ..logger import ComponentType, log_error, log_system_event
from . import __version__ as webui_version
from .log_stream import LogStreamer, parse_client_message


class DomainRequest(BaseModel):
    """Request to add or remove a domain."""

    domain: str


class StatsResponse(BaseModel):
    """Statistics response."""

    total: int
    allowed: int
    blocked: int
    ignored: int
    unique_domains: int
    firewall_blocked: int  # blocked by iptables
    proxy_allowed: int  # allowed by the Squid proxy
    proxy_blocked: int  # blocked by the Squid proxy


class CacheStatsResponse(BaseModel):
    """DNS cache statistics response."""

    enabled: bool
    size: int = 0
    hits: int = 0
    misses: int = 0
    hit_rate: float = 0.0


class LogEntry(BaseModel):
    """A log entry."""

    timestamp: float
    component: str
    action: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    domain: str | None = None
    reason: str | None = None


class DomainInfo(BaseModel):
    """Information about a domain."""

    domain: str
    query_count: int
    allowed_count: int
    blocked_count: int
    ignored_count: int = 0
    last_access: float
    status: str  # historical: "allowed", "blocked", "mixed"
    current_rule: str  # current rule: "allowed", "blocked_explicit", "blocked_default", "ignored"
    resolved_ips: list[str] | None = None  # the resolved IP addresses


class ProxyConfigResponse(BaseModel):
    """Proxy settings response."""

    enabled: bool
    port: int
    cache_enabled: bool
    cache_size_mb: int
    upstream_proxy: str | None = None
    upstream_proxy_tls: bool = False
    has_upstream_auth: bool = False


class SquidConfigResponse(BaseModel):
    """Squid configuration response."""

    available: bool
    config_text: str | None = None


class IptablesResponse(BaseModel):
    """iptables rules response."""

    available: bool
    filter_rules: str | None = None
    nat_rules: str | None = None
    error: str | None = None


class ConfigResponse(BaseModel):
    """Configuration information response."""

    version_package: str
    version_core: str
    version_webui: str
    proxy: ProxyConfigResponse
    squid: SquidConfigResponse
    iptables: IptablesResponse


class BlockedIPInfo(BaseModel):
    """Information about a blocked IP address."""

    ip_address: str
    block_count: int
    last_blocked: float
    ports: list[int]
    protocols: list[str]


class ConnectionManager:
    """Manages the WebSocket connections."""

    def __init__(self) -> None:
        """Initialize."""
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a WebSocket connection.

        Args:
            websocket: The WebSocket instance
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        log_system_event("WebSocket client connected", count=str(len(self.active_connections)))

    def disconnect(self, websocket: WebSocket) -> None:
        """Close a WebSocket connection.

        Args:
            websocket: The WebSocket instance
        """
        self.active_connections.remove(websocket)
        log_system_event("WebSocket client disconnected", count=str(len(self.active_connections)))

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to every client.

        Args:
            message: The message to broadcast
        """
        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Clean up connection errors afterwards
                disconnected.append(connection)

        # Drop the disconnected clients
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)


# FastAPI application
app = FastAPI(
    title="AI Security Gateway Dashboard",
    version="0.3.2",
    description="Real-time monitoring dashboard",
)

# Connection manager
manager = ConnectionManager()

# Database path (overridable through the environment)
DB_PATH = constants.DB_PATH
CONFIG_PATH = constants.CONFIG_PATH


async def get_db() -> aiosqlite.Connection:
    """Open a database connection.

    Returns:
        An aiosqlite connection
    """
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    # Wait briefly when colliding with a writer (DNS / monitor). 0.2.3; WAL itself is set
    # by DNSMapping.init_db.
    with contextlib.suppress(Exception):
        cursor = await db.execute("PRAGMA busy_timeout=5000")
        await cursor.close()  # an open statement pins reads to a stale snapshot
    return db


def load_config() -> dict:
    """Load the configuration file.

    Returns:
        The configuration as a dict
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f)  # type: ignore[no-any-return]
    except Exception as e:
        log_error(ComponentType.SYSTEM, f"Failed to load config: {e}")
        return {"allow_domains": [], "block_domains": []}


def get_current_rule(domain: str, config: dict) -> str:
    """Determine the current rule for a domain.

    Args:
        domain: The domain name
        config: The configuration dict

    Returns:
        The current rule: "allowed", "ignored", "blocked_explicit" or "blocked_default"
    """
    domain_lower = domain.lower().rstrip(".")
    allow_domains = config.get("allow_domains", [])
    block_domains = config.get("block_domains", [])
    ignore_domains = config.get("ignore_domains", [])

    # Block list first, it wins over everything else
    for blocked in block_domains:
        # Exact match
        if blocked == domain_lower:
            return "blocked_explicit"
        # Wildcard (the .example.com form)
        if blocked.startswith(".") and (
            domain_lower.endswith(blocked) or domain_lower.endswith(blocked[1:])
        ):
            return "blocked_explicit"

    # Ignore list, checked after block and before allow. These need no allow_domains
    # entry: the DNS answer is still NXDOMAIN, but the log noise goes away.
    for ignored in ignore_domains:
        if ignored == domain_lower:
            return "ignored"
        if ignored.startswith(".") and (
            domain_lower.endswith(ignored) or domain_lower.endswith(ignored[1:])
        ):
            return "ignored"

    # Allow list
    for allowed in allow_domains:
        # Exact match
        if allowed == domain_lower:
            return "allowed"
        # Wildcard (the .example.com form)
        if allowed.startswith(".") and (
            domain_lower.endswith(allowed) or domain_lower.endswith(allowed[1:])
        ):
            return "allowed"

    # Matched nothing, so denied by default
    return "blocked_default"


@app.get("/api/gateway-info")
async def get_gateway_info() -> dict:
    """Gateway information API.

    Returns:
        The gateway name and description
    """
    config = load_config()
    return {
        "name": config.get("name"),
        "description": config.get("description"),
    }


def _read_squid_config() -> SquidConfigResponse:
    """Read the Squid configuration file."""
    squid_path = Path(constants.SQUID_CONFIG_PATH)
    if squid_path.exists():
        try:
            return SquidConfigResponse(
                available=True,
                config_text=squid_path.read_text(encoding="utf-8"),
            )
        except Exception:
            return SquidConfigResponse(available=False)
    return SquidConfigResponse(available=False)


def _run_iptables(iptables_cmd: str) -> IptablesResponse:
    """Read the filter and nat table rules via the iptables command."""
    try:
        # filter table
        filter_result = subprocess.run(
            [iptables_cmd, "-L", "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if filter_result.returncode != 0:
            return IptablesResponse(available=False, error=filter_result.stderr.strip())

        # nat table
        nat_result = subprocess.run(
            [iptables_cmd, "-t", "nat", "-L", "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        nat_text = nat_result.stdout if nat_result.returncode == 0 else None

        return IptablesResponse(
            available=True,
            filter_rules=filter_result.stdout,
            nat_rules=nat_text,
        )
    except FileNotFoundError:
        return IptablesResponse(available=False, error=f"{iptables_cmd} not found")
    except subprocess.TimeoutExpired:
        return IptablesResponse(available=False, error="Command timed out")
    except Exception as e:
        return IptablesResponse(available=False, error=str(e))


@app.get("/api/config", response_model=ConfigResponse)
async def get_config() -> ConfigResponse:
    """Configuration API - returns the versions and the proxy, Squid and iptables settings.

    Returns:
        The configuration information
    """
    try:
        package_version = pkg_version("sekimore-gw")
    except PackageNotFoundError:
        package_version = "unknown"

    config = load_config()
    proxy_cfg = config.get("proxy", {})

    # Expose only whether credentials exist; never the password itself
    has_auth = bool(
        proxy_cfg.get("upstream_proxy_username") or os.getenv("SEKIMORE_UPSTREAM_PROXY_USERNAME")
    )

    proxy_response = ProxyConfigResponse(
        enabled=proxy_cfg.get("enabled", False),
        port=proxy_cfg.get("port", 3128),
        cache_enabled=proxy_cfg.get("cache_enabled", True),
        cache_size_mb=proxy_cfg.get("cache_size_mb", 1000),
        upstream_proxy=proxy_cfg.get("upstream_proxy"),
        upstream_proxy_tls=proxy_cfg.get("upstream_proxy_tls", False),
        has_upstream_auth=has_auth,
    )

    # Squid configuration
    squid_response = _read_squid_config()

    # iptables rules (iptables-legacy holds the firewall rules inside the container)
    iptables_response = _run_iptables("iptables-legacy")

    return ConfigResponse(
        version_package=package_version,
        version_core=core_version,
        version_webui=webui_version,
        proxy=proxy_response,
        squid=squid_response,
        iptables=iptables_response,
    )


class I18nResponse(BaseModel):
    """The Web UI string dictionary (0.2.4)."""

    lang: str
    supported: list[str]
    strings: dict[str, str]


@app.get("/api/i18n", response_model=I18nResponse)
async def get_i18n(request: Request, lang: str | None = None) -> I18nResponse:
    """Resolve the language and return its dictionary.

    Order: `?lang=` -> cookie -> `ui.language` in the config -> `Accept-Language` -> en.
    """
    config = load_config()
    ui = config.get("ui") if isinstance(config, dict) else None
    configured = ui.get("language", "auto") if isinstance(ui, dict) else "auto"
    resolved = i18n.resolve_lang(
        explicit=lang,
        cookie=request.cookies.get(i18n.COOKIE_NAME),
        accept_language=request.headers.get("accept-language"),
        configured=str(configured),
    )
    return I18nResponse(
        lang=resolved, supported=list(i18n.SUPPORTED), strings=i18n.strings(resolved)
    )


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """The main dashboard page.

    Returns:
        An HTML response
    """
    html_path = Path(__file__).parent / "templates" / "dashboard.html"

    if not html_path.exists():
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)

    with open(html_path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """Statistics API, covering the last 24 hours.

    Returns:
        The statistics
    """
    db = await get_db()

    # Cutoff timestamp for the last 24 hours
    one_day_ago = time.time() - 86400

    try:
        # Total accesses
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        total = row[0] if row else 0

        # Allowed
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'allowed'",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        allowed = row[0] if row else 0

        # Blocked
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'blocked'",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        blocked = row[0] if row else 0

        # Ignored
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'ignored'",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        ignored = row[0] if row else 0

        # Unique domains
        cursor = await db.execute(
            "SELECT COUNT(DISTINCT query_domain) FROM dns_queries WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        unique_domains = row[0] if row else 0

        # Firewall blocks
        cursor = await db.execute(
            "SELECT COUNT(*) FROM firewall_blocks WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        firewall_blocked = row[0] if row else 0

        # Proxy allows and blocks
        proxy_allowed = 0
        proxy_blocked = 0
        try:
            cursor = await db.execute(
                """
                SELECT action, COUNT(*) FROM proxy_logs
                WHERE timestamp > ?
                GROUP BY action
                """,
                (one_day_ago,),
            )
            async for row in cursor:
                if row[0] == "allowed":
                    proxy_allowed = row[1]
                elif row[0] == "blocked":
                    proxy_blocked = row[1]
        except Exception:
            pass

        return StatsResponse(
            total=total,
            allowed=allowed,
            blocked=blocked,
            ignored=ignored,
            unique_domains=unique_domains,
            firewall_blocked=firewall_blocked,
            proxy_allowed=proxy_allowed,
            proxy_blocked=proxy_blocked,
        )

    finally:
        await db.close()


@app.get("/api/cache-stats", response_model=CacheStatsResponse)
async def get_cache_stats() -> CacheStatsResponse:
    """DNS cache statistics API.

    Returns:
        The cache statistics
    """
    db = await get_db()

    try:
        # Latest statistics from the cache_stats table
        cursor = await db.execute(
            "SELECT size, hits, misses, hit_rate FROM cache_stats WHERE id = 1"
        )
        row = await cursor.fetchone()

        if row:
            return CacheStatsResponse(
                enabled=True,
                size=row[0],
                hits=row[1],
                misses=row[2],
                hit_rate=row[3],
            )

        # No cache statistics in the DB means the cache is disabled
        return CacheStatsResponse(enabled=False)

    except Exception:
        # e.g. the table does not exist
        return CacheStatsResponse(enabled=False)
    finally:
        await db.close()


@app.get("/api/logs", response_model=list[LogEntry])
async def get_logs(limit: int = 100) -> list[LogEntry]:
    """Return the most recent logs.

    Args:
        limit: How many entries to return

    Returns:
        A list of log entries
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, client_ip, query_domain, response_ips, status
            FROM dns_queries
            WHERE status != 'ignored'
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        action_map = {"allowed": "ALLOWED", "blocked": "BLOCKED", "ignored": "IGNORED"}

        logs = []
        async for row in cursor:
            status = row[4] if len(row) > 4 else "allowed"
            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="DNS",
                    action=action_map.get(status, "BLOCKED"),
                    src_ip=row[1],
                    domain=row[2],
                    dst_ip=row[3].split(",")[0] if row[3] else None,
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/firewall-blocks", response_model=list[LogEntry])
async def get_firewall_blocks(limit: int = 100) -> list[LogEntry]:
    """Return the most recent firewall block logs.

    Args:
        limit: How many entries to return

    Returns:
        A list of log entries
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, src_ip, dst_ip, dst_port, protocol
            FROM firewall_blocks
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            # Under Docker the log details are unavailable, so fall back to counter mode
            src_ip = row[1] if row[1] and row[1] != "blocked" else None
            dst_ip = row[2] if row[2] and row[2] != "blocked" else None
            protocol = row[4] if row[4] and row[4] != "IP" else "IP"

            # Show a different reason depending on whether the details came through
            if src_ip and dst_ip:
                reason = f"{protocol} traffic blocked by firewall"
            else:
                reason = "Traffic blocked by firewall (counter-based detection)"

            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="FIREWALL",
                    action="BLOCKED",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=row[3],
                    reason=reason,
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/proxy-logs", response_model=list[LogEntry])
async def get_proxy_logs(limit: int = 100) -> list[LogEntry]:
    """Return the most recent proxy access logs, both allowed and denied.

    Args:
        limit: How many entries to return

    Returns:
        A list of log entries
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, client_ip, method, url, status_code, squid_result, action
            FROM proxy_logs
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            action_str = "ALLOWED" if row[6] == "allowed" else "BLOCKED"
            if row[6] == "allowed":
                reason = f"{row[2]} via proxy ({row[5]})"
            else:
                reason = f"{row[2]} blocked by proxy ({row[5]}/{row[4]})"
            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="PROXY",
                    action=action_str,
                    src_ip=row[1],
                    domain=row[3],
                    reason=reason,
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/proxy-blocks", response_model=list[LogEntry])
async def get_proxy_blocks(limit: int = 100) -> list[LogEntry]:
    """Backward compatible endpoint: proxy block logs only."""
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, client_ip, method, url, status_code, squid_result, action
            FROM proxy_logs
            WHERE action = 'blocked'
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="PROXY",
                    action="BLOCKED",
                    src_ip=row[1],
                    domain=row[3],
                    reason=f"{row[2]} blocked by proxy ({row[5]}/{row[4]})",
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/blocked-ips", response_model=list[BlockedIPInfo])
async def get_blocked_ips(limit: int = 100) -> list[BlockedIPInfo]:
    """Return statistics about blocked IP addresses.

    Args:
        limit: How many entries to return

    Returns:
        A list of blocked IP address records
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT
                dst_ip,
                COUNT(*) as block_count,
                MAX(timestamp) as last_blocked,
                GROUP_CONCAT(DISTINCT dst_port) as ports,
                GROUP_CONCAT(DISTINCT protocol) as protocols
            FROM firewall_blocks
            WHERE dst_ip IS NOT NULL
                AND dst_ip != 'blocked'
                AND dst_ip != 'unknown'
                AND dst_ip != ''
            GROUP BY dst_ip
            ORDER BY block_count DESC
            LIMIT ?
            """,
            (limit,),
        )

        blocked_ips = []
        async for row in cursor:
            # Build the port list, dropping None
            ports = []
            if row["ports"]:
                for port_str in row["ports"].split(","):
                    port_str = port_str.strip()
                    if port_str and port_str != "None":
                        with contextlib.suppress(ValueError):
                            ports.append(int(port_str))

            # Build the protocol list
            protocols = []
            if row["protocols"]:
                for proto in row["protocols"].split(","):
                    proto = proto.strip()
                    if proto and proto not in ("unknown", "IP"):
                        protocols.append(proto)

            blocked_ips.append(
                BlockedIPInfo(
                    ip_address=row["dst_ip"],
                    block_count=row["block_count"],
                    last_blocked=row["last_blocked"],
                    ports=sorted(set(ports)),
                    protocols=sorted(set(protocols)),
                )
            )

        return blocked_ips

    finally:
        await db.close()


_streamer: LogStreamer | None = None


def get_streamer() -> LogStreamer:
    """The poller shared by every WebSocket connection; rebuilt when DB_PATH changed."""
    global _streamer
    if _streamer is None or _streamer.db_path != DB_PATH:
        _streamer = LogStreamer(
            DB_PATH,
            broadcast=manager.broadcast,
            has_clients=lambda: bool(manager.active_connections),
        )
    return _streamer


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint - real-time log delivery (DNS + Firewall + Proxy).

    0.2.3: on connect the client gets a snapshot (the latest 50 entries) in one message;
    after that the shared poller broadcasts new rows once a second as
    ``{"type": "logs", "entries": [...]}``. A client ``{"type": "resync"}`` gets another
    snapshot, which is what a tab coming back from the background sends. This replaces
    the old per-connection full-table scan that pushed one row at a time.

    Args:
        websocket: The WebSocket instance
    """
    await manager.connect(websocket)
    streamer = get_streamer()
    try:
        try:
            await websocket.send_json(await streamer.snapshot())
        except Exception as e:
            print(f"Warning: Failed to send initial logs: {e}")
        streamer.start()
        while True:
            text = await websocket.receive_text()
            if parse_client_message(text) == "resync":
                await websocket.send_json(await streamer.snapshot())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"Error: WebSocket connection error: {e}")
    finally:
        if websocket in manager.active_connections:
            manager.disconnect(websocket)
        if not manager.active_connections:
            await streamer.stop()


@app.get("/api/domains/allowed", response_model=list[str])
async def get_allowed_domains() -> list[str]:
    """Return the allowed domains.

    Returns:
        A list of allowed domains
    """
    config = load_config()
    return config.get("allow_domains", [])  # type: ignore[no-any-return]


@app.get("/api/domains/blocked", response_model=list[str])
async def get_blocked_domains() -> list[str]:
    """Return the configured blocked domains from config.yml.

    Returns:
        A list of blocked domains
    """
    config = load_config()
    return config.get("block_domains", [])  # type: ignore[no-any-return]


class BlockedDomainInfo(BaseModel):
    """Information about a blocked domain."""

    domain: str
    block_type: str  # "explicit" or "default"
    query_count: int
    last_access: float


@app.get("/api/domains/blocked-actual", response_model=list[BlockedDomainInfo])
async def get_blocked_actual_domains() -> list[BlockedDomainInfo]:
    """Return the domains actually blocked, taken from the access history.

    Returns:
        A list of blocked domain records
    """
    db = await get_db()
    config = load_config()

    try:
        # Fetch the blocked queries
        cursor = await db.execute(
            """
            SELECT
                query_domain,
                COUNT(*) as query_count,
                MAX(timestamp) as last_access
            FROM dns_queries
            WHERE status = 'blocked'
            GROUP BY query_domain
            ORDER BY query_count DESC
            """
        )

        blocked_domains = []
        async for row in cursor:
            domain = row[0]
            # Determine the current rule
            current_rule = get_current_rule(domain, config)

            # Keep only blocked_explicit and blocked_default domains
            if current_rule in ["blocked_explicit", "blocked_default"]:
                block_type = "explicit" if current_rule == "blocked_explicit" else "default"
                blocked_domains.append(
                    BlockedDomainInfo(
                        domain=domain,
                        block_type=block_type,
                        query_count=row[1],
                        last_access=row[2],
                    )
                )

        return blocked_domains

    finally:
        await db.close()


@app.get("/api/domains/unique", response_model=list[DomainInfo])
async def get_unique_domains() -> list[DomainInfo]:
    """Return the unique domains along with their access statistics.

    Returns:
        A list of domain records
    """
    db = await get_db()
    config = load_config()

    try:
        cursor = await db.execute(
            """
            SELECT
                query_domain,
                COUNT(*) as query_count,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_count,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) as ignored_count,
                MAX(timestamp) as last_access,
                GROUP_CONCAT(DISTINCT response_ips) as all_response_ips
            FROM dns_queries
            GROUP BY query_domain
            ORDER BY query_count DESC
            """
        )

        domains = []
        async for row in cursor:
            allowed_count = row["allowed_count"] or 0
            blocked_count = row["blocked_count"] or 0
            ignored_count = row["ignored_count"] or 0

            # Determine the historical status
            if allowed_count > 0 and blocked_count == 0:
                historical_status = "allowed"
            elif blocked_count > 0 and allowed_count == 0:
                historical_status = "blocked"
            else:
                historical_status = "mixed"

            # Determine the current rule
            current_rule = get_current_rule(row["query_domain"], config)

            # Ignored domains are excluded by default
            if current_rule == "ignored":
                continue

            # Build the deduplicated list of IP addresses
            resolved_ips = []
            all_response_ips = row["all_response_ips"]
            if all_response_ips:
                # Split the comma-separated addresses GROUP_CONCAT joined, then dedupe
                ip_set = set()
                for ip in all_response_ips.split(","):
                    ip = ip.strip()
                    if ip:
                        ip_set.add(ip)
                resolved_ips = sorted(ip_set)

            domains.append(
                DomainInfo(
                    domain=row["query_domain"],
                    query_count=row["query_count"],
                    allowed_count=allowed_count,
                    blocked_count=blocked_count,
                    ignored_count=ignored_count,
                    last_access=row["last_access"],
                    status=historical_status,
                    current_rule=current_rule,
                    resolved_ips=resolved_ips if resolved_ips else None,
                )
            )

        return domains

    finally:
        await db.close()


@app.get("/api/domains/ignored-config", response_model=list[str])
async def get_ignored_domains_config() -> list[str]:
    """Return the configured ignored domains from config.yml.

    Returns:
        A list of ignored domains
    """
    config = load_config()
    return config.get("ignore_domains", [])  # type: ignore[no-any-return]


@app.get("/api/domains/ignored", response_model=list[DomainInfo])
async def get_ignored_domains() -> list[DomainInfo]:
    """Return statistics for ignored domains, read from the database.

    Returns:
        A list of ignored domain records
    """
    db = await get_db()
    config = load_config()

    try:
        cursor = await db.execute(
            """
            SELECT
                query_domain,
                COUNT(*) as query_count,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_count,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) as ignored_count,
                MAX(timestamp) as last_access,
                GROUP_CONCAT(DISTINCT response_ips) as all_response_ips
            FROM dns_queries
            WHERE status = 'ignored'
            GROUP BY query_domain
            ORDER BY query_count DESC
            """
        )

        domains = []
        async for row in cursor:
            allowed_count = row["allowed_count"] or 0
            blocked_count = row["blocked_count"] or 0
            ignored_count = row["ignored_count"] or 0

            current_rule = get_current_rule(row["query_domain"], config)

            # Build the deduplicated list of IP addresses
            resolved_ips: list[str] = []
            all_response_ips = row["all_response_ips"]
            if all_response_ips:
                ip_set: set[str] = set()
                for ip in all_response_ips.split(","):
                    ip = ip.strip()
                    if ip:
                        ip_set.add(ip)
                resolved_ips = sorted(ip_set)

            domains.append(
                DomainInfo(
                    domain=row["query_domain"],
                    query_count=row["query_count"],
                    allowed_count=allowed_count,
                    blocked_count=blocked_count,
                    ignored_count=ignored_count,
                    last_access=row["last_access"],
                    status="ignored",
                    current_rule=current_rule,
                    resolved_ips=resolved_ips if resolved_ips else None,
                )
            )

        return domains

    finally:
        await db.close()


@app.post("/api/domains/allow")
async def add_allowed_domain(request: DomainRequest) -> dict:
    """Add an allowed domain by updating the configuration file.

    Args:
        request: The domain request

    Returns:
        A success response
    """
    # When implemented, this updates the config file and notifies the orchestrator
    log_system_event("Domain whitelist add request", domain=request.domain)

    return {"success": True, "domain": request.domain}


@app.delete("/api/domains/allow/{domain}")
async def remove_allowed_domain(domain: str) -> dict:
    """Remove an allowed domain.

    Args:
        domain: The domain name

    Returns:
        A success response
    """
    log_system_event("Domain whitelist remove request", domain=domain)

    return {"success": True, "domain": domain}


@app.post("/api/domains/block")
async def add_blocked_domain(request: DomainRequest) -> dict:
    """Add a denied domain.

    Args:
        request: The domain request

    Returns:
        A success response
    """
    log_system_event("Domain blocklist add request", domain=request.domain)

    return {"success": True, "domain": request.domain}


# Broadcasts a new log entry; called by the orchestrator
async def broadcast_log(log_entry: LogEntry) -> None:
    """Send a new log entry to every WebSocket client.

    Args:
        log_entry: The log entry
    """
    await manager.broadcast(log_entry.model_dump())


# ---- Relay tab: read-only over /data/relay; changes go through the sekimore-relay CLI ----
from . import relay_view  # noqa: E402


def _relay_state_dir() -> Path:
    return Path(relay_view.build_config(load_config()).state_dir)


@app.get("/api/relay/config", response_model=relay_view.RelayConfigResponse)
async def get_relay_config() -> relay_view.RelayConfigResponse:
    """The relay settings (domain_handlers / relay sections) and which state files exist."""
    return relay_view.build_config(load_config())


@app.get("/api/relay/stats", response_model=relay_view.RelayStatsResponse)
async def get_relay_stats() -> relay_view.RelayStatsResponse:
    """24h relay statistics: allowed / denied counts, tokens and registered keys."""
    return relay_view.build_stats(load_config())


@app.get("/api/relay/tokens", response_model=list[relay_view.RelayTokenInfo])
async def get_relay_tokens() -> list[relay_view.RelayTokenInfo]:
    """The project tokens: labels and metadata only, never the hash or the plaintext."""
    return relay_view.read_tokens(_relay_state_dir())


@app.get("/api/relay/audit", response_model=list[relay_view.RelayAuditEntry])
async def get_relay_audit(limit: int = 100, kind: str = "all") -> list[relay_view.RelayAuditEntry]:
    """The audit log, newest first. kind=allowed gives the access history, kind=blocked the blocks."""
    limit = max(1, min(limit, 1000))
    if kind not in ("all", "allowed", "blocked"):
        kind = "all"
    return relay_view.read_audit(_relay_state_dir(), limit=limit, kind=kind)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
