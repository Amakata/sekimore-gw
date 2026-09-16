"""Real-time log delivery (WebSocket) collapsed into a single poller (0.2.3).

Previously every WebSocket connection ran its own full-table scan once a second
(timestamp had no index) and pushed new rows one at a time. The client hits /api/stats
for each row it receives, so returning to a backgrounded tab meant chewing through the
backlog row by row, which made the log feel slow to catch up.

How 0.2.3 works:
- One poller. Once a second it reads only the new rows from the three tables using a
  rowid cursor (rowid is the primary key, so it is already indexed).
- As soon as there is at least one new row it broadcasts a single
  ``{"type": "logs", "entries": [...]}`` message to every client (one row stays one row,
  so it is still real-time; a burst arrives batched in the array).
- On connect the client gets ``{"type": "snapshot", "entries": [latest N]}``, and the
  same thing again whenever it sends ``{"type": "resync"}`` (so a tab coming back from
  the background can drop its backlog and redraw from the latest state).
- The poller stops once no clients remain.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import aiosqlite

SNAPSHOT_LIMIT = 50
POLL_INTERVAL = 1.0

# Tables streamed over the WebSocket, and their cursor names
_TABLES = ("dns", "fw", "proxy")


def _dns_entry(row: Any) -> dict[str, Any]:
    status = row[4] if len(row) > 4 and row[4] else "allowed"
    action = {"allowed": "ALLOWED", "blocked": "BLOCKED", "ignored": "IGNORED"}.get(
        status, "BLOCKED"
    )
    return {
        "timestamp": row[0],
        "component": "DNS",
        "action": action,
        "src_ip": row[1],
        "dst_ip": row[3].split(",")[0] if row[3] else None,
        "dst_port": None,
        "domain": row[2],
        "reason": None,
    }


def _fw_entry(row: Any) -> dict[str, Any]:
    # Under Docker the log details are sometimes unavailable (counter mode)
    src_ip = row[1] if row[1] and row[1] != "blocked" else None
    dst_ip = row[2] if row[2] and row[2] != "blocked" else None
    protocol = row[4] if row[4] and row[4] != "IP" else "IP"
    if src_ip and dst_ip:
        reason = f"{protocol} traffic blocked by firewall"
    else:
        reason = "Traffic blocked by firewall (counter-based detection)"
    return {
        "timestamp": row[0],
        "component": "FIREWALL",
        "action": "BLOCKED",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": row[3],
        "domain": None,
        "reason": reason,
    }


def _proxy_entry(row: Any) -> dict[str, Any]:
    allowed = row[6] == "allowed"
    reason = (
        f"{row[2]} via proxy ({row[5]})"
        if allowed
        else f"{row[2]} blocked by proxy ({row[5]}/{row[4]})"
    )
    return {
        "timestamp": row[0],
        "component": "PROXY",
        "action": "ALLOWED" if allowed else "BLOCKED",
        "src_ip": row[1],
        "dst_ip": None,
        "dst_port": None,
        "domain": row[3],
        "reason": reason,
    }


_QUERIES = {
    "dns": (
        "SELECT rowid, timestamp, client_ip, query_domain, response_ips, status FROM dns_queries "
        "WHERE rowid > ? AND status != 'ignored' ORDER BY rowid ASC",
        _dns_entry,
    ),
    "fw": (
        "SELECT rowid, timestamp, src_ip, dst_ip, dst_port, protocol FROM firewall_blocks "
        "WHERE rowid > ? ORDER BY rowid ASC",
        _fw_entry,
    ),
    "proxy": (
        "SELECT rowid, timestamp, client_ip, method, url, status_code, squid_result, action FROM proxy_logs "
        "WHERE rowid > ? ORDER BY rowid ASC",
        _proxy_entry,
    ),
}

_SNAPSHOT_QUERIES = {
    "dns": (
        "SELECT rowid, timestamp, client_ip, query_domain, response_ips, status FROM dns_queries "
        "WHERE status != 'ignored' ORDER BY timestamp DESC LIMIT ?",
        _dns_entry,
    ),
    "fw": (
        "SELECT rowid, timestamp, src_ip, dst_ip, dst_port, protocol FROM firewall_blocks "
        "ORDER BY timestamp DESC LIMIT ?",
        _fw_entry,
    ),
    "proxy": (
        "SELECT rowid, timestamp, client_ip, method, url, status_code, squid_result, action FROM proxy_logs "
        "ORDER BY timestamp DESC LIMIT ?",
        _proxy_entry,
    ),
}

_TABLE_NAMES = {"dns": "dns_queries", "fw": "firewall_blocks", "proxy": "proxy_logs"}


class LogStreamer:
    """Reads new rows from the three tables with a single poller and broadcasts them together."""

    def __init__(self, db_path: str, broadcast: Any, has_clients: Any) -> None:
        """Initialize.

        Args:
            db_path: Path to the SQLite database
            broadcast: Function sending to every client via ``await broadcast(message: dict)``
            has_clients: ``has_clients() -> bool``; the poller stops once it returns false
        """
        self.db_path = db_path
        self._broadcast = broadcast
        self._has_clients = has_clients
        self._task: asyncio.Task[None] | None = None
        self._cursors: dict[str, int] = {}
        self.poll_interval = POLL_INTERVAL

    # ---- On connect ----

    async def snapshot(self, limit: int = SNAPSHOT_LIMIT) -> dict[str, Any]:
        """The latest `limit` entries across all three tables, oldest first."""
        entries: list[dict[str, Any]] = []
        db = await aiosqlite.connect(self.db_path)
        try:
            await _pragmas(db)
            for sql, conv in _SNAPSHOT_QUERIES.values():
                try:
                    cursor = await db.execute(sql, (limit,))
                    async for row in cursor:
                        entries.append(conv(row[1:]))
                    await cursor.close()
                except Exception:  # e.g. the table does not exist yet
                    continue
        finally:
            await db.close()
        entries.sort(key=lambda e: e["timestamp"])
        return {"type": "snapshot", "entries": entries[-limit:]}

    # ---- Poller ----

    def start(self) -> None:
        """Start the poller; a no-op if it is already running."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _init_cursors(self, db: aiosqlite.Connection) -> None:
        """Start streaming from the tail as of startup; history comes from snapshot()."""
        for name in _TABLES:
            if name in self._cursors:
                continue
            try:
                cursor = await db.execute(
                    f"SELECT COALESCE(MAX(rowid), 0) FROM {_TABLE_NAMES[name]}"
                )
                row = await cursor.fetchone()
                await cursor.close()
                self._cursors[name] = int(row[0]) if row and row[0] is not None else 0
            except Exception:
                self._cursors[name] = 0

    async def poll_once(self, db: aiosqlite.Connection) -> list[dict[str, Any]]:
        """Read new rows and advance the cursors. Returns them oldest first."""
        await self._init_cursors(db)
        entries: list[dict[str, Any]] = []
        for name, (sql, conv) in _QUERIES.items():
            try:
                cursor = await db.execute(sql, (self._cursors[name],))
                async for row in cursor:
                    self._cursors[name] = max(self._cursors[name], int(row[0]))
                    entries.append(conv(row[1:]))
                await cursor.close()
            except Exception:  # table does not exist (e.g. the proxy is disabled)
                continue
        entries.sort(key=lambda e: e["timestamp"])
        return entries

    async def _run(self) -> None:
        db = await aiosqlite.connect(self.db_path)
        try:
            await _pragmas(db)
            await self._init_cursors(db)
            while self._has_clients():
                await asyncio.sleep(self.poll_interval)
                try:
                    entries = await self.poll_once(db)
                except Exception as e:  # e.g. the DB is briefly locked; retry next cycle
                    print(f"Warning: log stream poll error: {e}")
                    continue
                if entries:
                    await self._broadcast({"type": "logs", "entries": entries})
        finally:
            await db.close()


async def _pragmas(db: aiosqlite.Connection) -> None:
    """Keep reader connections from colliding with writers (DNSMapping already set WAL)."""
    # A PRAGMA returns a row. Leaving the cursor open leaves the statement open, which
    # pins this connection's reads to a stale snapshot and hides new rows, so close it.
    with contextlib.suppress(Exception):
        cursor = await db.execute("PRAGMA busy_timeout=5000")
        await cursor.close()


def parse_client_message(text: str) -> str | None:
    """The message type sent by a client ("resync" etc.), or None if it is malformed."""
    try:
        obj = json.loads(text)
    except (TypeError, ValueError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("type"), str):
        return str(obj["type"])
    return None
