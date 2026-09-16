"""ログのリアルタイム配信（WebSocket）を 1 本のポーラでまとめる（0.2.3）.

以前は WebSocket 接続ごとに 1 秒おきの全表走査（timestamp に索引なし）を行い、新着を 1 件ずつ送っていた。
クライアントは 1 件受けるごとに /api/stats を叩くので、タブが非表示で溜まった分を戻ったときに 1 件ずつ処理して
「ログが流れるのに時間がかかる」状態になっていた。

0.2.3 の形:
- ポーラは 1 つ。1 秒おきに rowid カーソルで 3 テーブルの新着だけを読む（rowid は主キーなので索引済み）
- 新着が 1 件でもあれば即時に 1 メッセージ ``{"type": "logs", "entries": [...]}`` を全クライアントに配信する
  （1 件なら 1 件のまま = リアルタイム、多ければ配列でまとめて届く）
- 接続時は ``{"type": "snapshot", "entries": [最新 N 件]}``。クライアントが ``{"type": "resync"}`` を送ってきたら
  同じものを返す（タブが非表示から戻ったときに、溜まった分を捨てて最新から描き直すため）
- クライアントが 1 つも居なければポーラは止まる
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import aiosqlite

SNAPSHOT_LIMIT = 50
POLL_INTERVAL = 1.0

# WebSocket で送るテーブルとカーソル名
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
    # Docker 環境ではログ詳細が取れないことがある（カウンターモード）
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
    """3 テーブルの新着を 1 本のポーラで読み、まとめて配信する."""

    def __init__(self, db_path: str, broadcast: Any, has_clients: Any) -> None:
        """初期化.

        Args:
            db_path: SQLite のパス
            broadcast: ``await broadcast(message: dict)`` で全クライアントに送る関数
            has_clients: ``has_clients() -> bool``。偽になったらポーラを止める
        """
        self.db_path = db_path
        self._broadcast = broadcast
        self._has_clients = has_clients
        self._task: asyncio.Task[None] | None = None
        self._cursors: dict[str, int] = {}
        self.poll_interval = POLL_INTERVAL

    # ---- 接続時 ----

    async def snapshot(self, limit: int = SNAPSHOT_LIMIT) -> dict[str, Any]:
        """最新 limit 件（3 テーブル合わせて、時刻の昇順）."""
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
                except Exception:  # テーブル未作成など
                    continue
        finally:
            await db.close()
        entries.sort(key=lambda e: e["timestamp"])
        return {"type": "snapshot", "entries": entries[-limit:]}

    # ---- ポーラ ----

    def start(self) -> None:
        """ポーラを起動する（既に動いていれば何もしない）."""
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
        """起動時点の末尾から配信する（履歴は snapshot が担う）."""
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
        """新着を読んでカーソルを進める。時刻の昇順で返す."""
        await self._init_cursors(db)
        entries: list[dict[str, Any]] = []
        for name, (sql, conv) in _QUERIES.items():
            try:
                cursor = await db.execute(sql, (self._cursors[name],))
                async for row in cursor:
                    self._cursors[name] = max(self._cursors[name], int(row[0]))
                    entries.append(conv(row[1:]))
                await cursor.close()
            except Exception:  # テーブル未作成（proxy 無効など）
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
                except Exception as e:  # DB が一時的にロックされた等。次の周期で再試行
                    print(f"Warning: log stream poll error: {e}")
                    continue
                if entries:
                    await self._broadcast({"type": "logs", "entries": entries})
        finally:
            await db.close()


async def _pragmas(db: aiosqlite.Connection) -> None:
    """読み取り側の接続でも書き込みと衝突しないように（WAL は DNSMapping が設定済み）."""
    # PRAGMA は 1 行返す。cursor を閉じずに置くと statement が開いたままになり、この接続の読み取りが
    # 古いスナップショットに固定される（新着が見えなくなる）ので必ず閉じる
    with contextlib.suppress(Exception):
        cursor = await db.execute("PRAGMA busy_timeout=5000")
        await cursor.close()


def parse_client_message(text: str) -> str | None:
    """クライアントからのメッセージ種別（"resync" など）。壊れていれば None."""
    try:
        obj = json.loads(text)
    except (TypeError, ValueError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("type"), str):
        return str(obj["type"])
    return None
