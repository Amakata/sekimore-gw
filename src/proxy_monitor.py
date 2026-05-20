"""Squidアクセスログ監視モジュール - プロキシアクセスの記録（許可・拒否両方）."""

import asyncio
import re

import aiosqlite

from .logger import ComponentType, log_error, log_system_event

SQUID_LOG_PATTERN = re.compile(r"^(\d+\.\d+)\s+\d+\s+(\S+)\s+(\S+)/(\d+)\s+\d+\s+(\S+)\s+(\S+)")

ALLOWED_RESULTS = frozenset(
    {
        "TCP_MISS",
        "TCP_HIT",
        "TCP_MEM_HIT",
        "TCP_REFRESH_HIT",
        "TCP_REFRESH_MISS",
        "TCP_TUNNEL",
    }
)

BLOCKED_RESULTS = frozenset(
    {
        "TCP_DENIED",
    }
)


class ProxyMonitor:
    """Squidアクセスログを監視してアクセスを記録（許可・拒否両方）."""

    def __init__(self, db_path: str, log_path: str = "/var/log/squid/access.log"):
        self.db_path = db_path
        self.log_path = log_path
        self.db: aiosqlite.Connection | None = None
        self.running = False

    async def init_db(self) -> None:
        """データベース初期化（proxy_logsテーブル作成 + proxy_blocksからのマイグレーション）."""
        self.db = await aiosqlite.connect(self.db_path)

        await self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_logs (
                timestamp REAL,
                client_ip TEXT,
                method TEXT,
                url TEXT,
                status_code INTEGER,
                squid_result TEXT,
                action TEXT DEFAULT 'allowed'
            )
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp
            ON proxy_logs(timestamp)
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_proxy_logs_action
            ON proxy_logs(action)
            """
        )

        await self._migrate_proxy_blocks()

        await self.db.commit()
        log_system_event("Proxy monitor database initialized", db_path=self.db_path)

    async def _migrate_proxy_blocks(self) -> None:
        """proxy_blocksテーブルからproxy_logsへデータをマイグレーション."""
        assert self.db is not None

        cursor = await self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_blocks'"
        )
        if not await cursor.fetchone():
            return

        cursor = await self.db.execute("SELECT COUNT(*) FROM proxy_blocks")
        row = await cursor.fetchone()
        count = row[0] if row else 0

        if count == 0:
            await self.db.execute("DROP TABLE proxy_blocks")
            return

        cursor = await self.db.execute("SELECT COUNT(*) FROM proxy_logs WHERE action = 'blocked'")
        row = await cursor.fetchone()
        existing = row[0] if row else 0

        if existing > 0:
            await self.db.execute("DROP TABLE proxy_blocks")
            return

        await self.db.execute(
            """
            INSERT INTO proxy_logs (timestamp, client_ip, method, url, status_code, squid_result, action)
            SELECT timestamp, client_ip, method, url, status_code, 'TCP_DENIED', 'blocked'
            FROM proxy_blocks
            """
        )
        await self.db.execute("DROP TABLE proxy_blocks")
        log_system_event("Migrated proxy_blocks to proxy_logs", count=str(count))

    async def record_access(
        self,
        timestamp: float,
        client_ip: str,
        method: str,
        url: str,
        status_code: int,
        squid_result: str,
        action: str,
    ) -> None:
        """プロキシアクセスイベントをDBに記録."""
        if not self.db:
            return

        try:
            await self.db.execute(
                """
                INSERT INTO proxy_logs
                (timestamp, client_ip, method, url, status_code, squid_result, action)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, method, url, status_code, squid_result, action),
            )
            await self.db.commit()

            if action == "blocked":
                log_system_event(
                    "Proxy access blocked",
                    client_ip=client_ip,
                    url=url,
                    status_code=str(status_code),
                )

        except Exception as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to record proxy access: {e}",
            )

    def _parse_squid_log_line(self, line: str) -> dict | None:
        """Squidログ行をパース.

        Squidログフォーマット:
        timestamp elapsed client_ip result_code/status bytes method URL - hierarchy/peername type
        """
        match = SQUID_LOG_PATTERN.match(line)
        if not match:
            return None

        squid_result = match.group(3)

        if squid_result in ALLOWED_RESULTS:
            action = "allowed"
        elif squid_result in BLOCKED_RESULTS:
            action = "blocked"
        else:
            return None

        return {
            "timestamp": float(match.group(1)),
            "client_ip": match.group(2),
            "method": match.group(5),
            "url": match.group(6),
            "status_code": int(match.group(4)),
            "squid_result": squid_result,
            "action": action,
        }

    async def _follow_log(self) -> None:
        """Squidログを監視（tail -f相当）."""
        try:
            with open(self.log_path) as f:
                f.seek(0, 2)

                while self.running:
                    line = f.readline()

                    if not line:
                        await asyncio.sleep(0.5)
                        continue

                    access_info = self._parse_squid_log_line(line.strip())
                    if access_info:
                        await self.record_access(**access_info)

        except FileNotFoundError:
            log_error(
                ComponentType.PROXY,
                f"Squid log file not found: {self.log_path}",
            )
        except Exception as e:
            log_error(
                ComponentType.PROXY,
                f"Error following Squid log: {e}",
            )

    async def start(self) -> None:
        """プロキシモニターを開始."""
        if self.running:
            return

        log_system_event("Starting proxy monitor...")

        await self.init_db()

        self.running = True

        try:
            await self._follow_log()
        except Exception as e:
            log_error(ComponentType.PROXY, f"Proxy monitor error: {e}")
            self.running = False

    async def stop(self) -> None:
        """プロキシモニターを停止."""
        if not self.running:
            return

        log_system_event("Stopping proxy monitor...")

        self.running = False

        if self.db:
            await self.db.close()
            self.db = None

        log_system_event("Proxy monitor stopped")
