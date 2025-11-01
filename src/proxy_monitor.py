"""Squidアクセスログ監視モジュール - ブロックされたプロキシアクセスの記録."""

import asyncio
import re

import aiosqlite

from .logger import ComponentType, log_error, log_system_event


class ProxyMonitor:
    """Squidアクセスログを監視してブロックされたアクセスを記録."""

    def __init__(self, db_path: str, log_path: str = "/var/log/squid/access.log"):
        """初期化.

        Args:
            db_path: SQLiteデータベースパス
            log_path: Squidアクセスログパス
        """
        self.db_path = db_path
        self.log_path = log_path
        self.db: aiosqlite.Connection | None = None
        self.running = False

    async def init_db(self) -> None:
        """データベース初期化."""
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_blocks (
                timestamp REAL,
                client_ip TEXT,
                method TEXT,
                url TEXT,
                status_code INTEGER,
                action TEXT DEFAULT 'blocked'
            )
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_proxy_timestamp
            ON proxy_blocks(timestamp)
            """
        )
        await self.db.commit()
        log_system_event("Proxy monitor database initialized", db_path=self.db_path)

    async def record_block(
        self,
        timestamp: float,
        client_ip: str,
        method: str,
        url: str,
        status_code: int,
    ) -> None:
        """プロキシブロックイベントをDBに記録.

        Args:
            timestamp: タイムスタンプ
            client_ip: クライアントIP
            method: HTTPメソッド（CONNECT, GET, POST等）
            url: アクセスURL
            status_code: ステータスコード（403等）
        """
        if not self.db:
            return

        try:
            await self.db.execute(
                """
                INSERT INTO proxy_blocks
                (timestamp, client_ip, method, url, status_code, action)
                VALUES (?, ?, ?, ?, ?, 'blocked')
                """,
                (timestamp, client_ip, method, url, status_code),
            )
            await self.db.commit()

            log_system_event(
                "Proxy access blocked",
                client_ip=client_ip,
                url=url,
                status_code=str(status_code),
            )

        except Exception as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to record proxy block: {e}",
            )

    async def _parse_squid_log_line(self, line: str) -> dict | None:
        """Squidログ行をパース.

        Squidログフォーマット:
        timestamp elapsed client_ip code/status bytes method URL - hierarchy/peername type

        Args:
            line: ログ行

        Returns:
            パース結果（ブロックでない場合はNone）
        """
        # Squidログのパターン: TCP_DENIED/403などをマッチ
        pattern = r"^(\d+\.\d+)\s+\d+\s+(\S+)\s+TCP_DENIED/(\d+)\s+\d+\s+(\S+)\s+(\S+)"
        match = re.match(pattern, line)

        if not match:
            return None

        timestamp = float(match.group(1))
        client_ip = match.group(2)
        status_code = int(match.group(3))
        method = match.group(4)
        url = match.group(5)

        return {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "status_code": status_code,
        }

    async def _follow_log(self) -> None:
        """Squidログを監視（tail -f相当）."""
        try:
            # ログファイルの最後から読み始める
            with open(self.log_path) as f:
                # ファイル末尾に移動
                f.seek(0, 2)

                while self.running:
                    line = f.readline()

                    if not line:
                        # 新しい行がない場合は少し待つ
                        await asyncio.sleep(0.5)
                        continue

                    # ブロックイベントをパース
                    block_info = await self._parse_squid_log_line(line.strip())

                    if block_info:
                        await self.record_block(**block_info)

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
