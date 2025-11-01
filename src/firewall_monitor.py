"""iptablesログ監視モジュール - ブロックされた通信の記録."""

import asyncio
import re
import time

import aiosqlite

from .logger import ComponentType, log_error, log_system_event


class FirewallMonitor:
    """iptablesログを監視してブロックされた通信を記録."""

    def __init__(self, db_path: str):
        """初期化.

        Args:
            db_path: SQLiteデータベースパス
        """
        self.db_path = db_path
        self.db: aiosqlite.Connection | None = None
        self.running = False

    async def init_db(self) -> None:
        """データベース初期化."""
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS firewall_blocks (
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                action TEXT DEFAULT 'blocked'
            )
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_firewall_timestamp
            ON firewall_blocks(timestamp)
            """
        )
        await self.db.commit()
        log_system_event("Firewall monitor database initialized", db_path=self.db_path)

    async def record_block(
        self, src_ip: str, dst_ip: str, dst_port: int | None, protocol: str
    ) -> None:
        """ブロックされた通信を記録.

        Args:
            src_ip: 送信元IP
            dst_ip: 宛先IP
            dst_port: 宛先ポート
            protocol: プロトコル（TCP/UDP/ICMP）
        """
        if self.db is None:
            return

        timestamp = time.time()
        await self.db.execute(
            """
            INSERT INTO firewall_blocks (timestamp, src_ip, dst_ip, dst_port, protocol)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp, src_ip, dst_ip, dst_port, protocol),
        )
        await self.db.commit()

        log_system_event(
            "Firewall block recorded",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=str(dst_port) if dst_port else "N/A",
            protocol=protocol,
        )

    def parse_iptables_log(self, log_line: str) -> dict | None:
        """iptablesログ行をパース.

        Args:
            log_line: iptablesログ行

        Returns:
            パースされた情報（辞書）、またはNone
        """
        # iptablesログのフォーマット例:
        # [FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=172.20.0.5 DST=8.8.8.8 ... PROTO=TCP SPT=54321 DPT=53

        if "[FIREWALL-BLOCK]" not in log_line:
            return None

        try:
            # 正規表現でパース
            src_match = re.search(r"SRC=([0-9\.]+)", log_line)
            dst_match = re.search(r"DST=([0-9\.]+)", log_line)
            proto_match = re.search(r"PROTO=(\w+)", log_line)
            dpt_match = re.search(r"DPT=(\d+)", log_line)

            if not (src_match and dst_match and proto_match):
                return None

            return {
                "src_ip": src_match.group(1),
                "dst_ip": dst_match.group(1),
                "dst_port": int(dpt_match.group(1)) if dpt_match else None,
                "protocol": proto_match.group(1),
            }
        except Exception as e:
            log_error(ComponentType.FIREWALL, f"Failed to parse iptables log: {e}")
            return None

    async def monitor_ulog_file(self) -> None:
        """ulogdログファイルを監視（Docker環境用）.

        ulogd2がiptables ULOGターゲットから受け取ったパケット情報を
        /var/log/ulog/firewall.logに記録。このファイルをtail -fで監視。
        """
        log_system_event("Starting firewall monitor (ulogd file mode)")
        self.running = True

        log_file = "/var/log/ulog/firewall.log"

        while self.running:
            try:
                # tail -f で継続的にログファイルを監視
                process = await asyncio.create_subprocess_exec(
                    "tail",
                    "-F",  # ファイルが存在しなくても待機、rotate対応
                    "-n",
                    "0",  # 既存行はスキップ、新規行のみ
                    log_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                log_system_event(f"Monitoring ulogd file: {log_file}")

                # 非同期で行を読み取り
                while self.running and process.returncode is None:
                    try:
                        line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)

                        if line_bytes:
                            line = line_bytes.decode("utf-8", errors="ignore").strip()

                            # iptablesログをパース
                            parsed = self.parse_iptables_log(line)
                            if parsed:
                                await self.record_block(
                                    src_ip=parsed["src_ip"],
                                    dst_ip=parsed["dst_ip"],
                                    dst_port=parsed["dst_port"],
                                    protocol=parsed["protocol"],
                                )

                    except TimeoutError:
                        # タイムアウトは正常（新しいログがない）
                        continue
                    except Exception as e:
                        log_error(ComponentType.FIREWALL, f"Error reading ulog: {e}")
                        await asyncio.sleep(1)

                # プロセス終了処理
                if process.returncode is None:
                    process.terminate()
                    await process.wait()

            except FileNotFoundError:
                log_error(ComponentType.FIREWALL, f"Ulog file not found: {log_file}, retrying...")
                await asyncio.sleep(10)
            except Exception as e:
                log_error(ComponentType.FIREWALL, f"Error monitoring ulog: {e}")
                await asyncio.sleep(10)

    async def start(self) -> None:
        """監視を開始."""
        await self.init_db()
        await self.monitor_ulog_file()

    async def stop(self) -> None:
        """監視を停止."""
        self.running = False
        if self.db:
            await self.db.close()
        log_system_event("Firewall monitor stopped")
