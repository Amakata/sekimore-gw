"""iptables log monitor - records blocked traffic."""

import asyncio
import re
import time

import aiosqlite

from . import constants
from .logger import ComponentType, log_error, log_system_event


class FirewallMonitor:
    """Watches the iptables log and records blocked traffic."""

    def __init__(self, db_path: str):
        """Initialize the monitor.

        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.db: aiosqlite.Connection | None = None
        self.running = False

    async def init_db(self) -> None:
        """Initialize the database."""
        self.db = await aiosqlite.connect(self.db_path)
        # 0.2.3: WAL (same DB as DNSMapping; applying these is idempotent) and busy_timeout
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA busy_timeout=5000",
        ):
            try:
                cursor = await self.db.execute(pragma)
                await cursor.close()
            except Exception:  # pragma: no cover
                pass
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
        """Record a blocked connection.

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            dst_port: Destination port
            protocol: Protocol (TCP/UDP/ICMP)
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
        """Parse an iptables log line.

        Args:
            log_line: iptables log line

        Returns:
            Dict of parsed fields, or None if the line does not match
        """
        # Example iptables log format:
        # [FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=172.20.0.5 DST=8.8.8.8 ... PROTO=TCP SPT=54321 DPT=53

        if "[FIREWALL-BLOCK]" not in log_line:
            return None

        try:
            # Pull out the fields with regexes
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
        """Monitor the ulogd log file (used in the Docker environment).

        ulogd2 writes the packet details it receives from the iptables ULOG
        target to constants.ULOG_FILE_PATH (/var/log/ulog/firewall.log unless
        SEKIMORE_ULOG_PATH says otherwise); this follows that file with tail -f.
        """
        log_system_event("Starting firewall monitor (ulogd file mode)")
        self.running = True

        log_file = constants.ULOG_FILE_PATH

        while self.running:
            try:
                # Follow the log file continuously with tail -f
                process = await asyncio.create_subprocess_exec(
                    "tail",
                    "-F",  # Wait for the file if missing, and survive rotation
                    "-n",
                    "0",  # Skip existing lines, only read new ones
                    log_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                log_system_event(f"Monitoring ulogd file: {log_file}")

                # Read lines asynchronously
                while self.running and process.returncode is None:
                    try:
                        if process.stdout is None:
                            break
                        line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)

                        if line_bytes:
                            line = line_bytes.decode("utf-8", errors="ignore").strip()

                            # Parse the iptables log line
                            parsed = self.parse_iptables_log(line)
                            if parsed:
                                await self.record_block(
                                    src_ip=parsed["src_ip"],
                                    dst_ip=parsed["dst_ip"],
                                    dst_port=parsed["dst_port"],
                                    protocol=parsed["protocol"],
                                )

                    except TimeoutError:
                        # A timeout is normal: no new log lines
                        continue
                    except Exception as e:
                        log_error(ComponentType.FIREWALL, f"Error reading ulog: {e}")
                        await asyncio.sleep(1)

                # Shut the process down
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
        """Start monitoring."""
        await self.init_db()
        await self.monitor_ulog_file()

    async def stop(self) -> None:
        """Stop monitoring."""
        self.running = False
        if self.db:
            await self.db.close()
        log_system_event("Firewall monitor stopped")
