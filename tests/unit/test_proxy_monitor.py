"""Unit tests for proxy_monitor module."""

import time

import pytest

from src.proxy_monitor import ProxyMonitor


def describe_proxy_monitor():
    """ProxyMonitor unit tests."""

    @pytest.mark.asyncio
    async def it_initializes_database(tmp_path):
        """Test init_db creates proxy_logs table."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)

        await monitor.init_db()

        assert monitor.db is not None

        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_logs'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "proxy_logs"

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_records_blocked_access(tmp_path):
        """Test record_access inserts blocked data."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        timestamp = time.time()
        await monitor.record_access(
            timestamp=timestamp,
            client_ip="192.168.1.100",
            method="CONNECT",
            url="https://blocked.com:443",
            status_code=403,
            squid_result="TCP_DENIED",
            action="blocked",
        )

        cursor = await monitor.db.execute("SELECT * FROM proxy_logs")
        row = await cursor.fetchone()
        assert row is not None
        assert row[1] == "192.168.1.100"
        assert row[2] == "CONNECT"
        assert row[3] == "https://blocked.com:443"
        assert row[4] == 403
        assert row[5] == "TCP_DENIED"
        assert row[6] == "blocked"

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_records_allowed_access(tmp_path):
        """Test record_access inserts allowed data."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        timestamp = time.time()
        await monitor.record_access(
            timestamp=timestamp,
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com/page.html",
            status_code=200,
            squid_result="TCP_MISS",
            action="allowed",
        )

        cursor = await monitor.db.execute("SELECT * FROM proxy_logs")
        row = await cursor.fetchone()
        assert row is not None
        assert row[4] == 200
        assert row[5] == "TCP_MISS"
        assert row[6] == "allowed"

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_handles_record_when_db_is_none():
        """Test record_access handles None database."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")
        monitor.db = None

        await monitor.record_access(
            timestamp=time.time(),
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            status_code=403,
            squid_result="TCP_DENIED",
            action="blocked",
        )

    def it_parses_blocked_squid_log_line():
        """Test _parse_squid_log_line parses TCP_DENIED log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.123 100 192.168.1.5 TCP_DENIED/403 0 CONNECT blocked.com:443 - HIER_NONE/- -"

        result = monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["timestamp"] == 1234567890.123
        assert result["client_ip"] == "192.168.1.5"
        assert result["method"] == "CONNECT"
        assert result["url"] == "blocked.com:443"
        assert result["status_code"] == 403
        assert result["squid_result"] == "TCP_DENIED"
        assert result["action"] == "blocked"

    def it_parses_allowed_tcp_miss():
        """Test _parse_squid_log_line parses TCP_MISS (allowed) log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.456 50 10.0.0.10 TCP_MISS/200 1234 GET http://example.com/page.html - DIRECT/93.184.216.34 text/html"

        result = monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["status_code"] == 200
        assert result["squid_result"] == "TCP_MISS"
        assert result["action"] == "allowed"
        assert result["method"] == "GET"
        assert result["url"] == "http://example.com/page.html"

    def it_parses_allowed_tcp_hit():
        """Test _parse_squid_log_line parses TCP_HIT (cache hit) log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.789 5 10.0.0.10 TCP_HIT/200 5678 GET http://cached.com/resource - HIER_DIRECT/- text/html"

        result = monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["squid_result"] == "TCP_HIT"
        assert result["action"] == "allowed"

    def it_parses_allowed_tcp_tunnel():
        """Test _parse_squid_log_line parses TCP_TUNNEL (HTTPS) log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.100 200 172.20.0.5 TCP_TUNNEL/200 12345 CONNECT example.com:443 - HIER_DIRECT/93.184.216.34 -"

        result = monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["squid_result"] == "TCP_TUNNEL"
        assert result["action"] == "allowed"
        assert result["method"] == "CONNECT"

    def it_returns_none_for_unknown_squid_result():
        """Test _parse_squid_log_line returns None for unrecognized result codes."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.456 50 10.0.0.10 TCP_UNKNOWN_THING/500 0 GET http://example.com - DIRECT/- -"

        result = monitor._parse_squid_log_line(log_line)

        assert result is None

    def it_returns_none_for_malformed_log():
        """Test _parse_squid_log_line returns None for malformed log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        result = monitor._parse_squid_log_line("Invalid log format")

        assert result is None

    @pytest.mark.asyncio
    async def it_stops_monitoring(tmp_path):
        """Test stop halts monitoring."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        monitor.running = True
        await monitor.stop()

        assert monitor.running is False

    @pytest.mark.asyncio
    async def it_handles_record_exception(tmp_path):
        """Test record_access handles exceptions gracefully."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        await monitor.db.close()

        await monitor.record_access(
            timestamp=time.time(),
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            status_code=403,
            squid_result="TCP_DENIED",
            action="blocked",
        )

    def it_parses_connect_with_port():
        """Test _parse_squid_log_line parses CONNECT with port number."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.789 200 172.20.0.5 TCP_DENIED/403 0 CONNECT malicious.com:8443 - HIER_NONE/- -"

        result = monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["method"] == "CONNECT"
        assert result["url"] == "malicious.com:8443"
        assert result["status_code"] == 403
        assert result["squid_result"] == "TCP_DENIED"
        assert result["action"] == "blocked"


def describe_proxy_monitor_migration():
    """ProxyMonitor migration tests."""

    @pytest.mark.asyncio
    async def it_migrates_proxy_blocks_to_proxy_logs(tmp_path):
        """Test migration from proxy_blocks to proxy_logs."""
        import aiosqlite

        db_path = str(tmp_path / "test_migration.db")

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """
                CREATE TABLE proxy_blocks (
                    timestamp REAL,
                    client_ip TEXT,
                    method TEXT,
                    url TEXT,
                    status_code INTEGER,
                    action TEXT DEFAULT 'blocked'
                )
                """
            )
            now = time.time()
            await db.execute(
                "INSERT INTO proxy_blocks VALUES (?, ?, ?, ?, ?, ?)",
                (now, "192.168.1.100", "CONNECT", "blocked.com:443", 403, "blocked"),
            )
            await db.execute(
                "INSERT INTO proxy_blocks VALUES (?, ?, ?, ?, ?, ?)",
                (now - 10, "192.168.1.101", "GET", "http://bad.com", 403, "blocked"),
            )
            await db.commit()

        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        cursor = await monitor.db.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE action = 'blocked'"
        )
        row = await cursor.fetchone()
        assert row[0] == 2

        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_blocks'"
        )
        assert await cursor.fetchone() is None

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_handles_empty_proxy_blocks(tmp_path):
        """Test migration drops empty proxy_blocks table."""
        import aiosqlite

        db_path = str(tmp_path / "test_migration.db")

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """
                CREATE TABLE proxy_blocks (
                    timestamp REAL,
                    client_ip TEXT,
                    method TEXT,
                    url TEXT,
                    status_code INTEGER,
                    action TEXT DEFAULT 'blocked'
                )
                """
            )
            await db.commit()

        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_blocks'"
        )
        assert await cursor.fetchone() is None

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_skips_migration_when_no_proxy_blocks(tmp_path):
        """Test init_db works when proxy_blocks table doesn't exist."""
        db_path = str(tmp_path / "test_fresh.db")

        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_logs'"
        )
        assert (await cursor.fetchone()) is not None

        await monitor.db.close()
