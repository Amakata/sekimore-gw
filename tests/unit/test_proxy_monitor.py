"""Unit tests for proxy_monitor module."""

import time

import pytest

from src.proxy_monitor import ProxyMonitor


def describe_proxy_monitor():
    """ProxyMonitor unit tests."""

    @pytest.mark.asyncio
    async def it_initializes_database(tmp_path):
        """Test init_db creates database schema."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)

        await monitor.init_db()

        assert monitor.db is not None

        # Verify table exists
        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_blocks'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "proxy_blocks"

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_records_block(tmp_path):
        """Test record_block inserts data."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        timestamp = time.time()
        await monitor.record_block(
            timestamp=timestamp,
            client_ip="192.168.1.100",
            method="CONNECT",
            url="https://blocked.com:443",
            status_code=403,
        )

        # Verify record was inserted
        cursor = await monitor.db.execute("SELECT * FROM proxy_blocks")
        row = await cursor.fetchone()
        assert row is not None
        assert row[1] == "192.168.1.100"  # client_ip
        assert row[2] == "CONNECT"  # method
        assert row[3] == "https://blocked.com:443"  # url
        assert row[4] == 403  # status_code

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_handles_record_when_db_is_none():
        """Test record_block handles None database."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")
        monitor.db = None

        # Should not raise exception
        await monitor.record_block(
            timestamp=time.time(),
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            status_code=403,
        )

    @pytest.mark.asyncio
    async def it_parses_squid_log_line():
        """Test _parse_squid_log_line parses Squid access log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        # Example Squid log line (403 Forbidden)
        log_line = "1234567890.123 100 192.168.1.5 TCP_DENIED/403 0 CONNECT blocked.com:443 - HIER_NONE/- -"

        result = await monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["timestamp"] == 1234567890.123
        assert result["client_ip"] == "192.168.1.5"
        assert result["method"] == "CONNECT"
        assert result["url"] == "blocked.com:443"
        assert result["status_code"] == 403

    @pytest.mark.asyncio
    async def it_ignores_non_blocked_requests():
        """Test _parse_squid_log_line ignores non-blocked requests (200 OK)."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        # Non-blocked request (TCP_MISS/200) should return None
        log_line = "1234567890.456 50 10.0.0.10 TCP_MISS/200 1234 GET http://example.com/page.html - DIRECT/93.184.216.34 text/html"

        result = await monitor._parse_squid_log_line(log_line)

        # Should return None because it's not TCP_DENIED
        assert result is None

    @pytest.mark.asyncio
    async def it_returns_none_for_malformed_log():
        """Test _parse_squid_log_line returns None for malformed log."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        # Malformed log line
        log_line = "Invalid log format"

        result = await monitor._parse_squid_log_line(log_line)

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
        """Test record_block handles exceptions gracefully."""
        db_path = str(tmp_path / "test_proxy.db")
        monitor = ProxyMonitor(db_path=db_path)
        await monitor.init_db()

        # Close db to cause exception
        await monitor.db.close()

        # Should not raise, just log error
        await monitor.record_block(
            timestamp=time.time(),
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            status_code=403,
        )

    @pytest.mark.asyncio
    async def it_parses_connect_with_port():
        """Test _parse_squid_log_line parses CONNECT with port number."""
        monitor = ProxyMonitor(db_path="/tmp/test.db")

        log_line = "1234567890.789 200 172.20.0.5 TCP_DENIED/403 0 CONNECT malicious.com:8443 - HIER_NONE/- -"

        result = await monitor._parse_squid_log_line(log_line)

        assert result is not None
        assert result["method"] == "CONNECT"
        assert result["url"] == "malicious.com:8443"
        assert result["status_code"] == 403
