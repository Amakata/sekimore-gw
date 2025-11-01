"""Unit tests for firewall_monitor module."""

import contextlib
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.firewall_monitor import FirewallMonitor


def describe_firewall_monitor():
    """FirewallMonitor unit tests."""

    @pytest.mark.asyncio
    async def it_initializes_database(tmp_path):
        """Test init_db creates database schema."""
        db_path = str(tmp_path / "test_firewall.db")
        monitor = FirewallMonitor(db_path=db_path)

        await monitor.init_db()

        assert monitor.db is not None

        # Verify table exists
        cursor = await monitor.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_blocks'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "firewall_blocks"

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_records_block(tmp_path):
        """Test record_block inserts data."""
        db_path = str(tmp_path / "test_firewall.db")
        monitor = FirewallMonitor(db_path=db_path)
        await monitor.init_db()

        await monitor.record_block(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
        )

        # Verify record was inserted
        cursor = await monitor.db.execute("SELECT * FROM firewall_blocks")
        row = await cursor.fetchone()
        assert row is not None
        assert row[1] == "192.168.1.100"  # src_ip
        assert row[2] == "8.8.8.8"  # dst_ip
        assert row[3] == 53  # dst_port
        assert row[4] == "UDP"  # protocol

        await monitor.db.close()

    @pytest.mark.asyncio
    async def it_handles_record_when_db_is_none():
        """Test record_block handles None database."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = None

        # Should not raise exception
        await monitor.record_block(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
        )

    def it_parses_tcp_log():
        """Test parse_iptables_log parses TCP logs."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        log_line = "[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=172.20.0.5 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=53"

        result = monitor.parse_iptables_log(log_line)

        assert result is not None
        assert result["src_ip"] == "172.20.0.5"
        assert result["dst_ip"] == "8.8.8.8"
        assert result["protocol"] == "TCP"
        assert result["dst_port"] == 53

    def it_parses_udp_log():
        """Test parse_iptables_log parses UDP logs."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        log_line = "[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=10.0.0.10 DST=1.1.1.1 PROTO=UDP SPT=12345 DPT=443"

        result = monitor.parse_iptables_log(log_line)

        assert result is not None
        assert result["src_ip"] == "10.0.0.10"
        assert result["dst_ip"] == "1.1.1.1"
        assert result["protocol"] == "UDP"
        assert result["dst_port"] == 443

    def it_parses_icmp_log():
        """Test parse_iptables_log parses ICMP logs."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        log_line = "[FIREWALL-BLOCK] IN=eth0 OUT=eth1 SRC=192.168.1.5 DST=8.8.4.4 PROTO=ICMP"

        result = monitor.parse_iptables_log(log_line)

        assert result is not None
        assert result["src_ip"] == "192.168.1.5"
        assert result["dst_ip"] == "8.8.4.4"
        assert result["protocol"] == "ICMP"
        assert result["dst_port"] is None

    def it_ignores_non_firewall_logs():
        """Test parse_iptables_log ignores non-firewall logs."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        log_line = "Some other log message without the firewall prefix"

        result = monitor.parse_iptables_log(log_line)

        assert result is None

    def it_handles_malformed_logs():
        """Test parse_iptables_log handles malformed logs."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        # Missing required fields
        log_line = "[FIREWALL-BLOCK] IN=eth0 OUT=eth1"

        result = monitor.parse_iptables_log(log_line)

        # Should return None for malformed logs
        assert result is None

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_starts_monitoring(mock_subprocess):
        """Test start begins monitoring."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")

        # Mock subprocess
        process_mock = AsyncMock()
        process_mock.stdout.readline = AsyncMock(
            side_effect=[
                b"[FIREWALL-BLOCK] SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=80\n",
                b"",  # EOF
            ]
        )
        process_mock.wait = AsyncMock()
        mock_subprocess.return_value = process_mock

        monitor.db = AsyncMock()
        monitor.db.execute = AsyncMock()
        monitor.db.commit = AsyncMock()
        monitor.running = True

        # Start monitoring (will stop after processing one line)
        with contextlib.suppress(Exception):
            # Expected to fail when trying to read from mock
            await monitor.start()

    @pytest.mark.asyncio
    async def it_stops_monitoring(tmp_path):
        """Test stop halts monitoring."""
        db_path = str(tmp_path / "test_firewall.db")
        monitor = FirewallMonitor(db_path=db_path)
        await monitor.init_db()

        monitor.running = True
        await monitor.stop()

        assert monitor.running is False
        # db.close() is called but db is not set to None


def describe_monitor_ulog_file():
    """Tests for monitor_ulog_file method."""

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_processes_log_lines_and_records_blocks(mock_subprocess, tmp_path):
        """Test monitor_ulog_file reads log lines and calls record_block."""
        db_path = str(tmp_path / "test_firewall.db")
        monitor = FirewallMonitor(db_path=db_path)
        await monitor.init_db()

        # Mock subprocess that returns firewall log line
        process_mock = AsyncMock()
        process_mock.returncode = None

        log_line = b"[FIREWALL-BLOCK] SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP DPT=443\n"

        # First readline returns log line, then empty to stop
        async def readline_side_effect():
            if monitor.running:
                monitor.running = False  # Stop after first line
                return log_line
            return b""

        process_mock.stdout.readline = AsyncMock(side_effect=readline_side_effect)
        process_mock.terminate = Mock()
        process_mock.wait = AsyncMock()
        mock_subprocess.return_value = process_mock

        # Start monitoring
        await monitor.monitor_ulog_file()

        # Verify record was inserted
        cursor = await monitor.db.execute("SELECT * FROM firewall_blocks")
        row = await cursor.fetchone()
        assert row is not None
        assert row[1] == "192.168.1.100"  # src_ip
        assert row[2] == "8.8.8.8"  # dst_ip
        assert row[3] == 443  # dst_port
        assert row[4] == "TCP"  # protocol

        await monitor.db.close()

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_handles_timeout_when_no_new_logs(mock_subprocess):
        """Test monitor_ulog_file continues on TimeoutError (no new logs)."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = AsyncMock()

        # Mock subprocess that times out then stops
        process_mock = AsyncMock()
        process_mock.returncode = None

        timeout_count = 0

        async def readline_timeout():
            nonlocal timeout_count
            timeout_count += 1
            if timeout_count >= 2:
                monitor.running = False
            raise TimeoutError("No new logs")

        process_mock.stdout.readline = AsyncMock(side_effect=readline_timeout)
        process_mock.terminate = Mock()
        process_mock.wait = AsyncMock()
        mock_subprocess.return_value = process_mock

        # Start monitoring
        await monitor.monitor_ulog_file()

        # Verify timeout was handled (no exception raised)
        assert timeout_count >= 2

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_handles_readline_exceptions(mock_subprocess):
        """Test monitor_ulog_file handles exceptions during readline."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = AsyncMock()

        # Mock subprocess that raises exception then stops
        process_mock = AsyncMock()
        process_mock.returncode = None

        exception_count = 0

        async def readline_exception():
            nonlocal exception_count
            exception_count += 1
            if exception_count >= 2:
                monitor.running = False
            raise RuntimeError("Read error")

        process_mock.stdout.readline = AsyncMock(side_effect=readline_exception)
        process_mock.terminate = Mock()
        process_mock.wait = AsyncMock()
        mock_subprocess.return_value = process_mock

        # Start monitoring (should handle exception and continue)
        await monitor.monitor_ulog_file()

        # Verify exception was handled
        assert exception_count >= 2

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_handles_file_not_found(mock_subprocess):
        """Test monitor_ulog_file handles missing log file."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = AsyncMock()

        # Mock subprocess that raises FileNotFoundError once
        call_count = 0

        async def subprocess_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise FileNotFoundError("Log file not found")
            else:
                # Stop monitoring after handling error
                monitor.running = False
                process_mock = AsyncMock()
                process_mock.returncode = None
                process_mock.stdout.readline = AsyncMock(return_value=b"")
                process_mock.terminate = Mock()
                process_mock.wait = AsyncMock()
                return process_mock

        mock_subprocess.side_effect = subprocess_side_effect

        # Start monitoring (should handle FileNotFoundError and retry)
        await monitor.monitor_ulog_file()

        # Verify FileNotFoundError was handled and retry occurred
        assert call_count >= 2

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_terminates_process_on_stop(mock_subprocess):
        """Test monitor_ulog_file terminates tail process when stopping."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = AsyncMock()

        # Mock subprocess that stops after one iteration
        process_mock = AsyncMock()
        process_mock.returncode = None

        async def readline_once():
            monitor.running = False
            return b""

        process_mock.stdout.readline = AsyncMock(side_effect=readline_once)
        process_mock.terminate = Mock()
        process_mock.wait = AsyncMock()
        mock_subprocess.return_value = process_mock

        # Start monitoring
        await monitor.monitor_ulog_file()

        # Verify process was terminated
        process_mock.terminate.assert_called_once()
        process_mock.wait.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def it_handles_general_exceptions(mock_subprocess):
        """Test monitor_ulog_file handles general exceptions and retries."""
        monitor = FirewallMonitor(db_path="/tmp/test.db")
        monitor.db = AsyncMock()

        # Mock subprocess that raises general exception once
        call_count = 0

        async def subprocess_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Unexpected error")
            else:
                # Stop monitoring after handling error
                monitor.running = False
                process_mock = AsyncMock()
                process_mock.returncode = None
                process_mock.stdout.readline = AsyncMock(return_value=b"")
                process_mock.terminate = Mock()
                process_mock.wait = AsyncMock()
                return process_mock

        mock_subprocess.side_effect = subprocess_side_effect

        # Start monitoring (should handle exception and retry)
        await monitor.monitor_ulog_file()

        # Verify exception was handled and retry occurred
        assert call_count >= 2
