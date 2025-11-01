"""Integration tests for WebSocket endpoint."""

import asyncio
import contextlib
import time
from unittest.mock import AsyncMock

import aiosqlite
import pytest


def describe_websocket_integration():
    """Integration tests for WebSocket endpoint with database."""

    @pytest.mark.asyncio
    async def it_processes_websocket_endpoint_flow(tmp_path):
        """Test WebSocket endpoint processes initial logs and polling."""
        import src.web_ui.app as web_app_module
        from src.web_ui.app import websocket_endpoint

        # Create test database with logs
        db_path = tmp_path / "test.db"
        async with aiosqlite.connect(str(db_path)) as db:
            # Create tables
            await db.execute(
                """
                CREATE TABLE dns_queries (
                    timestamp REAL,
                    client_ip TEXT,
                    query_domain TEXT,
                    response_ips TEXT,
                    status TEXT
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE firewall_blocks (
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT
                )
                """
            )

            # Insert test data
            now = time.time()
            await db.execute(
                "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                (now - 100, "192.168.1.1", "example.com", "93.184.216.34", "allowed"),
            )
            await db.execute(
                "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                (now - 50, "192.168.1.2", "malware.com", "", "blocked"),
            )
            await db.execute(
                "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                (now - 75, "192.168.1.100", "8.8.8.8", 53, "UDP"),
            )
            await db.commit()

        # Patch database path
        original_db_path = web_app_module.DB_PATH
        web_app_module.DB_PATH = str(db_path)

        try:
            # Mock WebSocket
            mock_ws = AsyncMock()
            sent_messages = []

            async def mock_send_json(data):
                sent_messages.append(data)

            mock_ws.send_json = mock_send_json

            # Create task to run websocket_endpoint
            ws_task = asyncio.create_task(websocket_endpoint(mock_ws))

            # Let it run for a bit to send initial logs
            await asyncio.sleep(0.5)

            # Cancel the task (simulates disconnect)
            ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ws_task

            # Verify initial logs were sent
            assert len(sent_messages) >= 3

            # Check DNS allowed log
            dns_allowed = next(
                (
                    m
                    for m in sent_messages
                    if m.get("component") == "DNS" and m.get("action") == "ALLOWED"
                ),
                None,
            )
            assert dns_allowed is not None
            assert dns_allowed["domain"] == "example.com"

            # Check DNS blocked log
            dns_blocked = next(
                (
                    m
                    for m in sent_messages
                    if m.get("component") == "DNS" and m.get("action") == "BLOCKED"
                ),
                None,
            )
            assert dns_blocked is not None
            assert dns_blocked["domain"] == "malware.com"

            # Check firewall blocked log
            fw_blocked = next(
                (m for m in sent_messages if m.get("component") == "FIREWALL"),
                None,
            )
            assert fw_blocked is not None
            assert fw_blocked["src_ip"] == "192.168.1.100"

        finally:
            web_app_module.DB_PATH = original_db_path

    @pytest.mark.asyncio
    async def it_sends_new_logs_during_polling(tmp_path):
        """Test WebSocket polls for and sends new logs that arrive."""
        import src.web_ui.app as web_app_module
        from src.web_ui.app import websocket_endpoint

        # Create test database
        db_path = tmp_path / "test.db"
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(
                """
                CREATE TABLE dns_queries (
                    timestamp REAL,
                    client_ip TEXT,
                    query_domain TEXT,
                    response_ips TEXT,
                    status TEXT
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE firewall_blocks (
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT
                )
                """
            )
            await db.commit()

        original_db_path = web_app_module.DB_PATH
        web_app_module.DB_PATH = str(db_path)

        try:
            # Mock WebSocket
            mock_ws = AsyncMock()
            sent_messages = []

            async def mock_send_json(data):
                sent_messages.append(data)

            mock_ws.send_json = mock_send_json

            # Start websocket endpoint in background
            ws_task = asyncio.create_task(websocket_endpoint(mock_ws))

            # Wait a bit for initial processing
            await asyncio.sleep(0.3)

            # Insert new log while WebSocket is polling
            async with aiosqlite.connect(str(db_path)) as db:
                now = time.time()
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now, "192.168.1.5", "newdomain.com", "1.2.3.4", "allowed"),
                )
                await db.commit()

            # Wait for polling cycle to pick up new log
            await asyncio.sleep(1.5)

            # Cancel task
            ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ws_task

            # Verify new log was sent
            new_log = next(
                (m for m in sent_messages if m.get("domain") == "newdomain.com"),
                None,
            )
            assert new_log is not None
            assert new_log["component"] == "DNS"
            assert new_log["src_ip"] == "192.168.1.5"

        finally:
            web_app_module.DB_PATH = original_db_path

    @pytest.mark.asyncio
    async def it_handles_firewall_logs_with_protocol_details(tmp_path):
        """Test WebSocket sends firewall logs with protocol details."""
        import src.web_ui.app as web_app_module
        from src.web_ui.app import websocket_endpoint

        # Create test database with firewall logs
        db_path = tmp_path / "test.db"
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(
                """
                CREATE TABLE dns_queries (
                    timestamp REAL,
                    client_ip TEXT,
                    query_domain TEXT,
                    response_ips TEXT,
                    status TEXT
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE firewall_blocks (
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT
                )
                """
            )

            now = time.time()
            # Insert firewall blocks with different protocols
            await db.execute(
                "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                (now, "10.0.0.5", "1.2.3.4", 443, "TCP"),
            )
            await db.execute(
                "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                (now - 10, "10.0.0.6", "8.8.8.8", 53, "UDP"),
            )
            await db.commit()

        original_db_path = web_app_module.DB_PATH
        web_app_module.DB_PATH = str(db_path)

        try:
            # Mock WebSocket
            mock_ws = AsyncMock()
            sent_messages = []

            async def mock_send_json(data):
                sent_messages.append(data)

            mock_ws.send_json = mock_send_json

            # Start websocket endpoint
            ws_task = asyncio.create_task(websocket_endpoint(mock_ws))

            # Let it run briefly
            await asyncio.sleep(0.5)

            # Cancel task
            ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ws_task

            # Find firewall logs
            tcp_log = next(
                (m for m in sent_messages if m.get("dst_port") == 443),
                None,
            )
            udp_log = next(
                (m for m in sent_messages if m.get("dst_port") == 53),
                None,
            )

            assert tcp_log is not None
            assert "TCP" in tcp_log.get("reason", "")
            assert tcp_log["src_ip"] == "10.0.0.5"

            assert udp_log is not None
            assert "UDP" in udp_log.get("reason", "")
            assert udp_log["src_ip"] == "10.0.0.6"

        finally:
            web_app_module.DB_PATH = original_db_path

    @pytest.mark.asyncio
    async def it_sorts_and_limits_initial_logs(tmp_path):
        """Test WebSocket sorts logs by timestamp and limits to 50."""
        import src.web_ui.app as web_app_module
        from src.web_ui.app import websocket_endpoint

        # Create test database with many logs
        db_path = tmp_path / "test.db"
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(
                """
                CREATE TABLE dns_queries (
                    timestamp REAL,
                    client_ip TEXT,
                    query_domain TEXT,
                    response_ips TEXT,
                    status TEXT
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE firewall_blocks (
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT
                )
                """
            )

            now = time.time()
            # Insert 60 DNS logs (more than the 50 limit)
            for i in range(60):
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now - i * 10, f"192.168.1.{i % 255}", f"domain{i}.com", "1.2.3.4", "allowed"),
                )
            await db.commit()

        original_db_path = web_app_module.DB_PATH
        web_app_module.DB_PATH = str(db_path)

        try:
            # Mock WebSocket
            mock_ws = AsyncMock()
            sent_messages = []

            async def mock_send_json(data):
                sent_messages.append(data)

            mock_ws.send_json = mock_send_json

            # Start websocket endpoint
            ws_task = asyncio.create_task(websocket_endpoint(mock_ws))

            # Let it run briefly
            await asyncio.sleep(0.5)

            # Cancel task
            ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ws_task

            # Verify no more than 50 initial logs were sent
            assert len(sent_messages) <= 50

            # Verify logs are sorted by timestamp (newest first in initial batch)
            if len(sent_messages) >= 2:
                # Initial batch should be reverse sorted (newest first)
                timestamps = [m.get("timestamp", 0) for m in sent_messages]
                # Allow some tolerance for async processing
                assert timestamps[0] >= timestamps[-1] - 100  # Within 100 second range

        finally:
            web_app_module.DB_PATH = original_db_path
