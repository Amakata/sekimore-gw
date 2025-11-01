"""Functional tests for Web UI API flow.

These tests verify the complete Web UI API functionality including
stats retrieval, log queries, and domain management.
"""

import time

import aiosqlite
from fastapi.testclient import TestClient

import src.constants


def describe_web_ui_api_functional_flow():
    """Functional tests for Web UI API endpoints."""

    def it_retrieves_stats_from_multiple_sources(tmp_path):
        """Test retrieving statistics from DNS, firewall, and proxy sources."""
        import asyncio

        import src.web_ui.app as web_app_module
        from src.web_ui.app import app

        db_path = tmp_path / "test.db"

        # Create database with comprehensive test data
        async def setup_db():
            async with aiosqlite.connect(str(db_path)) as db:
                # Create all tables
                await db.execute("""
                    CREATE TABLE dns_queries (
                        timestamp REAL,
                        client_ip TEXT,
                        query_domain TEXT,
                        response_ips TEXT,
                        status TEXT
                    )
                """)
                await db.execute("""
                    CREATE TABLE firewall_blocks (
                        timestamp REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        protocol TEXT
                    )
                """)
                await db.execute("""
                    CREATE TABLE proxy_blocks (
                        timestamp REAL,
                        client_ip TEXT,
                        method TEXT,
                        url TEXT,
                        status_code INTEGER
                    )
                """)

                now = time.time()
                # Insert DNS queries
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now, "192.168.1.1", "allowed.com", "1.2.3.4", "allowed"),
                )
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now - 100, "192.168.1.2", "blocked.com", "", "blocked"),
                )

                # Insert firewall blocks
                await db.execute(
                    "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                    (now, "10.0.0.5", "8.8.8.8", 53, "UDP"),
                )

                # Insert proxy blocks
                await db.execute(
                    "INSERT INTO proxy_blocks VALUES (?, ?, ?, ?, ?)",
                    (now, "10.0.0.6", "CONNECT", "blocked.com:443", 403),
                )

                await db.commit()

        asyncio.run(setup_db())

        # Patch DB_PATH
        import src.constants

        original_db_path = src.constants.DB_PATH
        original_web_db_path = web_app_module.DB_PATH
        src.constants.DB_PATH = str(db_path)
        web_app_module.DB_PATH = str(db_path)

        try:
            client = TestClient(app)
            response = client.get("/api/stats")

            assert response.status_code == 200
            data = response.json()

            # Verify stats from all sources
            assert data["total"] == 2  # DNS queries
            assert data["allowed"] == 1
            assert data["blocked"] == 1
            assert data["firewall_blocked"] == 1
            assert data["proxy_blocked"] == 1
            assert data["unique_domains"] == 2

        finally:
            src.constants.DB_PATH = original_db_path
            web_app_module.DB_PATH = original_web_db_path

    def it_retrieves_logs_with_time_filtering(tmp_path):
        """Test retrieving logs with time-based filtering."""
        import asyncio

        import src.web_ui.app as web_app_module
        from src.web_ui.app import app

        db_path = tmp_path / "test.db"

        async def setup_db():
            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute("""
                    CREATE TABLE dns_queries (
                        timestamp REAL,
                        client_ip TEXT,
                        query_domain TEXT,
                        response_ips TEXT,
                        status TEXT
                    )
                """)

                now = time.time()
                # Insert logs at different times
                for i in range(10):
                    await db.execute(
                        "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                        (now - i * 100, f"192.168.1.{i}", f"site{i}.com", "1.2.3.4", "allowed"),
                    )
                await db.commit()

        asyncio.run(setup_db())

        import src.constants

        original_db_path = src.constants.DB_PATH
        original_web_db_path = web_app_module.DB_PATH
        src.constants.DB_PATH = str(db_path)
        web_app_module.DB_PATH = str(db_path)

        try:
            client = TestClient(app)

            # Get limited logs
            response = client.get("/api/logs?limit=5")
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 5

            # Get more logs
            response = client.get("/api/logs?limit=10")
            data = response.json()
            assert len(data) == 10

        finally:
            src.constants.DB_PATH = original_db_path
            web_app_module.DB_PATH = original_web_db_path

    def it_retrieves_unique_domains_with_statistics(tmp_path):
        """Test retrieving unique domains with access statistics."""
        import asyncio

        import src.web_ui.app as web_app_module
        from src.web_ui.app import app

        db_path = tmp_path / "test.db"
        config_path = tmp_path / "config.yml"
        config_path.write_text("allow_domains:\n  - example.com\nblock_domains:\n  - malware.com\n")

        async def setup_db():
            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute("""
                    CREATE TABLE dns_queries (
                        timestamp REAL,
                        client_ip TEXT,
                        query_domain TEXT,
                        response_ips TEXT,
                        status TEXT
                    )
                """)

                now = time.time()
                # Insert queries for multiple domains
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now, "192.168.1.1", "example.com", "93.184.216.34", "allowed"),
                )
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now - 50, "192.168.1.1", "example.com", "93.184.216.34", "allowed"),
                )
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now - 100, "192.168.1.2", "malware.com", "", "blocked"),
                )
                await db.commit()

        asyncio.run(setup_db())

        original_db_path = web_app_module.DB_PATH
        original_config_path = web_app_module.CONFIG_PATH
        web_app_module.DB_PATH = str(db_path)
        web_app_module.CONFIG_PATH = config_path

        try:
            client = TestClient(app)
            response = client.get("/api/domains/unique")

            assert response.status_code == 200
            data = response.json()

            # Verify domain statistics
            assert len(data) == 2

            # Find example.com entry
            example = next((d for d in data if d["domain"] == "example.com"), None)
            assert example is not None
            assert example["query_count"] == 2
            assert example["allowed_count"] == 2
            assert example["blocked_count"] == 0
            assert example["status"] == "allowed"

            # Find malware.com entry
            malware = next((d for d in data if d["domain"] == "malware.com"), None)
            assert malware is not None
            assert malware["query_count"] == 1
            assert malware["blocked_count"] == 1
            assert malware["status"] == "blocked"

        finally:
            src.constants.DB_PATH = original_db_path
            src.constants.CONFIG_PATH = original_config_path

    def it_retrieves_firewall_block_events(tmp_path):
        """Test retrieving firewall block events."""
        import asyncio

        import src.web_ui.app as web_app_module
        from src.web_ui.app import app

        db_path = tmp_path / "test.db"

        async def setup_db():
            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute("""
                    CREATE TABLE firewall_blocks (
                        timestamp REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        protocol TEXT
                    )
                """)

                now = time.time()
                # Insert firewall block events
                await db.execute(
                    "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                    (now, "10.0.0.5", "8.8.8.8", 53, "UDP"),
                )
                await db.execute(
                    "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                    (now - 50, "10.0.0.6", "1.1.1.1", 443, "TCP"),
                )
                await db.commit()

        asyncio.run(setup_db())

        import src.constants

        original_db_path = src.constants.DB_PATH
        original_web_db_path = web_app_module.DB_PATH
        src.constants.DB_PATH = str(db_path)
        web_app_module.DB_PATH = str(db_path)

        try:
            client = TestClient(app)
            response = client.get("/api/firewall-blocks?limit=10")

            assert response.status_code == 200
            data = response.json()
            assert len(data) == 2

            # Verify event details
            assert any(e["src_ip"] == "10.0.0.5" and e["dst_port"] == 53 for e in data)
            assert any(e["src_ip"] == "10.0.0.6" and e["dst_port"] == 443 for e in data)

        finally:
            src.constants.DB_PATH = original_db_path
            web_app_module.DB_PATH = original_web_db_path

    def it_retrieves_blocked_ip_statistics(tmp_path):
        """Test retrieving blocked IP address statistics."""
        import asyncio

        import src.web_ui.app as web_app_module
        from src.web_ui.app import app

        db_path = tmp_path / "test.db"

        async def setup_db():
            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute("""
                    CREATE TABLE firewall_blocks (
                        timestamp REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        protocol TEXT
                    )
                """)

                now = time.time()
                # Insert multiple blocks for same IP with different ports/protocols
                for i in range(3):
                    await db.execute(
                        "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                        (
                            now - i * 10,
                            "10.0.0.100",
                            "8.8.8.8",
                            53 + i,
                            "UDP" if i % 2 == 0 else "TCP",
                        ),
                    )
                await db.commit()

        asyncio.run(setup_db())

        import src.constants

        original_db_path = src.constants.DB_PATH
        original_web_db_path = web_app_module.DB_PATH
        src.constants.DB_PATH = str(db_path)
        web_app_module.DB_PATH = str(db_path)

        try:
            client = TestClient(app)
            response = client.get("/api/blocked-ips?limit=10")

            assert response.status_code == 200
            data = response.json()

            # Verify IP statistics
            assert len(data) > 0
            blocked_ip = next((ip for ip in data if ip["ip_address"] == "8.8.8.8"), None)
            assert blocked_ip is not None
            assert blocked_ip["block_count"] == 3
            assert len(blocked_ip["ports"]) == 3  # 3 different ports
            assert len(blocked_ip["protocols"]) == 2  # UDP and TCP

        finally:
            src.constants.DB_PATH = original_db_path
            web_app_module.DB_PATH = original_web_db_path

    def it_serves_homepage_html(tmp_path):
        """Test serving HTML homepage."""
        from src.web_ui.app import app

        client = TestClient(app)
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # Verify it contains dashboard elements
        assert len(response.text) > 100  # Non-empty HTML

    def it_retrieves_allowed_domains_list(tmp_path):
        """Test retrieving configured allowed domains."""
        from unittest.mock import mock_open, patch

        from src.web_ui.app import app

        config_yaml = "allow_domains:\n  - example.com\n  - test.org\nblock_domains: []"

        with (
            patch("src.web_ui.app.CONFIG_PATH", "/tmp/config.yml"),
            patch("builtins.open", mock_open(read_data=config_yaml)),
        ):
            client = TestClient(app)
            response = client.get("/api/domains/allowed")

            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert "example.com" in data
            assert "test.org" in data

    def it_retrieves_blocked_domains_list(tmp_path):
        """Test retrieving configured blocked domains."""
        from unittest.mock import mock_open, patch

        from src.web_ui.app import app

        config_yaml = "allow_domains: []\nblock_domains:\n  - malware.com\n  - phishing.com"

        with (
            patch("src.web_ui.app.CONFIG_PATH", "/tmp/config.yml"),
            patch("builtins.open", mock_open(read_data=config_yaml)),
        ):
            client = TestClient(app)
            response = client.get("/api/domains/blocked")

            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert "malware.com" in data
            assert "phishing.com" in data
