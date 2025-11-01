"""Unit tests for dns_server module."""

import asyncio
import contextlib
import socket
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.dns_server import DNSCache, DNSCacheEntry


def describe_dns_cache():
    """DNSCache unit tests."""

    def it_initializes_empty_cache():
        """Test DNSCache initializes with empty cache."""
        cache = DNSCache()
        assert cache._cache == {}
        assert cache._cache_hits == 0
        assert cache._cache_misses == 0

    def it_stores_and_retrieves_entry():
        """Test storing and retrieving cache entry."""
        cache = DNSCache()
        domain = "example.com"
        ips = ["93.184.216.34"]
        ttl = 300

        cache.put(domain, ips, ttl, "A")
        result = cache.get(domain, "A")

        assert result == ips
        assert cache._cache_hits == 1
        assert cache._cache_misses == 0

    def it_returns_none_on_cache_miss():
        """Test cache returns None on miss."""
        cache = DNSCache()
        result = cache.get("nonexistent.com", "A")

        assert result is None
        assert cache._cache_hits == 0
        assert cache._cache_misses == 1

    def it_expires_old_entries():
        """Test cache expires old entries."""
        cache = DNSCache()
        domain = "example.com"
        ips = ["93.184.216.34"]
        ttl = 1  # 1 second

        cache.put(domain, ips, ttl, "A")

        # First retrieval should succeed
        result = cache.get(domain, "A")
        assert result == ips

        # Wait for expiry
        time.sleep(1.1)

        # Second retrieval should fail
        result = cache.get(domain, "A")
        assert result is None
        assert cache._cache_misses == 1

    def it_handles_multiple_query_types():
        """Test cache handles A and AAAA separately."""
        cache = DNSCache()
        domain = "example.com"
        ipv4 = ["93.184.216.34"]
        ipv6 = ["2606:2800:220:1:248:1893:25c8:1946"]

        cache.put(domain, ipv4, 300, "A")
        cache.put(domain, ipv6, 300, "AAAA")

        result_a = cache.get(domain, "A")
        result_aaaa = cache.get(domain, "AAAA")

        assert result_a == ipv4
        assert result_aaaa == ipv6

    def it_clears_expired_entries():
        """Test clearing expired entries."""
        cache = DNSCache()
        cache.put("example1.com", ["1.2.3.4"], 1, "A")
        cache.put("example2.com", ["5.6.7.8"], 100, "A")

        time.sleep(1.1)

        expired = cache.get_expired_entries()
        assert len(expired) >= 1
        assert any(e.domain == "example1.com" for e in expired)

    def it_tracks_statistics():
        """Test cache tracks hit/miss statistics."""
        cache = DNSCache()
        cache.put("example.com", ["1.2.3.4"], 300, "A")

        # Generate hits and misses
        cache.get("example.com", "A")  # hit
        cache.get("example.com", "A")  # hit
        cache.get("nonexistent.com", "A")  # miss
        cache.get("another.com", "A")  # miss

        stats = cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 2
        assert stats["hit_rate"] == 50.0  # 2/4 * 100 = 50%
        assert stats["size"] == 1  # Only "example.com" is cached

    def it_gets_expiring_soon_entries():
        """Test getting entries expiring soon."""
        cache = DNSCache()
        cache.put("example1.com", ["1.2.3.4"], 30, "A")  # Expires in 30s
        cache.put("example2.com", ["5.6.7.8"], 300, "A")  # Expires in 300s

        expiring = cache.get_expiring_soon_entries(threshold_seconds=60)
        assert len(expiring) == 1
        assert expiring[0].domain == "example1.com"

    def it_clears_cache():
        """Test clearing cache."""
        cache = DNSCache()
        cache.put("example1.com", ["1.2.3.4"], 300, "A")
        cache.put("example2.com", ["5.6.7.8"], 300, "A")

        assert len(cache._cache) == 2

        cache.clear()

        assert len(cache._cache) == 0

    def it_gets_cache_size():
        """Test getting cache size."""
        cache = DNSCache()
        cache.put("example1.com", ["1.2.3.4"], 300, "A")
        cache.put("example2.com", ["5.6.7.8"], 300, "A")

        stats = cache.get_stats()
        assert stats["size"] == 2


def describe_dns_cache_entry():
    """DNSCacheEntry unit tests."""

    def it_creates_entry_with_valid_data():
        """Test creating DNSCacheEntry with valid data."""
        entry = DNSCacheEntry(
            domain="example.com",
            ips=["93.184.216.34"],
            ttl=300,
            expiry=time.time() + 300,
            query_type="A",
        )

        assert entry.domain == "example.com"
        assert entry.ips == ["93.184.216.34"]
        assert entry.ttl == 300
        assert entry.query_type == "A"

    def it_supports_multiple_ips():
        """Test entry with multiple IPs."""
        entry = DNSCacheEntry(
            domain="example.com",
            ips=["93.184.216.34", "93.184.216.35"],
            ttl=300,
            expiry=time.time() + 300,
            query_type="A",
        )

        assert len(entry.ips) == 2


def describe_dns_mapping():
    """DNSMapping unit tests."""

    @pytest.mark.asyncio
    async def it_initializes_with_db_path():
        """Test DNSMapping initialization."""
        from src.dns_server import DNSMapping

        db = DNSMapping(db_path="/tmp/test.db")
        assert db.db_path == "/tmp/test.db"
        assert db.db is None

    @pytest.mark.asyncio
    async def it_initializes_database():
        """Test database initialization creates tables."""
        import tempfile

        from src.dns_server import DNSMapping

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        db = DNSMapping(db_path=db_path)
        await db.init_db()

        assert db.db is not None
        # Verify tables exist
        cursor = await db.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='dns_queries'"
        )
        result = await cursor.fetchone()
        assert result is not None

        await db.db.close()

    @pytest.mark.asyncio
    async def it_records_dns_query():
        """Test recording DNS query."""
        import tempfile

        from src.dns_server import DNSMapping

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        db = DNSMapping(db_path=db_path)
        await db.init_db()

        await db.record_query(
            client_ip="192.168.1.100",
            domain="example.com",
            ips=["93.184.216.34"],
            ttl=300,
            query_type="A",
            status="allowed",
        )

        # Verify record was inserted
        cursor = await db.db.execute("SELECT COUNT(*) FROM dns_queries")
        count = await cursor.fetchone()
        assert count[0] == 1

        await db.db.close()

    @pytest.mark.asyncio
    async def it_looks_up_domain_by_ip():
        """Test looking up domain by IP."""
        import tempfile

        from src.dns_server import DNSMapping

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        db = DNSMapping(db_path=db_path)
        await db.init_db()

        # Record a query
        await db.record_query(
            client_ip="192.168.1.100",
            domain="example.com",
            ips=["93.184.216.34"],
            ttl=300,
        )

        # Lookup by IP
        results = await db.lookup_ip("93.184.216.34")

        assert len(results) > 0
        assert results[0]["domain"] == "example.com"

        await db.db.close()


def describe_dns_server():
    """DNSServer unit tests."""

    @patch("subprocess.run")
    def it_detects_dns_bind_ip_from_interfaces(mock_run):
        """Test _detect_dns_bind_ip detects correct IP.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        Added required attributes for the test.
        """
        from src.dns_server import DNSServer

        # Mock ip addr show output
        mock_run.return_value = Mock(stdout="inet 172.20.0.2/24 brd 172.20.0.255 scope global eth0")

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.lan_ip = "172.20.0.2"
        dns_server.lan_subnets = ["172.20.0.0/24"]  # Required attribute

        ip = dns_server._detect_dns_bind_ip()

        assert ip == "172.20.0.2"

    def it_checks_allowed_domain_explicitly():
        """Test _is_allowed returns True for explicitly allowed domain.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com", "*.test.org"]
        dns_server.blocked_domains = []

        assert dns_server._is_allowed("example.com") is True
        assert dns_server._is_allowed("sub.example.com") is False

    def it_checks_allowed_domain_with_wildcard():
        """Test _is_allowed handles wildcard patterns.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        Changed wildcard format from *.example.com to .example.com
        to match implementation (dns_server.py:390).
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = [".example.com"]
        dns_server.blocked_domains = []

        assert dns_server._is_allowed("sub.example.com") is True
        assert dns_server._is_allowed("example.com") is True

    def it_checks_blocked_domain_explicitly():
        """Test _is_blocked returns True for explicitly blocked domain.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = ["malware.com", "*.phishing.org"]

        assert dns_server._is_blocked("malware.com") is True
        assert dns_server._is_blocked("sub.malware.com") is False

    def it_checks_blocked_domain_with_wildcard():
        """Test _is_blocked handles wildcard patterns.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        Changed wildcard format from *.ads.com to .ads.com
        to match implementation (dns_server.py:421).
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = [".ads.com"]

        assert dns_server._is_blocked("tracker.ads.com") is True
        assert dns_server._is_blocked("ads.com") is True

    def it_gets_cache_stats_when_cache_exists():
        """Test get_cache_stats returns stats when cache enabled.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        Added cache_enabled attribute required by get_cache_stats().
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = True  # Required attribute
        mock_cache = Mock()
        mock_cache.get_stats = Mock(
            return_value={
                "size": 1000,
                "hits": 800,
                "misses": 200,
                "hit_rate": 80.0,
            }
        )
        dns_server.cache = mock_cache

        stats = dns_server.get_cache_stats()

        assert stats is not None
        assert stats["size"] == 1000
        assert stats["hit_rate"] == 80.0

    def it_gets_cache_stats_when_cache_disabled():
        """Test get_cache_stats returns None when cache disabled.

        FIXED: Removed unnecessary __init__ mock and skip marker.
        Added cache_enabled attribute required by get_cache_stats().
        """
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = False  # Required attribute
        dns_server.cache = None

        stats = dns_server.get_cache_stats()

        assert stats is None


def describe_dns_server_domain_checking():
    """DNSServer domain checking methods."""

    def it_allows_exact_match_domain():
        """Test _is_allowed with exact match."""
        from src.dns_server import DNSServer

        # Create DNSServer with minimal mocking
        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com", "test.org"]
        dns_server.blocked_domains = []

        assert dns_server._is_allowed("example.com") is True
        assert dns_server._is_allowed("test.org") is True
        assert dns_server._is_allowed("other.com") is False

    def it_allows_wildcard_domain():
        """Test _is_allowed with wildcard match."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = [".example.com", "test.org"]
        dns_server.blocked_domains = []

        assert dns_server._is_allowed("sub.example.com") is True
        assert dns_server._is_allowed("example.com") is True
        assert dns_server._is_allowed("another.sub.example.com") is True
        assert dns_server._is_allowed("other.com") is False

    def it_blocks_exact_match_domain():
        """Test _is_blocked with exact match."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = ["malicious.com", "bad.org"]

        assert dns_server._is_blocked("malicious.com") is True
        assert dns_server._is_blocked("bad.org") is True
        assert dns_server._is_blocked("safe.com") is False

    def it_blocks_wildcard_domain():
        """Test _is_blocked with wildcard match."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = [".malicious.com"]

        assert dns_server._is_blocked("sub.malicious.com") is True
        assert dns_server._is_blocked("malicious.com") is True
        assert dns_server._is_blocked("another.sub.malicious.com") is True
        assert dns_server._is_blocked("safe.com") is False

    def it_handles_case_insensitive_domains():
        """Test domain checking is case insensitive."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        # Config lists should be lowercase (as loaded from YAML)
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = ["blocked.com"]

        # Domain queries with different cases should match
        assert dns_server._is_allowed("example.com") is True
        assert dns_server._is_allowed("EXAMPLE.COM") is True
        assert dns_server._is_allowed("Example.COM") is True
        assert dns_server._is_blocked("blocked.com") is True
        assert dns_server._is_blocked("BLOCKED.COM") is True
        assert dns_server._is_blocked("Blocked.Com") is True

    def it_strips_trailing_dots():
        """Test domain checking strips trailing dots."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = ["blocked.com"]

        assert dns_server._is_allowed("example.com.") is True
        assert dns_server._is_blocked("blocked.com.") is True


def describe_dns_server_resolution():
    """DNSServer DNS resolution tests."""

    @pytest.mark.asyncio
    async def it_resolves_domain_from_cache():
        """Test _resolve_domain returns cached result."""
        from src.dns_server import DNSCache, DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = True
        dns_server.cache = DNSCache()

        # Pre-populate cache
        dns_server.cache.put("example.com", ["93.184.216.34"], 300, "A")

        result = await dns_server._resolve_domain("example.com", "A")

        assert result is not None
        assert result[0] == ["93.184.216.34"]
        assert result[1] == 300  # TTL

    @pytest.mark.asyncio
    async def it_resolves_domain_from_upstream():
        """Test _resolve_domain queries upstream DNS."""
        import dns.resolver

        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.upstream_dns = "8.8.8.8"
        dns_server.resolver = dns.resolver.Resolver()
        dns_server.resolver.nameservers = ["8.8.8.8"]

        # Mock dns.resolver.resolve
        mock_answer = Mock()
        mock_answer.rrset = Mock()
        mock_answer.rrset.ttl = 300
        mock_answer.__iter__ = Mock(return_value=iter([Mock(__str__=lambda self: "93.184.216.34")]))

        with patch.object(dns_server.resolver, "resolve", return_value=mock_answer):
            result = await dns_server._resolve_domain("example.com", "A")

        assert result is not None
        assert result[0] == ["93.184.216.34"]
        assert result[1] == 300

    @pytest.mark.asyncio
    async def it_returns_none_on_resolution_failure():
        """Test _resolve_domain returns None on DNS error."""
        import dns.resolver

        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.upstream_dns = "8.8.8.8"
        dns_server.resolver = dns.resolver.Resolver()

        with patch.object(dns_server.resolver, "resolve", side_effect=Exception("DNS error")):
            result = await dns_server._resolve_domain("nonexistent.invalid", "A")

        assert result is None


def describe_dns_server_query_handling():
    """DNSServer query handling tests."""

    @pytest.mark.asyncio
    async def it_blocks_query_on_blocklist():
        """Test handle_query blocks queries on blocklist."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        # Create DNS query packet
        query = DNSRecord.question("malicious.com", "A")
        query_data = query.pack()

        # Setup DNS server
        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = ["malicious.com"]
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()

        response_data = await dns_server.handle_query(query_data, ("192.168.1.100", 53))

        # Parse response
        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 3  # NXDOMAIN

        await dns_server.mapping.db.close()

    @pytest.mark.asyncio
    async def it_blocks_query_not_in_allowlist():
        """Test handle_query blocks queries not in allowlist."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("notallowed.com", "A")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.gateway_hostname = None
        dns_server.gateway_ip = None

        response_data = await dns_server.handle_query(query_data, ("192.168.1.100", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 3  # NXDOMAIN

        await dns_server.mapping.db.close()

    @pytest.mark.asyncio
    async def it_allows_query_on_allowlist():
        """Test handle_query allows queries on allowlist."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("example.com", "A")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.firewall_manager = Mock()
        dns_server.firewall_manager.setup_domain = Mock()
        dns_server.gateway_hostname = None  # sekimore-gw自身の名前解決用
        dns_server.gateway_ip = None

        # Mock _resolve_domain to return IPs
        dns_server._resolve_domain = AsyncMock(return_value=(["93.184.216.34"], 300))

        response_data = await dns_server.handle_query(query_data, ("192.168.1.100", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 0  # NOERROR
        assert len(response.rr) == 1  # One answer record
        assert str(response.rr[0].rdata) == "93.184.216.34"

        await dns_server.mapping.db.close()

    @pytest.mark.asyncio
    async def it_handles_aaaa_queries():
        """Test handle_query handles AAAA (IPv6) queries."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("example.com", "AAAA")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.cache_enabled = False
        dns_server.firewall_manager = Mock()
        dns_server.firewall_manager.setup_domain = Mock()
        dns_server.gateway_hostname = None  # sekimore-gw自身の名前解決用
        dns_server.gateway_ip = None

        # Mock _resolve_domain for IPv6
        dns_server._resolve_domain = AsyncMock(
            return_value=(["2606:2800:220:1:248:1893:25c8:1946"], 300)
        )

        response_data = await dns_server.handle_query(query_data, ("192.168.1.100", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 0
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "2606:2800:220:1:248:1893:25c8:1946"

        await dns_server.mapping.db.close()


def describe_gateway_hostname_resolution():
    """Tests for gateway hostname resolution (bypassing allowlist)."""

    @pytest.mark.asyncio
    async def it_resolves_gateway_hostname_even_if_not_in_allowlist():
        """Test gateway hostname resolution bypasses allowlist check."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("sekimore-gw", "A")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]  # sekimore-gw is NOT in allowlist
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.firewall_manager = Mock()
        dns_server.gateway_hostname = "sekimore-gw"
        dns_server.gateway_ip = "172.22.0.2"  # internal-net IP

        response_data = await dns_server.handle_query(query_data, ("172.22.0.3", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 0  # NOERROR (not NXDOMAIN)
        assert len(response.rr) == 1
        assert str(response.rr[0].rdata) == "172.22.0.2"  # Returns internal-net IP

        await dns_server.mapping.db.close()

    @pytest.mark.asyncio
    async def it_returns_empty_for_gateway_hostname_aaaa_query():
        """Test gateway hostname AAAA query returns empty response."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("sekimore-gw", "AAAA")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = []
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.firewall_manager = Mock()
        dns_server.gateway_hostname = "sekimore-gw"
        dns_server.gateway_ip = "172.22.0.2"

        response_data = await dns_server.handle_query(query_data, ("172.22.0.3", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 0  # NOERROR
        assert len(response.rr) == 0  # No IPv6 address

        await dns_server.mapping.db.close()

    @pytest.mark.asyncio
    async def it_uses_allowlist_for_non_gateway_domains():
        """Test non-gateway domains still respect allowlist."""
        import tempfile

        from dnslib import DNSRecord

        from src.dns_server import DNSMapping, DNSServer

        query = DNSRecord.question("blocked.com", "A")
        query_data = query.pack()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            db_path = f.name

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.allowed_domains = ["example.com"]  # blocked.com is NOT in allowlist
        dns_server.blocked_domains = []
        dns_server.mapping = DNSMapping(db_path=db_path)
        await dns_server.mapping.init_db()
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.firewall_manager = Mock()
        dns_server.gateway_hostname = "sekimore-gw"
        dns_server.gateway_ip = "172.22.0.2"

        response_data = await dns_server.handle_query(query_data, ("172.22.0.3", 53))

        response = DNSRecord.parse(response_data)
        assert response.header.rcode == 3  # NXDOMAIN (blocked)

        await dns_server.mapping.db.close()


def describe_cache_refresh_worker():
    """Tests for cache refresh worker."""

    @pytest.mark.asyncio
    async def it_returns_early_when_cache_disabled():
        """Test _cache_refresh_worker returns early when cache is disabled."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = False
        dns_server.cache = None
        dns_server.running = True

        # Should return immediately without error
        await dns_server._cache_refresh_worker()

        # If we reach here, test passed (no infinite loop)
        assert True

    @pytest.mark.asyncio
    async def it_refreshes_expiring_cache_entries():
        """Test _cache_refresh_worker refreshes expiring cache entries."""
        import time

        from src.dns_server import DNSCache, DNSCacheEntry, DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = True
        dns_server.cache = DNSCache()
        dns_server.running = True
        dns_server.cache_refresh_interval = 0.1  # 100ms for testing
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.firewall_manager = None

        # Add expiring entry
        entry = DNSCacheEntry(
            domain="example.com", query_type="A", ips=["1.2.3.4"], ttl=1, expiry=time.time() + 1
        )
        dns_server.cache._cache["example.com:A"] = entry

        # Mock _resolve_domain to return new IPs
        dns_server._resolve_domain = AsyncMock(return_value=(["5.6.7.8"], 300))

        # Mock _save_cache_stats_to_db
        dns_server._save_cache_stats_to_db = AsyncMock()

        # Run worker for one iteration
        task = asyncio.create_task(dns_server._cache_refresh_worker())

        # Wait for first refresh cycle
        await asyncio.sleep(0.3)

        # Stop worker
        dns_server.running = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        # Verify _save_cache_stats_to_db was called
        assert dns_server._save_cache_stats_to_db.call_count >= 1

    @pytest.mark.asyncio
    async def it_updates_firewall_on_ip_change():
        """Test _cache_refresh_worker updates firewall when IP changes."""
        import time
        from unittest.mock import Mock

        from src.dns_server import DNSCache, DNSCacheEntry, DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = True
        dns_server.cache = DNSCache()
        dns_server.running = True
        dns_server.cache_refresh_interval = 0.1
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.firewall_manager = Mock()
        dns_server.firewall_manager.setup_domain = Mock()

        # Add expiring entry with old IPs
        entry = DNSCacheEntry(
            domain="example.com", query_type="A", ips=["1.2.3.4"], ttl=1, expiry=time.time() + 1
        )
        dns_server.cache._cache["example.com:A"] = entry

        # Mock _resolve_domain to return new IPs (IP changed!)
        dns_server._resolve_domain = AsyncMock(return_value=(["5.6.7.8"], 300))

        # Mock _save_cache_stats_to_db
        dns_server._save_cache_stats_to_db = AsyncMock()

        # Run worker for one iteration
        task = asyncio.create_task(dns_server._cache_refresh_worker())

        # Wait for first refresh cycle
        await asyncio.sleep(0.3)

        # Stop worker
        dns_server.running = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        # Verify firewall was updated
        assert dns_server.firewall_manager.setup_domain.call_count >= 1
        # Verify it was called with the new IPs
        call_args = dns_server.firewall_manager.setup_domain.call_args
        assert call_args[0][0] == "example.com"
        assert "5.6.7.8" in call_args[0][1]

    @pytest.mark.asyncio
    async def it_handles_refresh_errors_gracefully():
        """Test _cache_refresh_worker handles errors during refresh."""
        import time

        from src.dns_server import DNSCache, DNSCacheEntry, DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.cache_enabled = True
        dns_server.cache = DNSCache()
        dns_server.running = True
        dns_server.cache_refresh_interval = 0.1
        dns_server.allowed_domains = ["example.com"]
        dns_server.blocked_domains = []
        dns_server.firewall_manager = None

        # Add expiring entry
        entry = DNSCacheEntry(
            domain="example.com", query_type="A", ips=["1.2.3.4"], ttl=1, expiry=time.time() + 1
        )
        dns_server.cache._cache["example.com:A"] = entry

        # Mock _resolve_domain to raise exception
        dns_server._resolve_domain = AsyncMock(side_effect=Exception("DNS resolution failed"))

        # Mock _save_cache_stats_to_db
        dns_server._save_cache_stats_to_db = AsyncMock()

        # Run worker for one iteration (should not crash)
        task = asyncio.create_task(dns_server._cache_refresh_worker())

        # Wait for first refresh cycle
        await asyncio.sleep(0.3)

        # Stop worker
        dns_server.running = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        # If we reach here, error was handled gracefully
        assert True


def describe_resolve_domain():
    """Tests for _resolve_domain method."""

    @pytest.mark.asyncio
    async def it_resolves_using_docker_internal_dns():
        """Test _resolve_domain uses socket.getaddrinfo for Docker internal DNS."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.upstream_dns = "127.0.0.11"
        dns_server.cache_enabled = False
        dns_server.cache = None

        # Mock socket.getaddrinfo to return sample addresses
        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.2", 80)),
        ]

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_executor = AsyncMock(return_value=mock_addrinfo)
            mock_loop.return_value.run_in_executor = mock_executor

            result = await dns_server._resolve_domain("example.com", "A")

        assert result is not None
        ips, ttl = result
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips
        assert ttl == 300  # Default TTL for Docker DNS

    @pytest.mark.asyncio
    async def it_caches_resolved_domain():
        """Test _resolve_domain saves result to cache."""
        import dns.resolver

        from src.dns_server import DNSCache, DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.upstream_dns = "8.8.8.8"
        dns_server.cache_enabled = True
        dns_server.cache = DNSCache()
        dns_server.resolver = dns.resolver.Resolver()

        # Mock DNS resolver
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        mock_answers = Mock()
        mock_answers.rrset = mock_rrset
        mock_answers.__iter__ = Mock(return_value=iter([Mock(__str__=lambda self: "1.2.3.4")]))

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_executor = AsyncMock(return_value=mock_answers)
            mock_loop.return_value.run_in_executor = mock_executor

            result = await dns_server._resolve_domain("example.com", "A")

        assert result is not None
        ips, ttl = result
        assert "1.2.3.4" in ips
        assert ttl == 3600

        # Verify cache was populated
        cached_ips = dns_server.cache.get("example.com", "A")
        assert cached_ips is not None
        assert "1.2.3.4" in cached_ips

    @pytest.mark.asyncio
    async def it_resolves_ipv6_using_docker_dns():
        """Test _resolve_domain handles IPv6 queries with Docker DNS."""
        from src.dns_server import DNSServer

        dns_server = DNSServer.__new__(DNSServer)
        dns_server.upstream_dns = "127.0.0.11"
        dns_server.cache_enabled = False
        dns_server.cache = None

        # Mock socket.getaddrinfo for IPv6
        mock_addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 80, 0, 0)),
        ]

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_executor = AsyncMock(return_value=mock_addrinfo)
            mock_loop.return_value.run_in_executor = mock_executor

            result = await dns_server._resolve_domain("example.com", "AAAA")

        assert result is not None
        ips, ttl = result
        assert "2001:db8::1" in ips
        assert ttl == 300
