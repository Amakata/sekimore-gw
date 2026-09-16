"""DNS server - resolves domains and records the IP-to-domain mapping."""

import asyncio
import contextlib
import ipaddress
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import aiosqlite
import dns.resolver
from dnslib import AAAA, QTYPE, RR, A, DNSRecord

from . import constants
from .logger import ComponentType, log_dns_query, log_error, log_system_event

if TYPE_CHECKING:
    from .firewall_manager import FirewallManager  # type: ignore[import-untyped]


@dataclass
class DNSCacheEntry:
    """A DNS cache entry."""

    domain: str
    ips: list[str]
    ttl: int
    expiry: float  # timestamp when cache expires
    query_type: str  # A or AAAA


class DNSCache:
    """TTL-based DNS cache."""

    def __init__(self):
        """Initialize the cache."""
        self._cache: dict[str, DNSCacheEntry] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def get(self, domain: str, query_type: str = "A") -> list[str] | None:
        """Look up an entry in the cache.

        Args:
            domain: Domain name
            query_type: Query type (A, AAAA)

        Returns:
            List of IPs, or None on a cache miss
        """
        cache_key = f"{domain}:{query_type}"
        entry = self._cache.get(cache_key)

        if entry is None:
            self._cache_misses += 1
            return None

        # Has the TTL expired?
        if time.time() >= entry.expiry:
            # Drop the expired entry
            del self._cache[cache_key]
            self._cache_misses += 1
            return None

        self._cache_hits += 1
        log_system_event(
            "DNS cache hit",
            domain=domain,
            query_type=query_type,
            ttl_remaining=str(int(entry.expiry - time.time())),
        )
        return entry.ips

    def put(self, domain: str, ips: list[str], ttl: int, query_type: str = "A") -> None:
        """Store an entry in the cache.

        Args:
            domain: Domain name
            ips: List of IPs
            ttl: TTL in seconds
            query_type: Query type (A, AAAA)
        """
        cache_key = f"{domain}:{query_type}"
        expiry = time.time() + ttl

        self._cache[cache_key] = DNSCacheEntry(
            domain=domain,
            ips=ips,
            ttl=ttl,
            expiry=expiry,
            query_type=query_type,
        )

        log_system_event(
            "DNS cache stored",
            domain=domain,
            query_type=query_type,
            ttl=str(ttl),
            ip_count=str(len(ips)),
        )

    def get_expired_entries(self) -> list[DNSCacheEntry]:
        """Collect the expired entries, removing them from the cache.

        Returns:
            The expired entries
        """
        now = time.time()
        expired = []

        for cache_key, entry in list(self._cache.items()):
            if now >= entry.expiry:
                expired.append(entry)
                del self._cache[cache_key]

        return expired

    def get_expiring_soon_entries(self, threshold_seconds: int = 60) -> list[DNSCacheEntry]:
        """Collect the entries that are about to expire.

        Args:
            threshold_seconds: How many seconds ahead of expiry to look

        Returns:
            The entries expiring within the threshold
        """
        now = time.time()
        expiring = []

        for entry in self._cache.values():
            time_remaining = entry.expiry - now
            if 0 < time_remaining <= threshold_seconds:
                expiring.append(entry)

        return expiring

    def get_stats(self) -> dict[str, int]:
        """Return the cache statistics.

        Returns:
            Statistics for the cache
        """
        return {
            "size": len(self._cache),
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": (
                round(self._cache_hits / (self._cache_hits + self._cache_misses) * 100, 2)
                if (self._cache_hits + self._cache_misses) > 0
                else 0.0
            ),
        }

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        log_system_event("DNS cache cleared")


async def _apply_pragmas(db: "aiosqlite.Connection") -> None:
    """Apply WAL + synchronous=NORMAL + busy_timeout; failures (read-only FS, etc.) are not fatal."""
    for pragma in (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
    ):
        try:
            cursor = await db.execute(pragma)
            await cursor.close()
        except Exception as e:  # pragma: no cover - environment dependent
            log_error(ComponentType.DNS, f"{pragma} failed: {e}")


class DNSMapping:
    """Stores the mapping produced by DNS resolution."""

    def __init__(self, db_path: str):
        """Initialize the mapping store.

        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.db: aiosqlite.Connection | None = None

    async def init_db(self) -> None:
        """Initialize the database."""
        self.db = await aiosqlite.connect(self.db_path)
        # 0.2.3: WAL so that writes (one commit per query) and Web UI reads do not block
        # each other. synchronous=NORMAL is safe enough under WAL: a power loss can only
        # cost the last few transactions.
        await _apply_pragmas(self.db)
        await self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_queries (
                timestamp REAL,
                client_ip TEXT,
                query_domain TEXT,
                response_ips TEXT,
                ttl INTEGER,
                query_type TEXT,
                status TEXT DEFAULT 'allowed'
            )
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_response_ips ON dns_queries(response_ips)
            """
        )
        await self.db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_domain ON dns_queries(query_domain)
            """
        )
        # 0.2.3: keep the Web UI's "new arrivals", "last 24h summary" and "latest N"
        # queries off a full table scan
        await self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_queries(timestamp)"
        )
        await self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_dns_status_timestamp ON dns_queries(status, timestamp)"
        )
        await self.db.commit()
        log_system_event("DNS mapping database initialized", db_path=self.db_path)

    async def record_query(
        self,
        client_ip: str,
        domain: str,
        ips: list[str],
        ttl: int,
        query_type: str = "A",
        status: str = "allowed",
    ) -> None:
        """Record a DNS query.

        Args:
            client_ip: Client IP
            domain: Queried domain
            ips: Resolved IPs
            ttl: TTL value
            query_type: Query type (A, AAAA, etc.)
            status: Status ('allowed' or 'blocked')
        """
        if self.db is None:
            return

        timestamp = time.time()
        response_ips_json = ",".join(ips) if ips else ""

        await self.db.execute(
            """
            INSERT INTO dns_queries (timestamp, client_ip, query_domain, response_ips, ttl, query_type, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, client_ip, domain, response_ips_json, ttl, query_type, status),
        )
        await self.db.commit()

    async def lookup_ip(self, ip: str) -> list[dict[str, str]]:
        """Reverse-look up the domains seen for an IP.

        Args:
            ip: IP to look up

        Returns:
            Matching domain records
        """
        if self.db is None:
            return []

        # Only consider queries from the last hour
        one_hour_ago = time.time() - 3600

        cursor = await self.db.execute(
            """
            SELECT query_domain, timestamp, ttl
            FROM dns_queries
            WHERE response_ips LIKE ? AND timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 10
            """,
            (f"%{ip}%", one_hour_ago),
        )

        results = []
        async for row in cursor:
            results.append(
                {
                    "domain": row[0],
                    "timestamp": row[1],
                    "ttl": row[2],
                    "confidence": "high" if time.time() - row[1] < 300 else "medium",
                }
            )

        return results

    async def close(self) -> None:
        """Close the database connection."""
        if self.db:
            await self.db.close()


class DNSServer:
    """DNS server (UDP/53)."""

    def __init__(
        self,
        upstream_dns: str | None = None,
        port: int | None = None,
        blocked_domains: set[str] | None = None,
        allowed_domains: list[str] | None = None,
        db_path: str | None = None,
        firewall_manager: "FirewallManager | None" = None,
        cache_enabled: bool | None = None,
        cache_refresh_interval: int | None = None,
        lan_subnets: list[str] | None = None,
        ignored_domains: list[str] | None = None,
        domain_handlers: dict[str, str] | None = None,
    ):
        """Initialize the server.

        Args:
            upstream_dns: Upstream DNS server
                Default: 127.0.0.11 (Docker's built-in DNS)
                Rationale: it resolves both external domains (pypi.org etc.) and Docker
                    service names (sekimore etc.). Resolution goes through the system
                    resolver via socket.getaddrinfo(), so Docker DNS's NAT DNAT/SNAT
                    handles the dynamic port redirection.
            port: Port the DNS server listens on
                Default: 53 (the standard DNS port)
                Rationale: clients (ai-agent etc.) send their DNS queries to port 53.
            blocked_domains: Set of blocked domains
            allowed_domains: Domain allowlist (wildcards supported)
            db_path: Database path
            firewall_manager: Firewall manager, used for dynamic registration
            cache_enabled: Whether the DNS cache is enabled
            cache_refresh_interval: How often to check for cache refreshes, in seconds
            lan_subnets: LAN-side subnets, used to detect the bind IP
            ignored_domains: Domains to ignore (hidden in the UI, but resolved normally)
            domain_handlers: Per-domain handler (git-relay / deny / splice); exact FQDN -> handler name
        """
        self.upstream_dns = upstream_dns or constants.DEFAULT_UPSTREAM_DNS
        self.port = port or constants.DEFAULT_DNS_PORT
        self.blocked_domains = blocked_domains or set()
        self.allowed_domains = allowed_domains or []
        self.firewall_manager = firewall_manager
        self.mapping = DNSMapping(db_path or constants.DB_PATH)
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.upstream_dns]
        self.running = False
        self.lan_subnets = lan_subnets or constants.DEFAULT_LAN_SUBNETS
        self.ignored_domains = ignored_domains or []
        # The relay: git-relay domains resolve to the relay's own IP (doc/sekimore-gw/design/relay.md)
        self.domain_handlers: dict[str, str] = dict(domain_handlers or {})
        self._relay_ip_warned = False

        # DNS cache
        self.cache_enabled = (
            cache_enabled if cache_enabled is not None else constants.DNS_CACHE_ENABLED
        )
        self.cache = DNSCache() if self.cache_enabled else None
        self.cache_refresh_interval = cache_refresh_interval or constants.DNS_CACHE_REFRESH_INTERVAL
        self._cache_refresh_task: asyncio.Task | None = None

        # Used to resolve sekimore-gw's own hostname to its internal-net IP
        self.gateway_hostname: str | None = None
        self.gateway_ip: str | None = None

    def _handler_for(self, domain: str) -> str | None:
        """Return the exact-match handler from domain_handlers, or None."""
        handlers = getattr(self, "domain_handlers", None) or {}
        return handlers.get(domain.lower().rstrip("."))

    def _is_self_query(self, client_ip: str) -> bool:
        """Is the query from the relay itself (internal-net IP / loopback)? Avoids a self-referential loop."""
        return (
            client_ip == getattr(self, "gateway_ip", None)
            or client_ip.startswith("127.")
            or client_ip == "::1"
        )

    def _detect_dns_bind_ip(self) -> str:
        """Detect the IP address of the network the DNS service is served on.

        Returns:
            The detected IP address, or 0.0.0.0 if detection fails
        """
        try:
            # List the IP addresses of every interface
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            # Find an address that falls inside one of lan_subnets
            for line in result.stdout.split("\n"):
                if "inet " in line and "scope global" in line:
                    # inet 10.100.0.2/16 brd ... scope global eth0
                    ip_with_prefix = line.strip().split()[1]
                    ip_str = ip_with_prefix.split("/")[0]

                    # Is it in any of lan_subnets?
                    ip_addr = ipaddress.ip_address(ip_str)
                    for subnet_str in self.lan_subnets:
                        subnet = ipaddress.ip_network(subnet_str)
                        if ip_addr in subnet:
                            log_system_event(
                                "DNS bind IP detected",
                                ip=ip_str,
                                subnet=subnet_str,
                            )
                            return ip_str

        except Exception as e:
            log_error(ComponentType.DNS, f"Failed to detect DNS bind IP: {e}")

        log_system_event(
            "DNS bind IP detection failed, using 0.0.0.0",
            subnets=",".join(self.lan_subnets),
        )
        return "0.0.0.0"  # Fallback

    def _is_allowed(self, domain: str) -> bool:
        """Check whether a domain is on the allowlist.

        Args:
            domain: Domain to check

        Returns:
            True if allowed
        """
        domain_lower = domain.lower().rstrip(".")

        for allowed in self.allowed_domains:
            # Exact match
            if allowed == domain_lower:
                return True

            # Wildcard entries written as .example.com;
            # .pythonhosted.org matches files.pythonhosted.org, cdn.pythonhosted.org, etc.
            if allowed.startswith("."):
                # Does the domain match .example.com or *.example.com?
                suffix = allowed  # .pythonhosted.org
                if domain_lower.endswith(suffix) or domain_lower.endswith(suffix[1:]):
                    # files.pythonhosted.org -> endswith(".pythonhosted.org") -> True
                    # pythonhosted.org -> endswith("pythonhosted.org") -> True
                    return True

        return False

    def _is_ignored(self, domain: str) -> bool:
        """Check whether a domain is on the ignore list.

        Args:
            domain: Domain to check

        Returns:
            True if the domain should be ignored
        """
        domain_lower = domain.lower().rstrip(".")

        for ignored in self.ignored_domains:
            # Exact match
            if ignored == domain_lower:
                return True

            # Wildcard entries written as .example.com
            if ignored.startswith("."):
                suffix = ignored
                if domain_lower.endswith(suffix) or domain_lower.endswith(suffix[1:]):
                    return True

        return False

    def _is_blocked(self, domain: str) -> bool:
        """Check whether a domain is on the blocklist.

        Args:
            domain: Domain to check

        Returns:
            True if blocked
        """
        domain_lower = domain.lower().rstrip(".")

        # Exact match
        if domain_lower in self.blocked_domains:
            return True

        # Wildcard entries written as .example.com
        for blocked in self.blocked_domains:
            if blocked.startswith("."):
                suffix = blocked
                if domain_lower.endswith(suffix) or domain_lower.endswith(suffix[1:]):
                    return True

        return False

    async def _resolve_domain(
        self, domain: str, query_type: str = "A"
    ) -> tuple[list[str], int] | None:
        """Resolve a domain.

        Args:
            domain: Domain to resolve
            query_type: Query type (A, AAAA)

        Returns:
            A (list of IPs, TTL) tuple, or None if resolution fails
        """
        # Check the cache first
        if self.cache_enabled and self.cache:
            cached_ips = self.cache.get(domain, query_type)
            if cached_ips is not None:
                # Cache hit: report the original TTL stored on the entry
                cache_key = f"{domain}:{query_type}"
                entry = self.cache._cache.get(cache_key)
                ttl = entry.ttl if entry else 300
                return (cached_ips, ttl)

        # Cache miss: ask the upstream DNS
        try:
            # For Docker's built-in DNS (127.0.0.11), go through the system resolver
            if self.upstream_dns == "127.0.0.11":
                loop = asyncio.get_event_loop()

                # socket.getaddrinfo() uses the system resolver, which goes via 127.0.0.11.
                # AF_INET=IPv4, AF_INET6=IPv6
                family = socket.AF_INET if query_type == "A" else socket.AF_INET6

                addrinfo = await loop.run_in_executor(
                    None, socket.getaddrinfo, domain, None, family, socket.SOCK_STREAM
                )

                # Extract the addresses, de-duplicated
                ips: list[str] = list({str(addr[4][0]) for addr in addrinfo})

                # Docker DNS does not report a TTL, so use a default
                ttl = 300  # 5 minutes

                log_system_event(
                    "DNS resolved via system resolver (127.0.0.11)",
                    domain=domain,
                    query_type=query_type,
                    ttl=str(ttl),
                    ip_count=str(len(ips)),
                )
            else:
                # For a regular DNS server (8.8.8.8 etc.), use dnspython
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, self.resolver.resolve, domain, query_type
                )

                # Pull out the addresses and the TTL
                ips = [str(rdata) for rdata in answers]
                # Take the TTL from the first RRset (they are normally all the same)
                ttl = int(answers.rrset.ttl) if answers.rrset else 300

                log_system_event(
                    "DNS resolved from upstream",
                    domain=domain,
                    query_type=query_type,
                    ttl=str(ttl),
                    ip_count=str(len(ips)),
                )

            # Store in the cache
            if self.cache_enabled and self.cache:
                self.cache.put(domain, ips, ttl, query_type)

            return (ips, ttl)

        except Exception as e:
            log_error(
                ComponentType.DNS,
                f"DNS resolution failed for {domain}: {e}",
            )
            return None

    async def handle_query(self, data: bytes, client_addr: tuple[str, int]) -> bytes:
        """Handle a DNS query.

        Args:
            data: Query bytes
            client_addr: Client address

        Returns:
            Response bytes
        """
        request = DNSRecord.parse(data)
        reply = request.reply()

        query_name = str(request.q.qname).rstrip(".")
        query_type = QTYPE[request.q.qtype]

        # Blocklist check
        if self._is_blocked(query_name):
            # Answer with NXDOMAIN
            log_system_event(
                "DNS query blocked (blocklist)",
                domain=query_name,
                client_ip=client_addr[0],
            )

            # Record the blocked query in the database
            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="blocked",
            )

            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()  # type: ignore[no-any-return]

        # Ignore-list check, after the blocklist and before the allowlist.
        # The DNS answer is NXDOMAIN, same as a block, but it is recorded as
        # status='ignored' and the domain need not be in allow_domains.
        if self._is_ignored(query_name):
            log_system_event(
                "DNS query ignored",
                domain=query_name,
                client_ip=client_addr[0],
            )

            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="ignored",
            )

            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()  # type: ignore[no-any-return]

        # Resolve sekimore-gw's own hostname to its internal-net IP. Doing this before the
        # allowlist check means it resolves even when it is not in allow_domains, and avoids
        # the upstream DNS (127.0.0.11) answering with the internet-side IP.
        if self.gateway_hostname and self.gateway_ip and query_name == self.gateway_hostname:
            if query_type == "A":
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rdata=A(self.gateway_ip),
                        ttl=60,  # Short TTL, since the address can change
                    )
                )

                log_system_event(
                    "DNS query for gateway hostname (returning internal-net IP)",
                    domain=query_name,
                    client_ip=client_addr[0],
                    gateway_ip=self.gateway_ip,
                )

                # Record the mapping
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=[self.gateway_ip],
                    ttl=60,
                    query_type=query_type,
                )

                return reply.pack()  # type: ignore[no-any-return]
            # Never forward AAAA (IPv6) queries upstream: only IPv4 is supported
            elif query_type == "AAAA":
                # Answer with an empty response (no IPv6 address)
                return reply.pack()  # type: ignore[no-any-return]

        # The relay (domain_handlers): before the allowlist, after block / ignore / own hostname
        handler = self._handler_for(query_name)
        if handler == "deny":
            log_system_event(
                "DNS query denied (domain_handlers: deny)",
                domain=query_name,
                client_ip=client_addr[0],
            )
            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="blocked",
            )
            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()  # type: ignore[no-any-return]
        # 0.2.2: https-relay (only 443 goes through the relay) also answers with the relay IP;
        # the real IP is never added to the ipset
        if handler in ("git-relay", "https-relay") and not self._is_self_query(client_addr[0]):
            gateway_ip = getattr(self, "gateway_ip", None)
            if not gateway_ip or gateway_ip == "0.0.0.0":
                # Fall back to normal resolution when the relay IP is unknown, rather than answering 0.0.0.0
                if not getattr(self, "_relay_ip_warned", False):
                    log_error(
                        ComponentType.DNS,
                        f"git-relay handler for {query_name} but the gateway IP is unknown; "
                        "falling back to normal resolution",
                    )
                    self._relay_ip_warned = True
            elif query_type == "A":
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rdata=A(gateway_ip),
                        ttl=60,
                    )
                )
                log_system_event(
                    "DNS query redirected to git-relay (returning gateway IP)",
                    domain=query_name,
                    client_ip=client_addr[0],
                    gateway_ip=gateway_ip,
                )
                # Do not add the real IP to the ipset (no setup_domain call); record it as allowed
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=[gateway_ip],
                    ttl=60,
                    query_type=query_type,
                    status="allowed",
                )
                return reply.pack()  # type: ignore[no-any-return]
            elif query_type == "AAAA":
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=[],
                    ttl=60,
                    query_type=query_type,
                    status="allowed",
                )
                return reply.pack()  # type: ignore[no-any-return]

        # Allowlist check: block anything not in allow_domains
        if not self._is_allowed(query_name):
            # Answer with NXDOMAIN
            log_system_event(
                "DNS query blocked (not in allowlist)",
                domain=query_name,
                client_ip=client_addr[0],
            )

            # Record the blocked query in the database
            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="blocked",
            )

            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()  # type: ignore[no-any-return]

        # Ask the upstream DNS (only for allowlisted domains)
        if query_type in ["A", "AAAA"]:
            result = await self._resolve_domain(query_name, query_type)

            if result:
                ips, ttl = result

                # Add the answers, using the real TTL
                for ip in ips:
                    if query_type == "A":
                        reply.add_answer(
                            RR(
                                rname=request.q.qname,
                                rtype=QTYPE.A,
                                rdata=A(ip),
                                ttl=ttl,
                            )
                        )
                    else:  # AAAA
                        reply.add_answer(
                            RR(
                                rname=request.q.qname,
                                rtype=QTYPE.AAAA,
                                rdata=AAAA(ip),
                                ttl=ttl,
                            )
                        )

                # Record the mapping, using the real TTL
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=ips,
                    ttl=ttl,
                    query_type=query_type,
                )

                # For an allowlisted domain, register the IPs with the firewall
                if self._is_allowed(query_name) and self.firewall_manager:
                    self.firewall_manager.setup_domain(query_name, ips)
                    log_system_event(
                        "Firewall rule dynamically added",
                        domain=query_name,
                        ip_count=str(len(ips)),
                    )

                # Log the query, using the real TTL
                log_dns_query(
                    client_ip=client_addr[0],
                    query_domain=query_name,
                    response_ips=ips,
                    ttl=ttl,
                )

        return reply.pack()  # type: ignore[no-any-return]

    async def _save_cache_stats_to_db(self) -> None:
        """Persist the cache statistics to the database."""
        if not self.cache_enabled or not self.cache:
            return

        stats = self.cache.get_stats()

        try:
            db = await aiosqlite.connect(self.mapping.db_path)
            # Create the cache_stats table if it does not exist
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_stats (
                    id INTEGER PRIMARY KEY,
                    timestamp REAL,
                    size INTEGER,
                    hits INTEGER,
                    misses INTEGER,
                    hit_rate REAL
                )
                """
            )

            # Replace the existing row with the latest statistics
            await db.execute("DELETE FROM cache_stats")
            await db.execute(
                """
                INSERT INTO cache_stats (id, timestamp, size, hits, misses, hit_rate)
                VALUES (1, ?, ?, ?, ?, ?)
                """,
                (time.time(), stats["size"], stats["hits"], stats["misses"], stats["hit_rate"]),
            )
            await db.commit()
            await db.close()
        except Exception as e:
            log_error(ComponentType.DNS, f"Failed to save cache stats to DB: {e}")

    async def _cache_refresh_worker(self) -> None:
        """Background worker that refreshes the cache.

        It re-resolves entries whose TTL is about to expire and updates the firewall
        rules whenever the IPs have changed.
        """
        if not self.cache_enabled or not self.cache:
            return

        log_system_event("DNS cache refresh worker started")

        while self.running:
            try:
                await asyncio.sleep(self.cache_refresh_interval)

                # Persist the cache statistics
                await self._save_cache_stats_to_db()

                # Entries expiring within the next 60 seconds
                expiring = self.cache.get_expiring_soon_entries(threshold_seconds=60)

                for entry in expiring:
                    try:
                        # Re-resolve
                        result = await self._resolve_domain(entry.domain, entry.query_type)

                        if result:
                            new_ips, new_ttl = result
                            old_ips = set(entry.ips)
                            new_ips_set = set(new_ips)

                            # The IPs changed
                            if old_ips != new_ips_set:
                                log_system_event(
                                    "DNS cache entry IP changed",
                                    domain=entry.domain,
                                    old_ips=",".join(sorted(old_ips)),
                                    new_ips=",".join(sorted(new_ips_set)),
                                )

                                # Update the firewall rules
                                if self.firewall_manager and self._is_allowed(entry.domain):
                                    # Drop the rules for the old IPs and add the new ones
                                    self.firewall_manager.setup_domain(entry.domain, new_ips)
                                    log_system_event(
                                        "Firewall rules updated due to IP change",
                                        domain=entry.domain,
                                        ip_count=str(len(new_ips)),
                                    )
                            else:
                                log_system_event(
                                    "DNS cache entry refreshed (no IP change)",
                                    domain=entry.domain,
                                    ttl=str(new_ttl),
                                )

                    except Exception as e:
                        log_error(
                            ComponentType.DNS,
                            f"Failed to refresh cache entry for {entry.domain}: {e}",
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(ComponentType.DNS, f"Cache refresh worker error: {e}")

        log_system_event("DNS cache refresh worker stopped")

    def get_cache_stats(self) -> dict[str, int] | None:
        """Return the cache statistics.

        Returns:
            The cache statistics, or None when the cache is disabled
        """
        if self.cache_enabled and self.cache:
            return self.cache.get_stats()
        return None

    async def _handle_tcp_connections(self, tcp_sock: socket.socket) -> None:
        """Accept and dispatch TCP connections.

        Args:
            tcp_sock: Listening TCP socket
        """
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                # Accept a TCP connection
                client_sock, client_addr = await loop.sock_accept(tcp_sock)
                client_sock.setblocking(False)

                # Start a task to handle the TCP DNS query
                asyncio.create_task(self._handle_tcp_client(client_sock, client_addr))

            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(ComponentType.DNS, f"Error accepting TCP connection: {e}")

    async def _handle_tcp_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        """Handle a TCP DNS query.

        Args:
            client_sock: Client socket
            client_addr: Client address
        """
        loop = asyncio.get_event_loop()

        try:
            # RFC 1035: a TCP DNS query is a 2-byte length followed by the message
            length_data = await loop.sock_recv(client_sock, 2)
            if len(length_data) < 2:
                return

            query_length = int.from_bytes(length_data, byteorder="big")

            # Read the DNS query
            query_data = await loop.sock_recv(client_sock, query_length)
            if len(query_data) < query_length:
                return

            # Handle the DNS query
            response = await self.handle_query(query_data, client_addr)

            # RFC 1035: a TCP DNS response is likewise a 2-byte length plus the message
            response_length = len(response).to_bytes(2, byteorder="big")
            await loop.sock_sendall(client_sock, response_length + response)

        except Exception as e:
            log_error(ComponentType.DNS, f"Error handling TCP client {client_addr}: {e}")
        finally:
            client_sock.close()

    async def start(self) -> None:
        """Start the DNS server."""
        await self.mapping.init_db()

        loop = asyncio.get_event_loop()

        # Detect the DNS bind IP dynamically
        bind_ip = self._detect_dns_bind_ip()

        # Remember our own hostname and IP so we can answer queries for sekimore-gw
        # ourselves, instead of the upstream DNS (127.0.0.11) returning the internet-side IP
        import os

        self.gateway_hostname = os.getenv("HOSTNAME", "sekimore-gw")
        self.gateway_ip = bind_ip  # The internal-net IP

        # Create the UDP socket
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((bind_ip, self.port))
        udp_sock.setblocking(False)

        # Create the TCP socket (used by agent-setup.sh for detection)
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind((bind_ip, self.port))
        tcp_sock.listen(5)
        tcp_sock.setblocking(False)

        log_system_event(
            "DNS server started",
            bind_ip=bind_ip,
            port=str(self.port),
            upstream=self.upstream_dns,
            cache_enabled=str(self.cache_enabled),
            protocols="UDP+TCP",
        )

        self.running = True

        # Start the cache refresh worker
        if self.cache_enabled:
            self._cache_refresh_task = asyncio.create_task(self._cache_refresh_worker())

        # Start the TCP connection handler task
        tcp_task = asyncio.create_task(self._handle_tcp_connections(tcp_sock))

        # UDP listener loop
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(udp_sock, 512)
                response = await self.handle_query(data, addr)
                await loop.sock_sendto(udp_sock, response, addr)
            except Exception as e:
                log_error(ComponentType.DNS, f"Error handling query: {e}")

        # Cancel the TCP task
        tcp_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await tcp_task

    async def stop(self) -> None:
        """Stop the DNS server."""
        self.running = False

        # Stop the cache refresh worker
        if self._cache_refresh_task:
            self._cache_refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cache_refresh_task

        await self.mapping.close()
        log_system_event("DNS server stopped")
