"""DNSサーバーモジュール - ドメイン解決とIP-ドメインマッピング記録."""

import asyncio
import contextlib
import ipaddress
import socket
import subprocess
import time
from dataclasses import dataclass

import aiosqlite
import dns.resolver
from dnslib import AAAA, QTYPE, RR, A, DNSRecord

from . import constants
from .logger import ComponentType, log_dns_query, log_error, log_system_event


@dataclass
class DNSCacheEntry:
    """DNSキャッシュエントリ."""

    domain: str
    ips: list[str]
    ttl: int
    expiry: float  # timestamp when cache expires
    query_type: str  # A or AAAA


class DNSCache:
    """TTLベースのDNSキャッシュ."""

    def __init__(self):
        """初期化."""
        self._cache: dict[str, DNSCacheEntry] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def get(self, domain: str, query_type: str = "A") -> list[str] | None:
        """キャッシュから取得.

        Args:
            domain: ドメイン名
            query_type: クエリタイプ（A, AAAA）

        Returns:
            IPリスト（キャッシュミス時はNone）
        """
        cache_key = f"{domain}:{query_type}"
        entry = self._cache.get(cache_key)

        if entry is None:
            self._cache_misses += 1
            return None

        # TTL期限切れチェック
        if time.time() >= entry.expiry:
            # 期限切れエントリを削除
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
        """キャッシュに追加.

        Args:
            domain: ドメイン名
            ips: IPリスト
            ttl: TTL値（秒）
            query_type: クエリタイプ（A, AAAA）
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
        """期限切れエントリのリストを取得.

        Returns:
            期限切れエントリリスト
        """
        now = time.time()
        expired = []

        for cache_key, entry in list(self._cache.items()):
            if now >= entry.expiry:
                expired.append(entry)
                del self._cache[cache_key]

        return expired

    def get_expiring_soon_entries(self, threshold_seconds: int = 60) -> list[DNSCacheEntry]:
        """まもなく期限切れになるエントリのリストを取得.

        Args:
            threshold_seconds: 期限切れまでの秒数閾値

        Returns:
            まもなく期限切れになるエントリリスト
        """
        now = time.time()
        expiring = []

        for entry in self._cache.values():
            time_remaining = entry.expiry - now
            if 0 < time_remaining <= threshold_seconds:
                expiring.append(entry)

        return expiring

    def get_stats(self) -> dict[str, int]:
        """キャッシュ統計を取得.

        Returns:
            統計情報
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
        """キャッシュをクリア."""
        self._cache.clear()
        log_system_event("DNS cache cleared")


class DNSMapping:
    """DNS解決結果のマッピング管理."""

    def __init__(self, db_path: str):
        """初期化.

        Args:
            db_path: SQLiteデータベースパス
        """
        self.db_path = db_path
        self.db: aiosqlite.Connection | None = None

    async def init_db(self) -> None:
        """データベース初期化."""
        self.db = await aiosqlite.connect(self.db_path)
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
        """DNS クエリを記録.

        Args:
            client_ip: クライアントIP
            domain: クエリドメイン
            ips: 解決されたIPリスト
            ttl: TTL値
            query_type: クエリタイプ（A, AAAA等）
            status: ステータス（'allowed' or 'blocked'）
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
        """IPからドメインを逆引き.

        Args:
            ip: 検索するIP

        Returns:
            ドメイン情報のリスト
        """
        if self.db is None:
            return []

        # 過去1時間以内のクエリを検索
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
        """データベース接続をクローズ."""
        if self.db:
            await self.db.close()


class DNSServer:
    """DNSサーバー（UDP/53）."""

    def __init__(
        self,
        upstream_dns: str | None = None,
        port: int | None = None,
        blocked_domains: set[str] | None = None,
        allowed_domains: list[str] | None = None,
        db_path: str | None = None,
        firewall_manager: object | None = None,
        cache_enabled: bool | None = None,
        cache_refresh_interval: int | None = None,
        lan_subnets: list[str] | None = None,
    ):
        """初期化.

        Args:
            upstream_dns: 上位DNSサーバー
                デフォルト: 127.0.0.11（Docker内蔵DNS）
                理由: 外部ドメイン（pypi.org等）とDockerサービス名（sekimore等）の両方を解決可能
                    socket.getaddrinfo()経由でシステムリゾルバーを使用するため、
                    Docker DNSのNAT DNAT/SNAT機能により動的ポートリダイレクトが機能する
            port: DNSリスニングポート
                デフォルト: 53（DNS標準ポート）
                理由: クライアント（ai-agent等）は標準ポート53でDNSクエリを送信するため
            blocked_domains: ブロックドメインセット
            allowed_domains: 許可ドメインリスト（ワイルドカード対応）
            db_path: データベースパス
            firewall_manager: ファイアウォールマネージャー（動的登録用）
            cache_enabled: DNSキャッシュ有効化
            cache_refresh_interval: キャッシュ更新チェック間隔（秒）
            lan_subnets: LAN側ネットワークサブネット（バインドIP検出用）
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

        # DNSキャッシュ
        self.cache_enabled = (
            cache_enabled if cache_enabled is not None else constants.DNS_CACHE_ENABLED
        )
        self.cache = DNSCache() if self.cache_enabled else None
        self.cache_refresh_interval = cache_refresh_interval or constants.DNS_CACHE_REFRESH_INTERVAL
        self._cache_refresh_task: asyncio.Task | None = None

        # sekimore-gw自身の名前解決用（internal-net側IPを返すため）
        self.gateway_hostname: str | None = None
        self.gateway_ip: str | None = None

    def _detect_dns_bind_ip(self) -> str:
        """DNSサービスを提供するネットワークのIPアドレスを自動検出.

        Returns:
            検出されたIPアドレス（検出失敗時は0.0.0.0）
        """
        try:
            # 全インターフェースのIPアドレスを取得
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            # lan_subnetsに含まれるIPアドレスを検索
            for line in result.stdout.split("\n"):
                if "inet " in line and "scope global" in line:
                    # inet 10.100.0.2/16 brd ... scope global eth0
                    ip_with_prefix = line.strip().split()[1]
                    ip_str = ip_with_prefix.split("/")[0]

                    # lan_subnetsのいずれかに含まれるかチェック
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
        return "0.0.0.0"  # フォールバック

    def _is_allowed(self, domain: str) -> bool:
        """ドメインが許可リストに含まれるか確認.

        Args:
            domain: チェックするドメイン

        Returns:
            許可されている場合True
        """
        domain_lower = domain.lower().rstrip(".")

        for allowed in self.allowed_domains:
            # 完全一致
            if allowed == domain_lower:
                return True

            # .example.com 形式のワイルドカード
            # .pythonhosted.org は files.pythonhosted.org, cdn.pythonhosted.org などにマッチ
            if allowed.startswith("."):
                # ドメインが .example.com または *.example.com にマッチするか
                suffix = allowed  # .pythonhosted.org
                if domain_lower.endswith(suffix) or domain_lower.endswith(suffix[1:]):
                    # files.pythonhosted.org → endswith(".pythonhosted.org") → True
                    # pythonhosted.org → endswith("pythonhosted.org") → True
                    return True

        return False

    def _is_blocked(self, domain: str) -> bool:
        """ドメインがブロックリストに含まれるか確認.

        Args:
            domain: チェックするドメイン

        Returns:
            ブロックされている場合True
        """
        domain_lower = domain.lower().rstrip(".")

        # 完全一致チェック
        if domain_lower in self.blocked_domains:
            return True

        # .example.com 形式のワイルドカード
        for blocked in self.blocked_domains:
            if blocked.startswith("."):
                suffix = blocked
                if domain_lower.endswith(suffix) or domain_lower.endswith(suffix[1:]):
                    return True

        return False

    async def _resolve_domain(
        self, domain: str, query_type: str = "A"
    ) -> tuple[list[str], int] | None:
        """ドメインを解決.

        Args:
            domain: 解決するドメイン
            query_type: クエリタイプ（A, AAAA）

        Returns:
            (IPリスト, TTL値)のタプル（解決失敗時はNone）
        """
        # キャッシュチェック
        if self.cache_enabled and self.cache:
            cached_ips = self.cache.get(domain, query_type)
            if cached_ips is not None:
                # キャッシュヒット：TTLは元の値を返す（キャッシュエントリから取得）
                cache_key = f"{domain}:{query_type}"
                entry = self.cache._cache.get(cache_key)
                ttl = entry.ttl if entry else 300
                return (cached_ips, ttl)

        # キャッシュミス：上位DNSに問い合わせ
        try:
            # Docker内蔵DNS (127.0.0.11) の場合はシステムresolverを使用
            if self.upstream_dns == "127.0.0.11":
                loop = asyncio.get_event_loop()

                # socket.getaddrinfo()はシステムのresolverを使用（127.0.0.11経由で動作）
                # AF_INET=IPv4, AF_INET6=IPv6
                family = socket.AF_INET if query_type == "A" else socket.AF_INET6

                addrinfo = await loop.run_in_executor(
                    None, socket.getaddrinfo, domain, None, family, socket.SOCK_STREAM
                )

                # IPアドレスを抽出（重複除去）
                ips = list({addr[4][0] for addr in addrinfo})

                # Docker DNSはTTL情報を返さないため、デフォルト値を使用
                ttl = 300  # 5分

                log_system_event(
                    "DNS resolved via system resolver (127.0.0.11)",
                    domain=domain,
                    query_type=query_type,
                    ttl=str(ttl),
                    ip_count=str(len(ips)),
                )
            else:
                # 通常のDNSサーバー（8.8.8.8等）の場合はdnspythonを使用
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, self.resolver.resolve, domain, query_type
                )

                # IPアドレスとTTL値を取得
                ips = [str(rdata) for rdata in answers]
                # answersの最初のRRsetからTTL取得（通常すべて同じTTL）
                ttl = int(answers.rrset.ttl) if answers.rrset else 300

                log_system_event(
                    "DNS resolved from upstream",
                    domain=domain,
                    query_type=query_type,
                    ttl=str(ttl),
                    ip_count=str(len(ips)),
                )

            # キャッシュに保存
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
        """DNS クエリを処理.

        Args:
            data: クエリデータ
            client_addr: クライアントアドレス

        Returns:
            レスポンスデータ
        """
        request = DNSRecord.parse(data)
        reply = request.reply()

        query_name = str(request.q.qname).rstrip(".")
        query_type = QTYPE[request.q.qtype]

        # ブロックリストチェック
        if self._is_blocked(query_name):
            # NXDOMAINを返す
            log_system_event(
                "DNS query blocked (blocklist)",
                domain=query_name,
                client_ip=client_addr[0],
            )

            # ブロックされたクエリをデータベースに記録
            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="blocked",
            )

            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()

        # sekimore-gw自身の名前解決（internal-net側IPを返す）
        # allowlistチェックより前に実行することで、allow_domainsに含まれていなくても解決可能
        # これにより、upstream DNS (127.0.0.11) がinternet側IPを返す問題を回避
        if self.gateway_hostname and self.gateway_ip and query_name == self.gateway_hostname:
            if query_type == "A":
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rdata=A(self.gateway_ip),
                        ttl=60,  # 短いTTL（動的に変わる可能性を考慮）
                    )
                )

                log_system_event(
                    "DNS query for gateway hostname (returning internal-net IP)",
                    domain=query_name,
                    client_ip=client_addr[0],
                    gateway_ip=self.gateway_ip,
                )

                # マッピング記録
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=[self.gateway_ip],
                    ttl=60,
                    query_type=query_type,
                )

                return reply.pack()
            # AAAA (IPv6) クエリの場合は、upstream DNSに問い合わせない（IPv4のみサポート）
            elif query_type == "AAAA":
                # 空のレスポンスを返す（IPv6アドレスなし）
                return reply.pack()

        # ホワイトリストチェック（allow_domains にないドメインをブロック）
        if not self._is_allowed(query_name):
            # NXDOMAINを返す
            log_system_event(
                "DNS query blocked (not in allowlist)",
                domain=query_name,
                client_ip=client_addr[0],
            )

            # ブロックされたクエリをデータベースに記録
            await self.mapping.record_query(
                client_ip=client_addr[0],
                domain=query_name,
                ips=[],
                ttl=0,
                query_type=query_type,
                status="blocked",
            )

            reply.header.rcode = 3  # NXDOMAIN
            return reply.pack()

        # 上位DNSに問い合わせ（許可リストにある場合のみ）
        if query_type in ["A", "AAAA"]:
            result = await self._resolve_domain(query_name, query_type)

            if result:
                ips, ttl = result

                # レスポンスに追加（実際のTTL値を使用）
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

                # マッピング記録（実際のTTL値を使用）
                await self.mapping.record_query(
                    client_ip=client_addr[0],
                    domain=query_name,
                    ips=ips,
                    ttl=ttl,
                    query_type=query_type,
                )

                # 許可ドメインにマッチする場合、ファイアウォールに動的登録
                if self._is_allowed(query_name) and self.firewall_manager:
                    self.firewall_manager.setup_domain(query_name, ips)
                    log_system_event(
                        "Firewall rule dynamically added",
                        domain=query_name,
                        ip_count=str(len(ips)),
                    )

                # ログ出力（実際のTTL値を使用）
                log_dns_query(
                    client_ip=client_addr[0],
                    query_domain=query_name,
                    response_ips=ips,
                    ttl=ttl,
                )

        return reply.pack()

    async def _save_cache_stats_to_db(self) -> None:
        """キャッシュ統計をデータベースに保存."""
        if not self.cache_enabled or not self.cache:
            return

        stats = self.cache.get_stats()

        try:
            db = await aiosqlite.connect(self.mapping.db_path)
            # cache_statsテーブルを作成（存在しない場合）
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

            # 既存のレコードを削除して最新の統計を挿入
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
        """キャッシュリフレッシュワーカー（バックグラウンドタスク）.

        TTL期限が近いエントリを事前に更新し、IP変更があればファイアウォールルールを更新する。
        """
        if not self.cache_enabled or not self.cache:
            return

        log_system_event("DNS cache refresh worker started")

        while self.running:
            try:
                await asyncio.sleep(self.cache_refresh_interval)

                # キャッシュ統計をDBに保存
                await self._save_cache_stats_to_db()

                # まもなく期限切れになるエントリを取得（60秒以内）
                expiring = self.cache.get_expiring_soon_entries(threshold_seconds=60)

                for entry in expiring:
                    try:
                        # 再解決
                        result = await self._resolve_domain(entry.domain, entry.query_type)

                        if result:
                            new_ips, new_ttl = result
                            old_ips = set(entry.ips)
                            new_ips_set = set(new_ips)

                            # IP変更検出
                            if old_ips != new_ips_set:
                                log_system_event(
                                    "DNS cache entry IP changed",
                                    domain=entry.domain,
                                    old_ips=",".join(sorted(old_ips)),
                                    new_ips=",".join(sorted(new_ips_set)),
                                )

                                # ファイアウォールルール更新
                                if self.firewall_manager and self._is_allowed(entry.domain):
                                    # 古いIPのルールを削除して新しいIPを追加
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
        """キャッシュ統計を取得.

        Returns:
            キャッシュ統計（キャッシュ無効時はNone）
        """
        if self.cache_enabled and self.cache:
            return self.cache.get_stats()
        return None

    async def _handle_tcp_connections(self, tcp_sock: socket.socket) -> None:
        """TCP接続を処理.

        Args:
            tcp_sock: TCPソケット
        """
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                # TCP接続を受け入れ
                client_sock, client_addr = await loop.sock_accept(tcp_sock)
                client_sock.setblocking(False)

                # TCP DNSクエリ処理タスクを起動
                asyncio.create_task(self._handle_tcp_client(client_sock, client_addr))

            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(ComponentType.DNS, f"Error accepting TCP connection: {e}")

    async def _handle_tcp_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        """TCP DNSクエリを処理.

        Args:
            client_sock: クライアントソケット
            client_addr: クライアントアドレス
        """
        loop = asyncio.get_event_loop()

        try:
            # RFC 1035: TCP DNSクエリは2バイトの長さ + メッセージ
            length_data = await loop.sock_recv(client_sock, 2)
            if len(length_data) < 2:
                return

            query_length = int.from_bytes(length_data, byteorder="big")

            # DNSクエリを受信
            query_data = await loop.sock_recv(client_sock, query_length)
            if len(query_data) < query_length:
                return

            # DNSクエリを処理
            response = await self.handle_query(query_data, client_addr)

            # RFC 1035: TCP DNSレスポンスも2バイトの長さ + メッセージ
            response_length = len(response).to_bytes(2, byteorder="big")
            await loop.sock_sendall(client_sock, response_length + response)

        except Exception as e:
            log_error(ComponentType.DNS, f"Error handling TCP client {client_addr}: {e}")
        finally:
            client_sock.close()

    async def start(self) -> None:
        """DNSサーバーを起動."""
        await self.mapping.init_db()

        loop = asyncio.get_event_loop()

        # DNSバインドIPを動的に検出
        bind_ip = self._detect_dns_bind_ip()

        # sekimore-gw自身の名前解決用にホスト名とIPを保存
        # これにより、upstream DNS (127.0.0.11) が internet側IPを返す問題を回避
        import os

        self.gateway_hostname = os.getenv("HOSTNAME", "sekimore-gw")
        self.gateway_ip = bind_ip  # internal-net側のIP

        # UDPソケット作成
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((bind_ip, self.port))
        udp_sock.setblocking(False)

        # TCPソケット作成（agent-setup.shの検出用）
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

        # キャッシュリフレッシュワーカーを起動
        if self.cache_enabled:
            self._cache_refresh_task = asyncio.create_task(self._cache_refresh_worker())

        # TCP接続ハンドラタスクを起動
        tcp_task = asyncio.create_task(self._handle_tcp_connections(tcp_sock))

        # UDPリスナーループ
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(udp_sock, 512)
                response = await self.handle_query(data, addr)
                await loop.sock_sendto(udp_sock, response, addr)
            except Exception as e:
                log_error(ComponentType.DNS, f"Error handling query: {e}")

        # TCP taskをキャンセル
        tcp_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await tcp_task

    async def stop(self) -> None:
        """DNSサーバーを停止."""
        self.running = False

        # キャッシュリフレッシュワーカーを停止
        if self._cache_refresh_task:
            self._cache_refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cache_refresh_task

        await self.mapping.close()
        log_system_event("DNS server stopped")
