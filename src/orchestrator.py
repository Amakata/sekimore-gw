"""オーケストレータ - DNS、IP管理、ファイアウォールの3層統合."""

import asyncio
import contextlib
import fnmatch
import ipaddress
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

if TYPE_CHECKING:
    from watchdog.observers import Observer as ObserverType

from .config import load_config
from .dns_server import DNSServer
from .firewall import FirewallManager
from .firewall_monitor import FirewallMonitor
from .ip_manager import StaticIPManager
from .logger import ComponentType, log_error, log_system_event, setup_logging
from .proxy_manager import ProxyManager
from .proxy_monitor import ProxyMonitor


class ConfigFileEventHandler(FileSystemEventHandler):
    """設定ファイル変更を監視するイベントハンドラー."""

    def __init__(self, orchestrator: "SecurityGatewayOrchestrator", config_path: Path):
        """初期化.

        Args:
            orchestrator: オーケストレーターインスタンス
            config_path: 監視する設定ファイルパス
        """
        self.orchestrator = orchestrator
        self.config_path = config_path
        self._reload_lock = threading.Lock()
        self._last_reload_time = 0.0

    def on_modified(self, event: FileSystemEvent) -> None:
        """ファイル変更時のイベントハンドラー.

        Args:
            event: ファイルシステムイベント
        """
        # ディレクトリの変更は無視
        if event.is_directory:
            return

        # 監視対象のconfig.ymlのみ処理
        if Path(event.src_path).resolve() != self.config_path.resolve():
            return

        # 短時間に複数回トリガーされるのを防ぐ（デバウンス）
        current_time = time.time()
        with self._reload_lock:
            if current_time - self._last_reload_time < 1.0:  # 1秒以内は無視
                return
            self._last_reload_time = current_time

        log_system_event("Configuration file modified, reloading...")

        # 非同期メソッドを同期的に実行
        # watchdogは同期スレッドで動作するため、asyncio.run()を使用
        try:
            # 新しいイベントループを作成して実行
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success = loop.run_until_complete(self.orchestrator.reload_config())
                if success:
                    log_system_event("Configuration reloaded automatically")
                else:
                    log_error(ComponentType.ORCHESTRATOR, "Auto-reload failed")
            finally:
                loop.close()
        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Auto-reload error: {e}")


class SecurityGatewayOrchestrator:
    """セキュリティゲートウェイ統合管理."""

    @staticmethod
    def _detect_network_interfaces_from_docker_api() -> tuple[str, str, str, str, str, str] | None:
        """Docker API経由でネットワークインターフェースを動的検出（poc1方式）.

        環境変数からPROJECT_NAME, INTERNAL_NETWORK_NAME, INTERNET_NETWORK_NAMEを取得し、
        Docker APIでコンテナのIPアドレスを取得、インターフェースを判別する。

        Returns:
            (internet_interface, internal_interface, internal_ip, internet_ip, internet_gw, internal_subnet)のタプル
            検出できない場合はNone
        """
        try:
            # 環境変数取得
            project_name = os.getenv("PROJECT_NAME")
            internal_network_name = os.getenv("INTERNAL_NETWORK_NAME", "internal-net")
            internet_network_name = os.getenv("INTERNET_NETWORK_NAME", "internet")

            if not project_name:
                log_system_event("PROJECT_NAME not set, falling back to static subnet detection")
                return None

            # インターフェース準備待ち
            time.sleep(2)

            # コンテナID取得
            container_id = subprocess.run(
                ["hostname"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout.strip()

            log_system_event(
                "Docker API detection started",
                container_id=container_id,
                project_name=project_name,
            )

            # ネットワーク完全名構築
            internal_network_full = f"{project_name}_{internal_network_name}"
            internet_network_full = f"{project_name}_{internet_network_name}"

            # Docker APIでIPアドレス取得
            inspect_result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            inspect_data = json.loads(inspect_result.stdout)
            networks = inspect_data[0]["NetworkSettings"]["Networks"]

            internal_network_info = networks.get(internal_network_full, {})
            internal_ip = internal_network_info.get("IPAddress")
            internal_prefix_len = internal_network_info.get("IPPrefixLen", 16)  # デフォルト16

            internet_ip = networks.get(internet_network_full, {}).get("IPAddress")

            log_system_event(
                "Docker API IPs detected",
                internal_ip=internal_ip or "null",
                internal_prefix_len=str(internal_prefix_len),
                internet_ip=internet_ip or "null",
            )

            if not internal_ip or not internet_ip:
                log_error(
                    ComponentType.ORCHESTRATOR,
                    f"Failed to get IPs from Docker API: internal={internal_ip}, internet={internet_ip}",
                )
                return None

            # internal_ipとprefix_lenからサブネットを計算
            internal_network = ipaddress.ip_network(
                f"{internal_ip}/{internal_prefix_len}", strict=False
            )
            internal_subnet = str(internal_network)

            # IPからインターフェース判別
            internal_if = None
            internet_if = None

            for iface in ["eth0", "eth1", "eth2", "eth3"]:
                result = subprocess.run(
                    ["ip", "addr", "show", iface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    if f"{internal_ip}/" in result.stdout:
                        internal_if = iface
                    if f"{internet_ip}/" in result.stdout:
                        internet_if = iface

            if not internal_if or not internet_if:
                log_error(
                    ComponentType.ORCHESTRATOR,
                    f"Failed to detect interfaces: internal={internal_if}, internet={internet_if}",
                )
                return None

            # インターネット側ゲートウェイIP算出（.1）
            internet_gw = ".".join(internet_ip.split(".")[:-1]) + ".1"

            log_system_event(
                "Docker API detection successful",
                internet_interface=internet_if,
                internet_ip=internet_ip,
                internet_gw=internet_gw,
                internal_interface=internal_if,
                internal_ip=internal_ip,
                internal_subnet=internal_subnet,
            )

            return (
                internet_if,
                internal_if,
                internal_ip,
                internet_ip,
                internet_gw,
                internal_subnet,
            )

        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Docker API detection failed: {e}",
            )
            return None

    @staticmethod
    def _setup_default_route(internet_gw: str, internet_if: str) -> bool:
        """デフォルトルートを設定.

        Args:
            internet_gw: インターネット側ゲートウェイIP
            internet_if: インターネット側インターフェース

        Returns:
            成功した場合True
        """
        try:
            # 既存のデフォルトルート削除
            subprocess.run(
                ["ip", "route", "del", "default"],
                capture_output=True,
                timeout=5,
            )

            # 新しいデフォルトルート追加
            subprocess.run(
                ["ip", "route", "add", "default", "via", internet_gw, "dev", internet_if],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            log_system_event(
                "Default route set",
                gateway=internet_gw,
                interface=internet_if,
            )
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to set default route: {e.stderr}",
            )
            return False
        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to set default route: {e}",
            )
            return False

    @staticmethod
    def _detect_network_interfaces(lan_subnets: list[str]) -> tuple[str, str, str]:
        """ネットワークインターフェースを自動検出.

        lan_subnetsに含まれるIPを持つインターフェース = LAN側
        それ以外 = WAN側

        Args:
            lan_subnets: LAN側ネットワークサブネット（例: ["10.100.0.0/16"]）

        Returns:
            (wan_interface, lan_interface, lan_ip)のタプル
        """
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            lan_if = None
            wan_if = None
            lan_ip = None

            # インターフェース名とIPを解析
            current_if = None
            for line in result.stdout.split("\n"):
                # インターフェース行: "2: eth0@if194: <BROADCAST,MULTICAST,UP,LOWER_UP>..."
                if ":" in line and "<" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        # eth0@if194 → eth0 (peer interface indexを除去)
                        if_name = parts[1].strip()
                        current_if = if_name.split("@")[0]

                # IP行: "    inet 10.100.0.2/16 brd ... scope global eth0"
                elif "inet " in line and "scope global" in line and current_if:
                    ip_with_prefix = line.strip().split()[1]
                    ip_str = ip_with_prefix.split("/")[0]

                    # lan_subnetsに含まれるかチェック
                    ip_addr = ipaddress.ip_address(ip_str)
                    is_lan_net = False

                    for subnet_str in lan_subnets:
                        subnet = ipaddress.ip_network(subnet_str)
                        if ip_addr in subnet:
                            is_lan_net = True
                            # 最初に見つかったLAN側インターフェースのみ使用
                            if lan_if is None:
                                lan_if = current_if
                                lan_ip = ip_str
                                log_system_event(
                                    "LAN interface detected",
                                    interface=current_if,
                                    ip=ip_str,
                                    subnet=subnet_str,
                                )
                            else:
                                # 複数のLAN側インターフェースが検出された場合は警告
                                log_system_event(
                                    "Multiple LAN interfaces detected, using first one",
                                    first_interface=lan_if,
                                    first_ip=lan_ip,
                                    additional_interface=current_if,
                                    additional_ip=ip_str,
                                )
                            break

                    # lan_subnetsに含まれない = WAN側
                    # 最初に見つかったWAN側インターフェースのみ使用
                    if not is_lan_net and current_if != "lo":
                        if wan_if is None:
                            wan_if = current_if
                            log_system_event(
                                "WAN interface detected",
                                interface=current_if,
                                ip=ip_str,
                            )
                        else:
                            # 複数のWAN側インターフェースが検出された場合は警告
                            log_system_event(
                                "Multiple WAN interfaces detected, using first one",
                                first_interface=wan_if,
                                additional_interface=current_if,
                                additional_ip=ip_str,
                            )

            if not lan_if or not wan_if or not lan_ip:
                raise RuntimeError(
                    f"Failed to detect interfaces: lan={lan_if}, wan={wan_if}, lan_ip={lan_ip}"
                )

            return (wan_if, lan_if, lan_ip)

        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Interface detection failed: {e}, using defaults",
            )
            # フォールバック（従来の動作）
            # lan_subnetsの最初のサブネットから.2のIPアドレスを推測
            default_lan_ip = "10.100.0.2"
            if lan_subnets:
                try:
                    subnet = ipaddress.ip_network(lan_subnets[0])
                    # サブネットの2番目のIPアドレスを使用（.0はネットワーク、.1はゲートウェイが一般的）
                    default_lan_ip = str(list(subnet.hosts())[0])
                except Exception:
                    pass

            return ("eth0", "eth1", default_lan_ip)

    def __init__(
        self,
        config_path: Path | None = None,
    ):
        """初期化.

        Args:
            config_path: 設定ファイルパス
        """
        # 設定ファイルパスを保存（リロード用）
        self.config_path = config_path

        # 設定読み込み
        self.config = load_config(config_path)

        # インターフェース名とLAN側IPアドレスを動的検出
        # 優先順位: Docker API検出 → 静的サブネット検出
        docker_api_result = self._detect_network_interfaces_from_docker_api()

        if docker_api_result:
            # Docker API経由での検出成功（poc1方式）
            internet_if, internal_if, internal_ip, internet_ip, internet_gw, internal_subnet = (
                docker_api_result
            )

            # デフォルトルート設定
            self._setup_default_route(internet_gw, internet_if)

            # WAN = internet, LAN = internal
            wan_interface = internet_if
            lan_interface = internal_if
            lan_ip = internal_ip
            # Docker APIで検出したサブネットを使用（config.ymlより優先）
            detected_lan_subnets = [internal_subnet]

            log_system_event(
                "Using Docker API detection",
                wan_interface=wan_interface,
                lan_interface=lan_interface,
                lan_ip=lan_ip,
                lan_subnet=internal_subnet,
            )
        else:
            # フォールバック: 静的サブネット検出（従来方式）
            wan_interface, lan_interface, lan_ip = self._detect_network_interfaces(
                self.config.network.lan_subnets
            )
            # config.ymlのサブネットを使用
            detected_lan_subnets = self.config.network.lan_subnets

            log_system_event(
                "Using static subnet detection",
                wan_interface=wan_interface,
                lan_interface=lan_interface,
                lan_ip=lan_ip,
            )

        # コンポーネント初期化
        self.firewall = FirewallManager(
            wan_interface=wan_interface,
            lan_interface=lan_interface,
        )
        self.ip_manager = StaticIPManager()

        # ブロックドメインのセット
        blocked_domains = set(self.config.block_domains)

        # DNSサーバー（ファイアウォールへの参照を渡して動的登録を可能にする）
        # 初期化順序: firewall → dns_server（firewallへの参照が必要）
        # upstream_dns: Docker内蔵DNS（127.0.0.11）固定
        # port: DNS標準ポート（53）固定
        # lan_subnets: Docker APIで検出したサブネット、またはconfig.ymlのサブネットを使用
        self.dns_server = DNSServer(
            upstream_dns="127.0.0.11",  # Docker内蔵DNS（固定）
            port=53,  # DNS標準ポート（固定）
            blocked_domains=blocked_domains,
            allowed_domains=self.config.allow_domains,
            db_path=self.config.database_path,
            firewall_manager=self.firewall,
            lan_subnets=detected_lan_subnets,
        )

        # ファイアウォールモニター（iptablesログを監視）
        self.firewall_monitor = FirewallMonitor(db_path=self.config.database_path)

        # プロキシマネージャー（Squid）
        self.proxy_manager: ProxyManager | None = None
        if self.config.proxy.enabled:
            self.proxy_manager = ProxyManager(
                cache_enabled=self.config.proxy.cache_enabled,
                cache_size_mb=self.config.proxy.cache_size_mb,
                upstream_proxy=self.config.proxy.upstream_proxy,
                upstream_dns=lan_ip,  # ゲートウェイ自身のDNS（LAN側IPアドレスを動的検出）
                upstream_proxy_username=self.config.proxy.upstream_proxy_username,
                upstream_proxy_password=self.config.proxy.upstream_proxy_password,
            )

        # プロキシモニター（Squidアクセスログを監視）
        self.proxy_monitor: ProxyMonitor | None = None
        if self.config.proxy.enabled:
            self.proxy_monitor = ProxyMonitor(db_path=self.config.database_path)

        # ファイル監視（config.yml変更時に自動リロード）
        self.config_observer: ObserverType | None = None
        if self.config_path:
            # 設定ファイルのディレクトリを監視
            config_dir = Path(self.config_path).parent
            event_handler = ConfigFileEventHandler(self, Path(self.config_path))
            self.config_observer = Observer()
            self.config_observer.schedule(event_handler, str(config_dir), recursive=False)

    def _match_allowed_domain(self, domain: str) -> bool:
        """ドメインが許可リストに含まれるかチェック.

        Args:
            domain: チェックするドメイン

        Returns:
            許可されている場合True
        """
        domain_lower = domain.lower().rstrip(".")

        for allowed in self.config.allow_domains:
            # 完全一致
            if allowed == domain_lower:
                return True

            # ワイルドカード一致
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if domain_lower.endswith(suffix):
                    return True
            elif allowed.startswith("*"):
                suffix = allowed[1:]
                if domain_lower.endswith(suffix):
                    return True

            # fnmatch対応（より柔軟なパターンマッチング）
            if fnmatch.fnmatch(domain_lower, allowed):
                return True

        return False

    async def apply_domain_rule(self, domain: str, action: str = "allow") -> bool:
        """単一ドメインルールを3層すべてに適用.

        Args:
            domain: ドメイン名
            action: 'allow' または 'block'

        Returns:
            成功した場合True
        """
        if action == "block":
            # ブロックリストに追加
            self.dns_server.blocked_domains.add(domain)
            log_system_event("Domain blocked", domain=domain)
            return True

        # 許可ドメイン処理
        # 1. DNSでドメインを解決
        result = await self.dns_server._resolve_domain(domain, "A")

        if not result:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to resolve domain: {domain}",
            )
            return False

        ips, ttl = result

        # 2. IPv4アドレスのみをフィルタリング（ipsetはfamily inetでIPv4専用）
        ipv4_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    ipv4_ips.append(ip)
            except ValueError:
                log_error(ComponentType.ORCHESTRATOR, f"Invalid IP address: {ip}")
                continue

        if not ipv4_ips:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"No IPv4 addresses found for domain: {domain}",
            )
            return False

        # 3. iptables/ipsetルールを設定（IPv4のみ）
        if not self.firewall.setup_domain(domain, ipv4_ips):
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to setup firewall rules for domain: {domain}",
            )
            return False

        log_system_event(
            "Domain rule applied",
            domain=domain,
            action=action,
            ip_count=str(len(ipv4_ips)),
        )

        return True

    async def initialize(self) -> bool:
        """セキュリティゲートウェイを初期化.

        Returns:
            成功した場合True
        """
        log_system_event("Initializing Security Gateway...")

        # 1. ファイアウォール初期化
        if not self.firewall.initialize_firewall():
            log_error(ComponentType.ORCHESTRATOR, "Firewall initialization failed")
            return False

        # 2. 静的IP設定
        if not self.ip_manager.setup_static_ips(
            allow_ips=self.config.allow_ips,
            block_ips=self.config.block_ips,
        ):
            log_error(ComponentType.ORCHESTRATOR, "Static IP setup failed")
            return False

        # 3. 静的IPのiptablesルール追加
        if not self.firewall.setup_static_ip_rules(
            allow_ipset_name=self.ip_manager.allow_ipset_name,
            block_ipset_name=self.ip_manager.block_ipset_name,
        ):
            log_error(ComponentType.ORCHESTRATOR, "Static IP firewall rules setup failed")
            return False

        # 4. 許可ドメインのルールを適用（.で始まらないドメインのみ）
        for domain in self.config.allow_domains:
            # . で始まるワイルドカードは起動時にスキップ（DNSクエリ時に動的処理）
            if not domain.startswith("."):
                log_system_event(f"Applying domain rule for: {domain}")
                await self.apply_domain_rule(domain, action="allow")
                log_system_event(f"Domain rule applied successfully: {domain}")

        # 5. すべてのACCEPTルール設定完了後、ブロックログを有効化
        # これによりLOGルールが最後に配置され、ブロックされるパケットのみがログされる
        if not self.firewall.enable_block_logging():
            log_error(ComponentType.ORCHESTRATOR, "Failed to enable block logging")
            # ログ記録は失敗しても続行（ファイアウォール自体は機能する）

        # 6. Squidプロキシ設定（有効な場合）
        if self.proxy_manager:
            if not self.proxy_manager.generate_config(self.config.allow_domains):
                log_error(ComponentType.ORCHESTRATOR, "Failed to generate Squid config")
                # プロキシ設定失敗は続行（DNS/ファイアウォールは機能する）
            else:
                log_system_event("Squid proxy config generated")

        log_system_event(
            "Security Gateway initialized",
            allowed_domains=str(len(self.config.allow_domains)),
            blocked_domains=str(len(self.config.block_domains)),
            allowed_ips=str(len(self.config.allow_ips)),
            blocked_ips=str(len(self.config.block_ips)),
            proxy_enabled=str(self.config.proxy.enabled),
        )

        return True

    async def start(self) -> None:
        """セキュリティゲートウェイを起動."""
        # ログシステム初期化
        setup_logging()

        # 初期化
        if not await self.initialize():
            log_error(ComponentType.ORCHESTRATOR, "Initialization failed, exiting")
            return

        # Squidプロキシ起動（有効な場合）
        if self.proxy_manager and not self.proxy_manager.start():
            log_error(ComponentType.ORCHESTRATOR, "Failed to start Squid proxy")
            # プロキシ起動失敗は続行（DNS/ファイアウォールは機能する）

        # ファイアウォールモニターをバックグラウンドで起動
        firewall_monitor_task = asyncio.create_task(self.firewall_monitor.start())

        # プロキシモニターをバックグラウンドで起動（有効な場合）
        proxy_monitor_task = None
        if self.proxy_monitor:
            proxy_monitor_task = asyncio.create_task(self.proxy_monitor.start())

        # ファイル監視を開始（config.yml変更時の自動リロード）
        if self.config_observer:
            self.config_observer.start()
            log_system_event("Configuration file monitoring started")

        # DNSサーバー起動（メインループ）
        try:
            await self.dns_server.start()
        except KeyboardInterrupt:
            log_system_event("Shutdown signal received")
        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Fatal error: {e}")
        finally:
            # モニター停止
            await self.firewall_monitor.stop()
            firewall_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await firewall_monitor_task

            if self.proxy_monitor and proxy_monitor_task:
                await self.proxy_monitor.stop()
                proxy_monitor_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await proxy_monitor_task

            await self.cleanup()

    async def cleanup(self) -> None:
        """リソースをクリーンアップ."""
        log_system_event("Cleaning up...")

        # ファイル監視停止
        if self.config_observer:
            self.config_observer.stop()
            if self.config_observer.is_alive():
                self.config_observer.join()
            log_system_event("Configuration file monitoring stopped")

        # DNSサーバー停止
        await self.dns_server.stop()

        # Squidプロキシ停止
        if self.proxy_manager:
            self.proxy_manager.stop()

        # ファイアウォールクリーンアップ
        self.firewall.cleanup()

        # 静的IPクリーンアップ
        self.ip_manager.cleanup()

        log_system_event("Cleanup complete")

    async def reload_config(self) -> bool:
        """設定ファイルを再読み込みして差分を反映（ダウンタイムなし）.

        Returns:
            成功した場合True
        """
        try:
            log_system_event("Reloading configuration...")

            # 新しい設定を読み込み
            new_config = load_config(self.config_path)

            # 差分検出
            old_allow_domains = set(self.config.allow_domains)
            new_allow_domains = set(new_config.allow_domains)
            old_block_domains = set(self.config.block_domains)
            new_block_domains = set(new_config.block_domains)

            added_allow_domains = new_allow_domains - old_allow_domains
            removed_allow_domains = old_allow_domains - new_allow_domains
            added_block_domains = new_block_domains - old_block_domains
            removed_block_domains = old_block_domains - new_block_domains

            # DNS Server更新
            self.dns_server.allowed_domains = new_config.allow_domains
            self.dns_server.blocked_domains = set(new_config.block_domains)

            # 削除されたドメインのiptablesルールを削除
            for domain in removed_allow_domains:
                if not domain.startswith("."):  # ワイルドカードはスキップ
                    self.firewall.remove_domain(domain)

            # 追加されたドメインのルールを適用
            for domain in added_allow_domains:
                if not domain.startswith("."):  # ワイルドカードはスキップ
                    # DNSクエリ時に動的に処理されるため、ここでは何もしない
                    pass

            # Squidプロキシ設定更新（有効な場合）
            if self.proxy_manager:
                if not self.proxy_manager.generate_config(new_config.allow_domains):
                    log_error(ComponentType.ORCHESTRATOR, "Failed to regenerate Squid config")
                    return False
                if not self.proxy_manager.reload_config():
                    log_error(ComponentType.ORCHESTRATOR, "Failed to reload Squid config")
                    return False

            # 設定を更新
            self.config = new_config

            log_system_event(
                "Configuration reloaded successfully",
                added_allow_domains=str(len(added_allow_domains)),
                removed_allow_domains=str(len(removed_allow_domains)),
                added_block_domains=str(len(added_block_domains)),
                removed_block_domains=str(len(removed_block_domains)),
            )

            return True

        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Failed to reload configuration: {e}")
            return False

    async def restart_services(self) -> bool:
        """サービスを再起動（数秒のダウンタイムあり）.

        Returns:
            成功した場合True
        """
        try:
            log_system_event("Restarting services...")

            # 1. DNSサーバーを停止
            await self.dns_server.stop()
            log_system_event("DNS server stopped")

            # 2. Proxyを停止（有効な場合）
            if self.proxy_manager:
                self.proxy_manager.stop()
                log_system_event("Proxy stopped")

            # 3. 設定を再読み込み
            self.config = load_config(self.config_path)
            log_system_event("Configuration reloaded")

            # 4. DNS Serverの設定を更新
            self.dns_server.allowed_domains = self.config.allow_domains
            self.dns_server.blocked_domains = set(self.config.block_domains)

            # 5. DNSサーバーを再起動
            await self.dns_server.start()
            log_system_event("DNS server restarted")

            # 6. Proxyを再起動（有効な場合）
            if self.proxy_manager:
                if not self.proxy_manager.generate_config(self.config.allow_domains):
                    log_error(ComponentType.ORCHESTRATOR, "Failed to regenerate Squid config")
                    return False
                if not self.proxy_manager.start():
                    log_error(ComponentType.ORCHESTRATOR, "Failed to start Proxy")
                    return False
                log_system_event("Proxy restarted")

            log_system_event("Services restarted successfully")
            return True

        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Failed to restart services: {e}")
            return False


async def main() -> None:
    """メインエントリーポイント."""
    orchestrator = SecurityGatewayOrchestrator()
    await orchestrator.start()


if __name__ == "__main__":
    asyncio.run(main())
