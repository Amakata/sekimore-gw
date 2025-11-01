"""プロキシ管理モジュール - Squid設定生成と管理."""

import subprocess
from pathlib import Path

from . import constants
from .logger import ComponentType, log_error, log_system_event


class ProxyManager:
    """Squidプロキシサーバー管理."""

    def __init__(
        self,
        config_template_path: str | None = None,
        config_output_path: str | None = None,
        cache_enabled: bool = True,
        cache_size_mb: int = 10000,
        upstream_proxy: str | None = None,
        upstream_dns: str = "127.0.0.1",
        upstream_proxy_username: str | None = None,
        upstream_proxy_password: str | None = None,
    ):
        """初期化.

        Args:
            config_template_path: Squid設定テンプレートパス
            config_output_path: 出力先設定ファイルパス
            cache_enabled: キャッシュ有効化
            cache_size_mb: キャッシュサイズ（MB）
            upstream_proxy: 上位プロキシ（host:port）
            upstream_dns: 上位DNSサーバー（デフォルト: ゲートウェイ自身のDNS）
            upstream_proxy_username: 上位プロキシ認証ユーザー名
            upstream_proxy_password: 上位プロキシ認証パスワード
        """
        self.template_path = Path(config_template_path or constants.SQUID_TEMPLATE_PATH)
        self.output_path = Path(config_output_path or constants.SQUID_CONFIG_PATH)
        self.cache_enabled = cache_enabled
        self.cache_size_mb = cache_size_mb
        self.upstream_proxy = upstream_proxy
        self.upstream_dns = upstream_dns
        self.upstream_proxy_username = upstream_proxy_username
        self.upstream_proxy_password = upstream_proxy_password

    def generate_config(self, allowed_domains: list[str]) -> bool:
        """Squid設定ファイルを生成.

        Args:
            allowed_domains: 許可ドメインリスト

        Returns:
            成功した場合True
        """
        try:
            # テンプレート読み込み
            if not self.template_path.exists():
                log_error(
                    ComponentType.PROXY,
                    f"Template not found: {self.template_path}",
                )
                return False

            with open(self.template_path) as f:
                template = f.read()

            # 許可ドメインACL生成
            domain_acls = self._generate_domain_acls(allowed_domains)

            # キャッシュ設定
            cache_config = self._generate_cache_config()

            # 上位プロキシ設定
            upstream_config = self._generate_upstream_proxy_config()

            # テンプレート置換
            config = template.format(
                ALLOWED_DOMAINS_ACL=domain_acls,
                CACHE_CONFIG=cache_config,
                UPSTREAM_PROXY_CONFIG=upstream_config,
                DNS_NAMESERVERS=self.upstream_dns,
            )

            # 設定ファイル出力
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w") as f:
                f.write(config)

            log_system_event(
                "Squid config generated",
                output_path=str(self.output_path),
                domains_count=str(len(allowed_domains)),
            )

            return True

        except Exception as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to generate Squid config: {e}",
            )
            return False

    def _generate_domain_acls(self, domains: list[str]) -> str:
        """ドメインACLを生成.

        Args:
            domains: 許可ドメインリスト

        Returns:
            ACL設定文字列
        """
        acl_lines = []

        # ドメインごとにACLを定義
        for domain in domains:
            if domain.startswith("*."):
                # ワイルドカード: *.example.com → .example.com
                acl_lines.append(f"acl allowed_domains dstdomain {domain[1:]}")
            else:
                # 通常ドメイン
                acl_lines.append(f"acl allowed_domains dstdomain {domain}")

        return "\n".join(acl_lines)

    def _generate_cache_config(self) -> str:
        """キャッシュ設定を生成.

        Returns:
            キャッシュ設定文字列
        """
        if not self.cache_enabled:
            return "cache deny all"

        # キャッシュディレクトリとサイズ設定
        return f"""cache_dir ufs /var/spool/squid {self.cache_size_mb} 16 256
maximum_object_size 100 MB
cache_mem 256 MB"""

    def _generate_upstream_proxy_config(self) -> str:
        """上位プロキシ設定を生成.

        Returns:
            上位プロキシ設定文字列
        """
        if not self.upstream_proxy:
            return "# No upstream proxy configured"

        # host:port形式をパース
        parts = self.upstream_proxy.split(":")
        if len(parts) != 2:
            log_error(
                ComponentType.PROXY,
                f"Invalid upstream proxy format: {self.upstream_proxy}",
            )
            return "# Invalid upstream proxy configuration"

        host, port = parts

        # 認証情報がある場合はloginオプションを追加
        auth_option = ""
        if self.upstream_proxy_username and self.upstream_proxy_password:
            auth_option = f" login={self.upstream_proxy_username}:{self.upstream_proxy_password}"
            log_system_event(
                "Upstream proxy configured with Basic authentication",
                host=host,
                port=port,
                username=self.upstream_proxy_username,
            )
        else:
            log_system_event(
                "Upstream proxy configured without authentication",
                host=host,
                port=port,
            )

        return f"""# Upstream proxy configuration
cache_peer {host} parent {port} 0 no-query default{auth_option}
never_direct allow all"""

    def reload_config(self) -> bool:
        """Squid設定をリロード.

        Returns:
            成功した場合True
        """
        try:
            # squid -k reconfigure
            subprocess.run(
                ["squid", "-k", "reconfigure"],
                check=True,
                capture_output=True,
                text=True,
            )

            log_system_event("Squid config reloaded")
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to reload Squid: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.PROXY, "squid command not found")
            return False

    def start(self) -> bool:
        """Squidを起動.

        Returns:
            成功した場合True
        """
        try:
            # キャッシュディレクトリ初期化
            log_system_event("Initializing Squid cache directories")
            result = subprocess.run(
                ["squid", "-z"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                log_error(
                    ComponentType.PROXY,
                    f"Squid cache initialization failed: {result.stderr}",
                )
                # 初期化失敗してもSquid起動は試みる（キャッシュ無効の場合など）

            # squid -N (foreground mode)
            subprocess.Popen(
                ["squid", "-N"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            log_system_event("Squid proxy started")
            return True

        except FileNotFoundError:
            log_error(ComponentType.PROXY, "squid command not found")
            return False

    def stop(self) -> bool:
        """Squidを停止.

        Returns:
            成功した場合True
        """
        try:
            subprocess.run(
                ["squid", "-k", "shutdown"],
                check=True,
                capture_output=True,
                text=True,
            )

            log_system_event("Squid proxy stopped")
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to stop Squid: {e.stderr}",
            )
            return False
