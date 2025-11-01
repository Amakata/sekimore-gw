"""静的IP管理モジュール - IPアドレス、CIDR、レンジのipset管理."""

import ipaddress
import subprocess

from .logger import ComponentType, log_error, log_system_event


class StaticIPManager:
    """静的IPアドレスフィルタリング管理."""

    def __init__(self) -> None:
        """初期化."""
        self.allow_ipset_name = "allow_static_ips"
        self.block_ipset_name = "block_static_ips"

    def _expand_ip_range(self, ip_range: str) -> list[str]:
        """IPレンジを個別IPに展開.

        Args:
            ip_range: IPレンジ（例: 192.168.1.1-192.168.1.10）

        Returns:
            個別IPリスト
        """
        start_ip_str, end_ip_str = ip_range.split("-", 1)
        start_ip = ipaddress.ip_address(start_ip_str.strip())
        end_ip = ipaddress.ip_address(end_ip_str.strip())

        if start_ip.version != end_ip.version:
            raise ValueError(f"IP version mismatch in range: {ip_range}")

        ip_list = []
        current_ip = start_ip
        while current_ip <= end_ip:
            ip_list.append(str(current_ip))
            # IPv4/IPv6両対応
            current_ip = ipaddress.ip_address(int(current_ip) + 1)

            # 安全のため、最大1024個に制限
            if len(ip_list) > 1024:
                log_error(
                    ComponentType.FIREWALL,
                    f"IP range too large (>1024 IPs), truncating: {ip_range}",
                )
                break

        return ip_list

    def _run_ipset_command(self, args: list[str]) -> bool:
        """ipsetコマンドを実行.

        Args:
            args: ipsetコマンド引数

        Returns:
            成功した場合True
        """
        try:
            subprocess.run(
                ["ipset"] + args,
                check=True,
                capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            # すでに存在する場合のエラーは無視
            if "already" in e.stderr.lower() or "exist" in e.stderr.lower():
                return True
            log_error(
                ComponentType.FIREWALL,
                f"ipset command failed: {' '.join(args)}: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.FIREWALL, "ipset command not found")
            return False

    def create_ipsets(self) -> bool:
        """ipsetを作成（hash:net タイプでCIDR対応）."""
        # 既存のipsetを削除（クリーンスタート）
        self._run_ipset_command(["destroy", self.allow_ipset_name])
        self._run_ipset_command(["destroy", self.block_ipset_name])

        # hash:net タイプで作成（CIDR、IPv4対応）
        success = True
        success &= self._run_ipset_command(
            ["create", self.allow_ipset_name, "hash:net", "family", "inet"]
        )
        success &= self._run_ipset_command(
            ["create", self.block_ipset_name, "hash:net", "family", "inet"]
        )

        if success:
            log_system_event(
                "Static IP ipsets created",
                allow_set=self.allow_ipset_name,
                block_set=self.block_ipset_name,
            )

        return success

    def setup_static_ips(self, allow_ips: list[str], block_ips: list[str]) -> bool:
        """静的IPフィルタリングを設定.

        Args:
            allow_ips: 許可IPリスト（単一IP、CIDR、レンジ）
            block_ips: 拒否IPリスト（単一IP、CIDR、レンジ）

        Returns:
            成功した場合True
        """
        # ipset作成
        if not self.create_ipsets():
            return False

        # 許可IPを追加
        for ip_spec in allow_ips:
            if "/" in ip_spec:
                # CIDR: そのまま追加
                self._run_ipset_command(["add", self.allow_ipset_name, ip_spec])
            elif "-" in ip_spec:
                # IPレンジ: 個別IPに展開して追加
                for ip in self._expand_ip_range(ip_spec):
                    self._run_ipset_command(["add", self.allow_ipset_name, ip])
            else:
                # 単一IP: そのまま追加
                self._run_ipset_command(["add", self.allow_ipset_name, ip_spec])

        # 拒否IPを追加
        for ip_spec in block_ips:
            if "/" in ip_spec:
                self._run_ipset_command(["add", self.block_ipset_name, ip_spec])
            elif "-" in ip_spec:
                for ip in self._expand_ip_range(ip_spec):
                    self._run_ipset_command(["add", self.block_ipset_name, ip])
            else:
                self._run_ipset_command(["add", self.block_ipset_name, ip_spec])

        log_system_event(
            "Static IP filtering configured",
            allow_count=len(allow_ips),
            block_count=len(block_ips),
        )
        return True

    def cleanup(self) -> None:
        """ipsetをクリーンアップ."""
        self._run_ipset_command(["destroy", self.allow_ipset_name])
        self._run_ipset_command(["destroy", self.block_ipset_name])
        log_system_event("Static IP ipsets destroyed")
