"""ファイアウォール管理モジュール - iptables/ipset動的ルール管理."""

import subprocess

from .logger import ComponentType, log_error, log_system_event


class FirewallManager:
    """iptables/ipsetベースのファイアウォール管理."""

    def __init__(
        self,
        wan_interface: str,
        lan_interface: str,
    ):
        """初期化.

        Args:
            wan_interface: WAN側インターフェース（インターネット側、orchestratorで動的検出）
            lan_interface: LAN側インターフェース（ローカルネットワーク側、orchestratorで動的検出）
        """
        self.wan_if = wan_interface
        self.lan_if = lan_interface
        self.domain_ipsets: dict[str, str] = {}  # domain -> ipset_name のマッピング

        # iptables/ipsetコマンド（legacyを使用）
        self.iptables_cmd = "iptables-legacy"
        self.ipset_cmd = "ipset"

    def _run_command(self, cmd: list[str]) -> bool:
        """コマンドを実行.

        Args:
            cmd: コマンドリスト

        Returns:
            成功した場合True
        """
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            # "already exists" エラーは無視（追加操作で既存ルールがある場合）
            if "already" in e.stderr.lower():
                return True
            # "does not exist" または "no chain" エラーは削除失敗として扱う
            # （_remove_block_log_rule()のwhile Trueループを終了させるため）
            if "exist" in e.stderr.lower() or "no chain" in e.stderr.lower():
                return False
            log_error(
                ComponentType.FIREWALL,
                f"Command failed: {' '.join(cmd)}: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.FIREWALL, f"Command not found: {cmd[0]}")
            return False

    def initialize_firewall(self) -> bool:
        """ファイアウォールを初期化.

        Returns:
            成功した場合True
        """
        log_system_event("Initializing firewall...")

        # 1. sysctl 設定は docker-compose.yml の sysctls セクションで設定済み
        # (net.ipv4.ip_forward=1, net.ipv4.conf.*.send_redirects=0)

        # 2. 既存ルールをフラッシュ（Docker DNSのNATルールは保護）
        self._run_command([self.iptables_cmd, "-F"])
        # NATテーブルは完全にフラッシュしない（Docker DNSの127.0.0.11リダイレクトルールを保護）
        # 代わりに、POSTROUTINGチェーンのsekimore管理ルールのみ削除
        # ⚠️ iptables -t nat -F を実行すると、127.0.0.11へのNATルールが削除される
        self._run_command([self.iptables_cmd, "-X"])

        # 3. デフォルトポリシー設定
        self._run_command([self.iptables_cmd, "-P", "INPUT", "DROP"])  # 外部からの入力は拒否
        self._run_command([self.iptables_cmd, "-P", "OUTPUT", "ACCEPT"])  # sekimore自身の出力は許可
        self._run_command(
            [self.iptables_cmd, "-P", "FORWARD", "DROP"]
        )  # フォワードは明示的なルールのみ

        # 4. NAT設定（MASQUERADE）
        if not self._run_command(
            [
                self.iptables_cmd,
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                self.wan_if,
                "-j",
                "MASQUERADE",
            ]
        ):
            return False

        # 5. ループバックを許可（INPUT/OUTPUT）
        self._run_command([self.iptables_cmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        self._run_command([self.iptables_cmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

        # 6. 確立済み接続を許可（INPUT/OUTPUT/FORWARD）
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "FORWARD",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )

        # 7. INPUT: sekimore自身へのアクセスを最小限に許可
        # ICMP (ping) - LAN側からの疎通確認
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "icmp",
                "-j",
                "ACCEPT",
            ]
        )
        # DNS (53/udp) - ai-agentからのDNSクエリ
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # DNS (53/tcp) - ai-agentからのDNS検出（agent-setup.shが /dev/tcp を使用）
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # Squid Proxy (3128/tcp) - ai-agentからのHTTP/HTTPSリクエスト
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "tcp",
                "--dport",
                "3128",
                "-j",
                "ACCEPT",
            ]
        )
        # Web UI (8080/tcp) - 管理者からのアクセス
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "ACCEPT",
            ]
        )

        # 8. OUTPUT: sekimore自身からの必要な通信を許可
        # Dockerの内蔵DNS (127.0.0.11) - 全ポート許可（動的ポート使用のため）
        # Docker DNSは実際にはポート53でリスニングせず、ランダムな高ポート（例:51116）を使用
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-d",
                "127.0.0.11",
                "-j",
                "ACCEPT",
            ]
        )
        # 上位DNS (53/udp) - 名前解決
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # HTTP/HTTPS (80/443) - パッケージ取得、上位プロキシ等
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ]
        )
        # 上位プロキシ (3128/8080) - 企業プロキシ接続用
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "3128",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "ACCEPT",
            ]
        )

        log_system_event(
            "Firewall initialized",
            wan_if=self.wan_if,
            lan_if=self.lan_if,
        )
        return True

    def enable_block_logging(self) -> bool:
        """ブロックパケットのログ記録を有効化.

        すべてのACCEPTルール設定後に呼び出すこと。
        FORWARDチェーンの最後に到達したパケット（=ブロックされるパケット）をログに記録。

        Returns:
            成功した場合True
        """
        log_system_event("Enabling firewall block logging...")
        result = self._add_block_log_rule()

        if result:
            log_system_event("Firewall block logging enabled")
        else:
            log_error(ComponentType.FIREWALL, "Failed to enable block logging")

        return result

    def _add_block_log_rule(self) -> bool:
        """NFLOGルールを追加（内部ヘルパー）.

        ulogd2を使用してユーザースペースでログ記録。
        Docker環境でもアクセス可能。
        NFLOGはULOGの後継で、最新カーネルでサポートされている。

        Returns:
            成功した場合True
        """
        return self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "FORWARD",
                "-j",
                "NFLOG",
                "--nflog-group",
                "1",
                "--nflog-prefix",
                "[FIREWALL-BLOCK] ",
            ]
        )

    def _remove_block_log_rule(self) -> bool:
        """NFLOGルールを削除（内部ヘルパー）.

        複数のNFLOGルールが存在する場合、すべて削除する。

        Returns:
            成功した場合True（ルールが存在しない場合もTrue）
        """
        # NFLOGルールを削除（複数存在する可能性があるため繰り返す）
        while True:
            result = self._run_command(
                [
                    self.iptables_cmd,
                    "-D",
                    "FORWARD",
                    "-j",
                    "NFLOG",
                    "--nflog-group",
                    "1",
                    "--nflog-prefix",
                    "[FIREWALL-BLOCK] ",
                ]
            )
            # 削除に失敗したら（ルールが存在しない）終了
            if not result:
                break

        return True

    def setup_domain(self, domain: str, ips: list[str]) -> bool:
        """ドメインに対するipsetとiptablesルールを設定.

        Args:
            domain: ドメイン名
            ips: 許可するIPリスト

        Returns:
            成功した場合True
        """
        # ipset名を生成（英数字とアンダースコアのみ）
        ipset_name = f"allow_{domain.replace('.', '_').replace('*', 'wildcard')}"
        ipset_name = ipset_name[:31]  # ipset名は31文字まで

        # LAN専用ドメインか判定（.lanで終わる、またはコンテナ名）
        is_lan_only = domain.endswith(".lan") or "." not in domain

        # IPv4アドレスのみをフィルタリング
        ipv4_ips = [ip for ip in ips if ":" not in ip]

        # IPv4アドレスがない場合は既存のipsetを保持（IPv6のみのクエリ結果対策）
        if not ipv4_ips:
            return True

        # 既存ipsetのルールを削除（重複防止）
        if not is_lan_only:
            # WAN向けの場合はインターフェース条件付きで削除を試行
            self._run_command(
                [
                    self.iptables_cmd,
                    "-D",
                    "FORWARD",
                    "-i",
                    self.lan_if,
                    "-o",
                    self.wan_if,
                    "-m",
                    "set",
                    "--match-set",
                    ipset_name,
                    "dst",
                    "-j",
                    "ACCEPT",
                ]
            )
        else:
            # LAN専用の場合は-iのみで削除を試行
            self._run_command(
                [
                    self.iptables_cmd,
                    "-D",
                    "FORWARD",
                    "-i",
                    self.lan_if,
                    "-m",
                    "set",
                    "--match-set",
                    ipset_name,
                    "dst",
                    "-j",
                    "ACCEPT",
                ]
            )

        # 既存ipsetを削除
        self._run_command([self.ipset_cmd, "destroy", ipset_name])

        # ipset作成（hash:ip、IPv4）
        if not self._run_command(
            [self.ipset_cmd, "create", ipset_name, "hash:ip", "family", "inet"]
        ):
            return False

        # IPv4アドレスを追加
        for ip in ipv4_ips:
            self._run_command([self.ipset_cmd, "add", ipset_name, ip])

        # LOGルールを一時的に削除
        self._remove_block_log_rule()

        # iptablesルール追加（インターフェース条件付き）
        if is_lan_only:
            # LAN専用トラフィック（sekimore.lan等）は-iのみ
            self._run_command(
                [
                    self.iptables_cmd,
                    "-A",
                    "FORWARD",
                    "-i",
                    self.lan_if,
                    "-m",
                    "set",
                    "--match-set",
                    ipset_name,
                    "dst",
                    "-j",
                    "ACCEPT",
                ]
            )
        else:
            # WAN向けトラフィック（外部ドメイン）は-i と -o 両方
            self._run_command(
                [
                    self.iptables_cmd,
                    "-A",
                    "FORWARD",
                    "-i",
                    self.lan_if,
                    "-o",
                    self.wan_if,
                    "-m",
                    "set",
                    "--match-set",
                    ipset_name,
                    "dst",
                    "-j",
                    "ACCEPT",
                ]
            )

        # LOGルールを再追加（ACCEPTルールの後に配置）
        self._add_block_log_rule()

        self.domain_ipsets[domain] = ipset_name

        log_system_event(
            "Domain firewall rule added",
            domain=domain,
            ipset=ipset_name,
            ip_count=str(len(ips)),
            is_lan_only=str(is_lan_only),
        )

        return True

    def update_domain_ips(self, domain: str, new_ips: list[str]) -> bool:
        """ドメインのIPリストを更新（TTL期限切れ時など）.

        Args:
            domain: ドメイン名
            new_ips: 新しいIPリスト

        Returns:
            成功した場合True
        """
        if domain not in self.domain_ipsets:
            return self.setup_domain(domain, new_ips)

        ipset_name = self.domain_ipsets[domain]

        # 既存IPを取得
        try:
            result = subprocess.run(
                [self.ipset_cmd, "list", ipset_name],
                check=True,
                capture_output=True,
                text=True,
            )
            existing_ips = set()
            in_members = False
            for line in result.stdout.splitlines():
                if line.startswith("Members:"):
                    in_members = True
                    continue
                if in_members and line.strip():
                    existing_ips.add(line.strip())

        except subprocess.CalledProcessError:
            existing_ips = set()

        new_ips_set = set(new_ips)

        # 差分更新
        ips_to_add = new_ips_set - existing_ips
        ips_to_remove = existing_ips - new_ips_set

        for ip in ips_to_add:
            self._run_command([self.ipset_cmd, "add", ipset_name, ip])

        for ip in ips_to_remove:
            self._run_command([self.ipset_cmd, "del", ipset_name, ip])

        if ips_to_add or ips_to_remove:
            log_system_event(
                "Domain IPs updated",
                domain=domain,
                added=str(len(ips_to_add)),
                removed=str(len(ips_to_remove)),
            )

        return True

    def remove_domain(self, domain: str) -> bool:
        """ドメインのルールを削除.

        Args:
            domain: ドメイン名

        Returns:
            成功した場合True
        """
        if domain not in self.domain_ipsets:
            return True

        ipset_name = self.domain_ipsets[domain]

        # iptablesルール削除
        self._run_command(
            [
                self.iptables_cmd,
                "-D",
                "FORWARD",
                "-m",
                "set",
                "--match-set",
                ipset_name,
                "dst",
                "-j",
                "ACCEPT",
            ]
        )

        # ipset削除
        self._run_command([self.ipset_cmd, "destroy", ipset_name])

        del self.domain_ipsets[domain]

        log_system_event("Domain firewall rule removed", domain=domain)

        return True

    def setup_static_ip_rules(self, allow_ipset_name: str, block_ipset_name: str) -> bool:
        """静的IPのiptablesルールを設定.

        Args:
            allow_ipset_name: 許可IPのipset名
            block_ipset_name: 拒否IPのipset名

        Returns:
            成功した場合True
        """
        # ブロックIPルール（最優先）
        self._run_command(
            [
                self.iptables_cmd,
                "-I",
                "FORWARD",
                "1",
                "-m",
                "set",
                "--match-set",
                block_ipset_name,
                "dst",
                "-j",
                "DROP",
            ]
        )

        # 許可IPルール
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "FORWARD",
                "-m",
                "set",
                "--match-set",
                allow_ipset_name,
                "dst",
                "-j",
                "ACCEPT",
            ]
        )

        log_system_event(
            "Static IP firewall rules added",
            allow_set=allow_ipset_name,
            block_set=block_ipset_name,
        )

        return True

    def setup_host_firewall_rules(
        self,
        internal_ip: str,
        project_name: str,
        internal_network_name: str = "internal-net",
        internet_network_name: str = "internet",
        uplink_if: str = "eth0",
    ) -> bool:
        """ホスト側ファイアウォールルールを設定（poc1方式）.

        Args:
            internal_ip: sekimoreのinternal側IPアドレス
            project_name: Docker Composeプロジェクト名
            internal_network_name: internal側ネットワーク名
            internet_network_name: internet側ネットワーク名
            uplink_if: ホスト側アップリンクインターフェース

        Returns:
            成功した場合True
        """
        try:
            log_system_event(
                "Setting up host-side firewall rules",
                internal_ip=internal_ip,
                project_name=project_name,
            )

            # ネットワーク完全名構築
            internal_network_full = f"{project_name}_{internal_network_name}"
            internet_network_full = f"{project_name}_{internet_network_name}"

            # ブリッジインターフェース名を取得
            import json

            internal_result = subprocess.run(
                ["docker", "network", "inspect", internal_network_full],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            internal_data = json.loads(internal_result.stdout)
            internal_bridge_id = internal_data[0]["Id"][:12]
            br_internal = f"br-{internal_bridge_id}"

            internet_result = subprocess.run(
                ["docker", "network", "inspect", internet_network_full],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            internet_data = json.loads(internet_result.stdout)
            internet_bridge_id = internet_data[0]["Id"][:12]
            br_internet = f"br-{internet_bridge_id}"

            # internetサブネット取得
            internet_subnet = internet_data[0]["IPAM"]["Config"][0]["Subnet"]

            log_system_event(
                "Bridge interfaces detected",
                internal_bridge=br_internal,
                internet_bridge=br_internet,
                internet_subnet=internet_subnet,
            )

            # iptablesコマンド（ホスト側ではlegacyでない可能性もあるため、両方試す）
            iptables_cmds = ["iptables", "iptables-legacy"]

            for iptables_cmd in iptables_cmds:
                try:
                    subprocess.run(
                        [iptables_cmd, "--version"],
                        capture_output=True,
                        check=True,
                        timeout=5,
                    )
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            else:
                log_error(ComponentType.FIREWALL, "No iptables command found on host")
                return False

            # ホスト側FORWARD制御ルール追加（重複チェック付き）
            host_rules = [
                # 戻りトラフィック許可（外→内）
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internet,
                    "-o",
                    br_internal,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internet,
                    "-o",
                    br_internal,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                # sekimoreから internal→internet は許可
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "ACCEPT",
                ],
                # その他 internal→internet は DROP
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-j",
                    "DROP",
                ],
                # FORWARD許可（internet subnet → uplink）
                [
                    "-C",
                    "FORWARD",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "ACCEPT",
                ],
                # 戻りトラフィック許可（uplink → internet subnet）
                [
                    "-C",
                    "FORWARD",
                    "-d",
                    internet_subnet,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-d",
                    internet_subnet,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            ]

            # DNS Exfiltration対策ルール（sekimore以外のポート53をブロック）
            dns_filter_rules = [
                # UDP/53 LOG
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                # TCP/53 LOG
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                # UDP/53 DROP
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                # TCP/53 DROP
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
            ]

            # ホスト側NATルール
            nat_rules = [
                [
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "MASQUERADE",
                ],
                [
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "MASQUERADE",
                ],
            ]

            # ルール適用（-Cチェック→-A追加のペアで実行）
            all_rules = host_rules + dns_filter_rules + nat_rules

            for i in range(0, len(all_rules), 2):
                check_rule = all_rules[i]
                add_rule = all_rules[i + 1]

                # チェック実行
                check_result = subprocess.run(
                    [iptables_cmd] + check_rule,
                    capture_output=True,
                    timeout=5,
                )

                # 存在しない場合のみ追加
                if check_result.returncode != 0:
                    subprocess.run(
                        [iptables_cmd] + add_rule,
                        capture_output=True,
                        check=False,
                        timeout=5,
                    )

            log_system_event("Host-side firewall rules configured successfully")
            return True

        except Exception as e:
            log_error(
                ComponentType.FIREWALL,
                f"Failed to setup host firewall rules: {e}",
            )
            return False

    def cleanup(self) -> None:
        """ファイアウォールルールをクリーンアップ."""
        # すべてのドメインルールを削除
        for domain in list(self.domain_ipsets.keys()):
            self.remove_domain(domain)

        # iptablesフラッシュ（Docker DNSのNATルールは保護）
        self._run_command([self.iptables_cmd, "-F"])
        # NATテーブルはフラッシュしない（Docker DNSルールを保護）
        self._run_command([self.iptables_cmd, "-X"])

        log_system_event("Firewall cleaned up")
