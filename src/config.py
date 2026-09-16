"""設定管理モジュール - config.ymlの読み込みとバリデーション."""

import ipaddress
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class DNSConfig(BaseModel):
    """DNS設定.

    全ての設定値はコード内で固定（設定ファイルでの変更不可）:
    - upstream: 127.0.0.11（Docker内蔵DNS）
    - port: 53（DNS標準ポート）
    - min_ttl: 60秒
    - max_ttl: 86400秒（24時間）

    理由: 誤設定を防止するため（例: 127.0.0.1に変更されるとSquid Proxyが失敗）
    """

    pass  # 設定項目なし（全て固定値）


class ProxyConfig(BaseModel):
    """プロキシ設定."""

    enabled: bool = Field(default=False, description="プロキシ有効化")
    port: int = Field(default=3128, description="プロキシポート")
    cache_enabled: bool = Field(default=True, description="キャッシュ有効化")
    cache_size_mb: int = Field(default=1000, description="キャッシュサイズ（MB）")
    upstream_proxy: str | None = Field(default=None, description="上位プロキシ（host:port）")
    upstream_proxy_tls: bool = Field(default=False, description="上位プロキシへの接続にTLSを使用")
    upstream_proxy_username: str | None = Field(
        default=None,
        description="上位プロキシ認証ユーザー名（環境変数SEKIMORE_UPSTREAM_PROXY_USERNAMEで上書き可能）",
    )
    upstream_proxy_password: str | None = Field(
        default=None,
        description="上位プロキシ認証パスワード（環境変数SEKIMORE_UPSTREAM_PROXY_PASSWORDで上書き可能）",
    )

    def model_post_init(self, __context) -> None:
        """環境変数から認証情報を読み取る."""
        # 環境変数から上位プロキシ認証情報を読み取り（config.ymlより優先）
        # SEKIMORE_プレフィックスで名前空間を分離
        if os.getenv("SEKIMORE_UPSTREAM_PROXY_USERNAME"):
            self.upstream_proxy_username = os.getenv("SEKIMORE_UPSTREAM_PROXY_USERNAME")
        if os.getenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD"):
            self.upstream_proxy_password = os.getenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD")


class NetworkConfig(BaseModel):
    """ネットワーク設定."""

    lan_subnets: list[str] = Field(
        default_factory=lambda: ["10.100.0.0/16"],
        description="LAN側ネットワークサブネット（docker-compose.yml の lan ネットワークと一致）",
    )
    # 0.2.2: 許可ドメイン / 許可 IP へ通す宛先 TCP ポート。空なら従来どおり全ポート。
    # IP 直指定の SSH など、別プロトコルで関所を迂回する経路を塞ぐ（例: [80, 443]）。変更は再起動で反映
    allowed_ports: list[int] = Field(
        default_factory=list,
        description="許可ドメイン・許可 IP へ通す宛先 TCP ポート（空 = 全ポート）。例: [80, 443]",
    )

    @field_validator("allowed_ports")
    @classmethod
    def validate_allowed_ports(cls, v: list[int]) -> list[int]:
        """1〜65535 の整数、重複なし."""
        out: list[int] = []
        for p in v:
            if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
                raise ValueError(f"network.allowed_ports: {p!r} is not a TCP port (1-65535)")
            if p not in out:
                out.append(p)
        return out


class DomainHandlerConfig(BaseModel):
    """domain_handlers の 1 エントリ（中継関所）."""

    handler: Literal["splice", "git-relay", "https-relay", "deny"] = Field(
        default="splice",
        description=(
            "splice=従来どおり / git-relay=関所の SSH で受ける（DNS は関所 IP）/ "
            "https-relay=443 だけを関所の passthrough で通す（送信上限を掛ける。0.2.2）/ deny=拒否"
        ),
    )
    # 0.2.2: 443 passthrough の送信上限（バイト）。省略時は relay.https_max_upload_bytes、-1 で無制限。relay が読む
    max_upload_bytes: int | None = Field(
        default=None,
        description="443 passthrough で dev → 上流へ送れる 1 接続あたりの上限バイト数。-1 で無制限。省略時は relay の既定",
    )

    @field_validator("max_upload_bytes")
    @classmethod
    def validate_max_upload_bytes(cls, v: int | None) -> int | None:
        if v is not None and (v == 0 or v < -1):
            raise ValueError(
                "max_upload_bytes must be -1 (unlimited) or a positive number of bytes; "
                "0 would block every HTTPS request"
            )
        return v

    # 0.2.0: 複数の git-relay ドメインはポートで分ける（SSH の exec はリポジトリパスしか運ばない）
    ssh_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="git-relay: 関所側 SSH ポート。省略時は relay.ssh_listen のポート（既定上流）",
    )
    upstream: str | None = Field(
        default=None, description="git-relay: 上流ホスト。省略時はドメイン名（残りは relay が読む）"
    )


class RelayConfig(BaseModel):
    """relay セクションのうち Python が読む部分.

    残りのキーは relay バイナリ（Rust）が所有する。Pydantic の既定（未知キー無視）で素通しする。
    """

    ssh_listen: str = Field(default="0.0.0.0:22", description="関所 SSH の listen アドレス")
    api_listen: str = Field(default="0.0.0.0:8420", description="関所 HTTP API の listen アドレス")
    https_listen: str = Field(
        default="0.0.0.0:443", description="同一ドメインの 443 を受けるアドレス"
    )
    https: Literal["passthrough", "reject"] = Field(
        default="passthrough",
        description="443 の扱い（passthrough=実 upstream へ素通し / reject=即切断）",
    )


def _port_of(listen: str, default: int) -> int:
    """'host:port' からポートを取り出す."""
    try:
        return int(str(listen).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return default


class Config(BaseModel):
    """AI Security Gateway 設定."""

    # ゲートウェイ情報
    name: str | None = Field(default=None, description="ゲートウェイ名称")
    description: str | None = Field(default=None, description="ゲートウェイ説明")

    # ドメインフィルタリング
    allow_domains: list[str] = Field(default_factory=list, description="許可ドメインリスト")
    block_domains: list[str] = Field(default_factory=list, description="拒否ドメインリスト")
    ignore_domains: list[str] = Field(
        default_factory=list, description="無視ドメインリスト（UI非表示）"
    )

    # IPフィルタリング
    allow_ips: list[str] = Field(default_factory=list, description="許可IPリスト")
    block_ips: list[str] = Field(default_factory=list, description="拒否IPリスト")

    # コンポーネント設定
    dns: DNSConfig = Field(default_factory=DNSConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)

    # データベース
    database_path: str = Field(
        default="/data/security_gateway.db", description="SQLiteデータベースパス"
    )

    # 中継関所（relay）。無ければ既存挙動は不変（doc/sekimore-gw/requirements/04-relay.md）
    domain_handlers: dict[str, DomainHandlerConfig] = Field(
        default_factory=dict,
        description="ドメイン別 handler（git-relay / deny / splice）。完全一致 FQDN",
    )
    relay: RelayConfig = Field(default_factory=RelayConfig)

    @field_validator("domain_handlers", mode="before")
    @classmethod
    def normalize_domain_handlers(cls, v: Any) -> Any:
        """キーを正規化（lower、末尾 . 除去）し、ワイルドカード・空・重複を拒否する."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("domain_handlers must be a mapping of domain -> {handler: ...}")
        out: dict[str, Any] = {}
        for key, val in v.items():
            norm = str(key).strip().rstrip(".").lower()
            if not norm:
                raise ValueError("domain_handlers: empty domain key")
            if norm.startswith(".") or "*" in norm:
                raise ValueError(
                    f"domain_handlers: {key!r} must be an exact FQDN "
                    "(a wildcard would redirect every subdomain, e.g. api.github.com)"
                )
            if norm in out:
                raise ValueError(f"domain_handlers: duplicate domain {norm!r}")
            out[norm] = val if val is not None else {}
        return out

    @model_validator(mode="after")
    def validate_git_relay_ports(self) -> "Config":
        """複数の git-relay ドメインは別々の SSH ポートで受ける（0.2.0）.

        SSH の exec はリポジトリパスしか運ばないので、上流はポートで区別する。
        ssh_port を省いたエントリは relay.ssh_listen のポート（既定上流）になり、1 つまで。
        """
        if self.https_relay_domains() and not self.git_relay_domains():
            raise ValueError(
                "domain_handlers: https-relay needs at least one git-relay domain in this version "
                "(the relay's 443 passthrough is started with it)"
            )
        seen: dict[int, str] = {}
        for domain, port in self.git_relay_ssh_ports().items():
            if port in seen:
                raise ValueError(
                    f"domain_handlers: git-relay domains {seen[port]!r} and {domain!r} would both "
                    f"listen on ssh port {port}; every git-relay domain but the default one needs "
                    "its own ssh_port because the SSH exec request carries only the repository path"
                )
            seen[port] = domain
        return self

    def git_relay_ssh_ports(self) -> dict[str, int]:
        """git-relay ドメイン → 関所側 SSH ポート（ssh_port 省略時は relay.ssh_listen のポート）."""
        default_port = _port_of(self.relay.ssh_listen, 22)
        return {
            d: (h.ssh_port if h.ssh_port is not None else default_port)
            for d, h in self.domain_handlers.items()
            if h.handler == "git-relay"
        }

    def git_relay_domains(self) -> list[str]:
        """handler が git-relay のドメイン."""
        return [d for d, h in self.domain_handlers.items() if h.handler == "git-relay"]

    def https_relay_domains(self) -> list[str]:
        """handler が https-relay のドメイン（0.2.2。443 だけ関所を通す）."""
        return [d for d, h in self.domain_handlers.items() if h.handler == "https-relay"]

    def relay_domains(self) -> list[str]:
        """DNS で関所 IP を返すドメイン（git-relay + https-relay）."""
        return self.git_relay_domains() + self.https_relay_domains()

    def has_git_relay(self) -> bool:
        return bool(self.git_relay_domains())

    def relay_input_ports(self) -> list[int]:
        """relay のために lan_if 側 INPUT で開けるポート。git-relay が無ければ空.

        443 は https の設定に関係なく開ける（reject でも relay が受けて即切断する。
        INPUT で落とすと無言タイムアウトになる）。
        """
        if not self.has_git_relay():
            return []
        ssh_ports: list[int] = [_port_of(self.relay.ssh_listen, 22)]
        for port in self.git_relay_ssh_ports().values():
            if port not in ssh_ports:
                ssh_ports.append(port)
        return [
            *ssh_ports,
            _port_of(self.relay.api_listen, 8420),
            _port_of(self.relay.https_listen, 443),
        ]

    @field_validator("allow_ips", "block_ips")
    @classmethod
    def validate_ip_entries(cls, v: list[str]) -> list[str]:
        """IPエントリーのバリデーション（単一IP、CIDR、レンジ）."""
        for entry in v:
            if "-" in entry:
                # IPレンジ形式: 192.168.1.1-192.168.1.10
                start_ip_str, end_ip_str = entry.split("-", 1)
                try:
                    ipaddress.ip_address(start_ip_str.strip())
                    ipaddress.ip_address(end_ip_str.strip())
                except ValueError as e:
                    raise ValueError(f"Invalid IP range: {entry}") from e
            elif "/" in entry:
                # CIDR形式: 192.168.1.0/24
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR notation: {entry}") from e
            else:
                # 単一IP: 192.168.1.1
                try:
                    ipaddress.ip_address(entry)
                except ValueError as e:
                    raise ValueError(f"Invalid IP address: {entry}") from e
        return v

    @classmethod
    def from_yaml(cls, path: Path) -> "Config":
        """YAMLファイルから設定を読み込む."""
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)

        if data is None:
            data = {}

        return cls(**data)

    def to_yaml(self, path: Path) -> None:
        """設定をYAMLファイルに書き込む."""
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, allow_unicode=True)


def load_config(config_path: Path | None = None) -> Config:
    """設定ファイルを読み込む.

    Args:
        config_path: 設定ファイルパス（未指定時は環境変数またはデフォルトパス）

    Returns:
        Config: 読み込んだ設定
    """
    if config_path is None:
        config_path = Path("/etc/sekimore/config.yml")

    if not config_path.exists():
        # デフォルト設定で初期化
        return Config()

    return Config.from_yaml(config_path)
