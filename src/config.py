"""設定管理モジュール - config.ymlの読み込みとバリデーション."""

import ipaddress
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


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


class Config(BaseModel):
    """AI Security Gateway 設定."""

    # ドメインフィルタリング
    allow_domains: list[str] = Field(default_factory=list, description="許可ドメインリスト")
    block_domains: list[str] = Field(default_factory=list, description="拒否ドメインリスト")

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
