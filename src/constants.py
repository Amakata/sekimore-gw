"""共通定数定義.

環境変数からオーバーライド可能な設定値を一元管理します。
"""

import os

# データベースパス
DB_PATH = os.getenv("SEKIMORE_DB_PATH", "/data/security_gateway.db")

# 設定ファイルパス
CONFIG_PATH = os.getenv("SEKIMORE_CONFIG_PATH", "/etc/sekimore/config.yml")

# ログファイルパス
ULOG_FILE_PATH = os.getenv("SEKIMORE_ULOG_PATH", "/var/log/ulog/syslogemu.log")

# Squid設定パス
SQUID_CONFIG_PATH = os.getenv("SEKIMORE_SQUID_CONFIG", "/etc/squid/squid.conf")
SQUID_TEMPLATE_PATH = os.getenv("SEKIMORE_SQUID_TEMPLATE", "/etc/squid/squid.conf.template")

# デフォルトネットワーク設定
DEFAULT_LAN_SUBNETS = ["172.20.0.0/16", "192.168.0.0/16", "10.0.0.0/8"]

# DNS設定
DEFAULT_DNS_PORT = int(os.getenv("SEKIMORE_DNS_PORT", "53"))
DEFAULT_UPSTREAM_DNS = os.getenv("SEKIMORE_UPSTREAM_DNS", "127.0.0.11")

# Web UI設定
WEB_UI_HOST = os.getenv("SEKIMORE_WEB_HOST", "0.0.0.0")
WEB_UI_PORT = int(os.getenv("SEKIMORE_WEB_PORT", "8080"))

# キャッシュ設定
DNS_CACHE_ENABLED = os.getenv("SEKIMORE_DNS_CACHE_ENABLED", "true").lower() == "true"
DNS_CACHE_REFRESH_INTERVAL = int(os.getenv("SEKIMORE_DNS_CACHE_REFRESH", "30"))


def get_db_path(override: str | None = None) -> str:
    """データベースパスを取得.

    Args:
        override: オーバーライドするパス（テスト用）

    Returns:
        データベースパス
    """
    return override or DB_PATH


def get_config_path(override: str | None = None) -> str:
    """設定ファイルパスを取得.

    Args:
        override: オーバーライドするパス（テスト用）

    Returns:
        設定ファイルパス
    """
    return override or CONFIG_PATH
