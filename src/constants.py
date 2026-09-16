"""Shared constants.

Centralizes the settings that can be overridden through environment variables.
"""

import os

# Database path
DB_PATH = os.getenv("SEKIMORE_DB_PATH", "/data/security_gateway.db")

# Configuration file path
CONFIG_PATH = os.getenv("SEKIMORE_CONFIG_PATH", "/etc/sekimore/config.yml")

# Log file path
ULOG_FILE_PATH = os.getenv("SEKIMORE_ULOG_PATH", "/var/log/ulog/syslogemu.log")

# Squid configuration paths
SQUID_CONFIG_PATH = os.getenv("SEKIMORE_SQUID_CONFIG", "/etc/squid/squid.conf")
SQUID_TEMPLATE_PATH = os.getenv("SEKIMORE_SQUID_TEMPLATE", "/etc/squid/squid.conf.template")

# Default network settings
DEFAULT_LAN_SUBNETS = ["172.20.0.0/16", "192.168.0.0/16", "10.0.0.0/8"]

# DNS settings
DEFAULT_DNS_PORT = int(os.getenv("SEKIMORE_DNS_PORT", "53"))
DEFAULT_UPSTREAM_DNS = os.getenv("SEKIMORE_UPSTREAM_DNS", "127.0.0.11")

# Web UI settings
WEB_UI_HOST = os.getenv("SEKIMORE_WEB_HOST", "0.0.0.0")
WEB_UI_PORT = int(os.getenv("SEKIMORE_WEB_PORT", "8080"))

# Cache settings
DNS_CACHE_ENABLED = os.getenv("SEKIMORE_DNS_CACHE_ENABLED", "true").lower() == "true"
DNS_CACHE_REFRESH_INTERVAL = int(os.getenv("SEKIMORE_DNS_CACHE_REFRESH", "30"))


def get_db_path(override: str | None = None) -> str:
    """Return the database path.

    Args:
        override: Path to use instead (for tests)

    Returns:
        The database path
    """
    return override or DB_PATH


def get_config_path(override: str | None = None) -> str:
    """Return the configuration file path.

    Args:
        override: Path to use instead (for tests)

    Returns:
        The configuration file path
    """
    return override or CONFIG_PATH
