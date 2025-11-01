"""pytest configuration and fixtures for sekimore-gw tests."""

import pytest


@pytest.fixture
def sample_allow_domains():
    """Sample allowed domains list for testing."""
    return [
        "pypi.org",
        ".pythonhosted.org",
        ".github.com",
        "api.openai.com",
    ]


@pytest.fixture
def sample_block_domains():
    """Sample blocked domains list for testing."""
    return [
        ".malicious.com",
        "adserver.example.com",
    ]


@pytest.fixture
def sample_allow_ips():
    """Sample allowed IPs list for testing."""
    return [
        "192.168.1.0/24",
        "10.0.0.1",
    ]


@pytest.fixture
def sample_block_ips():
    """Sample blocked IPs list for testing."""
    return [
        "203.0.113.0/24",
    ]


@pytest.fixture
def sample_config_data():
    """Sample configuration data for testing."""
    return {
        "allow_domains": [
            "pypi.org",
            ".pythonhosted.org",
            ".github.com",
        ],
        "block_domains": [
            ".malicious.com",
        ],
        "allow_ips": [],
        "block_ips": ["203.0.113.0/24"],
        "proxy": {
            "enabled": True,
            "port": 3128,
            "cache_enabled": True,
            "cache_size_mb": 1000,
            "upstream_proxy": None,
            "upstream_proxy_username": None,
            "upstream_proxy_password": None,
        },
        "network": {
            "lan_subnets": ["10.100.0.0/16"],
        },
        "database_path": "/data/security_gateway.db",
    }
