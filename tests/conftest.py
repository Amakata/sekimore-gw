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
def sample_ignore_domains():
    """Sample ignored domains list for testing."""
    return [
        ".telemetry.example.com",
        "healthcheck.example.com",
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
        "ignore_domains": [
            ".telemetry.example.com",
            "healthcheck.example.com",
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


@pytest.fixture(autouse=True)
def _stop_the_shared_log_streamer():
    """Leave no background task behind when the suite ends.

    `web_ui.app` keeps one `LogStreamer` in a module global, and it owns an asyncio task that
    polls the database. A test that touches the streaming endpoint leaves that task running, and
    pytest's process then has something to wait for after the last test reports. Locally the loop
    is already closed by then and nothing notices; on a CI runner the process hung for nine
    minutes after printing "426 passed", until the job timed out.

    Clearing the global after every test costs nothing and removes the class of failure.
    """
    yield
    try:
        from src.web_ui import app as _app
    except Exception:  # the module is not importable in every test environment
        return
    streamer = getattr(_app, "_streamer", None)
    if streamer is None:
        return
    task = getattr(streamer, "_task", None)
    if task is not None and not task.done():
        task.cancel()
    _app._streamer = None
