"""Unit tests for config module."""

import pytest
import yaml

from src.config import Config, NetworkConfig, ProxyConfig


def describe_config():
    """Tests for Config class."""

    def it_loads_default_config(tmp_path, sample_config_data):
        """Test loading default config from YAML."""
        from pathlib import Path

        config_file = tmp_path / "test_config.yml"
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        config = Config.from_yaml(Path(config_file))

        assert isinstance(config, Config)
        assert "pypi.org" in config.allow_domains
        assert ".malicious.com" in config.block_domains
        assert config.proxy.enabled is True
        assert config.proxy.port == 3128

    def it_validates_allow_domains(sample_config_data):
        """Test that allow_domains validation works."""
        config = Config(**sample_config_data)
        assert "pypi.org" in config.allow_domains
        assert ".pythonhosted.org" in config.allow_domains

    def it_validates_proxy_config(sample_config_data):
        """Test that proxy config validation works."""
        config = Config(**sample_config_data)
        assert config.proxy.enabled is True
        assert config.proxy.cache_enabled is True
        assert config.proxy.cache_size_mb == 1000


def describe_proxy_config():
    """Tests for ProxyConfig class."""

    def it_has_default_values():
        """Test ProxyConfig default values."""
        proxy = ProxyConfig()
        assert proxy.enabled is False
        assert proxy.port == 3128
        assert proxy.cache_enabled is True
        assert proxy.cache_size_mb == 1000
        assert proxy.upstream_proxy is None


def describe_network_config():
    """Tests for NetworkConfig class."""

    def it_has_default_lan_subnets():
        """Test NetworkConfig default LAN subnets."""
        network = NetworkConfig()
        assert "10.100.0.0/16" in network.lan_subnets

    def it_validates_lan_subnets():
        """Test LAN subnet validation."""
        network = NetworkConfig(lan_subnets=["192.168.1.0/24", "10.0.0.0/8"])
        assert len(network.lan_subnets) == 2


def describe_load_config():
    """Tests for load_config function."""

    def it_loads_config_from_file(tmp_path, sample_config_data):
        """Test load_config loads from file."""
        from pathlib import Path

        from src.config import load_config

        config_file = tmp_path / "test_config.yml"
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        config = load_config(Path(config_file))

        assert config is not None
        assert "pypi.org" in config.allow_domains
        assert config.proxy.enabled is True

    def it_loads_config_with_defaults(tmp_path):
        """Test load_config handles minimal config.

        FIXED: Removed dns.cache_enabled check as DNSConfig has no attributes.
        DNSConfig is an empty class (pass only) with all values fixed in code.
        Also simplified minimal_config to match actual schema.
        """
        from pathlib import Path

        from src.config import load_config

        minimal_config = {
            "allow_domains": [],
            "block_domains": [],
            "priority_ips": [],
            "network": {
                "lan_subnets": [],
                "static_allow_ips": [],
                "static_block_ips": [],
            },
            "proxy": {
                "enabled": False,
                "port": 3128,
                "cache_enabled": False,
                "cache_size_mb": 0,
            },
        }

        config_file = tmp_path / "minimal_config.yml"
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(minimal_config, f)

        config = load_config(Path(config_file))

        assert config.allow_domains == []
        assert config.proxy.enabled is False
        assert config.proxy.cache_enabled is False


def describe_proxy_config_auth():
    """Tests for ProxyConfig authentication."""

    def it_loads_auth_from_environment(monkeypatch):
        """Test model_post_init loads credentials from environment."""
        monkeypatch.setenv("SEKIMORE_UPSTREAM_PROXY_USERNAME", "testuser")
        monkeypatch.setenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD", "testpass")

        # model_post_init is called automatically during instantiation
        proxy = ProxyConfig()

        assert proxy.upstream_proxy_username == "testuser"
        assert proxy.upstream_proxy_password == "testpass"

    def it_loads_only_username_from_environment(monkeypatch):
        """Test model_post_init with only username set."""
        monkeypatch.setenv("SEKIMORE_UPSTREAM_PROXY_USERNAME", "onlyuser")

        proxy = ProxyConfig()

        assert proxy.upstream_proxy_username == "onlyuser"
        assert proxy.upstream_proxy_password is None

    def it_loads_only_password_from_environment(monkeypatch):
        """Test model_post_init with only password set."""
        monkeypatch.setenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD", "onlypass")

        proxy = ProxyConfig()

        assert proxy.upstream_proxy_password == "onlypass"


def describe_ip_validation():
    """Tests for IP validation."""

    def it_validates_ip_range():
        """Test validate_ip_entries accepts valid IP ranges."""
        config_data = {
            "allow_ips": ["192.168.1.1-192.168.1.10"],
            "block_ips": [],
        }
        config = Config(**config_data)
        assert "192.168.1.1-192.168.1.10" in config.allow_ips

    def it_rejects_invalid_ip_range():
        """Test validate_ip_entries rejects invalid IP ranges."""
        with pytest.raises(ValueError, match="Invalid IP range"):
            Config(allow_ips=["192.168.1.1-invalid"])

    def it_validates_cidr_notation():
        """Test validate_ip_entries accepts CIDR notation."""
        config = Config(allow_ips=["192.168.1.0/24"])
        assert "192.168.1.0/24" in config.allow_ips

    def it_rejects_invalid_cidr():
        """Test validate_ip_entries rejects invalid CIDR."""
        with pytest.raises(ValueError, match="Invalid CIDR notation"):
            Config(allow_ips=["192.168.1.0/999"])

    def it_validates_single_ip():
        """Test validate_ip_entries accepts single IP."""
        config = Config(allow_ips=["192.168.1.1"])
        assert "192.168.1.1" in config.allow_ips

    def it_rejects_invalid_single_ip():
        """Test validate_ip_entries rejects invalid single IP."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            Config(allow_ips=["not.an.ip.address"])


def describe_yaml_operations():
    """Tests for YAML file operations."""

    def it_raises_on_missing_yaml_file():
        """Test from_yaml raises FileNotFoundError for missing file."""
        from pathlib import Path

        with pytest.raises(FileNotFoundError, match="Config file not found"):
            Config.from_yaml(Path("/nonexistent/config.yml"))

    def it_handles_empty_yaml_file(tmp_path):
        """Test from_yaml handles empty YAML file."""
        from pathlib import Path

        config_file = tmp_path / "empty.yml"
        with open(config_file, "w", encoding="utf-8") as f:
            f.write("")  # Empty file

        config = Config.from_yaml(Path(config_file))

        # Should create config with defaults
        assert config.allow_domains == []
        assert config.proxy.enabled is False

    def it_writes_to_yaml_file(tmp_path, sample_config_data):
        """Test to_yaml writes config to file."""
        from pathlib import Path

        config = Config(**sample_config_data)
        output_file = tmp_path / "output.yml"

        config.to_yaml(Path(output_file))

        assert output_file.exists()

        # Verify can be loaded back
        loaded_config = Config.from_yaml(Path(output_file))
        assert loaded_config.allow_domains == config.allow_domains
        assert loaded_config.proxy.enabled == config.proxy.enabled


def describe_load_config_function():
    """Tests for load_config convenience function."""

    def it_returns_default_when_path_not_exists():
        """Test load_config returns default config when file doesn't exist."""
        from pathlib import Path

        from src.config import load_config

        # Use a path that doesn't exist
        config = load_config(Path("/nonexistent/sekimore/config.yml"))

        # Should return default config
        assert config.allow_domains == []
        assert config.proxy.enabled is False
