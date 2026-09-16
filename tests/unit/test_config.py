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

    def it_validates_ignore_domains(sample_config_data):
        """Test that ignore_domains validation works."""
        config = Config(**sample_config_data)
        assert ".telemetry.example.com" in config.ignore_domains
        assert "healthcheck.example.com" in config.ignore_domains

    def it_defaults_name_and_description_to_none():
        """Test that name and description default to None."""
        config = Config()
        assert config.name is None
        assert config.description is None

    def it_loads_name_and_description():
        """Test that name and description can be set."""
        config = Config(name="My Gateway", description="Test gateway")
        assert config.name == "My Gateway"
        assert config.description == "Test gateway"

    def it_defaults_ignore_domains_to_empty():
        """Test that ignore_domains defaults to empty list."""
        config = Config()
        assert config.ignore_domains == []

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
        assert proxy.upstream_proxy_tls is False

    def it_supports_upstream_proxy_tls():
        """Test ProxyConfig with upstream_proxy_tls enabled."""
        proxy = ProxyConfig(
            upstream_proxy="proxy.example.com:3129",
            upstream_proxy_tls=True,
        )
        assert proxy.upstream_proxy_tls is True
        assert proxy.upstream_proxy == "proxy.example.com:3129"


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


def describe_domain_handlers():
    """domain_handlers / relay（中継関所）の設定."""

    def it_defaults_to_empty_and_no_relay_ports(sample_config_data):
        config = Config(**sample_config_data)
        assert config.domain_handlers == {}
        assert config.git_relay_domains() == []
        assert config.has_git_relay() is False
        assert config.relay_input_ports() == []
        assert Config().domain_handlers == {}
        assert Config().relay.https == "passthrough"

    def it_parses_git_relay_and_normalizes_keys():
        config = Config(
            domain_handlers={
                "GitHub.COM.": {"handler": "git-relay"},
                "telemetry.example.com": {"handler": "deny"},
                "static.example.com": {},
            }
        )
        assert config.domain_handlers["github.com"].handler == "git-relay"
        assert config.domain_handlers["telemetry.example.com"].handler == "deny"
        assert config.domain_handlers["static.example.com"].handler == "splice"
        assert config.git_relay_domains() == ["github.com"]
        assert config.has_git_relay() is True
        assert config.relay_input_ports() == [22, 8420, 443]

    def it_rejects_invalid_handler_wildcard_empty_and_duplicates():
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Config(domain_handlers={"github.com": {"handler": "proxy"}})
        with pytest.raises(ValidationError):
            Config(domain_handlers={".github.com": {"handler": "git-relay"}})
        with pytest.raises(ValidationError):
            Config(domain_handlers={"*.github.com": {"handler": "git-relay"}})
        with pytest.raises(ValidationError):
            Config(domain_handlers={"": {"handler": "deny"}})
        with pytest.raises(ValidationError):
            Config(
                domain_handlers={
                    "github.com": {"handler": "deny"},
                    "GITHUB.com": {"handler": "deny"},
                }
            )
        with pytest.raises(ValidationError):
            Config(domain_handlers="github.com")

    def it_rejects_two_git_relay_domains_on_the_same_ssh_port():
        from pydantic import ValidationError

        # ssh_port を省いた 2 つは同じ 22 になる
        with pytest.raises(ValidationError, match="both listen on ssh port 22"):
            Config(
                domain_handlers={
                    "a.example.com": {"handler": "git-relay"},
                    "b.example.com": {"handler": "git-relay"},
                }
            )
        with pytest.raises(ValidationError, match="both listen on ssh port 2222"):
            Config(
                domain_handlers={
                    "a.example.com": {"handler": "git-relay", "ssh_port": 2222},
                    "b.example.com": {"handler": "git-relay", "ssh_port": 2222},
                }
            )

    def it_splits_multiple_git_relay_domains_by_ssh_port():
        # 0.2.0: 2 つ目以降の上流は別ポートで受け、firewall の INPUT にもそのポートを開ける
        config = Config(
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "ghe.example.com": {
                    "handler": "git-relay",
                    "ssh_port": 2222,
                    "upstream": "ghe.example.com",
                    "oauth_client_id": "abc",  # relay だけが読むキーは無視される
                },
            }
        )
        assert config.git_relay_domains() == ["github.com", "ghe.example.com"]
        assert config.git_relay_ssh_ports() == {"github.com": 22, "ghe.example.com": 2222}
        assert config.relay_input_ports() == [22, 2222, 8420, 443]
        assert config.domain_handlers["ghe.example.com"].upstream == "ghe.example.com"
        # ssh_port を明示した 1 つだけでも動く（listen ポートと同じなら重複しない）
        one = Config(domain_handlers={"github.com": {"handler": "git-relay", "ssh_port": 22}})
        assert one.relay_input_ports() == [22, 8420, 443]

    def it_reads_relay_ports_and_ignores_relay_only_keys():
        config = Config(
            domain_handlers={"github.com": {"handler": "git-relay"}},
            relay={
                "ssh_listen": "0.0.0.0:2222",
                "api_listen": "127.0.0.1:9000",
                "https": "reject",
                "token_ttl": "12h",
                "bootstrap": "auto",
                "project": {"name": "x", "repos": [], "permissions": ["pr:create"]},
            },
        )
        assert config.relay.https == "reject"
        # reject でも 443 は開ける（relay が受けて即切断する。INPUT で落とすと無言タイムアウト）
        assert config.relay_input_ports() == [2222, 9000, 443]

    def it_needs_no_ports_for_deny_or_splice_only():
        config = Config(
            domain_handlers={
                "x.example.com": {"handler": "deny"},
                "y.example.com": {"handler": "splice"},
            }
        )
        assert config.relay_input_ports() == []
        assert config.has_git_relay() is False

    def it_loads_shared_fixtures_like_the_relay_binary():
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        without = Config.from_yaml(root / "tests" / "fixtures" / "config_without_relay.yml")
        assert without.domain_handlers == {}
        assert without.relay_input_ports() == []
        with_relay = Config.from_yaml(root / "tests" / "fixtures" / "config_with_relay.yml")
        assert with_relay.git_relay_domains() == ["github.com"]
        assert with_relay.domain_handlers["telemetry.example.com"].handler == "deny"
        assert with_relay.domain_handlers["static.example.com"].handler == "splice"
        assert with_relay.relay_input_ports() == [22, 8420, 443]
        assert "pypi.org" in with_relay.allow_domains

    def it_round_trips_through_yaml(tmp_path):
        from pathlib import Path

        config = Config(domain_handlers={"github.com": {"handler": "git-relay"}})
        out = tmp_path / "out.yml"
        config.to_yaml(Path(out))
        again = Config.from_yaml(Path(out))
        assert again.domain_handlers["github.com"].handler == "git-relay"
