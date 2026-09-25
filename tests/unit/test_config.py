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
    """domain_handlers / relay (the relay) configuration."""

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
            allow_domains=["github.com"],
            domain_handlers={
                "GitHub.COM.": {"handler": "git-relay"},
                "telemetry.example.com": {"handler": "deny"},
                "static.example.com": {},
            },
        )
        assert config.domain_handlers["github.com"].handler == "github"
        assert config.domain_handlers["telemetry.example.com"].handler == "deny"
        assert config.domain_handlers["static.example.com"].handler == "splice"
        assert config.git_relay_domains() == ["github.com"]
        assert config.has_git_relay() is True
        assert config.relay_input_ports() == [22, 8420, 443]

    def it_still_accepts_the_original_git_relay_spelling(sample_config_data):
        """0.2.6 renamed the handler to `github`; a config written for 0.1.x must keep working."""
        allow = ["github.com", "ghe.example.com"]
        old = Config(allow_domains=allow, domain_handlers={"github.com": {"handler": "git-relay"}})
        new = Config(allow_domains=allow, domain_handlers={"github.com": {"handler": "github"}})
        assert old.domain_handlers["github.com"].handler == "github"
        assert old.model_dump() == new.model_dump()
        # Everything downstream of the name behaves the same
        assert old.git_relay_domains() == new.git_relay_domains() == ["github.com"]
        assert old.has_git_relay() is new.has_git_relay() is True
        assert old.relay_input_ports() == new.relay_input_ports()
        # Mixing the two spellings across domains is fine; both normalize
        mixed = Config(
            allow_domains=allow,
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "ghe.example.com": {"handler": "github", "ssh_port": 2222},
            },
        )
        assert sorted(mixed.git_relay_domains()) == ["ghe.example.com", "github.com"]

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

        # Two entries without an ssh_port both land on 22
        with pytest.raises(ValidationError, match="both listen on ssh port 22"):
            Config(
                allow_domains=["a.example.com", "b.example.com"],
                domain_handlers={
                    "a.example.com": {"handler": "git-relay"},
                    "b.example.com": {"handler": "git-relay"},
                },
            )
        with pytest.raises(ValidationError, match="both listen on ssh port 2222"):
            Config(
                allow_domains=["a.example.com", "b.example.com"],
                domain_handlers={
                    "a.example.com": {"handler": "git-relay", "ssh_port": 2222},
                    "b.example.com": {"handler": "git-relay", "ssh_port": 2222},
                },
            )

    def it_splits_multiple_git_relay_domains_by_ssh_port():
        # 0.2.0: every upstream after the first listens on its own port, and the firewall opens that port in INPUT
        config = Config(
            allow_domains=["github.com", "ghe.example.com"],
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "ghe.example.com": {
                    "handler": "git-relay",
                    "ssh_port": 2222,
                    "upstream": "ghe.example.com",
                    "oauth_client_id": "abc",  # Keys only the relay reads are ignored here
                },
            },
        )
        assert config.git_relay_domains() == ["github.com", "ghe.example.com"]
        assert config.git_relay_ssh_ports() == {"github.com": 22, "ghe.example.com": 2222}
        assert config.relay_input_ports() == [22, 2222, 8420, 443]
        assert config.domain_handlers["ghe.example.com"].upstream == "ghe.example.com"
        # A single entry with an explicit ssh_port works too (no duplicate when it matches the listen port)
        one = Config(
            allow_domains=["github.com"],
            domain_handlers={"github.com": {"handler": "git-relay", "ssh_port": 22}},
        )
        assert one.relay_input_ports() == [22, 8420, 443]

    def it_reads_relay_ports_and_ignores_relay_only_keys():
        config = Config(
            allow_domains=["github.com"],
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
        # Even with reject, 443 stays open: the relay accepts and closes immediately, whereas dropping it in INPUT would time out silently
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

        config = Config(
            allow_domains=["github.com"],
            domain_handlers={"github.com": {"handler": "git-relay"}},
        )
        out = tmp_path / "out.yml"
        config.to_yaml(Path(out))
        again = Config.from_yaml(Path(out))
        assert again.domain_handlers["github.com"].handler == "github"


def describe_relayed_domains_must_be_allowed():
    """0.2.15: DNS answers with the gateway for a relayed domain, so allow_domains has to cover it.

    Reproduced on a live gateway on 2026-09-18: api.github.com was added as a handler and dropped
    from allow_domains, and the relayed calls began failing with nothing saying why.
    """

    def it_refuses_a_relayed_domain_the_allow_list_does_not_cover():
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="not covered by allow_domains"):
            Config(
                allow_domains=["github.com"],
                domain_handlers={
                    "github.com": {"handler": "git-relay"},
                    "api.github.com": {"handler": "https-relay"},
                },
            )

    def it_accepts_a_wildcard_that_covers_it():
        cfg = Config(
            allow_domains=[".github.com"],
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "api.github.com": {"handler": "https-relay"},
            },
        )
        assert cfg.relay_domains() == ["github.com", "api.github.com"]

    def it_matches_on_label_boundaries():
        """`.github.com` covers api.github.com and not evilgithub.com — a name anyone can register."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="evilgithub.com"):
            Config(
                allow_domains=[".github.com"],
                domain_handlers={
                    "github.com": {"handler": "git-relay"},
                    "evilgithub.com": {"handler": "https-relay"},
                },
            )

    def it_ignores_deny_and_splice():
        """A deny entry exists to refuse a domain; requiring it in the allow list is backwards.

        splice resolves normally, so it never points at the gateway either. Only the handlers that
        redirect DNS are checked.
        """
        cfg = Config(
            allow_domains=["github.com"],
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "telemetry.example.com": {"handler": "deny"},
                "static.example.com": {"handler": "splice"},
            },
        )
        assert cfg.relay_domains() == ["github.com"]

    def it_says_which_domains_are_missing():
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as e:
            Config(
                allow_domains=["github.com"],
                domain_handlers={
                    "github.com": {"handler": "git-relay"},
                    "ghcr.io": {"handler": "https-relay"},
                    "pkg-containers.githubusercontent.com": {"handler": "https-relay"},
                },
            )
        msg = str(e.value)
        assert "ghcr.io" in msg and "pkg-containers.githubusercontent.com" in msg


def describe_allowed_ports_config():
    """0.2.2: network.allowed_ports."""

    def it_defaults_to_all_ports_and_validates_values():
        from pydantic import ValidationError

        assert Config().network.allowed_ports == []
        cfg = Config(network={"allowed_ports": [443, 80, 443]})
        assert cfg.network.allowed_ports == [443, 80]  # Duplicates are dropped, order is preserved
        # pydantic coerces numeric strings to int (so YAML's "443" is accepted)
        assert Config(network={"allowed_ports": ["443"]}).network.allowed_ports == [443]
        for bad in ([0], [70000], ["https"]):
            with pytest.raises(ValidationError):
                Config(network={"allowed_ports": bad})


def describe_https_relay_handler():
    """0.2.2: https-relay (only 443 goes through the relay) and the max_upload_bytes upload cap (-1 = unlimited)."""

    def it_accepts_https_relay_next_to_git_relay_and_validates_caps():
        from pydantic import ValidationError

        cfg = Config(
            allow_domains=["github.com", "ghcr.io", "registry-1.docker.io"],
            domain_handlers={
                "github.com": {"handler": "git-relay", "max_upload_bytes": 262144},
                "ghcr.io": {"handler": "https-relay", "max_upload_bytes": -1},
                "registry-1.docker.io": {"handler": "https-relay"},
            },
        )
        assert cfg.https_relay_domains() == ["ghcr.io", "registry-1.docker.io"]
        assert cfg.relay_domains() == ["github.com", "ghcr.io", "registry-1.docker.io"]
        assert cfg.git_relay_ssh_ports() == {"github.com": 22}  # https-relay has no SSH port
        assert cfg.relay_input_ports() == [22, 8420, 443]
        for bad in (0, -2):
            with pytest.raises(ValidationError, match="max_upload_bytes"):
                Config(
                    domain_handlers={
                        "ghcr.io": {"handler": "https-relay", "max_upload_bytes": bad},
                        "github.com": {"handler": "git-relay"},
                    }
                )
        # https-relay without a git-relay is a configuration error
        with pytest.raises(ValidationError, match="needs at least one git-relay"):
            Config(domain_handlers={"ghcr.io": {"handler": "https-relay"}})


def describe_proxy_allowlist_excludes_relayed_domains():
    """Squid resolves names itself through Docker's DNS, so it never sees the DNS filter's
    answers. A relayed domain left in its allowlist stays reachable by pointing a client at
    the proxy (`https_proxy=gw:3128`), which skips the relay's policy entirely."""

    def a_relayed_domain_is_removed():
        cfg = Config(
            allow_domains=["github.com", "api.github.com", "deb.debian.org"],
            domain_handlers={"github.com": {"handler": "git-relay"}},
        )
        assert cfg.proxy_denied_domains() == ["github.com"]
        assert cfg.proxy_allow_domains() == ["api.github.com", "deb.debian.org"]

    def https_relay_and_deny_are_removed_too():
        cfg = Config(
            allow_domains=["github.com", "ghcr.io", "evil.example.com", "pypi.org"],
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "ghcr.io": {"handler": "https-relay"},
                "evil.example.com": {"handler": "deny"},
            },
        )
        assert cfg.proxy_allow_domains() == ["pypi.org"]

    def splice_stays_because_it_is_meant_to_go_out_directly():
        cfg = Config(
            allow_domains=["example.com", "github.com"],
            domain_handlers={
                "example.com": {"handler": "splice"},
                "github.com": {"handler": "git-relay"},
            },
        )
        assert cfg.proxy_allow_domains() == ["example.com"]

    def a_wildcard_covering_a_relayed_domain_stays():
        # `.github.com` is how api.github.com and codeload.github.com are usually allowed, and
        # neither is the relay's to own. Dropping the wildcard would take them out with it, so
        # the generated Squid config denies the exact name ahead of the allow rule instead —
        # see the proxy_manager tests.
        for wildcard in (".github.com", "*.github.com"):
            cfg = Config(
                allow_domains=[wildcard, "api.github.com", "pypi.org"],
                domain_handlers={"github.com": {"handler": "git-relay"}},
            )
            assert cfg.proxy_allow_domains() == [wildcard, "api.github.com", "pypi.org"]

    def without_handlers_the_allowlist_is_unchanged():
        domains = ["github.com", ".debian.org", "pypi.org"]
        cfg = Config(allow_domains=domains)
        assert cfg.proxy_allow_domains() == domains

    def a_trailing_dot_or_upper_case_still_matches():
        cfg = Config(
            allow_domains=["GitHub.com.", "pypi.org"],
            domain_handlers={"github.com": {"handler": "git-relay"}},
        )
        assert cfg.proxy_allow_domains() == ["pypi.org"]


def describe_reload_mode():
    """0.2.13: when a change to config.yml takes effect. The file is writable from dev, so
    applying on save lets an agent rewrite the rules it is held by."""

    def the_default_is_auto_so_existing_deployments_do_not_change():
        assert Config().reload == "auto"
        assert Config().reload_window_seconds() is None
        assert Config().reload_is_windowed() is False

    def manual_is_accepted():
        assert Config(reload="manual").reload == "manual"
        assert Config(reload="manual").reload_window_seconds() is None

    def a_duration_opens_a_window():
        assert Config(reload="30m").reload_window_seconds() == 1800
        assert Config(reload="2h").reload_window_seconds() == 7200
        assert Config(reload="90s").reload_window_seconds() == 90
        assert Config(reload="1d").reload_window_seconds() == 86400
        assert Config(reload="30m").reload_is_windowed() is True

    def the_value_is_case_insensitive_and_trimmed():
        assert Config(reload="  AUTO ").reload == "auto"
        assert Config(reload="30M").reload_window_seconds() == 1800

    def anything_else_is_refused():
        from pydantic import ValidationError

        # Silently falling back to auto would leave the window open without saying so.
        for bad in ("sometimes", "0m", "-5m", "30", "m", "", "30x"):
            with pytest.raises(ValidationError, match="reload"):
                Config(reload=bad)


def describe_direct_egress():
    """#212: whether dev's ordinary traffic may leave the gateway without the upstream proxy."""

    def the_default_is_allow_so_existing_deployments_do_not_change():
        assert Config().proxy.direct_egress == "allow"
        assert Config().proxy.direct_egress_denied() is False

    def deny_needs_an_upstream_proxy():
        from pydantic import ValidationError

        # Without one it would only cut dev off from every allowed domain, with DNS still
        # answering -- which reads as the network failing, not as a setting.
        with pytest.raises(ValidationError, match="direct_egress"):
            Config(proxy=ProxyConfig(enabled=True, direct_egress="deny"))

    def deny_needs_squid_running_too():
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="direct_egress"):
            Config(
                proxy=ProxyConfig(
                    enabled=False, upstream_proxy="proxy.corp:8080", direct_egress="deny"
                )
            )

    def deny_with_an_upstream_proxy_is_accepted_and_in_force():
        cfg = Config(
            proxy=ProxyConfig(enabled=True, upstream_proxy="proxy.corp:8080", direct_egress="deny")
        )
        assert cfg.proxy.direct_egress_denied() is True

    def allow_is_never_in_force_whatever_the_proxy_says():
        cfg = Config(proxy=ProxyConfig(enabled=True, upstream_proxy="proxy.corp:8080"))
        assert cfg.proxy.uses_upstream() is True
        assert cfg.proxy.direct_egress_denied() is False

    def an_unknown_mode_is_refused():
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ProxyConfig(direct_egress="sometimes")


def describe_no_proxy():
    """#212: the extra NO_PROXY entries handed to the dev container."""

    def the_default_is_empty():
        assert ProxyConfig().no_proxy == []
        assert ProxyConfig().normalized_no_proxy() == []

    def a_glob_is_read_as_the_suffix_form_the_tools_understand():
        # curl, Go and Python only know `.test`; `*.test` is how a shell habit writes it.
        assert ProxyConfig(no_proxy=["*.test"]).normalized_no_proxy() == [".test"]

    def the_dotted_form_and_a_bare_host_pass_through():
        cfg = ProxyConfig(no_proxy=[".internal", "mirror.example.com"])
        assert cfg.normalized_no_proxy() == [".internal", "mirror.example.com"]

    def a_cidr_passes_through_untouched():
        assert ProxyConfig(no_proxy=["10.20.0.0/16"]).normalized_no_proxy() == ["10.20.0.0/16"]

    def the_two_spellings_of_one_suffix_collapse_and_order_is_kept():
        cfg = ProxyConfig(no_proxy=["*.test", "a.example.com", ".test", "b.example.com"])
        assert cfg.normalized_no_proxy() == [".test", "a.example.com", "b.example.com"]

    def blanks_are_dropped():
        assert ProxyConfig(no_proxy=["  ", "", ".test"]).normalized_no_proxy() == [".test"]

    def a_comma_separated_string_is_refused():
        from pydantic import ValidationError

        # Written as one item it would land in NO_PROXY as a single entry and match nothing.
        with pytest.raises(ValidationError, match="no_proxy"):
            ProxyConfig(no_proxy=["a.test,b.test"])

    def an_entry_with_a_space_is_refused():
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="no_proxy"):
            ProxyConfig(no_proxy=["a.test b.test"])
