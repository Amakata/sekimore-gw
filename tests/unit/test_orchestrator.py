"""Unit tests for orchestrator module."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.orchestrator import ReloadWindow, SecurityGatewayOrchestrator


def describe_security_gateway_orchestrator():
    """SecurityGatewayOrchestrator unit tests."""

    @patch("subprocess.run")
    @patch("os.getenv")
    def it_detects_network_interfaces_from_docker_api(mock_getenv, mock_run):
        """Test _detect_network_interfaces_from_docker_api successful detection."""
        # Mock environment variables
        mock_getenv.side_effect = lambda key, default=None: {
            "PROJECT_NAME": "test-project",
            "INTERNAL_NETWORK_NAME": "internal-net",
            "INTERNET_NETWORK_NAME": "internet",
        }.get(key, default)

        # Mock hostname command
        hostname_mock = Mock()
        hostname_mock.stdout = "container123\n"

        # Mock docker inspect command with proper network data
        inspect_mock = Mock()
        inspect_data = [
            {
                "NetworkSettings": {
                    "Networks": {
                        "test-project_internal-net": {"IPAddress": "172.20.0.2"},
                        "test-project_internet": {"IPAddress": "172.21.0.2"},
                    }
                }
            }
        ]
        inspect_mock.stdout = json.dumps(inspect_data)

        # Mock ip addr show commands
        eth0_mock = Mock()
        eth0_mock.returncode = 0
        eth0_mock.stdout = "inet 172.20.0.2/24"

        eth1_mock = Mock()
        eth1_mock.returncode = 0
        eth1_mock.stdout = "inet 172.21.0.2/24"

        def run_side_effect(cmd, **kwargs):
            if cmd == ["hostname"]:
                return hostname_mock
            elif cmd[0] == "docker" and "inspect" in cmd:
                return inspect_mock
            elif "eth0" in cmd:
                return eth0_mock
            elif "eth1" in cmd:
                return eth1_mock
            else:
                result = Mock()
                result.returncode = 1
                return result

        mock_run.side_effect = run_side_effect

        result = SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api()

        assert result is not None
        internet_if, internal_if, internal_ip, internet_ip, internal_gw, internal_subnet = result
        assert internet_if == "eth1"
        assert internal_if == "eth0"
        assert internal_ip == "172.20.0.2"
        assert internet_ip == "172.21.0.2"
        assert internal_gw == "172.21.0.1"
        assert internal_subnet == "172.20.0.0/16"  # Calculated from IP and prefix length

    @patch("os.getenv", return_value=None)
    def it_returns_none_when_project_name_not_set(mock_getenv):
        """Test returns None when PROJECT_NAME is not set."""
        result = SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api()
        assert result is None

    @patch("subprocess.run")
    @patch("os.getenv")
    def it_handles_docker_api_failure(mock_getenv, mock_run):
        """Test handles Docker API failures gracefully."""
        mock_getenv.side_effect = lambda key, default=None: {
            "PROJECT_NAME": "test-project",
        }.get(key, default)

        mock_run.side_effect = Exception("Docker API error")

        result = SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api()
        assert result is None

    @patch("subprocess.run")
    def it_sets_up_default_route(mock_run):
        """Test _setup_default_route sets up routing."""
        mock_run.return_value = Mock(returncode=0)

        result = SecurityGatewayOrchestrator._setup_default_route("192.168.1.1", "eth0")

        assert result is True
        # Verify route commands were called
        assert mock_run.call_count >= 2

    @patch("subprocess.run")
    def it_handles_route_setup_failure(mock_run):
        """Test handles route setup failures."""
        mock_run.side_effect = Exception("Route setup failed")

        result = SecurityGatewayOrchestrator._setup_default_route("192.168.1.1", "eth0")

        assert result is False

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.FirewallManager")
    @patch("src.orchestrator.DNSServer")
    @patch("src.orchestrator.StaticIPManager")
    def it_initializes_with_config_path(
        mock_static_ip, mock_dns, mock_firewall, mock_route, mock_detect, mock_load_config
    ):
        """Test initialization with config path."""
        # Mock config
        mock_config = Mock()
        mock_config.allow_domains = ["example.com"]
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        # Mock network detection (6 values: internet_if, internal_if, internal_ip, internet_ip, internet_gw, internal_subnet)
        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        config_path = Path("/etc/sekimore/config.yml")
        orchestrator = SecurityGatewayOrchestrator(config_path=config_path)

        assert orchestrator.config == mock_config
        assert orchestrator.firewall is not None
        mock_load_config.assert_called_once_with(config_path)

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces")
    @patch("src.orchestrator.FirewallManager")
    @patch("src.orchestrator.DNSServer")
    @patch("src.orchestrator.StaticIPManager")
    def it_handles_network_detection_failure_with_fallback(
        mock_static_ip,
        mock_dns,
        mock_firewall,
        mock_static_detect,
        mock_docker_detect,
        mock_load_config,
    ):
        """Test handles Docker API detection failure and falls back to static detection."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.network.lan_subnets = ["10.100.0.0/16"]
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        # Docker API detection fails
        mock_docker_detect.return_value = None
        # Static detection succeeds
        mock_static_detect.return_value = ("eth0", "eth1", "10.100.0.2")

        orchestrator = SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Should successfully fall back to static detection
        assert orchestrator.config == mock_config
        assert orchestrator.firewall is not None
        mock_static_detect.assert_called_once()

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.FirewallManager")
    def it_initializes_firewall_manager(mock_firewall, mock_route, mock_detect, mock_load_config):
        """Test FirewallManager is initialized."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Verify FirewallManager was instantiated
        mock_firewall.assert_called_once()

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.DNSServer")
    def it_initializes_dns_server(mock_dns, mock_route, mock_detect, mock_load_config):
        """Test DNSServer is initialized."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Verify DNSServer was instantiated
        mock_dns.assert_called_once()

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.StaticIPManager")
    def it_initializes_static_ip_manager(mock_ip_mgr, mock_route, mock_detect, mock_load_config):
        """Test StaticIPManager is initialized."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = ["1.2.3.4"]
        mock_config.network.static_block_ips = ["10.0.0.1"]
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Verify StaticIPManager was instantiated
        mock_ip_mgr.assert_called_once()

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.ProxyManager")
    def it_initializes_proxy_manager_when_enabled(
        mock_proxy, mock_route, mock_detect, mock_load_config
    ):
        """Test ProxyManager is initialized when enabled."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = True
        mock_config.proxy.port = 3128
        mock_config.proxy.allow_domains = []
        mock_config.proxy.cache_enabled = True
        mock_config.proxy.cache_size_mb = 1000
        mock_config.proxy.upstream_proxy = None
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Verify ProxyManager was instantiated
        mock_proxy.assert_called_once()

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    def it_does_not_initialize_proxy_when_disabled(mock_route, mock_detect, mock_load_config):
        """Test ProxyManager is not initialized when disabled."""
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = []
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        orchestrator = SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        assert orchestrator.proxy_manager is None

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.FirewallManager")
    @patch("src.orchestrator.DNSServer")
    @patch("src.orchestrator.StaticIPManager")
    def it_stores_priority_ips(
        mock_static_ip, mock_dns, mock_firewall, mock_route, mock_detect, mock_load_config
    ):
        """Test initialization processes priority IPs."""
        # Mock config
        mock_config = Mock()
        mock_config.allow_domains = []
        mock_config.block_domains = []
        mock_config.priority_ips = ["8.8.8.8", "1.1.1.1"]
        mock_config.network.static_allow_ips = []
        mock_config.network.static_block_ips = []
        mock_config.proxy.enabled = False
        mock_load_config.return_value = mock_config

        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        orchestrator = SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        # Verify priority_ips were stored
        assert orchestrator.config.priority_ips == ["8.8.8.8", "1.1.1.1"]

    @patch("subprocess.run")
    def it_detects_network_interfaces_from_static_subnet(mock_run):
        """Test _detect_network_interfaces detects from LAN subnets."""
        # Mock ip addr show output with multiple interfaces
        mock_run.return_value = Mock(
            stdout="""
1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 10.100.0.2/16 brd 10.100.255.255 scope global eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 172.16.0.2/24 brd 172.16.0.255 scope global eth1
"""
        )

        result = SecurityGatewayOrchestrator._detect_network_interfaces(["10.100.0.0/16"])

        assert result is not None
        wan_if, lan_if, lan_ip = result
        # eth0 should be LAN (matches 10.100.0.0/16)
        # eth1 should be WAN
        assert lan_if == "eth0"
        assert lan_ip == "10.100.0.2"
        assert wan_if == "eth1"

    @patch("subprocess.run")
    def it_handles_static_detection_with_no_match(mock_run):
        """Test _detect_network_interfaces when no interface matches LAN subnet."""
        mock_run.return_value = Mock(
            stdout="""
1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.2/24 brd 192.168.1.255 scope global eth0
"""
        )

        result = SecurityGatewayOrchestrator._detect_network_interfaces(["10.100.0.0/16"])

        # Should return default eth0/eth1 when no match
        assert result is not None
        wan_if, lan_if, lan_ip = result
        assert lan_if in ["eth0", "eth1"]

    @patch("subprocess.run")
    def it_detects_with_multiple_lan_subnets(mock_run):
        """Test _detect_network_interfaces with multiple LAN subnets."""
        mock_run.return_value = Mock(
            stdout="""
1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.2/24 brd 192.168.1.255 scope global eth0
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 172.16.0.2/24 brd 172.16.0.255 scope global eth1
"""
        )

        result = SecurityGatewayOrchestrator._detect_network_interfaces(
            ["192.168.0.0/16", "10.0.0.0/8"]
        )

        assert result is not None
        wan_if, lan_if, lan_ip = result
        # eth0 matches 192.168.0.0/16, so should be LAN
        assert lan_if == "eth0"
        assert lan_ip == "192.168.1.2"

    @patch("subprocess.run")
    def it_checks_exact_domain_match(mock_run, tmp_path, sample_config_data):
        """Test _match_allowed_domain with exact match."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Exact match
        assert orch._match_allowed_domain("pypi.org") is True
        assert orch._match_allowed_domain("nonexistent.com") is False

    @patch("subprocess.run")
    def it_checks_wildcard_domain_match(mock_run, tmp_path, sample_config_data):
        """Test _match_allowed_domain with wildcard patterns."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        # Add wildcard domains to config
        sample_config_data["allow_domains"].extend(["*.example.com", "*github.io"])

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Wildcard match *.example.com
        assert orch._match_allowed_domain("subdomain.example.com") is True
        assert orch._match_allowed_domain("deep.subdomain.example.com") is True

        # Wildcard match *github.io
        assert orch._match_allowed_domain("mysite.github.io") is True
        assert orch._match_allowed_domain("github.io") is True

    @patch("subprocess.run")
    def it_checks_domain_case_insensitivity(mock_run, tmp_path, sample_config_data):
        """Test _match_allowed_domain is case-insensitive."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Case insensitive
        assert orch._match_allowed_domain("PYPI.ORG") is True
        assert orch._match_allowed_domain("PyPi.Org") is True

    @patch("subprocess.run")
    def it_strips_trailing_dot_from_domain(mock_run, tmp_path, sample_config_data):
        """Test _match_allowed_domain strips trailing dots."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Trailing dot should be stripped
        assert orch._match_allowed_domain("pypi.org.") is True

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_applies_block_rule(mock_run, tmp_path, sample_config_data):
        """Test apply_domain_rule blocks domains."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))
        orch.dns_server.blocked_domains = set()

        result = await orch.apply_domain_rule("malicious.com", action="block")

        assert result is True
        assert "malicious.com" in orch.dns_server.blocked_domains

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_applies_allow_rule_successfully(mock_run, tmp_path, sample_config_data):
        """Test apply_domain_rule allows domains after DNS resolution."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock DNS resolution
        orch.dns_server._resolve_domain = AsyncMock(return_value=(["93.184.216.34"], 300))

        # Mock firewall setup
        orch.firewall.setup_domain = Mock(return_value=True)

        result = await orch.apply_domain_rule("example.com", action="allow")

        assert result is True
        orch.firewall.setup_domain.assert_called_once_with("example.com", ["93.184.216.34"])

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_handles_dns_resolution_failure(mock_run, tmp_path, sample_config_data):
        """Test apply_domain_rule handles DNS resolution failure."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock DNS resolution failure
        orch.dns_server._resolve_domain = AsyncMock(return_value=None)

        result = await orch.apply_domain_rule("nonexistent.invalid", action="allow")

        assert result is False

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_filters_ipv4_only(mock_run, tmp_path, sample_config_data):
        """Test apply_domain_rule filters IPv6 addresses."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock DNS with both IPv4 and IPv6
        orch.dns_server._resolve_domain = AsyncMock(
            return_value=(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"], 300)
        )

        # Mock firewall setup
        orch.firewall.setup_domain = Mock(return_value=True)

        result = await orch.apply_domain_rule("example.com", action="allow")

        assert result is True
        # Should only pass IPv4 address to firewall
        orch.firewall.setup_domain.assert_called_once_with("example.com", ["93.184.216.34"])

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_handles_firewall_setup_failure(mock_run, tmp_path, sample_config_data):
        """Test apply_domain_rule handles firewall setup failure."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock DNS resolution
        orch.dns_server._resolve_domain = AsyncMock(return_value=(["1.2.3.4"], 300))

        # Mock firewall setup failure
        orch.firewall.setup_domain = Mock(return_value=False)

        result = await orch.apply_domain_rule("example.com", action="allow")

        assert result is False

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_initializes_successfully(mock_run, tmp_path, sample_config_data):
        """Test initialize sets up all components."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        # Simplify config to avoid domain resolution
        sample_config_data["allow_domains"] = []

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock components
        orch.firewall.initialize_firewall = Mock(return_value=True)
        orch.ip_manager.setup_static_ips = Mock(return_value=True)
        orch.firewall.setup_static_ip_rules = Mock(return_value=True)
        orch.firewall.enable_block_logging = Mock(return_value=True)

        result = await orch.initialize()

        assert result is True
        orch.firewall.initialize_firewall.assert_called_once()
        orch.ip_manager.setup_static_ips.assert_called_once()
        orch.firewall.setup_static_ip_rules.assert_called_once()

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_handles_initialization_failure(mock_run, tmp_path, sample_config_data):
        """Test initialize handles component failure."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock firewall initialization failure
        orch.firewall.initialize_firewall = Mock(return_value=False)

        result = await orch.initialize()

        assert result is False

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_cleans_up_resources(mock_run, tmp_path, sample_config_data):
        """Test cleanup stops all components."""
        config_file = tmp_path / "test_config.yml"
        import yaml

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(sample_config_data, f)

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=Path(config_file))

        # Mock component cleanup methods
        orch.dns_server.stop = AsyncMock()
        orch.firewall.cleanup = Mock()
        orch.ip_manager.cleanup = Mock()

        await orch.cleanup()

        orch.dns_server.stop.assert_called_once()
        orch.firewall.cleanup.assert_called_once()
        orch.ip_manager.cleanup.assert_called_once()


def describe_config_reload():
    """Configuration reload functionality tests."""

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_reloads_config_successfully(mock_run, tmp_path):
        """Test reload_config successfully reloads configuration."""
        # Create initial config
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
  - test.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)

        # Mock DNS server and firewall methods
        orch.dns_server.allowed_domains = ["example.com", "test.com"]
        orch.dns_server.blocked_domains = []
        orch.firewall.remove_domain = Mock()
        orch.proxy_manager = None  # No proxy for this test

        # Update config file with new domain
        config_file.write_text("""
allow_domains:
  - example.com
  - newdomain.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        # Reload config
        result = await orch.reload_config()

        assert result is True
        # Check that DNS server's allowed_domains was updated
        assert "newdomain.com" in orch.dns_server.allowed_domains
        # Check that removed domain's firewall rule was deleted
        orch.firewall.remove_domain.assert_called_once_with("test.com")

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_detects_added_and_removed_domains(mock_run, tmp_path):
        """Test reload_config detects added and removed domains."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - domain1.com
  - domain2.com
block_domains:
  - blocked1.com
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.dns_server.allowed_domains = ["domain1.com", "domain2.com"]
        orch.dns_server.blocked_domains = {"blocked1.com"}
        orch.firewall.remove_domain = Mock()
        orch.proxy_manager = None

        # Update config: remove domain1, add domain3, add blocked2
        config_file.write_text("""
allow_domains:
  - domain2.com
  - domain3.com
block_domains:
  - blocked1.com
  - blocked2.com
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        result = await orch.reload_config()

        assert result is True
        # Check DNS server updates
        assert set(orch.dns_server.allowed_domains) == {"domain2.com", "domain3.com"}
        assert orch.dns_server.blocked_domains == {"blocked1.com", "blocked2.com"}
        # Check firewall rule removal
        orch.firewall.remove_domain.assert_called_once_with("domain1.com")

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_reloads_proxy_config_when_enabled(mock_run, tmp_path):
        """Test reload_config reloads proxy configuration when enabled."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: true
  cache_enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.dns_server.allowed_domains = ["example.com"]
        orch.dns_server.blocked_domains = set()
        orch.firewall.remove_domain = Mock()

        # Mock proxy manager
        orch.proxy_manager = Mock()
        orch.proxy_manager.generate_config = Mock(return_value=True)
        orch.proxy_manager.reload_config = Mock(return_value=True)

        # Update config
        config_file.write_text("""
allow_domains:
  - example.com
  - newdomain.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: true
  cache_enabled: false
database_path: /tmp/test.db
""")

        result = await orch.reload_config()

        assert result is True
        # Check proxy config was regenerated and reloaded
        orch.proxy_manager.generate_config.assert_called_once()
        orch.proxy_manager.reload_config.assert_called_once()

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_handles_reload_failure_gracefully(mock_run, tmp_path):
        """Test reload_config handles failures gracefully."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: true
  cache_enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.dns_server.allowed_domains = ["example.com"]
        orch.dns_server.blocked_domains = set()
        orch.firewall.remove_domain = Mock()

        # Mock proxy manager to fail
        orch.proxy_manager = Mock()
        orch.proxy_manager.generate_config = Mock(return_value=False)  # Fail!

        # Update config
        config_file.write_text("""
allow_domains:
  - newdomain.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: true
  cache_enabled: false
database_path: /tmp/test.db
""")

        result = await orch.reload_config()

        assert result is False  # Should return False on failure


def describe_service_restart():
    """Service restart functionality tests."""

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_restarts_services_successfully(mock_run, tmp_path):
        """Test restart_services successfully restarts DNS and Proxy."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)

        # Mock DNS server methods
        orch.dns_server.stop = AsyncMock()
        orch.dns_server.start = AsyncMock()
        orch.dns_server.allowed_domains = ["example.com"]
        orch.dns_server.blocked_domains = set()
        orch.proxy_manager = None

        # Update config
        config_file.write_text("""
allow_domains:
  - newdomain.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
""")

        result = await orch.restart_services()

        assert result is True
        # Check DNS server was stopped and restarted
        orch.dns_server.stop.assert_called_once()
        orch.dns_server.start.assert_called_once()
        # Check config was reloaded
        assert orch.dns_server.allowed_domains == ["newdomain.com"]

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_restarts_proxy_when_enabled(mock_run, tmp_path):
        """Test restart_services restarts proxy when enabled."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: true
  cache_enabled: false
database_path: /tmp/test.db
""")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.dns_server.stop = AsyncMock()
        orch.dns_server.start = AsyncMock()
        orch.dns_server.allowed_domains = ["example.com"]
        orch.dns_server.blocked_domains = set()

        # Mock proxy manager
        orch.proxy_manager = Mock()
        orch.proxy_manager.stop = Mock()
        orch.proxy_manager.generate_config = Mock(return_value=True)
        orch.proxy_manager.start = Mock(return_value=True)

        result = await orch.restart_services()

        assert result is True
        # Check proxy was stopped and restarted
        orch.proxy_manager.stop.assert_called_once()
        orch.proxy_manager.start.assert_called_once()


def describe_relay_wiring():
    """Passing domain_handlers / relay_ports through, and how they are handled on reload."""

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.DNSServer")
    @patch("src.orchestrator.FirewallManager")
    def it_passes_handlers_and_ports_when_configured(
        mock_firewall, mock_dns, mock_route, mock_detect, mock_load_config
    ):
        from src.config import Config

        mock_load_config.return_value = Config(
            allow_domains=["github.com"],
            domain_handlers={
                "github.com": {"handler": "git-relay"},
                "t.example.com": {"handler": "deny"},
            },
            network={"lan_subnets": ["172.20.0.0/16"]},
        )
        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        assert mock_firewall.call_args.kwargs["relay_ports"] == [22, 8420, 443]
        assert mock_dns.call_args.kwargs["domain_handlers"] == {
            "github.com": "github",
            "t.example.com": "deny",
        }

    @patch("src.orchestrator.load_config")
    @patch(
        "src.orchestrator.SecurityGatewayOrchestrator._detect_network_interfaces_from_docker_api"
    )
    @patch("src.orchestrator.SecurityGatewayOrchestrator._setup_default_route")
    @patch("src.orchestrator.DNSServer")
    @patch("src.orchestrator.FirewallManager")
    def it_passes_nothing_without_handlers(
        mock_firewall, mock_dns, mock_route, mock_detect, mock_load_config
    ):
        from src.config import Config

        mock_load_config.return_value = Config(allow_domains=["example.com"])
        mock_detect.return_value = (
            "eth1",
            "eth0",
            "172.20.0.2",
            "172.21.0.2",
            "172.21.0.1",
            "172.20.0.0/16",
        )
        mock_route.return_value = True

        SecurityGatewayOrchestrator(config_path=Path("/etc/sekimore/config.yml"))

        assert mock_firewall.call_args.kwargs["relay_ports"] == []
        assert mock_dns.call_args.kwargs["domain_handlers"] == {}

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_keeps_old_handlers_on_reload_and_asks_for_restart(mock_run, tmp_path):
        config_file = tmp_path / "config.yml"
        base = """
allow_domains:
  - github.com
block_domains: []
allow_ips: []
block_ips: []
network:
  lan_subnets:
    - "172.20.0.0/16"
proxy:
  enabled: false
database_path: /tmp/test.db
"""
        config_file.write_text(base)
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.firewall.remove_domain = Mock()
        orch.proxy_manager = None
        assert orch.dns_server.domain_handlers == {}

        config_file.write_text(
            base
            + """
domain_handlers:
  github.com:
    handler: git-relay
relay:
  project:
    name: x
"""
        )
        with patch("src.orchestrator.log_error") as mock_err:
            assert await orch.reload_config() is True
        assert orch.config.domain_handlers == {}, "relay settings must not change without a restart"
        assert orch.dns_server.domain_handlers == {}
        assert any("restart" in str(c.args) for c in mock_err.call_args_list)

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def it_warns_when_relay_is_not_listening(mock_run, tmp_path):
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            "allow_domains: [github.com]\nnetwork:\n  lan_subnets: ['172.20.0.0/16']\n"
        )
        mock_run.return_value = Mock(
            returncode=0, stdout="LISTEN 0 4096 0.0.0.0:53 0.0.0.0:*\n", stderr=""
        )
        orch = SecurityGatewayOrchestrator(config_path=config_file)
        with patch("src.orchestrator.log_error") as mock_err:
            assert await orch._warn_if_relay_not_listening(22, delay=0) is False
        assert any("not listening" in str(c.args) for c in mock_err.call_args_list)
        mock_run.return_value = Mock(
            returncode=0, stdout="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n", stderr=""
        )
        with patch("src.orchestrator.log_error") as mock_err:
            assert await orch._warn_if_relay_not_listening(22, delay=0) is True
        assert not mock_err.called


def describe_relay_settings_change_detection():
    """0.2.0: a change to a handler's ssh_port also counts as "restart required" (the INPUT port changes)."""

    def it_detects_ssh_port_changes():
        from src.config import Config
        from src.orchestrator import _relay_settings_changed

        base = {
            "github.com": {"handler": "git-relay"},
            "ghe.example.com": {"handler": "git-relay", "ssh_port": 2222},
        }
        old = Config(domain_handlers=base)
        same = Config(domain_handlers=base)
        moved = Config(
            domain_handlers={
                **base,
                "ghe.example.com": {"handler": "git-relay", "ssh_port": 2223},
            }
        )
        assert _relay_settings_changed(old, same) is False
        assert _relay_settings_changed(old, moved) is True

    def it_treats_allowed_ports_changes_as_restart_needed():
        from src.config import Config
        from src.orchestrator import _allowed_ports_of, _relay_settings_changed

        a = Config(network={"allowed_ports": [80, 443]})
        b = Config(network={"allowed_ports": [443]})
        assert _allowed_ports_of(a) == [80, 443]
        assert _relay_settings_changed(a, Config(network={"allowed_ports": [80, 443]})) is False
        assert _relay_settings_changed(a, b) is True
        assert _allowed_ports_of(object()) == []


def describe_squid_never_serves_a_relayed_domain():
    """Squid resolves names through Docker's DNS, bypassing the DNS filter, and reaches
    anything in its allowlist. A domain the relay owns must therefore be withheld from it,
    or `https_proxy=gw:3128` becomes a way around the relay's policy."""

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def the_startup_config_excludes_it(mock_run, tmp_path):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - github.com
  - api.github.com
  - pypi.org
domain_handlers:
  github.com:
    handler: github
proxy:
  enabled: true
  cache_enabled: false
network:
  lan_subnets:
    - "172.20.0.0/16"
database_path: /tmp/test.db
""")
        orch = SecurityGatewayOrchestrator(config_path=config_file)
        assert orch.config.proxy_allow_domains() == ["api.github.com", "pypi.org"]
        assert "github.com" in orch.config.allow_domains

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def the_reloaded_config_excludes_it(mock_run, tmp_path):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - github.com
  - pypi.org
domain_handlers:
  github.com:
    handler: github
proxy:
  enabled: true
  cache_enabled: false
network:
  lan_subnets:
    - "172.20.0.0/16"
database_path: /tmp/test.db
""")
        orch = SecurityGatewayOrchestrator(config_path=config_file)
        orch.dns_server.allowed_domains = ["github.com", "pypi.org"]
        orch.dns_server.blocked_domains = set()
        orch.firewall.remove_domain = Mock()
        orch.proxy_manager = Mock()
        orch.proxy_manager.generate_config = Mock(return_value=True)
        orch.proxy_manager.reload_config = Mock(return_value=True)

        # Dropping the handler must not hand github.com back to Squid: domain_handlers
        # changes need a restart, so the relay is still running with the old set.
        config_file.write_text("""
allow_domains:
  - github.com
  - pypi.org
proxy:
  enabled: true
  cache_enabled: false
network:
  lan_subnets:
    - "172.20.0.0/16"
database_path: /tmp/test.db
""")
        assert await orch.reload_config() is True
        served, relayed = orch.proxy_manager.generate_config.call_args[0]
        assert "github.com" not in served
        assert "pypi.org" in served
        # and it is denied outright, so a wildcard in the allowlist cannot serve it either
        assert "github.com" in relayed


def describe_reload_window():
    """0.2.13: config.yml is writable from dev and the gateway applied it on save, so an
    agent that has read a hostile prompt could rewrite the rules it is held by. The window
    decides whether a save takes effect."""

    def auto_applies_on_save_as_before(tmp_path):
        w = ReloadWindow("auto", None, tmp_path / "w.json")
        assert w.is_open() is True
        assert w.seconds_left() is None

    def manual_never_applies_on_save(tmp_path):
        w = ReloadWindow("manual", None, tmp_path / "w.json")
        assert w.is_open() is False

    def a_window_is_open_at_first_and_shuts_when_it_runs_out(tmp_path):
        w = ReloadWindow("windowed", 1800, tmp_path / "w.json")
        assert w.is_open() is True
        assert 0 < (w.seconds_left() or 0) <= 1800
        # A window whose length has already elapsed is shut, which is the state a session
        # reaches by leaving the gateway running.
        assert ReloadWindow("windowed", 0, tmp_path / "w.json").is_open() is False

    def freeze_shuts_it_whatever_the_mode(tmp_path):
        # What the operator runs before handing the session to an agent.
        for mode, secs in (("auto", None), ("windowed", 1800)):
            w = ReloadWindow(mode, secs, tmp_path / f"w-{mode}-{secs}.json")
            assert w.is_open() is True
            w.freeze()
            assert w.is_open() is False

    def follow_reopens_it(tmp_path):
        w = ReloadWindow("manual", None, tmp_path / "w.json")
        assert w.is_open() is False
        w.follow(600)
        assert w.is_open() is True
        assert 0 < (w.seconds_left() or 0) <= 600

    def follow_lifts_a_freeze(tmp_path):
        w = ReloadWindow("windowed", 1800, tmp_path / "w.json")
        w.freeze()
        assert w.is_open() is False
        w.follow(600)
        assert w.is_open() is True

    def the_description_says_whether_a_save_applies(tmp_path):
        # Read by a human deciding whether it is safe to start an agent, so it has to say
        # what happens, not just name the mode.
        state = tmp_path / "w.json"
        assert "applies on save" in ReloadWindow("auto", None, state).describe()
        assert "does not apply on save" in ReloadWindow("manual", None, state).describe()
        assert "does not apply on save" in ReloadWindow("windowed", 0, state).describe()
        assert "applies on save" in ReloadWindow("windowed", 1800, state).describe()
        w = ReloadWindow("auto", None, state)
        w.freeze()
        assert "does not apply on save" in w.describe()
        # and how to get it back
        assert "reload-follow" in w.describe()

    def the_description_never_disagrees_with_is_open(tmp_path):
        # A line saying the window is open while saves are dropped sends the reader looking
        # in the wrong place.
        state = tmp_path / "w.json"
        for mode, secs in (("auto", None), ("manual", None), ("windowed", 1800), ("windowed", 0)):
            w = ReloadWindow(mode, secs, state.with_name(f"w-{mode}-{secs}.json"))
            says_open = "does not apply" not in w.describe()
            assert says_open is w.is_open(), (mode, secs, w.describe())


def describe_a_change_arriving_with_the_window_shut():
    """Not applying it is half the job; the attempt has to be visible."""

    @patch("subprocess.run")
    def it_is_counted_rather_than_applied(mock_run, tmp_path):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        config_file = tmp_path / "config.yml"
        config_file.write_text("""
allow_domains:
  - example.com
reload: manual
network:
  lan_subnets:
    - "172.20.0.0/16"
database_path: /tmp/test.db
""")
        orch = SecurityGatewayOrchestrator(config_path=config_file)
        assert orch.reload_window.is_open() is False
        assert orch.has_unapplied_changes() is False
        orch.note_unapplied_change()
        assert orch.has_unapplied_changes() is True

    @patch("subprocess.run")
    def the_window_follows_the_configured_mode(mock_run, tmp_path):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        for mode, expected in (("auto", True), ("manual", False), ("30m", True)):
            config_file = tmp_path / f"config-{mode}.yml"
            config_file.write_text(f"""
allow_domains:
  - example.com
reload: {mode}
network:
  lan_subnets:
    - "172.20.0.0/16"
database_path: /tmp/test.db
""")
            orch = SecurityGatewayOrchestrator(config_path=config_file)
            assert orch.reload_window.is_open() is expected, mode


def describe_the_window_survives_a_restart():
    """The operator reopens the window from a separate process, so the two sides meet in a
    file on the gateway's volume — which the dev container does not mount."""

    def follow_is_picked_up_by_a_later_instance(tmp_path):
        state = tmp_path / "reload-window.json"
        ReloadWindow("manual", None, state).follow(600)
        # A restart, or the gateway process reading what the maint command wrote.
        later = ReloadWindow("manual", None, state)
        assert later.is_open() is True
        assert 0 < (later.seconds_left() or 0) <= 600

    def freeze_is_picked_up_by_a_later_instance(tmp_path):
        state = tmp_path / "reload-window.json"
        ReloadWindow("auto", None, state).freeze()
        later = ReloadWindow("auto", None, state)
        assert later.is_open() is False

    def follow_narrows_an_auto_config_rather_than_leaving_it_open(tmp_path):
        # `follow` means "open until this runs out". Reading it as "auto, plus a note" would
        # leave an auto deployment permanently open after one --follow.
        state = tmp_path / "reload-window.json"
        ReloadWindow("auto", None, state).follow(600)
        later = ReloadWindow("auto", None, state)
        assert later.is_open() is True
        assert (later.seconds_left() or 0) <= 600

    def an_expired_override_is_ignored(tmp_path):
        state = tmp_path / "reload-window.json"
        state.write_text('{"until": 1}')  # long past
        w = ReloadWindow("manual", None, state)
        assert w.is_open() is False

    def a_damaged_state_file_does_not_stop_the_gateway(tmp_path):
        # Falling back to the configured mode is right: the file is a convenience, and the
        # config is what the operator actually declared.
        for body in ("", "{", "null", "[]", '{"until": "soon"}', '{"other": 1}'):
            state = tmp_path / f"s-{abs(hash(body))}.json"
            state.write_text(body)
            assert ReloadWindow("manual", None, state).is_open() is False
            assert ReloadWindow("auto", None, state).is_open() is True

    def a_missing_state_file_is_the_normal_case(tmp_path):
        state = tmp_path / "absent.json"
        assert ReloadWindow("auto", None, state).is_open() is True
        assert ReloadWindow("manual", None, state).is_open() is False
