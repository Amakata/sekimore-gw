"""Unit tests for orchestrator module."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.orchestrator import SecurityGatewayOrchestrator


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
