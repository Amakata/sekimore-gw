"""Integration tests for orchestrator module.

These tests verify that components work together correctly.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest


def describe_orchestrator_integration():
    """Integration tests for orchestrator with other components."""

    @pytest.mark.asyncio
    async def it_starts_and_handles_shutdown(tmp_path):
        """Test orchestrator starts all components and handles shutdown."""
        from src.config import Config, ProxyConfig
        from src.orchestrator import SecurityGatewayOrchestrator

        # Create real DB
        db_path = tmp_path / "test.db"

        # Mock config
        mock_config = Config(
            allow_domains=["example.com"],
            block_domains=[],
            proxy=ProxyConfig(enabled=False),
        )

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=mock_config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            # Mock subprocess calls
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            orchestrator = SecurityGatewayOrchestrator()

            # Initialize
            result = await orchestrator.initialize()
            assert result is True

            # Mock monitors
            orchestrator.firewall_monitor.start = AsyncMock()
            orchestrator.firewall_monitor.stop = AsyncMock()

            # Mock DNS server to stop immediately (simulate shutdown)
            orchestrator.dns_server.start = AsyncMock(side_effect=KeyboardInterrupt())

            # Start (will stop due to mocked KeyboardInterrupt)
            await orchestrator.start()

            # Verify components were initialized
            assert orchestrator.dns_server is not None
            assert orchestrator.firewall is not None

            # Verify cleanup was performed
            orchestrator.firewall_monitor.stop.assert_awaited_once()

    @pytest.mark.asyncio
    async def it_handles_initialization_failure(tmp_path):
        """Test orchestrator handles initialization failure gracefully."""
        from src.orchestrator import SecurityGatewayOrchestrator

        db_path = tmp_path / "test.db"

        with (
            patch("src.config.load_config") as mock_load_config,
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            # Mock config load failure
            mock_load_config.side_effect = FileNotFoundError("Config not found")

            orchestrator = SecurityGatewayOrchestrator()

            # Initialize should fail gracefully
            try:
                result = await orchestrator.initialize()
                # If it doesn't raise, it should return False
                assert result is False
            except FileNotFoundError:
                # Also acceptable
                pass

    @pytest.mark.asyncio
    async def it_handles_dns_server_exception(tmp_path):
        """Test orchestrator handles DNS server runtime exceptions."""
        from src.config import Config, ProxyConfig
        from src.orchestrator import SecurityGatewayOrchestrator

        db_path = tmp_path / "test.db"

        mock_config = Config(
            allow_domains=["example.com"],
            block_domains=[],
            proxy=ProxyConfig(enabled=False),
        )

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=mock_config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            orchestrator = SecurityGatewayOrchestrator()
            await orchestrator.initialize()

            # Mock DNS server to raise exception
            orchestrator.dns_server.start = AsyncMock(side_effect=RuntimeError("DNS failed"))

            # Mock monitors
            orchestrator.firewall_monitor.start = AsyncMock()
            orchestrator.firewall_monitor.stop = AsyncMock()

            # Start orchestrator (should handle exception and cleanup)
            await orchestrator.start()

            # Verify cleanup was performed despite exception
            orchestrator.firewall_monitor.stop.assert_awaited_once()


def describe_domain_rule_application():
    """Integration tests for domain rule application without infinite loops."""

    @pytest.mark.timeout(10)
    @pytest.mark.asyncio
    async def it_applies_domain_rules_without_hanging(tmp_path):
        """Test that applying domain rules completes without infinite loops.

        This test verifies the fix for the infinite loop bug in _remove_block_log_rule().
        The timeout ensures that if an infinite loop occurs, the test will fail.
        """
        from subprocess import CalledProcessError

        from src.config import Config, ProxyConfig
        from src.orchestrator import SecurityGatewayOrchestrator

        db_path = tmp_path / "test.db"

        mock_config = Config(
            allow_domains=["example.com"],
            block_domains=[],
            proxy=ProxyConfig(enabled=False),
        )

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=mock_config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            # Mock iptables commands to succeed initially, then fail with "does not exist"
            # This simulates the scenario where NFLOG rules are deleted until none remain
            call_count = 0

            def run_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1

                # Check if this is a NFLOG deletion command
                cmd = args[0] if args else kwargs.get("args", [])
                is_nflog_delete = isinstance(cmd, list) and "-D" in cmd and "NFLOG" in cmd

                if is_nflog_delete and call_count > 20:
                    # After 20 calls, simulate "does not exist" error
                    raise CalledProcessError(
                        1,
                        cmd,
                        stderr="iptables: Bad rule (does a matching rule exist in that chain?).",
                    )

                # All other commands succeed
                return Mock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = run_side_effect

            orchestrator = SecurityGatewayOrchestrator()
            await orchestrator.initialize()

            # Apply domain rule - this should complete without infinite loop
            # The timeout decorator will fail the test if it hangs
            await orchestrator.apply_domain_rule("example.com", action="allow")

            # If we reach here, the test passed (no infinite loop)
            assert True

    @pytest.mark.timeout(10)
    @pytest.mark.asyncio
    async def it_handles_no_chain_errors_correctly(tmp_path):
        """Test that 'no chain' errors break the while loop in _remove_block_log_rule().

        This test simulates the scenario where iptables returns 'No chain' error,
        which should cause the deletion loop to terminate (not continue infinitely).
        """
        from subprocess import CalledProcessError

        from src.config import Config, ProxyConfig
        from src.orchestrator import SecurityGatewayOrchestrator

        db_path = tmp_path / "test.db"

        mock_config = Config(
            allow_domains=["example.com"],
            block_domains=[],
            proxy=ProxyConfig(enabled=False),
        )

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=mock_config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            # First call succeeds (setup), subsequent calls return "No chain" error
            call_count = 0

            def run_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1

                # First few calls succeed (chain creation, etc.)
                if call_count <= 5:
                    return Mock(returncode=0, stdout="", stderr="")

                # Subsequent calls fail with "No chain" - should break the loop
                raise CalledProcessError(
                    1,
                    args[0] if args else ["iptables"],
                    stderr="iptables: No chain/target/match by that name.",
                )

            mock_run.side_effect = run_side_effect

            orchestrator = SecurityGatewayOrchestrator()
            await orchestrator.initialize()

            # Apply domain rule - should complete even with "No chain" errors
            await orchestrator.apply_domain_rule("example.com", action="allow")

            # Verify that subprocess.run was called a reasonable number of times
            # If infinite loop occurred, this would timeout or have 1000+ calls
            assert call_count < 50, f"Too many subprocess calls: {call_count}"


def describe_dns_and_firewall_integration():
    """Integration tests for DNS server and Firewall coordination."""

    @pytest.mark.skip(reason="Implementation details changed - covered by unit tests")
    @pytest.mark.asyncio
    async def it_coordinates_dns_and_firewall(tmp_path):
        """Test DNS resolution coordinates with firewall ipset updates."""
        from src.config import Config
        from src.dns_server import DNSServer
        from src.firewall import FirewallManager

        config = Config(
            allow_domains=["example.com"],
            block_domains=["malware.com"],
        )

        db_path = tmp_path / "test.db"

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            # Mock subprocess for iptables/ipset
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            # Create firewall
            firewall = FirewallManager(wan_interface="eth0", lan_interface="eth1")

            # Create DNS server with firewall integration
            dns_server = DNSServer(firewall_manager=firewall)

            # Mock DNS resolution
            dns_server._resolve_domain = AsyncMock(return_value=(["93.184.216.34"], 300))

            # Process allowed domain query
            await dns_server._handle_query(
                query_name="example.com",
                query_type="A",
                client_ip="172.20.0.5",
            )

            # Verify ipset commands were called for allowed domain
            ipset_calls = [str(call) for call in mock_run.call_args_list if "ipset" in str(call)]
            assert len(ipset_calls) > 0

    @pytest.mark.skip(reason="Implementation details changed - covered by unit tests")
    @pytest.mark.asyncio
    async def it_blocks_malware_without_firewall_update(tmp_path):
        """Test blocked domains are refused without firewall updates."""
        from src.config import Config
        from src.dns_server import DNSServer
        from src.firewall import FirewallManager

        config = Config(
            allow_domains=["example.com"],
            block_domains=["malware.com"],
        )

        db_path = tmp_path / "test.db"

        with (
            patch("subprocess.run") as mock_run,
            patch("src.config.load_config", return_value=config),
            patch("src.constants.DB_PATH", str(db_path)),
        ):
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            firewall = FirewallManager(wan_interface="eth0", lan_interface="eth1")
            dns_server = DNSServer(firewall_manager=firewall)

            # Track calls before blocked domain
            initial_call_count = len(mock_run.call_args_list)

            # Process blocked domain
            response = await dns_server._handle_query(
                query_name="malware.com",
                query_type="A",
                client_ip="172.20.0.5",
            )

            # Verify domain was blocked
            assert response is not None

            # Verify no new ipset calls (blocked domains shouldn't update firewall)
            new_ipset_calls = [
                str(call)
                for call in mock_run.call_args_list[initial_call_count:]
                if "ipset" in str(call)
            ]
            assert len(new_ipset_calls) == 0
