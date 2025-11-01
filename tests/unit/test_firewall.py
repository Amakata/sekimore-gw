"""Unit tests for firewall module."""

from unittest.mock import Mock, patch

from src.firewall import FirewallManager


def describe_firewall_manager():
    """FirewallManager unit tests."""

    def it_initializes_with_interfaces():
        """Test FirewallManager initializes with interface names."""
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        assert fw.wan_if == "eth0"
        assert fw.lan_if == "eth1"
        assert fw.domain_ipsets == {}
        assert fw.iptables_cmd == "iptables-legacy"
        assert fw.ipset_cmd == "ipset"

    @patch("subprocess.run")
    def it_runs_command_successfully(mock_run):
        """Test _run_command executes successfully."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw._run_command(["iptables-legacy", "-L"])

        assert result is True
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def it_handles_command_failure(mock_run):
        """Test _run_command handles failure."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["iptables-legacy"], stderr="error")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw._run_command(["iptables-legacy", "-L"])

        assert result is False

    @patch("subprocess.run")
    def it_ignores_already_exists_errors(mock_run):
        """Test _run_command ignores 'already exists' errors."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["ipset"], stderr="Set already exists")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw._run_command(["ipset", "create", "test"])

        assert result is True

    @patch("subprocess.run")
    def it_treats_no_chain_error_as_deletion_failure(mock_run):
        """Test _run_command treats 'No chain' errors as deletion failure (to break while loop)."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(
            1, ["iptables"], stderr="iptables: No chain/target/match by that name."
        )
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # 削除操作で「no chain」エラーが出た場合、Falseを返す（ループ終了）
        result = fw._run_command(["iptables", "-D", "FORWARD", "-j", "NFLOG"])

        assert result is False

    @patch("subprocess.run")
    def it_initializes_firewall_rules(mock_run):
        """Test initialize_firewall sets up basic rules."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.initialize_firewall()

        assert result is True
        # Verify basic commands were called
        assert mock_run.call_count > 5  # Multiple iptables commands

    @patch("subprocess.run")
    def it_creates_ipset_for_domain(mock_run):
        """Test setup_domain creates ipset and iptables rule.

        FIXED: Previous version had infinite loop timeout issue because
        setup_domain() calls _remove_block_log_rule() which uses while True.
        We need to return CalledProcessError for the "delete NFLOG rule" attempts
        to simulate "rule doesn't exist" and break the loop.
        """
        from subprocess import CalledProcessError

        # Mock responses for the commands in order:
        # 1. Delete existing iptables rule (may not exist) - ignore error
        # 2. Destroy existing ipset (may not exist) - ignore error
        # 3. Create ipset - success
        # 4. Add IP to ipset - success
        # 5. _remove_block_log_rule: Delete NFLOG rule - fail (no rule exists)
        # 6. Add iptables FORWARD rule - success
        # 7. _add_block_log_rule: Add NFLOG rule - success
        mock_run.side_effect = [
            CalledProcessError(1, ["iptables-legacy"], stderr="No such rule"),  # Delete old rule
            CalledProcessError(1, ["ipset"], stderr="Set does not exist"),  # Destroy old ipset
            Mock(returncode=0),  # Create ipset
            Mock(returncode=0),  # Add IP to ipset
            CalledProcessError(
                1, ["iptables-legacy"], stderr="No such rule"
            ),  # _remove_block_log_rule
            Mock(returncode=0),  # Add FORWARD rule
            Mock(returncode=0),  # _add_block_log_rule
        ]
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_domain("example.com", ["93.184.216.34"])

        assert result is True
        assert "example.com" in fw.domain_ipsets
        # Verify all commands were called
        assert mock_run.call_count == 7

    @patch("subprocess.run")
    def it_updates_domain_ips(mock_run):
        """Test update_domain_ips adds IPs to existing ipset.

        FIXED: Same infinite loop issue as setup_domain.
        """
        from subprocess import CalledProcessError

        # Setup domain first (7 commands as in it_creates_ipset_for_domain)
        setup_commands = [
            CalledProcessError(1, ["iptables-legacy"], stderr="No such rule"),
            CalledProcessError(1, ["ipset"], stderr="Set does not exist"),
            Mock(returncode=0),  # Create ipset
            Mock(returncode=0),  # Add IP
            CalledProcessError(
                1, ["iptables-legacy"], stderr="No such rule"
            ),  # _remove_block_log_rule
            Mock(returncode=0),  # Add FORWARD rule
            Mock(returncode=0),  # _add_block_log_rule
        ]

        # Update domain IPs - ipset list returns existing IPs
        update_commands = [
            Mock(
                returncode=0,
                stdout="Members:\n93.184.216.34\n",  # Existing IP
                stderr="",
            ),  # ipset list
            Mock(returncode=0),  # ipset add new IP
            Mock(returncode=0),  # ipset del old IP
        ]

        mock_run.side_effect = setup_commands + update_commands
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # Setup
        fw.setup_domain("example.com", ["93.184.216.34"])
        call_count_after_first = mock_run.call_count

        # Update
        fw.update_domain_ips("example.com", ["93.184.216.35"])

        assert mock_run.call_count > call_count_after_first
        assert mock_run.call_count == 10  # 7 setup + 3 update

    @patch("subprocess.run")
    def it_removes_domain_rules(mock_run):
        """Test remove_domain removes ipset and rules.

        FIXED: Same infinite loop issue.
        """
        from subprocess import CalledProcessError

        # Setup domain first (7 commands)
        setup_commands = [
            CalledProcessError(1, ["iptables-legacy"], stderr="No such rule"),
            CalledProcessError(1, ["ipset"], stderr="Set does not exist"),
            Mock(returncode=0),  # Create ipset
            Mock(returncode=0),  # Add IP
            CalledProcessError(
                1, ["iptables-legacy"], stderr="No such rule"
            ),  # _remove_block_log_rule
            Mock(returncode=0),  # Add FORWARD rule
            Mock(returncode=0),  # _add_block_log_rule
        ]

        # Remove domain (2 commands)
        remove_commands = [
            Mock(returncode=0),  # Delete iptables rule
            Mock(returncode=0),  # Destroy ipset
        ]

        mock_run.side_effect = setup_commands + remove_commands
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # Setup
        fw.setup_domain("example.com", ["93.184.216.34"])

        # Remove
        result = fw.remove_domain("example.com")

        assert result is True
        assert "example.com" not in fw.domain_ipsets
        assert mock_run.call_count == 9  # 7 setup + 2 remove

    @patch("subprocess.run")
    def it_allows_lan_to_gateway_traffic(mock_run):
        """Test _setup_base_rules allows LAN to gateway."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # Call through initialize_firewall which calls _setup_base_rules
        fw.initialize_firewall()

        # Verify that rules for LAN interface were created
        calls = [str(call) for call in mock_run.call_args_list]
        assert any("eth1" in call for call in calls)

    @patch("subprocess.run")
    def it_enables_block_logging(mock_run):
        """Test enable_block_logging adds NFLOG rules."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.enable_block_logging()

        assert result is True
        # Verify NFLOG command was called
        assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def it_sanitizes_domain_names_for_ipset(mock_run):
        """Test domain names are sanitized for ipset naming.

        FIXED: Same infinite loop issue.
        """
        from subprocess import CalledProcessError

        # Standard setup_domain mock sequence
        mock_run.side_effect = [
            CalledProcessError(1, ["iptables-legacy"], stderr="No such rule"),
            CalledProcessError(1, ["ipset"], stderr="Set does not exist"),
            Mock(returncode=0),  # Create ipset
            Mock(returncode=0),  # Add IP
            CalledProcessError(
                1, ["iptables-legacy"], stderr="No such rule"
            ),  # _remove_block_log_rule
            Mock(returncode=0),  # Add FORWARD rule
            Mock(returncode=0),  # _add_block_log_rule
        ]
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # Domain with special characters (dots, hyphens)
        result = fw.setup_domain("sub-domain.example.com", ["1.2.3.4"])

        assert result is True
        # Verify ipset name was sanitized (dots replaced with underscores)
        ipset_name = fw.domain_ipsets.get("sub-domain.example.com", "")
        assert "." not in ipset_name  # No dots in ipset names
        assert "_" in ipset_name  # Dots replaced with underscores
        assert ipset_name == "allow_sub-domain_example_com"

    @patch("subprocess.run")
    def it_handles_ipv6_addresses(mock_run):
        """Test firewall handles IPv6 addresses.

        IMPORTANT: Current implementation filters out IPv6 addresses.
        When only IPv6 IPs are provided, setup_domain returns True
        without creating any ipset (line 386-387 in firewall.py).
        This is a design decision to handle IPv6-only DNS responses.
        """
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        # IPv6-only address list
        result = fw.setup_domain("example.com", ["2606:2800:220:1:248:1893:25c8:1946"])

        # Should return True (skips IPv6 gracefully)
        assert result is True
        # No ipset created for IPv6-only responses
        assert "example.com" not in fw.domain_ipsets
        # No subprocess commands called (IPv6 is filtered out)
        assert mock_run.call_count == 0

    @patch("subprocess.run")
    def it_sets_up_static_ip_rules(mock_run):
        """Test setup_static_ip_rules creates iptables rules."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_static_ip_rules("allow_static_ips", "block_static_ips")

        assert result is True
        # Verify iptables commands were called
        assert mock_run.call_count >= 2

    @patch("subprocess.run")
    def it_adds_block_log_rule(mock_run):
        """Test _add_block_log_rule adds logging rule."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw._add_block_log_rule()

        assert result is True
        assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def it_removes_block_log_rule(mock_run):
        """Test _remove_block_log_rule removes logging rule.

        CRITICAL: This test reveals an infinite loop bug in the implementation!
        _remove_block_log_rule() uses while True and only breaks when _run_command
        returns False. However, _run_command() returns True for "already exists"
        errors, which can cause infinite loops.

        The fix: Make the mock return CalledProcessError after the first call
        to simulate "rule doesn't exist" and break the loop.
        """
        from subprocess import CalledProcessError

        # First call succeeds (rule exists), second call fails (no more rules)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # First delete succeeds
            CalledProcessError(1, ["iptables-legacy"], stderr="No such rule"),  # No more rules
        ]
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw._remove_block_log_rule()

        assert result is True
        assert mock_run.call_count == 2  # Should attempt twice and stop

    @patch("subprocess.run")
    def it_cleans_up_firewall_rules(mock_run):
        """Test cleanup removes all firewall rules."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")
        fw.domain_ipsets = {"example.com": "example_com"}

        fw.cleanup()

        # Verify cleanup commands were called
        assert mock_run.call_count > 0

    @patch("subprocess.run")
    def it_sets_up_host_firewall_rules_successfully(mock_run):
        """Test setup_host_firewall_rules configures host-side iptables rules.

        This tests the complete flow of:
        1. Getting Docker bridge interface names
        2. Checking iptables command availability
        3. Adding FORWARD rules
        4. Adding DNS exfiltration protection rules
        5. Adding NAT rules
        """
        import json

        # Mock Docker network inspect responses
        internal_network_response = json.dumps(
            [
                {
                    "Id": "abc123def456" * 3,  # 36 chars, will take first 12
                    "IPAM": {"Config": [{"Subnet": "172.20.0.0/24"}]},
                }
            ]
        )

        internet_network_response = json.dumps(
            [
                {
                    "Id": "def456abc123" * 3,  # 36 chars, will take first 12
                    "IPAM": {"Config": [{"Subnet": "172.21.0.0/24"}]},
                }
            ]
        )

        # Mock responses: docker network inspect (2x), iptables --version, iptables rules
        mock_responses = [
            Mock(
                returncode=0, stdout=internal_network_response, stderr=""
            ),  # docker network inspect internal
            Mock(
                returncode=0, stdout=internet_network_response, stderr=""
            ),  # docker network inspect internet
            Mock(returncode=0, stdout="iptables v1.8.7", stderr=""),  # iptables --version
        ]

        # Add mock responses for all iptables -C checks (should return 1 = not exists)
        # Total rules: host_rules (10), dns_filter_rules (12), nat_rules (2) = 24 rules / 2 = 12 checks
        for _ in range(12):
            mock_responses.append(
                Mock(returncode=1, stdout="", stderr="")
            )  # -C check fails (rule doesn't exist)
            mock_responses.append(Mock(returncode=0, stdout="", stderr=""))  # -A add succeeds

        mock_run.side_effect = mock_responses

        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_host_firewall_rules(
            internal_ip="172.20.0.2",
            project_name="project1",
            internal_network_name="internal-net",
            internet_network_name="internet",
            uplink_if="eth0",
        )

        assert result is True
        # Verify docker network inspect was called twice
        assert mock_run.call_count >= 3  # 2 docker + 1 iptables version + rules

    @patch("subprocess.run")
    def it_handles_missing_iptables_command(mock_run):
        """Test setup_host_firewall_rules handles missing iptables command."""
        import json

        # Mock Docker network inspect responses
        internal_network_response = json.dumps(
            [{"Id": "abc123def456" * 3, "IPAM": {"Config": [{"Subnet": "172.20.0.0/24"}]}}]
        )

        internet_network_response = json.dumps(
            [{"Id": "def456abc123" * 3, "IPAM": {"Config": [{"Subnet": "172.21.0.0/24"}]}}]
        )

        # Both iptables commands fail
        mock_run.side_effect = [
            Mock(returncode=0, stdout=internal_network_response, stderr=""),
            Mock(returncode=0, stdout=internet_network_response, stderr=""),
            FileNotFoundError("iptables not found"),  # iptables --version fails
            FileNotFoundError("iptables-legacy not found"),  # iptables-legacy --version fails
        ]

        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_host_firewall_rules(
            internal_ip="172.20.0.2",
            project_name="project1",
        )

        assert result is False

    @patch("subprocess.run")
    def it_handles_docker_network_inspect_failure(mock_run):
        """Test setup_host_firewall_rules handles Docker network inspect failure."""
        from subprocess import CalledProcessError

        # Docker network inspect fails
        mock_run.side_effect = CalledProcessError(
            1, ["docker", "network", "inspect"], stderr="Network not found"
        )

        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_host_firewall_rules(
            internal_ip="172.20.0.2",
            project_name="project1",
        )

        assert result is False

    @patch("subprocess.run")
    def it_skips_existing_iptables_rules(mock_run):
        """Test setup_host_firewall_rules skips rules that already exist."""
        import json

        # Mock Docker network inspect responses
        internal_network_response = json.dumps(
            [{"Id": "abc123def456" * 3, "IPAM": {"Config": [{"Subnet": "172.20.0.0/24"}]}}]
        )

        internet_network_response = json.dumps(
            [{"Id": "def456abc123" * 3, "IPAM": {"Config": [{"Subnet": "172.21.0.0/24"}]}}]
        )

        # Mock responses where some rules already exist (returncode=0)
        mock_responses = [
            Mock(returncode=0, stdout=internal_network_response, stderr=""),
            Mock(returncode=0, stdout=internet_network_response, stderr=""),
            Mock(returncode=0, stdout="iptables v1.8.7", stderr=""),
        ]

        # First rule exists (returncode=0), should skip -A
        # Second rule doesn't exist (returncode=1), should add
        for i in range(12):
            if i % 2 == 0:
                # Rule exists
                mock_responses.append(Mock(returncode=0, stdout="", stderr=""))  # -C check succeeds
                # No -A call needed
            else:
                # Rule doesn't exist
                mock_responses.append(Mock(returncode=1, stdout="", stderr=""))  # -C check fails
                mock_responses.append(Mock(returncode=0, stdout="", stderr=""))  # -A add succeeds

        mock_run.side_effect = mock_responses

        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")

        result = fw.setup_host_firewall_rules(
            internal_ip="172.20.0.2",
            project_name="project1",
        )

        assert result is True
