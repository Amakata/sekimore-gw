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

        # A delete that fails with "no chain" returns False (ending the loop)
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


def describe_relay_ports():
    """Opening INPUT for the relay (limited to lan_if; no rules are added without one)."""

    def _input_dport_rules(mock_run):
        rules = []
        for c in mock_run.call_args_list:
            cmd = c.args[0]
            if len(cmd) > 3 and cmd[1:3] == ["-A", "INPUT"] and "--dport" in cmd:
                rules.append(cmd)
        return rules

    @patch("subprocess.run")
    def it_does_not_add_relay_rules_by_default(mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        FirewallManager(wan_interface="eth0", lan_interface="eth1").initialize_firewall()
        baseline = [c.args[0] for c in mock_run.call_args_list]
        ports = {r[r.index("--dport") + 1] for r in _input_dport_rules(mock_run)}
        assert ports == {"53", "3128", "8080"}

        mock_run.reset_mock()
        FirewallManager(
            wan_interface="eth0", lan_interface="eth1", relay_ports=[]
        ).initialize_firewall()
        assert [c.args[0] for c in mock_run.call_args_list] == baseline, (
            "relay_ports=[] must be byte-identical"
        )

    @patch("subprocess.run")
    def it_opens_relay_ports_on_lan_interface_only(mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        FirewallManager(
            wan_interface="eth0", lan_interface="eth1", relay_ports=[22, 8420, 443]
        ).initialize_firewall()
        cmds = [c.args[0] for c in mock_run.call_args_list]
        for port in ("22", "8420", "443"):
            assert [
                "iptables-legacy",
                "-A",
                "INPUT",
                "-i",
                "eth1",
                "-p",
                "tcp",
                "--dport",
                port,
                "-j",
                "ACCEPT",
            ] in cmds
        for rule in _input_dport_rules(mock_run):
            if rule[rule.index("--dport") + 1] in ("22", "8420", "443"):
                assert "-i" in rule and rule[rule.index("-i") + 1] == "eth1", rule
        # Relay rules come before the Web UI (8080) in the INPUT chain
        idx = [
            i
            for i, c in enumerate(cmds)
            if len(c) > 3 and c[1:3] == ["-A", "INPUT"] and "--dport" in c
        ]
        dports = [cmds[i][cmds[i].index("--dport") + 1] for i in idx]
        assert dports.index("22") < dports.index("8080")


def describe_allowed_ports():
    """0.2.2: restricting the destination ports allowed to allowed domains / IPs (all ports as before when unset)."""

    def _forward_accepts(mock_run):
        return [
            c.args[0]
            for c in mock_run.call_args_list
            if len(c.args[0]) > 2 and c.args[0][1:3] == ["-A", "FORWARD"] and "ACCEPT" in c.args[0]
        ]

    def _ok_except_nflog_delete(mock_run):
        """Every command succeeds, except deleting the NFLOG rule reports "not found" (to stop the while loop in _remove_block_log_rule)."""
        from subprocess import CalledProcessError

        def run(cmd, **_kw):
            if cmd[1] == "-D" and "--nflog-prefix" in cmd:
                raise CalledProcessError(1, cmd, stderr="No such rule")
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run

    @patch("subprocess.run")
    def it_keeps_the_single_all_ports_rule_by_default(mock_run):
        _ok_except_nflog_delete(mock_run)
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")
        fw.setup_domain("example.com", ["93.184.216.34"])
        baseline = [c.args[0] for c in mock_run.call_args_list]
        accepts = _forward_accepts(mock_run)
        assert len(accepts) == 1 and "--dport" not in accepts[0]

        mock_run.reset_mock()
        FirewallManager(wan_interface="eth0", lan_interface="eth1", allowed_ports=[]).setup_domain(
            "example.com", ["93.184.216.34"]
        )
        assert [c.args[0] for c in mock_run.call_args_list] == baseline, (
            "allowed_ports=[] must be byte-identical"
        )

    @patch("subprocess.run")
    def it_adds_one_tcp_rule_per_port_and_deletes_them_the_same_way(mock_run):
        _ok_except_nflog_delete(mock_run)
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1", allowed_ports=[443, 80])
        fw.setup_domain("example.com", ["93.184.216.34"])
        accepts = _forward_accepts(mock_run)
        assert [r[r.index("--dport") + 1] for r in accepts] == ["443", "80"]
        for r in accepts:
            assert r[:9] == [
                "iptables-legacy",
                "-A",
                "FORWARD",
                "-i",
                "eth1",
                "-o",
                "eth0",
                "-p",
                "tcp",
            ], r
            assert "--match-set" in r and r[-2:] == ["-j", "ACCEPT"]
        # Not a single rule allows all ports
        assert all("--dport" in r for r in accepts)
        # The dedup deletes are per-port as well
        deletes = [
            c.args[0]
            for c in mock_run.call_args_list
            if len(c.args[0]) > 2
            and c.args[0][1:3] == ["-D", "FORWARD"]
            and "--match-set" in c.args[0]
        ]
        assert sorted(r[r.index("--dport") + 1] for r in deletes) == ["443", "80"]

        # remove_domain deletes per-port too
        mock_run.reset_mock()
        fw.remove_domain("example.com")
        deletes = [
            c.args[0]
            for c in mock_run.call_args_list
            if len(c.args[0]) > 2
            and c.args[0][1:3] == ["-D", "FORWARD"]
            and "--match-set" in c.args[0]
        ]
        assert sorted(r[r.index("--dport") + 1] for r in deletes) == ["443", "80"]

    @patch("subprocess.run")
    def it_restricts_static_allow_ips_and_lan_only_domains_too(mock_run):
        _ok_except_nflog_delete(mock_run)
        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1", allowed_ports=[443])
        fw.setup_static_ip_rules("allow_static", "block_static")
        accepts = _forward_accepts(mock_run)
        assert len(accepts) == 1 and accepts[0][3:7] == ["-p", "tcp", "--dport", "443"]
        assert "-i" not in accepts[0]
        # DROP is unchanged
        drops = [c.args[0] for c in mock_run.call_args_list if "DROP" in c.args[0]]
        assert len(drops) == 1 and "--dport" not in drops[0]

        mock_run.reset_mock()
        fw.setup_domain("sekimore.lan", ["10.100.0.2"])
        accepts = _forward_accepts(mock_run)
        assert len(accepts) == 1 and accepts[0][3:5] == ["-i", "eth1"] and "-o" not in accepts[0]
        assert "--dport" in accepts[0]


def describe_ipset_names_are_unique_per_domain():
    """setup_domain destroys and recreates the set on every resolution, so two domains sharing
    one name means each resolution drops the other's addresses, and removing either takes
    both. Truncating to 31 characters made that happen for any pair agreeing on their first
    25 — and a wildcard entry creates subdomains as they resolve, so the pair need not both
    be written in the config."""

    from src.firewall import _ipset_name

    def a_short_name_stays_readable():
        assert _ipset_name("pypi.org") == "allow_pypi_org"
        assert _ipset_name("github.com") == "allow_github_com"

    def every_name_fits_the_limit():
        for d in (
            "a.com",
            "pkg-containers.githubusercontent.com",
            "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
            "x" * 200 + ".example.com",
        ):
            assert len(_ipset_name(d)) <= 31, d

    def two_domains_agreeing_on_their_first_25_characters_do_not_collide():
        # The shape that made this reachable: same prefix, different name.
        a = "pkg-containers.githubusercontent.com"
        b = "pkg-containers.githubusercontentx.com"
        assert a[:25] == b[:25]
        assert _ipset_name(a) != _ipset_name(b)

    def the_githubusercontent_hosts_in_this_deployment_are_distinct():
        names = {
            _ipset_name(d)
            for d in (
                "pkg-containers.githubusercontent.com",
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
                "raw.githubusercontent.com",
            )
        }
        assert len(names) == 4

    def the_name_is_stable_for_a_given_domain():
        # setup_domain and remove_domain compute it separately; a name that moved would leave
        # the set behind.
        assert _ipset_name("a.very.long.subdomain.example.com") == _ipset_name(
            "a.very.long.subdomain.example.com"
        )

    def a_wildcard_keeps_its_own_name():
        assert _ipset_name("*.example.com") != _ipset_name(".example.com")


def describe_concurrent_rule_changes():
    """0.2.15: the config watcher and the DNS handler both reach these methods.

    domain_ipsets had no lock, and the NFLOG bracket is worse than a plain race: setup_domain and
    remove_domain each remove the LOG rule, change the ACCEPTs and put it back, so two brackets
    crossing can leave it ahead of the ACCEPTs or drop it — blocked packets stop being logged, or
    every packet is.
    """

    def _recording_firewall():
        """A FirewallManager whose commands are recorded with the thread that ran them.

        The sleep widens the window: without the lock the two callers interleave essentially
        every run, and with it they cannot.
        """
        import threading
        import time

        fw = FirewallManager(wan_interface="eth0", lan_interface="eth1")
        trace: list[tuple[int, str]] = []
        trace_lock = threading.Lock()

        def record(cmd):
            with trace_lock:
                trace.append((threading.get_ident(), " ".join(cmd)))
            time.sleep(0.001)
            # _remove_block_log_rule deletes NFLOG rules until one fails, so a fake that always
            # succeeds never leaves the loop
            return "NFLOG" not in cmd

        fw._run_command = record  # type: ignore[method-assign]
        return fw, trace

    def it_serializes_two_callers():
        import threading

        fw, trace = _recording_firewall()
        fw.domain_ipsets["b.example.com"] = "sekimore_b"

        threads = [
            threading.Thread(target=fw.setup_domain, args=("a.example.com", ["10.0.0.1"])),
            threading.Thread(target=fw.remove_domain, args=("b.example.com",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every command of one caller comes before every command of the other. Without the lock
        # the two runs interleave and this switches back and forth.
        switches = sum(1 for a, b in zip(trace, trace[1:], strict=False) if a[0] != b[0])
        assert switches <= 1, f"the two callers interleaved: {trace}"

    def it_keeps_the_log_rule_bracket_contiguous():
        """The LOG rule must go back before anyone else starts moving ACCEPT rules."""
        import threading

        fw, trace = _recording_firewall()
        fw.domain_ipsets["b.example.com"] = "sekimore_b"

        threads = [
            threading.Thread(target=fw.setup_domain, args=("a.example.com", ["10.0.0.1"])),
            threading.Thread(target=fw.setup_domain, args=("c.example.com", ["10.0.0.2"])),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        switches = sum(1 for a, b in zip(trace, trace[1:], strict=False) if a[0] != b[0])
        assert switches <= 1, f"two setup_domain brackets crossed: {trace}"
        assert set(fw.domain_ipsets) == {"a.example.com", "b.example.com", "c.example.com"}

    def it_is_reentrant_so_update_can_call_setup():
        """update_domain_ips calls setup_domain, and cleanup calls remove_domain."""
        fw, _ = _recording_firewall()

        assert fw.update_domain_ips("new.example.com", ["10.0.0.9"]) is True
        assert "new.example.com" in fw.domain_ipsets

        fw.cleanup()
        assert fw.domain_ipsets == {}
