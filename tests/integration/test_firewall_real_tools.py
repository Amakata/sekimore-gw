"""setup_domain and remove_domain against the real iptables-legacy and ipset.

iptables -D deletes only an exact match, which a mocked command cannot show: remove_domain once
deleted without the interfaces the rule was added with, and the rule and its set stayed.

Needs root with CAP_NET_ADMIN and both tools; skipped otherwise, and failed instead of skipped
when SEKIMORE_E2E_REQUIRED=1. Run it in a throwaway container, for example:

    docker run --rm --cap-add NET_ADMIN -v "$PWD:/src" -w /src <image with the tools and uv> \
        uv run pytest tests/integration/test_firewall_real_tools.py

It touches only the names below, plus the NFLOG rule that setup_domain moves to the end of
FORWARD, which it removes afterwards if it was not there before.
"""

import os
import shutil
import subprocess

import pytest

from src.firewall import FirewallManager, _ipset_name, _is_lan_only

IPTABLES = "iptables-legacy"
IPSET = "ipset"
DOMAINS = ["real-tools.example.com", "real-tools.lan"]
WILDCARD_SUBDOMAINS = ["a.real-tools.example.net", "b.real-tools.example.net"]
PORTS = [[], [443]]


def _usable() -> str | None:
    """Why the tools cannot be used here, or None when they can."""
    if os.geteuid() != 0:
        return "not root"
    for tool in (IPTABLES, IPSET):
        if shutil.which(tool) is None:
            return f"{tool} not found"
    for cmd in ([IPTABLES, "-S", "FORWARD"], [IPSET, "list", "-n"]):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return f"{' '.join(cmd)} failed (CAP_NET_ADMIN?): {result.stderr.strip()}"
    return None


def _forward() -> str:
    return subprocess.run([IPTABLES, "-S", "FORWARD"], capture_output=True, text=True).stdout


def _sets() -> list[str]:
    return subprocess.run([IPSET, "list", "-n"], capture_output=True, text=True).stdout.split()


@pytest.fixture
def firewall():
    reason = _usable()
    if reason:
        if os.environ.get("SEKIMORE_E2E_REQUIRED") == "1":
            pytest.fail(f"SEKIMORE_E2E_REQUIRED=1 but iptables/ipset are not usable: {reason}")
        pytest.skip(reason)

    had_nflog = "NFLOG" in _forward()
    fw = FirewallManager(wan_interface="sgwtest-wan", lan_interface="sgwtest-lan")
    yield fw

    # Leave nothing behind, also when remove_domain left the rule and the set
    for domain in DOMAINS + WILDCARD_SUBDOMAINS:
        for ports in PORTS:
            fw.allowed_ports = ports
            for rule in fw._forward_accept_rules(
                _ipset_name(domain), _is_lan_only(domain), action="-D"
            ):
                subprocess.run(rule, capture_output=True)
        subprocess.run([IPSET, "destroy", _ipset_name(domain)], capture_output=True)
    if not had_nflog:
        fw._remove_block_log_rule()


def describe_remove_domain_with_the_real_tools():
    @pytest.mark.parametrize("allowed_ports", PORTS)
    @pytest.mark.parametrize("domain", DOMAINS)
    def it_leaves_no_rule_and_no_set(firewall, domain, allowed_ports):
        firewall.allowed_ports = allowed_ports
        assert firewall.setup_domain(domain, ["192.0.2.30", "198.51.100.30"]) is True
        ipset_name = firewall.domain_ipsets[domain]
        assert ipset_name in _forward()
        assert ipset_name in _sets()

        assert firewall.remove_domain(domain) is True

        assert ipset_name not in _forward()
        assert ipset_name not in _sets()
        assert domain not in firewall.domain_ipsets


def describe_reload_withdrawal_with_the_real_tools():
    def it_withdraws_the_subdomains_of_a_dropped_wildcard(firewall):
        """What reload_config does once DNS has the new lists, without a DNS server."""
        from types import SimpleNamespace

        from src.dns_server import DNSServer
        from src.orchestrator import SecurityGatewayOrchestrator

        for name in WILDCARD_SUBDOMAINS:
            assert firewall.setup_domain(name, ["203.0.113.30"]) is True
        sets = [firewall.domain_ipsets[name] for name in WILDCARD_SUBDOMAINS]

        # The new lists: the wildcard is gone
        dns = DNSServer.__new__(DNSServer)
        dns.allowed_domains = ["example.org"]
        dns.blocked_domains = set()
        dns.ignored_domains = []
        dns.domain_handlers = {}
        SecurityGatewayOrchestrator._withdraw_refused_admissions(
            SimpleNamespace(firewall=firewall, dns_server=dns)  # type: ignore[arg-type]
        )

        forward, listed = _forward(), _sets()
        for ipset_name in sets:
            assert ipset_name not in forward
            assert ipset_name not in listed
        assert firewall.domain_ipsets == {}
