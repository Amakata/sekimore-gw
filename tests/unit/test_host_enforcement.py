"""Unit tests for the host-side enforcement: DOCKER-USER (#186) and INPUT (#190)."""

import json
import subprocess
from unittest.mock import patch

from src import host_enforcement
from src.host_enforcement import (
    FORWARD_CHAIN,
    INPUT_CHAIN,
    HostEnforcement,
    bridge_name_from_inspect,
    rules_for,
    stale_rules,
    tag_for,
)

TAG = tag_for("proj")
BR = "br-abe36c21b0f0"


def _inspect(network_id: str = "abe36c21b0f0" + "0" * 52, options: dict | None = None) -> str:
    return json.dumps([{"Id": network_id, "Options": options or {}}])


def _completed(
    cmd: list[str], returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")


class FakeHost:
    """Answers the commands HostEnforcement runs, and records them."""

    def __init__(self, listing: str = "", host_iptables: bool = True, insert_rc: int = 0):
        self.calls: list[list[str]] = []
        self.listing = listing
        self.host_iptables = host_iptables
        self.insert_rc = insert_rc

    def __call__(self, cmd: list[str], **_: object) -> subprocess.CompletedProcess:
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, 0, _inspect())
        # nsenter ... -- <iptables> -w <args>
        after = cmd[cmd.index("--") + 1 :]
        binary, args = after[0], after[2:]
        if binary == "iptables" and not self.host_iptables:
            return _completed(cmd, 127)  # no iptables in the host's mount namespace
        if args[:1] == ["-S"]:
            # one listing for every chain; stale_rules picks the chain's own lines
            return _completed(cmd, 0, self.listing)
        if args[:1] == ["-I"]:
            return _completed(cmd, self.insert_rc)
        return _completed(cmd, 0)

    def iptables_args(self) -> list[list[str]]:
        return [c[c.index("--") + 3 :] for c in self.calls if "--" in c]


def describe_rules_for():
    def it_returns_same_bridge_traffic_before_dropping_the_rest_in_docker_user():
        forward = [body for chain, body in rules_for(BR, TAG) if chain == FORWARD_CHAIN]
        assert len(forward) == 2
        assert forward[0][-1] == "RETURN"
        assert forward[0][:4] == ["-i", BR, "-o", BR]
        assert forward[1][-1] == "DROP"
        assert forward[1][:2] == ["-i", BR]
        assert "-o" not in forward[1]

    def it_accepts_replies_before_dropping_the_rest_in_input():
        inp = [body for chain, body in rules_for(BR, TAG) if chain == INPUT_CHAIN]
        assert len(inp) == 2
        assert inp[0][-1] == "ACCEPT"
        assert (
            "--ctstate" in inp[0] and inp[0][inp[0].index("--ctstate") + 1] == "RELATED,ESTABLISHED"
        )
        assert inp[0][:2] == ["-i", BR]
        assert inp[1][-1] == "DROP"
        assert inp[1][:2] == ["-i", BR]
        assert "--ctstate" not in inp[1]

    def it_tags_every_rule():
        for _chain, rule in rules_for(BR, TAG):
            assert rule[rule.index("--comment") + 1] == TAG


def describe_bridge_name_from_inspect():
    def it_derives_the_name_from_the_network_id():
        assert bridge_name_from_inspect(_inspect()) == BR

    def it_prefers_a_custom_bridge_name():
        custom = _inspect(options={"com.docker.network.bridge.name": "sgw0"})
        assert bridge_name_from_inspect(custom) == "sgw0"

    def it_returns_none_for_an_empty_listing_or_a_short_id():
        assert bridge_name_from_inspect("[]") is None
        assert bridge_name_from_inspect(_inspect(network_id="abc")) is None


LISTING = "\n".join(
    [
        f"-A {FORWARD_CHAIN} -i br-old0000000 -o br-old0000000 -m comment --comment {TAG} -j RETURN",
        f"-A {FORWARD_CHAIN} -i br-old0000000 -m comment --comment {TAG} -j DROP",
        f"-A {FORWARD_CHAIN} -i br-other00000 -m comment --comment sekimore:other -j DROP",
        f'-A {FORWARD_CHAIN} -i br-x -m comment --comment "sekimore:proj and more" -j DROP',
        f"-A {FORWARD_CHAIN} -i eth0 -j ACCEPT",
        f"-A {FORWARD_CHAIN} ! -i eth0 -o services1 -p tcp -m tcp --dport 3128 -j ACCEPT",
        f"-A {INPUT_CHAIN} -i br-old0000000 -m conntrack --ctstate RELATED,ESTABLISHED"
        f" -m comment --comment {TAG} -j ACCEPT",
        f"-A {INPUT_CHAIN} -i br-old0000000 -m comment --comment {TAG} -j DROP",
        f"-A {INPUT_CHAIN} -i lo -j ACCEPT",
    ]
)


def describe_stale_rules():
    def it_turns_our_rules_of_that_chain_into_deletes():
        deletes = stale_rules(LISTING, TAG, FORWARD_CHAIN)
        assert len(deletes) == 2
        assert all(d[0] == "-D" and d[1] == FORWARD_CHAIN for d in deletes)
        assert deletes[0][2:4] == ["-i", "br-old0000000"]

        deletes = stale_rules(LISTING, TAG, INPUT_CHAIN)
        assert len(deletes) == 2
        assert all(d[1] == INPUT_CHAIN for d in deletes)
        assert "RELATED,ESTABLISHED" in deletes[0]

    def it_leaves_other_projects_and_docker_desktops_rules_alone():
        joined = [" ".join(d) for d in stale_rules(LISTING, TAG, FORWARD_CHAIN)]
        joined += [" ".join(d) for d in stale_rules(LISTING, TAG, INPUT_CHAIN)]
        assert not any("sekimore:other" in d for d in joined)
        assert not any("and more" in d for d in joined)
        assert not any("eth0" in d for d in joined)
        assert not any("-i lo" in d for d in joined)

    def it_returns_nothing_for_an_empty_chain():
        assert stale_rules("", TAG, FORWARD_CHAIN) == []


def describe_apply():
    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=False)
    def it_refuses_without_the_hosts_pid_namespace(_reachable):
        host = FakeHost()
        he = HostEnforcement("proj", runner=host)
        assert he.apply() is False
        assert he.in_place is False
        assert host.calls == []  # nothing is touched in our own namespace

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_removes_its_old_rules_and_inserts_the_new_ones_at_the_top_of_each_chain(_reachable):
        host = FakeHost(listing=LISTING)
        he = HostEnforcement("proj", runner=host)

        assert he.apply() is True
        assert he.in_place is True
        assert he.bridge == BR

        args = host.iptables_args()
        deletes = [a for a in args if a[:1] == ["-D"]]
        inserts = [a for a in args if a[:1] == ["-I"]]
        assert len(deletes) == 4 and all("br-old0000000" in d for d in deletes)
        assert not any("br-other00000" in " ".join(d) for d in deletes)
        forward = [i for i in inserts if i[1] == FORWARD_CHAIN]
        inp = [i for i in inserts if i[1] == INPUT_CHAIN]
        assert [i[2] for i in forward] == ["1", "2"]
        assert [i[-1] for i in forward] == ["RETURN", "DROP"]
        assert [i[2] for i in inp] == ["1", "2"]
        assert [i[-1] for i in inp] == ["ACCEPT", "DROP"]
        assert all(BR in i for i in inserts)
        # deletes happen before inserts
        assert args.index(deletes[-1]) < args.index(inserts[0])

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_prefers_the_hosts_iptables(_reachable):
        host = FakeHost()
        he = HostEnforcement("proj", runner=host)
        assert he.apply() is True
        first = host.calls[0]
        assert first[:6] == ["nsenter", "-t", "1", "-m", "-n", "--"]
        assert first[6] == "iptables"

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_falls_back_to_its_own_iptables_nft_in_the_hosts_netns(_reachable):
        host = FakeHost(host_iptables=False)
        he = HostEnforcement("proj", runner=host)
        assert he.apply() is True
        chosen = [c for c in host.calls if "-I" in c][0]
        assert chosen[:5] == ["nsenter", "-t", "1", "-n", "--"]
        assert chosen[5] == "iptables-nft"

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_reports_failure_when_an_insert_fails(_reachable):
        host = FakeHost(insert_rc=1)
        he = HostEnforcement("proj", runner=host)
        assert he.apply() is False
        assert he.in_place is False

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_uses_the_projects_internal_network(_reachable):
        host = FakeHost()
        he = HostEnforcement("proj", internal_network_name="lan", runner=host)
        he.apply()
        assert ["docker", "network", "inspect", "proj_lan"] in host.calls


def describe_verify():
    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_is_true_while_every_rule_is_present(_reachable):
        host = FakeHost()
        he = HostEnforcement("proj", runner=host)
        he.apply()
        assert he.verify() is True
        checks = [a for a in host.iptables_args() if a[:1] == ["-C"]]
        assert len(checks) == 4
        assert sorted({c[1] for c in checks}) == sorted([FORWARD_CHAIN, INPUT_CHAIN])

    @patch.object(host_enforcement.HostEnforcement, "host_netns_reachable", return_value=True)
    def it_is_false_once_a_rule_is_gone(_reachable):
        class Gone(FakeHost):
            def __call__(self, cmd, **kw):
                if "-C" in cmd and INPUT_CHAIN in cmd:
                    return _completed(cmd, 1)
                return super().__call__(cmd, **kw)

        he = HostEnforcement("proj", runner=Gone())
        he.apply()
        assert he.verify() is False

    def it_is_false_before_apply():
        assert HostEnforcement("proj", runner=FakeHost()).verify() is False
