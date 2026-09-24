"""Host-side FORWARD enforcement (#186).

The container firewall sees only the traffic an agent routes through the gateway. A root
process in an agent container can point its default route at Docker's own bridge gateway and
leave through the host's NAT instead, past every layer here — confirmed in PoC-3. The rule that
stops it has to live where the agent cannot reach: the host's FORWARD path, which Docker hands
to the DOCKER-USER chain before any rule of its own.

Two rules per internal bridge, inserted at the top of DOCKER-USER:

    -i br-X -o br-X -j RETURN   # dev <-> gateway on the same bridge. br_netfilter sends bridged
                                # frames through FORWARD too, so this has to be explicit
    -i br-X         -j DROP     # anything else that came in from the internal bridge

The gateway reaches the host's network namespace through PID 1 (`pid: host` on the gateway
service) with nsenter. The host's own iptables is preferred, so the rules land in the backend
dockerd uses (nf_tables on Docker Desktop). Each rule carries the comment `sekimore:<project>`,
and every start removes the rules with our tag before inserting: a recreated network has a new
bridge name, and the old rules would only be dead weight. The rules are left in place on
shutdown on purpose — with the gateway down, the agent must stay confined.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
from collections.abc import Callable

from .logger import ComponentType, log_error, log_system_event

CHAIN = "DOCKER-USER"
_NSENTER = ["nsenter", "-t", "1"]
# In order of preference. The first one whose `-S DOCKER-USER` succeeds is used.
_IPTABLES_CANDIDATES: list[tuple[list[str], str]] = [
    ([*_NSENTER, "-m", "-n", "--", "iptables", "-w"], "the host's own iptables"),
    ([*_NSENTER, "-n", "--", "iptables-nft", "-w"], "iptables-nft in the host's network namespace"),
    (
        [*_NSENTER, "-n", "--", "iptables-legacy", "-w"],
        "iptables-legacy in the host's network namespace",
    ),
]

Runner = Callable[..., subprocess.CompletedProcess[str]]


def tag_for(project_name: str) -> str:
    """The comment that marks this project's rules."""
    return f"sekimore:{project_name}"


def bridge_name_from_inspect(inspect_json: str) -> str | None:
    """The host-side bridge interface of a network, from `docker network inspect` output.

    Docker names the bridge `br-` + the first 12 characters of the network id, unless the
    network sets `com.docker.network.bridge.name`.
    """
    data = json.loads(inspect_json)
    if not data:
        return None
    network = data[0]
    custom = (network.get("Options") or {}).get("com.docker.network.bridge.name")
    if custom:
        return str(custom)
    network_id = str(network.get("Id", ""))
    return f"br-{network_id[:12]}" if len(network_id) >= 12 else None


def rules_for(bridge: str, tag: str) -> list[list[str]]:
    """The rule bodies, in evaluation order. Index + 1 is the position in DOCKER-USER."""
    return [
        ["-i", bridge, "-o", bridge, "-m", "comment", "--comment", tag, "-j", "RETURN"],
        ["-i", bridge, "-m", "comment", "--comment", tag, "-j", "DROP"],
    ]


def stale_rules(listing: str, tag: str) -> list[list[str]]:
    """The delete commands for our tagged rules in an `iptables -S DOCKER-USER` listing.

    Only a rule whose comment is exactly our tag is ours: another project's rules carry
    another tag, and Docker Desktop's own rules carry none.
    """
    deletes: list[list[str]] = []
    for line in listing.splitlines():
        parts = shlex.split(line)
        if len(parts) < 3 or parts[0] != "-A" or parts[1] != CHAIN:
            continue
        if "--comment" in parts and parts[parts.index("--comment") + 1] == tag:
            deletes.append(["-D", *parts[1:]])
    return deletes


class HostEnforcement:
    """Keeps the two DOCKER-USER rules for one project's internal bridge in place."""

    def __init__(
        self,
        project_name: str,
        internal_network_name: str = "internal-net",
        runner: Runner = subprocess.run,
    ):
        self.project_name = project_name
        self.network = f"{project_name}_{internal_network_name}"
        self.tag = tag_for(project_name)
        self._run = runner
        self._iptables: list[str] | None = None
        self.bridge: str | None = None
        self.in_place = False

    def _exec(self, cmd: list[str], timeout: float = 10) -> subprocess.CompletedProcess[str]:
        return self._run(cmd, capture_output=True, text=True, timeout=timeout)

    @staticmethod
    def host_netns_reachable() -> bool:
        """PID 1 has to be the host's init, not our own entrypoint.

        Without `pid: host`, `nsenter -t 1 -n` would land in this container's own namespace,
        where DOCKER-USER does not exist and nothing would be enforced. Comparing the network
        namespaces tells the two apart.
        """
        try:
            return os.readlink("/proc/1/ns/net") != os.readlink("/proc/self/ns/net")
        except OSError:
            return False

    def _iptables_cmd(self) -> list[str] | None:
        if self._iptables:
            return self._iptables
        for cmd, label in _IPTABLES_CANDIDATES:
            try:
                result = self._exec([*cmd, "-S", CHAIN])
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0:
                self._iptables = cmd
                log_system_event("Host-side enforcement uses " + label)
                return cmd
        return None

    def bridge_name(self) -> str | None:
        try:
            result = self._exec(["docker", "network", "inspect", self.network])
        except (OSError, subprocess.TimeoutExpired) as e:
            log_error(ComponentType.FIREWALL, f"docker network inspect {self.network}: {e}")
            return None
        if result.returncode != 0:
            log_error(
                ComponentType.FIREWALL,
                f"docker network inspect {self.network}: {result.stderr.strip()}",
            )
            return None
        try:
            return bridge_name_from_inspect(result.stdout)
        except (ValueError, KeyError, TypeError) as e:
            log_error(ComponentType.FIREWALL, f"docker network inspect {self.network}: {e}")
            return None

    def apply(self) -> bool:
        """Remove our old rules and insert the current ones at the top of DOCKER-USER."""
        self.in_place = False
        if not self.host_netns_reachable():
            log_error(
                ComponentType.FIREWALL,
                "Host-side FORWARD enforcement is not in place: PID 1 is not the host's init. "
                "The gateway service needs `pid: host` and `privileged: true` in "
                "docker-compose.yml (#186)",
            )
            return False
        iptables = self._iptables_cmd()
        if not iptables:
            log_error(
                ComponentType.FIREWALL,
                f"Host-side FORWARD enforcement is not in place: no iptables reaches the host's "
                f"{CHAIN} chain through nsenter",
            )
            return False
        bridge = self.bridge_name()
        if not bridge:
            return False
        self.bridge = bridge

        try:
            listing = self._exec([*iptables, "-S", CHAIN])
            for delete in stale_rules(listing.stdout, self.tag):
                self._exec([*iptables, *delete])
            for position, body in enumerate(rules_for(bridge, self.tag), start=1):
                result = self._exec([*iptables, "-I", CHAIN, str(position), *body])
                if result.returncode != 0:
                    log_error(
                        ComponentType.FIREWALL,
                        f"Host-side FORWARD enforcement: {CHAIN} insert failed: "
                        f"{result.stderr.strip()}",
                    )
                    return False
        except (OSError, subprocess.TimeoutExpired) as e:
            # nsenter or iptables went away between the probe and the insert. The gateway
            # keeps starting; the watcher retries, and the log says the agent is not confined.
            log_error(ComponentType.FIREWALL, f"Host-side FORWARD enforcement: {e}")
            return False
        self.in_place = True
        log_system_event("Host-side FORWARD enforcement in place", bridge=bridge, chain=CHAIN)
        return True

    def verify(self) -> bool:
        """True while both rules are present for the bridge we applied them to."""
        if not (self._iptables and self.bridge):
            return False
        for body in rules_for(self.bridge, self.tag):
            try:
                result = self._exec([*self._iptables, "-C", CHAIN, *body])
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode != 0:
                return False
        return True

    async def watch(self, interval: float = 30.0) -> None:
        """Re-apply whenever the rules are gone.

        A Docker (or Docker Desktop) restart rebuilds the host's tables without them, and a
        recreated network has a different bridge name.
        """
        while True:
            await asyncio.sleep(interval)
            try:
                bridge_now = await asyncio.to_thread(self.bridge_name)
                if (
                    self.in_place
                    and bridge_now == self.bridge
                    and await asyncio.to_thread(self.verify)
                ):
                    continue
                log_system_event(
                    "Host-side FORWARD enforcement missing; re-applying",
                    bridge=bridge_now or "unknown",
                )
                await asyncio.to_thread(self.apply)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — the watcher must outlive any single failure
                log_error(ComponentType.FIREWALL, f"Host-side FORWARD enforcement watcher: {e}")
