"""Firewall management - dynamic iptables/ipset rule handling."""

import hashlib
import subprocess

from .logger import ComponentType, log_error, log_system_event


def _ipset_name(domain: str) -> str:
    """The ipset holding a domain's addresses. At most 31 characters, and unique per domain.

    Truncating to 31 made two domains that agree on their first 25 characters share one set,
    and setup_domain destroys and recreates it on every resolution — so one domain's addresses
    would drop the other's, and removing either would take both. A wildcard entry means the
    subdomains are created as they are resolved, so the pair need not both be in the config.
    Names short enough to survive intact keep their readable form.
    """
    readable = f"allow_{domain.replace('.', '_').replace('*', 'wildcard')}"
    if len(readable) <= 31:
        return readable
    # 7 for the prefix leaves 24 for the digest, which is well clear of a collision.
    digest = hashlib.sha256(domain.encode()).hexdigest()[:24]
    return f"allow_h{digest}"


class FirewallManager:
    """iptables/ipset-based firewall management."""

    def __init__(
        self,
        wan_interface: str,
        lan_interface: str,
        relay_ports: list[int] | None = None,
        allowed_ports: list[int] | None = None,
    ):
        """Initialize the manager.

        Args:
            wan_interface: WAN-side interface (internet side, detected dynamically by the orchestrator)
            lan_interface: LAN-side interface (local network side, detected dynamically by the orchestrator)
            relay_ports: TCP ports to open on lan_if INPUT for the relay (no rules are added if empty)
            allowed_ports: Destination TCP ports allowed towards allowlisted domains / IPs (empty means all ports, as before)
        """
        self.wan_if = wan_interface
        self.lan_if = lan_interface
        self.relay_ports: list[int] = list(relay_ports or [])
        self.allowed_ports: list[int] = list(allowed_ports or [])
        self.domain_ipsets: dict[str, str] = {}  # domain -> ipset_name

        # iptables/ipset commands (the legacy variant)
        self.iptables_cmd = "iptables-legacy"
        self.ipset_cmd = "ipset"

    def _run_command(self, cmd: list[str]) -> bool:
        """Run a command.

        Args:
            cmd: Command and arguments

        Returns:
            True on success
        """
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            # Ignore "already exists" errors (an add whose rule is already present)
            if "already" in e.stderr.lower():
                return True
            # Treat "does not exist" / "no chain" as a failed delete, so that the
            # while True loop in _remove_block_log_rule() terminates
            if "exist" in e.stderr.lower() or "no chain" in e.stderr.lower():
                return False
            log_error(
                ComponentType.FIREWALL,
                f"Command failed: {' '.join(cmd)}: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.FIREWALL, f"Command not found: {cmd[0]}")
            return False

    def initialize_firewall(self) -> bool:
        """Initialize the firewall.

        Returns:
            True on success
        """
        log_system_event("Initializing firewall...")

        # 1. sysctl settings are already applied by the sysctls section of docker-compose.yml
        # (net.ipv4.ip_forward=1, net.ipv4.conf.*.send_redirects=0)

        # 2. Flush existing rules (Docker DNS NAT rules are preserved)
        self._run_command([self.iptables_cmd, "-F"])
        # Never flush the whole NAT table: that would drop Docker DNS's 127.0.0.11
        # redirect rules. Only sekimore's own POSTROUTING rules are removed.
        # WARNING: `iptables -t nat -F` deletes the NAT rules for 127.0.0.11.
        self._run_command([self.iptables_cmd, "-X"])

        # 3. Default policies
        self._run_command([self.iptables_cmd, "-P", "INPUT", "DROP"])  # Reject inbound traffic
        self._run_command([self.iptables_cmd, "-P", "OUTPUT", "ACCEPT"])  # Allow our own outbound
        self._run_command(
            [self.iptables_cmd, "-P", "FORWARD", "DROP"]
        )  # Forwarding only via explicit rules

        # 4. NAT (MASQUERADE)
        if not self._run_command(
            [
                self.iptables_cmd,
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                self.wan_if,
                "-j",
                "MASQUERADE",
            ]
        ):
            return False

        # 5. Allow loopback (INPUT/OUTPUT)
        self._run_command([self.iptables_cmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        self._run_command([self.iptables_cmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

        # 6. Allow established connections (INPUT/OUTPUT/FORWARD)
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "FORWARD",
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )

        # 7. INPUT: allow only the minimum access to sekimore itself
        # ICMP (ping) - connectivity checks from the LAN side
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "icmp",
                "-j",
                "ACCEPT",
            ]
        )
        # DNS (53/udp) - DNS queries from ai-agent
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # DNS (53/tcp) - DNS probing from ai-agent (agent-setup.sh uses /dev/tcp)
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # Squid Proxy (3128/tcp) - HTTP/HTTPS requests from ai-agent
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-i",
                self.lan_if,
                "-p",
                "tcp",
                "--dport",
                "3128",
                "-j",
                "ACCEPT",
            ]
        )
        # The relay (sekimore-relay) - SSH(git) / HTTP API / 443 from ai-agent, on lan_if only.
        # When relay_ports is empty (no domain_handlers) the command sequence is unchanged.
        for relay_port in self.relay_ports:
            self._run_command(
                [
                    self.iptables_cmd,
                    "-A",
                    "INPUT",
                    "-i",
                    self.lan_if,
                    "-p",
                    "tcp",
                    "--dport",
                    str(relay_port),
                    "-j",
                    "ACCEPT",
                ]
            )
        # Web UI (8080/tcp) - administrator access
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "ACCEPT",
            ]
        )

        # 8. OUTPUT: allow the traffic sekimore itself needs
        # Docker's built-in DNS (127.0.0.11) - all ports, because the port is dynamic:
        # Docker DNS does not actually listen on 53 but on a random high port (e.g. 51116)
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-d",
                "127.0.0.11",
                "-j",
                "ACCEPT",
            ]
        )
        # Upstream DNS (53/udp) - name resolution
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ]
        )
        # HTTP/HTTPS (80/443) - package downloads, upstream proxy, etc.
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ]
        )
        # Upstream proxy (3128/8080) - for connecting to a corporate proxy
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "3128",
                "-j",
                "ACCEPT",
            ]
        )
        self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "ACCEPT",
            ]
        )

        log_system_event(
            "Firewall initialized",
            wan_if=self.wan_if,
            lan_if=self.lan_if,
        )
        return True

    def enable_block_logging(self) -> bool:
        """Enable logging of blocked packets.

        Call this after all ACCEPT rules are in place. Packets that reach the end of
        the FORWARD chain (i.e. the ones that get blocked) are logged.

        Returns:
            True on success
        """
        log_system_event("Enabling firewall block logging...")
        result = self._add_block_log_rule()

        if result:
            log_system_event("Firewall block logging enabled")
        else:
            log_error(ComponentType.FIREWALL, "Failed to enable block logging")

        return result

    def _add_block_log_rule(self) -> bool:
        """Add the NFLOG rule (internal helper).

        Logging happens in user space via ulogd2, which also works inside Docker.
        NFLOG is the successor to ULOG and is supported by current kernels.

        Returns:
            True on success
        """
        return self._run_command(
            [
                self.iptables_cmd,
                "-A",
                "FORWARD",
                "-j",
                "NFLOG",
                "--nflog-group",
                "1",
                "--nflog-prefix",
                "[FIREWALL-BLOCK] ",
            ]
        )

    def _remove_block_log_rule(self) -> bool:
        """Remove the NFLOG rule (internal helper).

        Removes every NFLOG rule if more than one is present.

        Returns:
            True on success (also True when no rule exists)
        """
        # Loop, since several NFLOG rules may be present
        while True:
            result = self._run_command(
                [
                    self.iptables_cmd,
                    "-D",
                    "FORWARD",
                    "-j",
                    "NFLOG",
                    "--nflog-group",
                    "1",
                    "--nflog-prefix",
                    "[FIREWALL-BLOCK] ",
                ]
            )
            # Stop once the delete fails, meaning no rule is left
            if not result:
                break

        return True

    def _forward_accept_rules(
        self, ipset_name: str, is_lan_only: bool | None, action: str = "-A"
    ) -> list[list[str]]:
        """Build the FORWARD ACCEPT rules targeting an ipset.

        With allowed_ports empty this is a single rule covering all ports, as before;
        otherwise one `-p tcp --dport <port>` rule per port. is_lan_only=None is for
        static IPs (no interface match). action is "-A" (add) or "-D" (delete).
        """
        base = [self.iptables_cmd, action, "FORWARD"]
        if is_lan_only is True:
            base += ["-i", self.lan_if]
        elif is_lan_only is False:
            base += ["-i", self.lan_if, "-o", self.wan_if]
        tail = ["-m", "set", "--match-set", ipset_name, "dst", "-j", "ACCEPT"]
        if not self.allowed_ports:
            return [base + tail]
        return [base + ["-p", "tcp", "--dport", str(port)] + tail for port in self.allowed_ports]

    def setup_domain(self, domain: str, ips: list[str]) -> bool:
        """Set up the ipset and iptables rules for a domain.

        Args:
            domain: Domain name
            ips: IPs to allow

        Returns:
            True on success
        """
        ipset_name = _ipset_name(domain)

        # LAN-only domain? (ends in .lan, or is a bare container name)
        is_lan_only = domain.endswith(".lan") or "." not in domain

        # Keep only IPv4 addresses
        ipv4_ips = [ip for ip in ips if ":" not in ip]

        # With no IPv4 address, keep the existing ipset (guards against IPv6-only answers)
        if not ipv4_ips:
            return True

        # Drop the existing rules for this ipset to avoid duplicates; with allowed_ports
        # set, that means the per-port rules
        for rule in self._forward_accept_rules(ipset_name, is_lan_only, action="-D"):
            self._run_command(rule)

        # Destroy the existing ipset
        self._run_command([self.ipset_cmd, "destroy", ipset_name])

        # Create the ipset (hash:ip, IPv4)
        if not self._run_command(
            [self.ipset_cmd, "create", ipset_name, "hash:ip", "family", "inet"]
        ):
            return False

        # Add the IPv4 addresses
        for ip in ipv4_ips:
            self._run_command([self.ipset_cmd, "add", ipset_name, ip])

        # Temporarily remove the LOG rule
        self._remove_block_log_rule()

        # Add the iptables rules, matching on interface (one rule per -p tcp --dport when
        # allowed_ports is set). LAN-only traffic (sekimore.lan etc.) matches -i only;
        # WAN-bound traffic matches both -i and -o.
        for rule in self._forward_accept_rules(ipset_name, is_lan_only, action="-A"):
            self._run_command(rule)

        # Re-add the LOG rule so it sits after the ACCEPT rules
        self._add_block_log_rule()

        self.domain_ipsets[domain] = ipset_name

        log_system_event(
            "Domain firewall rule added",
            domain=domain,
            ipset=ipset_name,
            ip_count=str(len(ips)),
            is_lan_only=str(is_lan_only),
        )

        return True

    def update_domain_ips(self, domain: str, new_ips: list[str]) -> bool:
        """Update a domain's IP list, e.g. when the TTL expires.

        Args:
            domain: Domain name
            new_ips: New IP list

        Returns:
            True on success
        """
        if domain not in self.domain_ipsets:
            return self.setup_domain(domain, new_ips)

        ipset_name = self.domain_ipsets[domain]

        # Read back the current members
        try:
            result = subprocess.run(
                [self.ipset_cmd, "list", ipset_name],
                check=True,
                capture_output=True,
                text=True,
            )
            existing_ips = set()
            in_members = False
            for line in result.stdout.splitlines():
                if line.startswith("Members:"):
                    in_members = True
                    continue
                if in_members and line.strip():
                    existing_ips.add(line.strip())

        except subprocess.CalledProcessError:
            existing_ips = set()

        new_ips_set = set(new_ips)

        # Apply the difference
        ips_to_add = new_ips_set - existing_ips
        ips_to_remove = existing_ips - new_ips_set

        for ip in ips_to_add:
            self._run_command([self.ipset_cmd, "add", ipset_name, ip])

        for ip in ips_to_remove:
            self._run_command([self.ipset_cmd, "del", ipset_name, ip])

        if ips_to_add or ips_to_remove:
            log_system_event(
                "Domain IPs updated",
                domain=domain,
                added=str(len(ips_to_add)),
                removed=str(len(ips_to_remove)),
            )

        return True

    def remove_domain(self, domain: str) -> bool:
        """Remove a domain's rules.

        Args:
            domain: Domain name

        Returns:
            True on success
        """
        if domain not in self.domain_ipsets:
            return True

        ipset_name = self.domain_ipsets[domain]

        # Remove the iptables rules
        if self.allowed_ports:
            is_lan_only = domain.endswith(".lan") or "." not in domain
            for rule in self._forward_accept_rules(ipset_name, is_lan_only, action="-D"):
                self._run_command(rule)
        else:
            self._run_command(
                [
                    self.iptables_cmd,
                    "-D",
                    "FORWARD",
                    "-m",
                    "set",
                    "--match-set",
                    ipset_name,
                    "dst",
                    "-j",
                    "ACCEPT",
                ]
            )

        # Destroy the ipset
        self._run_command([self.ipset_cmd, "destroy", ipset_name])

        del self.domain_ipsets[domain]

        log_system_event("Domain firewall rule removed", domain=domain)

        return True

    def setup_static_ip_rules(self, allow_ipset_name: str, block_ipset_name: str) -> bool:
        """Set up the iptables rules for static IPs.

        Args:
            allow_ipset_name: ipset name for allowlisted IPs
            block_ipset_name: ipset name for denied IPs

        Returns:
            True on success
        """
        # Block rule first, so it takes precedence
        self._run_command(
            [
                self.iptables_cmd,
                "-I",
                "FORWARD",
                "1",
                "-m",
                "set",
                "--match-set",
                block_ipset_name,
                "dst",
                "-j",
                "DROP",
            ]
        )

        # Allow rule (one per port when allowed_ports is set)
        for rule in self._forward_accept_rules(allow_ipset_name, None, action="-A"):
            self._run_command(rule)

        log_system_event(
            "Static IP firewall rules added",
            allow_set=allow_ipset_name,
            block_set=block_ipset_name,
        )

        return True

    def setup_host_firewall_rules(
        self,
        internal_ip: str,
        project_name: str,
        internal_network_name: str = "internal-net",
        internet_network_name: str = "internet",
        uplink_if: str = "eth0",
    ) -> bool:
        """Set up the host-side firewall rules (the poc1 approach).

        Args:
            internal_ip: sekimore's IP address on the internal network
            project_name: Docker Compose project name
            internal_network_name: Name of the internal network
            internet_network_name: Name of the internet network
            uplink_if: Host-side uplink interface

        Returns:
            True on success
        """
        try:
            log_system_event(
                "Setting up host-side firewall rules",
                internal_ip=internal_ip,
                project_name=project_name,
            )

            # Build the fully qualified network names
            internal_network_full = f"{project_name}_{internal_network_name}"
            internet_network_full = f"{project_name}_{internet_network_name}"

            # Look up the bridge interface names
            import json

            internal_result = subprocess.run(
                ["docker", "network", "inspect", internal_network_full],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            internal_data = json.loads(internal_result.stdout)
            internal_bridge_id = internal_data[0]["Id"][:12]
            br_internal = f"br-{internal_bridge_id}"

            internet_result = subprocess.run(
                ["docker", "network", "inspect", internet_network_full],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            internet_data = json.loads(internet_result.stdout)
            internet_bridge_id = internet_data[0]["Id"][:12]
            br_internet = f"br-{internet_bridge_id}"

            # Get the internet subnet
            internet_subnet = internet_data[0]["IPAM"]["Config"][0]["Subnet"]

            log_system_event(
                "Bridge interfaces detected",
                internal_bridge=br_internal,
                internet_bridge=br_internet,
                internet_subnet=internet_subnet,
            )

            # The host may not use the legacy iptables, so try both commands
            iptables_cmds = ["iptables", "iptables-legacy"]

            for iptables_cmd in iptables_cmds:
                try:
                    subprocess.run(
                        [iptables_cmd, "--version"],
                        capture_output=True,
                        check=True,
                        timeout=5,
                    )
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            else:
                log_error(ComponentType.FIREWALL, "No iptables command found on host")
                return False

            # Host-side FORWARD rules, each preceded by a duplicate check
            host_rules = [
                # Allow return traffic (outside -> inside)
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internet,
                    "-o",
                    br_internal,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internet,
                    "-o",
                    br_internal,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                # Allow internal -> internet from sekimore
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "ACCEPT",
                ],
                # DROP any other internal -> internet traffic
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-j",
                    "DROP",
                ],
                # Allow forwarding (internet subnet -> uplink)
                [
                    "-C",
                    "FORWARD",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "ACCEPT",
                ],
                # Allow return traffic (uplink -> internet subnet)
                [
                    "-C",
                    "FORWARD",
                    "-d",
                    internet_subnet,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-d",
                    internet_subnet,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            ]

            # DNS exfiltration guard: block port 53 for everyone but sekimore
            dns_filter_rules = [
                # UDP/53 LOG
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                # TCP/53 LOG
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "[fw-dns-block] ",
                ],
                # UDP/53 DROP
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                # TCP/53 DROP
                [
                    "-C",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
                [
                    "-A",
                    "FORWARD",
                    "-i",
                    br_internal,
                    "-o",
                    br_internet,
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "!",
                    "-s",
                    f"{internal_ip}/32",
                    "-j",
                    "DROP",
                ],
            ]

            # Host-side NAT rules
            nat_rules = [
                [
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "MASQUERADE",
                ],
                [
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    internet_subnet,
                    "-o",
                    uplink_if,
                    "-j",
                    "MASQUERADE",
                ],
            ]

            # Apply the rules in -C check / -A add pairs
            all_rules = host_rules + dns_filter_rules + nat_rules

            for i in range(0, len(all_rules), 2):
                check_rule = all_rules[i]
                add_rule = all_rules[i + 1]

                # Run the check
                check_result = subprocess.run(
                    [iptables_cmd] + check_rule,
                    capture_output=True,
                    timeout=5,
                )

                # Only add the rule when it is missing
                if check_result.returncode != 0:
                    subprocess.run(
                        [iptables_cmd] + add_rule,
                        capture_output=True,
                        check=False,
                        timeout=5,
                    )

            log_system_event("Host-side firewall rules configured successfully")
            return True

        except Exception as e:
            log_error(
                ComponentType.FIREWALL,
                f"Failed to setup host firewall rules: {e}",
            )
            return False

    def cleanup(self) -> None:
        """Tear down the firewall rules."""
        # Remove every domain rule
        for domain in list(self.domain_ipsets.keys()):
            self.remove_domain(domain)

        # Flush iptables (Docker DNS NAT rules are preserved)
        self._run_command([self.iptables_cmd, "-F"])
        # Do not flush the NAT table, to preserve the Docker DNS rules
        self._run_command([self.iptables_cmd, "-X"])

        log_system_event("Firewall cleaned up")
