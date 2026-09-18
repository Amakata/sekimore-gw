"""Static IP management - maintains ipsets of IP addresses, CIDRs and ranges."""

import ipaddress
import subprocess

from .logger import ComponentType, log_error, log_system_event


class StaticIPManager:
    """Manages static IP address filtering."""

    def __init__(self) -> None:
        """Initialize the manager."""
        self.allow_ipset_name = "allow_static_ips"
        self.block_ipset_name = "block_static_ips"

    def _expand_ip_range(self, ip_range: str) -> list[str]:
        """Expand an IP range into individual addresses.

        Args:
            ip_range: IP range (e.g. 192.168.1.1-192.168.1.10)

        Returns:
            List of individual IP addresses
        """
        start_ip_str, end_ip_str = ip_range.split("-", 1)
        start_ip = ipaddress.ip_address(start_ip_str.strip())
        end_ip = ipaddress.ip_address(end_ip_str.strip())

        if start_ip.version != end_ip.version:
            raise ValueError(f"IP version mismatch in range: {ip_range}")

        ip_list = []
        current_ip = start_ip
        while current_ip <= end_ip:  # type: ignore[operator]
            ip_list.append(str(current_ip))
            # Works for both IPv4 and IPv6
            current_ip = ipaddress.ip_address(int(current_ip) + 1)

            # Cap at 1024 addresses as a safety limit
            if len(ip_list) > 1024:
                log_error(
                    ComponentType.FIREWALL,
                    f"IP range too large (>1024 IPs), truncating: {ip_range}",
                )
                break

        return ip_list

    def _run_ipset_command(self, args: list[str]) -> bool:
        """Run an ipset command.

        Args:
            args: ipset command arguments

        Returns:
            True on success
        """
        try:
            subprocess.run(
                ["ipset"] + args,
                check=True,
                capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            # Ignore "already exists" errors
            if "already" in e.stderr.lower() or "exist" in e.stderr.lower():
                return True
            log_error(
                ComponentType.FIREWALL,
                f"ipset command failed: {' '.join(args)}: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.FIREWALL, "ipset command not found")
            return False

    def create_ipsets(self) -> bool:
        """Create the ipsets (hash:net type, so CIDRs are supported).

        Flushed rather than destroyed when they already exist: on a reload the iptables rules
        still reference them, and ipset refuses to destroy a set in use — which would leave
        the reload failing on a config that is perfectly valid. Flushing empties them, so an
        address taken out of the config stops being matched.
        """
        for name in (self.allow_ipset_name, self.block_ipset_name):
            if not self._run_ipset_command(["flush", name]):
                # Not there yet; the create below makes it.
                self._run_ipset_command(["destroy", name])

        # Create as hash:net (supports CIDR, IPv4). `-exist` because the flush above leaves
        # the set in place when it was already there.
        success = True
        success &= self._run_ipset_command(
            ["create", "-exist", self.allow_ipset_name, "hash:net", "family", "inet"]
        )
        success &= self._run_ipset_command(
            ["create", "-exist", self.block_ipset_name, "hash:net", "family", "inet"]
        )

        if success:
            log_system_event(
                "Static IP ipsets created",
                allow_set=self.allow_ipset_name,
                block_set=self.block_ipset_name,
            )

        return success

    def setup_static_ips(self, allow_ips: list[str], block_ips: list[str]) -> bool:
        """Configure static IP filtering.

        Args:
            allow_ips: Allowlisted IPs (single IP, CIDR or range)
            block_ips: Denied IPs (single IP, CIDR or range)

        Returns:
            True on success
        """
        # Create the ipsets
        if not self.create_ipsets():
            return False

        # Add allowlisted IPs
        for ip_spec in allow_ips:
            if "/" in ip_spec:
                # CIDR: add as-is
                self._run_ipset_command(["add", self.allow_ipset_name, ip_spec])
            elif "-" in ip_spec:
                # IP range: expand into individual addresses
                for ip in self._expand_ip_range(ip_spec):
                    self._run_ipset_command(["add", self.allow_ipset_name, ip])
            else:
                # Single IP: add as-is
                self._run_ipset_command(["add", self.allow_ipset_name, ip_spec])

        # Add denied IPs
        for ip_spec in block_ips:
            if "/" in ip_spec:
                self._run_ipset_command(["add", self.block_ipset_name, ip_spec])
            elif "-" in ip_spec:
                for ip in self._expand_ip_range(ip_spec):
                    self._run_ipset_command(["add", self.block_ipset_name, ip])
            else:
                self._run_ipset_command(["add", self.block_ipset_name, ip_spec])

        log_system_event(
            "Static IP filtering configured",
            allow_count=str(len(allow_ips)),
            block_count=str(len(block_ips)),
        )
        return True

    def cleanup(self) -> None:
        """Tear down the ipsets."""
        self._run_ipset_command(["destroy", self.allow_ipset_name])
        self._run_ipset_command(["destroy", self.block_ipset_name])
        log_system_event("Static IP ipsets destroyed")
