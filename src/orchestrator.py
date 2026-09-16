"""Orchestrator - ties together the DNS, IP management and firewall layers."""

import asyncio
import contextlib
import fnmatch
import ipaddress
import json
import os
import subprocess
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .config import load_config
from .dns_server import DNSServer
from .firewall import FirewallManager
from .firewall_monitor import FirewallMonitor
from .ip_manager import StaticIPManager
from .logger import ComponentType, log_error, log_system_event, setup_logging
from .proxy_manager import ProxyManager
from .proxy_monitor import ProxyMonitor


class ConfigFileEventHandler(FileSystemEventHandler):
    """Event handler that watches the configuration file for changes."""

    def __init__(self, orchestrator: "SecurityGatewayOrchestrator", config_path: Path):
        """Initialize.

        Args:
            orchestrator: The orchestrator instance
            config_path: Path of the configuration file to watch
        """
        self.orchestrator = orchestrator
        self.config_path = config_path
        self._reload_lock = threading.Lock()
        self._last_reload_time = 0.0

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle a file modification event.

        Args:
            event: The filesystem event
        """
        # Ignore directory changes
        if event.is_directory:
            return

        # Only handle the config.yml we are watching
        if Path(str(event.src_path)).resolve() != self.config_path.resolve():
            return

        # Debounce, so a burst of events triggers only one reload
        current_time = time.time()
        with self._reload_lock:
            if current_time - self._last_reload_time < 1.0:  # ignore within 1 second
                return
            self._last_reload_time = current_time

        log_system_event("Configuration file modified, reloading...")

        # Run the async method synchronously: watchdog calls us from a plain thread.
        try:
            # Create a fresh event loop and run on it
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success = loop.run_until_complete(self.orchestrator.reload_config())
                if success:
                    log_system_event("Configuration reloaded automatically")
                else:
                    log_error(ComponentType.ORCHESTRATOR, "Auto-reload failed")
            finally:
                loop.close()
        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Auto-reload error: {e}")


def _domain_handlers_of(config: object) -> dict[str, str]:
    """Flatten config.domain_handlers into {domain: handler name}, tolerating mock configs."""
    handlers = getattr(config, "domain_handlers", None)
    if not isinstance(handlers, dict):
        return {}
    out: dict[str, str] = {}
    for domain, h in handlers.items():
        name = getattr(h, "handler", h)
        if isinstance(name, str):
            out[str(domain)] = name
    return out


def _relay_ports_of(config: object) -> list[int]:
    """Ports to open in INPUT for the relay; empty when git-relay is not configured."""
    fn = getattr(config, "relay_input_ports", None)
    ports = fn() if callable(fn) else []
    if not isinstance(ports, list):
        return []
    return [p for p in ports if isinstance(p, int)]


def _allowed_ports_of(config: object) -> list[int]:
    """Destination ports allowed towards allowed domains / IPs (network.allowed_ports; empty = every port)."""
    network = getattr(config, "network", None)
    ports = getattr(network, "allowed_ports", None)
    if not isinstance(ports, list):
        return []
    return [p for p in ports if isinstance(p, int) and not isinstance(p, bool)]


def _relay_settings_changed(old: object, new: object) -> bool:
    """Whether domain_handlers / relay / network.allowed_ports differ, i.e. a restart is needed.

    0.2.0: a changed handler ssh_port (the port opened in INPUT) also needs a restart.
    0.2.2: network.allowed_ports (the FORWARD destination ports) is likewise fixed at
    startup, so it is treated the same way.
    """
    return (
        _domain_handlers_of(old) != _domain_handlers_of(new)
        or _relay_ports_of(old) != _relay_ports_of(new)
        or _allowed_ports_of(old) != _allowed_ports_of(new)
        or getattr(old, "relay", None) != getattr(new, "relay", None)
    )


class SecurityGatewayOrchestrator:
    """Top-level management of the security gateway."""

    @staticmethod
    def _detect_network_interfaces_from_docker_api() -> tuple[str, str, str, str, str, str] | None:
        """Detect the network interfaces through the Docker API (the poc1 approach).

        Reads PROJECT_NAME, INTERNAL_NETWORK_NAME and INTERNET_NETWORK_NAME from the
        environment, looks up the container's IP addresses via the Docker API, and works
        out which interface is which.

        Returns:
            A tuple of (internet_interface, internal_interface, internal_ip, internet_ip,
            internet_gw, internal_subnet), or None if detection fails
        """
        try:
            # Environment variables
            project_name = os.getenv("PROJECT_NAME")
            internal_network_name = os.getenv("INTERNAL_NETWORK_NAME", "internal-net")
            internet_network_name = os.getenv("INTERNET_NETWORK_NAME", "internet")

            if not project_name:
                log_system_event("PROJECT_NAME not set, falling back to static subnet detection")
                return None

            # Wait for the interfaces to come up
            time.sleep(2)

            # Container ID
            container_id = subprocess.run(
                ["hostname"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout.strip()

            log_system_event(
                "Docker API detection started",
                container_id=container_id,
                project_name=project_name,
            )

            # Build the fully qualified network names
            internal_network_full = f"{project_name}_{internal_network_name}"
            internet_network_full = f"{project_name}_{internet_network_name}"

            # IP addresses from the Docker API
            inspect_result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            inspect_data = json.loads(inspect_result.stdout)
            networks = inspect_data[0]["NetworkSettings"]["Networks"]

            internal_network_info = networks.get(internal_network_full, {})
            internal_ip = internal_network_info.get("IPAddress")
            internal_prefix_len = internal_network_info.get("IPPrefixLen", 16)  # default 16

            internet_ip = networks.get(internet_network_full, {}).get("IPAddress")

            log_system_event(
                "Docker API IPs detected",
                internal_ip=internal_ip or "null",
                internal_prefix_len=str(internal_prefix_len),
                internet_ip=internet_ip or "null",
            )

            if not internal_ip or not internet_ip:
                log_error(
                    ComponentType.ORCHESTRATOR,
                    f"Failed to get IPs from Docker API: internal={internal_ip}, internet={internet_ip}",
                )
                return None

            # Derive the subnet from internal_ip and prefix_len
            internal_network = ipaddress.ip_network(
                f"{internal_ip}/{internal_prefix_len}", strict=False
            )
            internal_subnet = str(internal_network)

            # Identify the interfaces by IP
            internal_if = None
            internet_if = None

            for iface in ["eth0", "eth1", "eth2", "eth3"]:
                result = subprocess.run(
                    ["ip", "addr", "show", iface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    if f"{internal_ip}/" in result.stdout:
                        internal_if = iface
                    if f"{internet_ip}/" in result.stdout:
                        internet_if = iface

            if not internal_if or not internet_if:
                log_error(
                    ComponentType.ORCHESTRATOR,
                    f"Failed to detect interfaces: internal={internal_if}, internet={internet_if}",
                )
                return None

            # Derive the internet-side gateway IP (.1)
            internet_gw = ".".join(internet_ip.split(".")[:-1]) + ".1"

            log_system_event(
                "Docker API detection successful",
                internet_interface=internet_if,
                internet_ip=internet_ip,
                internet_gw=internet_gw,
                internal_interface=internal_if,
                internal_ip=internal_ip,
                internal_subnet=internal_subnet,
            )

            return (
                internet_if,
                internal_if,
                internal_ip,
                internet_ip,
                internet_gw,
                internal_subnet,
            )

        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Docker API detection failed: {e}",
            )
            return None

    @staticmethod
    def _setup_default_route(internet_gw: str, internet_if: str) -> bool:
        """Set the default route.

        Args:
            internet_gw: Internet-side gateway IP
            internet_if: Internet-side interface

        Returns:
            True on success
        """
        try:
            # Drop the existing default route
            subprocess.run(
                ["ip", "route", "del", "default"],
                capture_output=True,
                timeout=5,
            )

            # Add the new default route
            subprocess.run(
                ["ip", "route", "add", "default", "via", internet_gw, "dev", internet_if],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            log_system_event(
                "Default route set",
                gateway=internet_gw,
                interface=internet_if,
            )
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to set default route: {e.stderr}",
            )
            return False
        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to set default route: {e}",
            )
            return False

    @staticmethod
    def _detect_network_interfaces(lan_subnets: list[str]) -> tuple[str, str, str]:
        """Auto-detect the network interfaces.

        An interface whose IP falls inside lan_subnets is the LAN side; anything else is
        the WAN side.

        Args:
            lan_subnets: LAN-side network subnets (e.g. ["10.100.0.0/16"])

        Returns:
            A tuple of (wan_interface, lan_interface, lan_ip)
        """
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )

            lan_if = None
            wan_if = None
            lan_ip = None

            # Parse interface names and IPs
            current_if = None
            for line in result.stdout.split("\n"):
                # Interface line: "2: eth0@if194: <BROADCAST,MULTICAST,UP,LOWER_UP>..."
                if ":" in line and "<" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        # eth0@if194 -> eth0 (strip the peer interface index)
                        if_name = parts[1].strip()
                        current_if = if_name.split("@")[0]

                # IP line: "    inet 10.100.0.2/16 brd ... scope global eth0"
                elif "inet " in line and "scope global" in line and current_if:
                    ip_with_prefix = line.strip().split()[1]
                    ip_str = ip_with_prefix.split("/")[0]

                    # Check whether it falls inside lan_subnets
                    ip_addr = ipaddress.ip_address(ip_str)
                    is_lan_net = False

                    for subnet_str in lan_subnets:
                        subnet = ipaddress.ip_network(subnet_str)
                        if ip_addr in subnet:
                            is_lan_net = True
                            # Use only the first LAN interface found
                            if lan_if is None:
                                lan_if = current_if
                                lan_ip = ip_str
                                log_system_event(
                                    "LAN interface detected",
                                    interface=current_if,
                                    ip=ip_str,
                                    subnet=subnet_str,
                                )
                            else:
                                # Warn when more than one LAN interface is detected
                                log_system_event(
                                    "Multiple LAN interfaces detected, using first one",
                                    first_interface=lan_if,
                                    first_ip=lan_ip or "",
                                    additional_interface=current_if,
                                    additional_ip=ip_str,
                                )
                            break

                    # Outside lan_subnets means the WAN side; use only the first WAN
                    # interface found
                    if not is_lan_net and current_if != "lo":
                        if wan_if is None:
                            wan_if = current_if
                            log_system_event(
                                "WAN interface detected",
                                interface=current_if,
                                ip=ip_str,
                            )
                        else:
                            # Warn when more than one WAN interface is detected
                            log_system_event(
                                "Multiple WAN interfaces detected, using first one",
                                first_interface=wan_if,
                                additional_interface=current_if,
                                additional_ip=ip_str,
                            )

            if not lan_if or not wan_if or not lan_ip:
                raise RuntimeError(
                    f"Failed to detect interfaces: lan={lan_if}, wan={wan_if}, lan_ip={lan_ip}"
                )

            return (wan_if, lan_if, lan_ip)

        except Exception as e:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Interface detection failed: {e}, using defaults",
            )
            # Fall back to the legacy behaviour: guess the .2 address from the first
            # subnet in lan_subnets
            default_lan_ip = "10.100.0.2"
            if lan_subnets:
                try:
                    subnet = ipaddress.ip_network(lan_subnets[0])
                    # Use the second address in the subnet (.0 is the network and .1 is
                    # conventionally the gateway)
                    default_lan_ip = str(list(subnet.hosts())[0])
                except Exception:
                    pass

            return ("eth0", "eth1", default_lan_ip)

    def __init__(
        self,
        config_path: Path | None = None,
    ):
        """Initialize.

        Args:
            config_path: Path to the configuration file
        """
        # Keep the config path around for reloads
        self.config_path = config_path

        # Load the configuration
        self.config = load_config(config_path)

        # Detect the interface names and the LAN-side IP address, preferring Docker API
        # detection and falling back to static subnet detection
        docker_api_result = self._detect_network_interfaces_from_docker_api()

        if docker_api_result:
            # Docker API detection succeeded (the poc1 approach)
            internet_if, internal_if, internal_ip, internet_ip, internet_gw, internal_subnet = (
                docker_api_result
            )

            # Set the default route
            self._setup_default_route(internet_gw, internet_if)

            # WAN = internet, LAN = internal
            wan_interface = internet_if
            lan_interface = internal_if
            lan_ip = internal_ip
            # Prefer the subnet detected through the Docker API over config.yml
            detected_lan_subnets = [internal_subnet]

            log_system_event(
                "Using Docker API detection",
                wan_interface=wan_interface,
                lan_interface=lan_interface,
                lan_ip=lan_ip,
                lan_subnet=internal_subnet,
            )
        else:
            # Fall back to static subnet detection (the legacy approach)
            wan_interface, lan_interface, lan_ip = self._detect_network_interfaces(
                self.config.network.lan_subnets
            )
            # Use the subnets from config.yml
            detected_lan_subnets = self.config.network.lan_subnets

            log_system_event(
                "Using static subnet detection",
                wan_interface=wan_interface,
                lan_interface=lan_interface,
                lan_ip=lan_ip,
            )

        # Initialize the components
        self.firewall = FirewallManager(
            wan_interface=wan_interface,
            lan_interface=lan_interface,
            relay_ports=_relay_ports_of(self.config),
            allowed_ports=_allowed_ports_of(self.config),
        )
        self.ip_manager = StaticIPManager()

        # Set of blocked domains
        blocked_domains = set(self.config.block_domains)

        # DNS server. It gets a reference to the firewall so it can register rules
        # dynamically, which is why the firewall is constructed first.
        # upstream_dns is pinned to Docker's embedded DNS (127.0.0.11) and port to the
        # standard DNS port (53); lan_subnets comes from Docker API detection, or from
        # config.yml when that is unavailable.
        self.dns_server = DNSServer(
            upstream_dns="127.0.0.11",  # Docker's embedded DNS (fixed)
            port=53,  # standard DNS port (fixed)
            blocked_domains=blocked_domains,
            allowed_domains=self.config.allow_domains,
            db_path=self.config.database_path,
            firewall_manager=self.firewall,
            lan_subnets=detected_lan_subnets,
            ignored_domains=self.config.ignore_domains,
            domain_handlers=_domain_handlers_of(self.config),
        )

        # Firewall monitor, tailing the iptables log
        self.firewall_monitor = FirewallMonitor(db_path=self.config.database_path)

        # Proxy manager (Squid)
        self.proxy_manager: ProxyManager | None = None
        if self.config.proxy.enabled:
            self.proxy_manager = ProxyManager(
                cache_enabled=self.config.proxy.cache_enabled,
                cache_size_mb=self.config.proxy.cache_size_mb,
                upstream_proxy=self.config.proxy.upstream_proxy,
                upstream_proxy_tls=self.config.proxy.upstream_proxy_tls,
                upstream_dns="127.0.0.11",  # Docker's embedded DNS; squid runs inside the gateway, so it needs no filtering
                upstream_proxy_username=self.config.proxy.upstream_proxy_username,
                upstream_proxy_password=self.config.proxy.upstream_proxy_password,
            )

        # Proxy monitor, tailing the Squid access log
        self.proxy_monitor: ProxyMonitor | None = None
        if self.config.proxy.enabled:
            self.proxy_monitor = ProxyMonitor(db_path=self.config.database_path)

        # File watcher that reloads automatically when config.yml changes
        self.config_observer: Observer | None = None  # type: ignore[valid-type]
        # Task checking that the relay is listening (only when git-relay is configured)
        self._relay_check_task: asyncio.Task[bool] | None = None
        if self.config_path:
            # Watch the directory containing the configuration file
            config_dir = Path(self.config_path).parent
            event_handler = ConfigFileEventHandler(self, Path(self.config_path))
            self.config_observer = Observer()
            self.config_observer.schedule(event_handler, str(config_dir), recursive=False)

    def _match_allowed_domain(self, domain: str) -> bool:
        """Check whether a domain is on the allow list.

        Args:
            domain: The domain to check

        Returns:
            True when it is allowed
        """
        domain_lower = domain.lower().rstrip(".")

        for allowed in self.config.allow_domains:
            # Exact match
            if allowed == domain_lower:
                return True

            # Wildcard match
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if domain_lower.endswith(suffix):
                    return True
            elif allowed.startswith("*"):
                suffix = allowed[1:]
                if domain_lower.endswith(suffix):
                    return True

            # fnmatch, for more flexible patterns
            if fnmatch.fnmatch(domain_lower, allowed):
                return True

        return False

    async def apply_domain_rule(self, domain: str, action: str = "allow") -> bool:
        """Apply a single domain rule across all three layers.

        Args:
            domain: The domain name
            action: 'allow' or 'block'

        Returns:
            True on success
        """
        if action == "block":
            # Add it to the block list
            self.dns_server.blocked_domains.add(domain)
            log_system_event("Domain blocked", domain=domain)
            return True

        # Allowed domain
        # 1. Resolve the domain over DNS
        result = await self.dns_server._resolve_domain(domain, "A")

        if not result:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to resolve domain: {domain}",
            )
            return False

        ips, ttl = result

        # 2. Keep only IPv4 addresses (the ipset uses family inet, IPv4 only)
        ipv4_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    ipv4_ips.append(ip)
            except ValueError:
                log_error(ComponentType.ORCHESTRATOR, f"Invalid IP address: {ip}")
                continue

        if not ipv4_ips:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"No IPv4 addresses found for domain: {domain}",
            )
            return False

        # 3. Set up the iptables/ipset rules (IPv4 only)
        if not self.firewall.setup_domain(domain, ipv4_ips):
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Failed to setup firewall rules for domain: {domain}",
            )
            return False

        log_system_event(
            "Domain rule applied",
            domain=domain,
            action=action,
            ip_count=str(len(ipv4_ips)),
        )

        return True

    async def _warn_if_relay_not_listening(self, port: int, delay: float = 10.0) -> bool:
        """Check with `ss -tln` that the relay is listening; log an ERROR if not.

        Otherwise agents would hit a silent connection refused.
        """
        await asyncio.sleep(delay)
        try:
            result = subprocess.run(["ss", "-tln"], capture_output=True, text=True, check=False)
            listening = f":{port} " in result.stdout or result.stdout.rstrip().endswith(f":{port}")
        except (FileNotFoundError, OSError) as e:
            log_error(ComponentType.ORCHESTRATOR, f"cannot check relay listener: {e}")
            return False
        if not listening:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"domain_handlers has git-relay but sekimore-relay is not listening on :{port}; "
                "agents will get connection refused for git. Check `sekimore-relay needs-relay` and the container log.",
            )
        return listening

    async def initialize(self) -> bool:
        """Initialize the security gateway.

        Returns:
            True on success
        """
        log_system_event("Initializing Security Gateway...")

        # 1. Initialize the firewall
        if not self.firewall.initialize_firewall():
            log_error(ComponentType.ORCHESTRATOR, "Firewall initialization failed")
            return False

        # 2. Configure the static IPs
        if not self.ip_manager.setup_static_ips(
            allow_ips=self.config.allow_ips,
            block_ips=self.config.block_ips,
        ):
            log_error(ComponentType.ORCHESTRATOR, "Static IP setup failed")
            return False

        # 3. Add the iptables rules for the static IPs
        if not self.firewall.setup_static_ip_rules(
            allow_ipset_name=self.ip_manager.allow_ipset_name,
            block_ipset_name=self.ip_manager.block_ipset_name,
        ):
            log_error(ComponentType.ORCHESTRATOR, "Static IP firewall rules setup failed")
            return False

        # 4. Apply the rules for allowed domains (only those not starting with ".")
        for domain in self.config.allow_domains:
            # Wildcards starting with "." are skipped at startup and handled
            # dynamically when a DNS query arrives
            if not domain.startswith("."):
                log_system_event(f"Applying domain rule for: {domain}")
                await self.apply_domain_rule(domain, action="allow")
                log_system_event(f"Domain rule applied successfully: {domain}")

        # 5. Enable block logging once every ACCEPT rule is in place, so the LOG rule
        # lands last and only blocked packets get logged
        if not self.firewall.enable_block_logging():
            log_error(ComponentType.ORCHESTRATOR, "Failed to enable block logging")
            # Carry on if logging fails; the firewall itself still works

        # 6. Configure the Squid proxy, when enabled
        if self.proxy_manager:
            if not self.proxy_manager.generate_config(self.config.allow_domains):
                log_error(ComponentType.ORCHESTRATOR, "Failed to generate Squid config")
                # Carry on if the proxy config fails; DNS and the firewall still work
            else:
                log_system_event("Squid proxy config generated")

        # 7. The relay: log an ERROR when git-relay is configured but nothing is listening
        relay_ports = _relay_ports_of(self.config)
        if relay_ports:
            self._relay_check_task = asyncio.create_task(
                self._warn_if_relay_not_listening(relay_ports[0])
            )

        log_system_event(
            "Security Gateway initialized",
            allowed_domains=str(len(self.config.allow_domains)),
            blocked_domains=str(len(self.config.block_domains)),
            allowed_ips=str(len(self.config.allow_ips)),
            blocked_ips=str(len(self.config.block_ips)),
            proxy_enabled=str(self.config.proxy.enabled),
            git_relay_domains=str(_domain_handlers_of(self.config)),
            relay_ports=str(relay_ports),
        )

        return True

    async def start(self) -> None:
        """Start the security gateway."""
        # Initialize logging
        setup_logging()

        # Initialize
        if not await self.initialize():
            log_error(ComponentType.ORCHESTRATOR, "Initialization failed, exiting")
            return

        # Start the Squid proxy, when enabled
        if self.proxy_manager and not self.proxy_manager.start():
            log_error(ComponentType.ORCHESTRATOR, "Failed to start Squid proxy")
            # Carry on if the proxy fails to start; DNS and the firewall still work

        # Start the firewall monitor in the background
        firewall_monitor_task = asyncio.create_task(self.firewall_monitor.start())

        # Start the proxy monitor in the background, when enabled
        proxy_monitor_task = None
        if self.proxy_monitor:
            proxy_monitor_task = asyncio.create_task(self.proxy_monitor.start())

        # Start watching the file, to reload automatically when config.yml changes
        if self.config_observer:
            self.config_observer.start()  # type: ignore[attr-defined]
            log_system_event("Configuration file monitoring started")

        # Start the DNS server (the main loop)
        try:
            await self.dns_server.start()
        except KeyboardInterrupt:
            log_system_event("Shutdown signal received")
        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Fatal error: {e}")
        finally:
            # Stop the monitors
            await self.firewall_monitor.stop()
            firewall_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await firewall_monitor_task

            if self.proxy_monitor and proxy_monitor_task:
                await self.proxy_monitor.stop()
                proxy_monitor_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await proxy_monitor_task

            await self.cleanup()

    async def cleanup(self) -> None:
        """Release resources."""
        log_system_event("Cleaning up...")

        # Stop the file watcher
        if self.config_observer:
            self.config_observer.stop()  # type: ignore[attr-defined]
            if self.config_observer.is_alive():  # type: ignore[attr-defined]
                self.config_observer.join()  # type: ignore[attr-defined]
            log_system_event("Configuration file monitoring stopped")

        # Stop the DNS server
        await self.dns_server.stop()

        # Stop the Squid proxy
        if self.proxy_manager:
            self.proxy_manager.stop()

        # Clean up the firewall
        self.firewall.cleanup()

        # Clean up the static IPs
        self.ip_manager.cleanup()

        log_system_event("Cleanup complete")

    async def reload_config(self) -> bool:
        """Reload the configuration file and apply the differences, without downtime.

        Returns:
            True on success
        """
        try:
            log_system_event("Reloading configuration...")

            # Load the new configuration
            new_config = load_config(self.config_path)

            # domain_handlers / relay are fixed at startup (the relay process and the
            # INPUT rules). Switching only DNS here would create a silent hang, so keep
            # the old values and ask for a restart instead.
            if _relay_settings_changed(self.config, new_config):
                log_error(
                    ComponentType.ORCHESTRATOR,
                    "domain_handlers / relay changed in config.yml; restart the container to apply "
                    "(the relay process and INPUT rules are decided at startup). Keeping the old values.",
                )
                new_config = new_config.model_copy(
                    update={
                        "domain_handlers": self.config.domain_handlers,
                        "relay": self.config.relay,
                    }
                )

            # Compute the differences
            old_allow_domains = set(self.config.allow_domains)
            new_allow_domains = set(new_config.allow_domains)
            old_block_domains = set(self.config.block_domains)
            new_block_domains = set(new_config.block_domains)

            added_allow_domains = new_allow_domains - old_allow_domains
            removed_allow_domains = old_allow_domains - new_allow_domains
            added_block_domains = new_block_domains - old_block_domains
            removed_block_domains = old_block_domains - new_block_domains

            # Update the DNS server
            self.dns_server.allowed_domains = new_config.allow_domains
            self.dns_server.blocked_domains = set(new_config.block_domains)
            self.dns_server.ignored_domains = new_config.ignore_domains

            # Remove the iptables rules for domains that went away
            for domain in removed_allow_domains:
                if not domain.startswith("."):  # skip wildcards
                    self.firewall.remove_domain(domain)

            # Apply the rules for newly added domains
            for domain in added_allow_domains:
                if not domain.startswith("."):  # skip wildcards
                    # Handled dynamically when a DNS query arrives, so nothing to do here
                    pass

            # Update the Squid proxy configuration, when enabled
            if self.proxy_manager:
                if not self.proxy_manager.generate_config(new_config.allow_domains):
                    log_error(ComponentType.ORCHESTRATOR, "Failed to regenerate Squid config")
                    return False
                if not self.proxy_manager.reload_config():
                    log_error(ComponentType.ORCHESTRATOR, "Failed to reload Squid config")
                    return False

            # Swap in the new configuration
            self.config = new_config

            log_system_event(
                "Configuration reloaded successfully",
                added_allow_domains=str(len(added_allow_domains)),
                removed_allow_domains=str(len(removed_allow_domains)),
                added_block_domains=str(len(added_block_domains)),
                removed_block_domains=str(len(removed_block_domains)),
            )

            return True

        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Failed to reload configuration: {e}")
            return False

    async def restart_services(self) -> bool:
        """Restart the services, with a few seconds of downtime.

        Returns:
            True on success
        """
        try:
            log_system_event("Restarting services...")

            # 1. Stop the DNS server
            await self.dns_server.stop()
            log_system_event("DNS server stopped")

            # 2. Stop the proxy, when enabled
            if self.proxy_manager:
                self.proxy_manager.stop()
                log_system_event("Proxy stopped")

            # 3. Reload the configuration
            reloaded = load_config(self.config_path)
            if _relay_settings_changed(self.config, reloaded):
                log_error(
                    ComponentType.ORCHESTRATOR,
                    "domain_handlers / relay changed; restart the container to apply. Keeping the old values.",
                )
                reloaded = reloaded.model_copy(
                    update={
                        "domain_handlers": self.config.domain_handlers,
                        "relay": self.config.relay,
                    }
                )
            self.config = reloaded
            log_system_event("Configuration reloaded")

            # 4. Update the DNS server settings
            self.dns_server.allowed_domains = self.config.allow_domains
            self.dns_server.blocked_domains = set(self.config.block_domains)
            self.dns_server.ignored_domains = self.config.ignore_domains

            # 5. Restart the DNS server
            await self.dns_server.start()
            log_system_event("DNS server restarted")

            # 6. Restart the proxy, when enabled
            if self.proxy_manager:
                if not self.proxy_manager.generate_config(self.config.allow_domains):
                    log_error(ComponentType.ORCHESTRATOR, "Failed to regenerate Squid config")
                    return False
                if not self.proxy_manager.start():
                    log_error(ComponentType.ORCHESTRATOR, "Failed to start Proxy")
                    return False
                log_system_event("Proxy restarted")

            log_system_event("Services restarted successfully")
            return True

        except Exception as e:
            log_error(ComponentType.ORCHESTRATOR, f"Failed to restart services: {e}")
            return False


async def main() -> None:
    """Main entry point."""
    orchestrator = SecurityGatewayOrchestrator()
    await orchestrator.start()


if __name__ == "__main__":
    asyncio.run(main())
