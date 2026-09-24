"""Orchestrator - ties together the DNS, IP management and firewall layers."""

import asyncio
import contextlib
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from . import constants
from .config import load_config
from .dns_server import DNSServer
from .domains import domain_matches
from .firewall import FirewallManager
from .firewall_monitor import FirewallMonitor
from .ip_manager import StaticIPManager
from .logger import ComponentType, log_error, log_system_event, setup_logging
from .proxy_manager import ProxyManager
from .proxy_monitor import ProxyMonitor
from .secret_store import (
    PROXY_NAME,
    PROXY_NAMESPACE,
    Locked,
    NotFound,
    SecretStoreError,
    get_secret,
    is_unlocked,
)

# How long the watcher thread waits for a reload it handed to the main loop. Bounded so a reload
# that never returns cannot pin a watchdog thread for the life of the process.
RELOAD_TIMEOUT_SECONDS = 120.0


class ReloadWindow:
    """Whether a change to config.yml is applied when it is saved.

    The config file is writable from the dev container, and the gateway applies it on save,
    so an agent that has read a hostile prompt can rewrite the rules it is held by. Closing
    the window leaves the gateway on the configuration it already had, where a human can see
    the change and undo it.

    `auto` keeps the old behaviour, `manual` never applies on save, and a duration opens the
    window for that long after start-up. The duration is the one to reach for: debugging a
    policy needs saves to take effect, and a window that expires does not depend on anyone
    remembering to close it again.

    Only the operator can reopen it, from inside the gateway
    (`docker compose exec … sekimore-relay reload --follow`), which the agent cannot run.
    """

    def __init__(self, mode: str, window_seconds: int | None, state_path: str | Path | None = None):
        self.mode = mode
        self.window_seconds = window_seconds
        self._opened_at: float | None = time.time() if window_seconds else None
        self._frozen = False
        self._lock = threading.Lock()
        # The operator reopens the window with a separate command, in a separate process, so
        # the two sides meet in a file on the gateway's own volume.
        self._state_path = Path(state_path) if state_path else Path(constants.RELOAD_STATE_PATH)
        self._state_mtime: float | None = None
        with self._lock:
            self._refresh_locked()

    def _refresh_locked(self) -> None:
        """Pick up an override written by `python -m src.maint reload-*`.

        The operator's command runs in its own process, so the running gateway only learns
        about a freeze by reading the file. Checked on every read rather than at start-up:
        `reload-freeze` is run to shut the window *now*, before handing the session over, and
        a freeze that waited for a restart would be worse than useless.

        Caller holds the lock. Stats the file first so a closed window costs one stat.
        """
        try:
            mtime = self._state_path.stat().st_mtime
        except OSError:
            return
        if mtime == self._state_mtime:
            return
        self._state_mtime = mtime
        try:
            raw = json.loads(self._state_path.read_text())
        except (OSError, ValueError) as e:
            # Not fatal, but the operator's intent is being ignored, so say so.
            log_error(ComponentType.ORCHESTRATOR, f"Cannot read the reload window state: {e}")
            return
        if not isinstance(raw, dict):
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Reload window state is not an object: {self._state_path}",
            )
            return
        if raw.get("frozen"):
            self._frozen = True
            return
        try:
            until = float(raw["until"])
        except (KeyError, TypeError, ValueError):
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Reload window state has no usable 'until': {self._state_path}",
            )
            return
        left = until - time.time()
        if left > 0:
            self._frozen = False
            self.window_seconds = int(left)
            self._opened_at = time.time()
            # An override outlives a restart, and it also narrows an `auto` config: `follow`
            # means "open until this runs out", which is not the same as "always open".
            self.mode = "windowed"

    def _write_state(self, payload: dict[str, object]) -> bool:
        """Persist an override. False when it could not be written.

        The caller has to surface a failure: `reload-freeze` reporting success while the
        window stayed open would send the operator off to start an agent believing the
        config is protected.
        """
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(self._state_path)
        except OSError as e:
            log_error(ComponentType.ORCHESTRATOR, f"Cannot record the reload window: {e}")
            return False
        self._state_mtime = None  # force the next read to pick this up
        return True

    def is_open(self) -> bool:
        """True when a save should be applied."""
        with self._lock:
            self._refresh_locked()
            if self._frozen:
                return False
            if self.mode == "auto":
                return True
            if self.mode == "manual":
                return False
            if self._opened_at is None or self.window_seconds is None:
                return False
            return (time.time() - self._opened_at) < self.window_seconds

    def seconds_left(self) -> int | None:
        """Seconds until the window closes; None when it is not time-limited."""
        with self._lock:
            self._refresh_locked()
            if self._frozen:
                return None
            if self._opened_at is None or self.window_seconds is None:
                return None
            left = self.window_seconds - (time.time() - self._opened_at)
            return max(0, int(left))

    def follow(self, seconds: int) -> bool:
        """Reopen the window for `seconds` from now. False when it could not be recorded."""
        with self._lock:
            self._frozen = False
            self.window_seconds = seconds
            self._opened_at = time.time()
            if self.mode == "manual":
                self.mode = "windowed"
            return self._write_state({"until": time.time() + seconds})

    def freeze(self) -> bool:
        """Close the window now, whatever the mode. False when it could not be recorded.

        Run before handing the session to an agent, so a silent failure here is the one that
        matters most.
        """
        with self._lock:
            self._frozen = True
            return self._write_state({"frozen": True})

    def describe(self) -> str:
        """One line for `check` and `whoami`. Says whether a save would be applied right now.

        Reads the same state as is_open(), so the two cannot disagree — a line saying the
        window is open while saves are being dropped would send someone looking in the wrong
        place.
        """
        open_now = self.is_open()
        with self._lock:
            frozen, mode, window = self._frozen, self.mode, self.window_seconds
        if mode == "auto" and not frozen:
            return "auto (applies on save)"
        if frozen:
            return "frozen (does not apply on save; reload-follow to reopen)"
        if window is None:
            return "manual (does not apply on save)"
        left = self.seconds_left() or 0
        if not open_now or left <= 0:
            return "window closed (does not apply on save; reload-follow to reopen)"
        return f"open for {left // 60}m {left % 60}s (applies on save)"


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

        # 0.2.13: apply only while the reload window is open. The file is writable from dev,
        # so a change arriving here is not necessarily the operator's.
        window = getattr(self.orchestrator, "reload_window", None)
        if window is not None and not window.is_open():
            log_system_event(
                "Configuration file modified but not applied",
                reason="reload window closed",
                reload=window.describe(),
            )
            self.orchestrator.note_unapplied_change()
            return

        log_system_event("Configuration file modified, reloading...")

        # watchdog calls this on a plain thread. Hand the reload to the main loop rather than
        # running it on a loop of our own: reload_config touches the firewall, and so does the
        # DNS handler for a query arriving at the same moment. On one loop they take turns.
        loop = self.orchestrator._main_loop
        if loop is None or loop.is_closed():
            log_error(
                ComponentType.ORCHESTRATOR,
                "Auto-reload skipped: the main loop is not running",
            )
            return
        try:
            future = asyncio.run_coroutine_threadsafe(self.orchestrator.reload_config(), loop)
            # Bounded so a reload that never returns cannot pin a watchdog thread for good
            success = future.result(timeout=RELOAD_TIMEOUT_SECONDS)
            if success:
                log_system_event("Configuration reloaded automatically")
            else:
                log_error(ComponentType.ORCHESTRATOR, "Auto-reload failed")
        except TimeoutError:
            log_error(
                ComponentType.ORCHESTRATOR,
                f"Auto-reload did not finish within {RELOAD_TIMEOUT_SECONDS}s",
            )
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


def _proxy_of(config: object) -> dict[str, object]:
    """The proxy settings, flattened. ProxyManager is built once at start-up, so every key
    here is fixed until a restart — including `enabled`, which decides whether there is a
    Squid to configure at all."""
    proxy = getattr(config, "proxy", None)
    if proxy is None:
        return {}
    keys = (
        "enabled",
        "port",
        "cache_enabled",
        "cache_size_mb",
        "upstream_proxy",
        "upstream_proxy_tls",
        "upstream_proxy_username",
        "upstream_proxy_password",
    )
    return {k: getattr(proxy, k, None) for k in keys}


def _relay_settings_changed(old: object, new: object) -> bool:
    """Whether domain_handlers / relay / proxy / network.allowed_ports differ, i.e. a restart is needed.

    0.2.0: a changed handler ssh_port (the port opened in INPUT) also needs a restart.
    0.2.2: network.allowed_ports (the FORWARD destination ports) is likewise fixed at
    startup, so it is treated the same way.
    0.2.14: so is `proxy`. ProxyManager is built once in __init__, so turning proxy.enabled
    on did nothing until a restart — and nothing said so, which is how an afternoon went
    into working out why Squid was not running.
    """
    return (
        _domain_handlers_of(old) != _domain_handlers_of(new)
        or _relay_ports_of(old) != _relay_ports_of(new)
        or _allowed_ports_of(old) != _allowed_ports_of(new)
        or getattr(old, "relay", None) != getattr(new, "relay", None)
        # The model keeps four relay keys; the project's repositories, permissions and upload
        # caps are the Rust binary's and do not survive it. Compared through the model, adding
        # a repository the agent may write to reads as no change at all.
        or getattr(old, "relay_fingerprint", "") != getattr(new, "relay_fingerprint", "")
        or _proxy_of(old) != _proxy_of(new)
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
            resolve_deny_cidrs=self.config.resolve_deny_cidrs,
            resolve_allow_cidrs=self.config.resolve_allow_cidrs,
        )

        # Firewall monitor, tailing the iptables log
        self.firewall_monitor = FirewallMonitor(db_path=self.config.database_path)

        # Proxy manager (Squid)
        # 0.2.22 (#53): set when the credential is in the store but the store was locked, so the
        # Squid config has to be redone once someone unlocks.
        self._proxy_credential_pending = False
        self.proxy_manager: ProxyManager | None = None
        if self.config.proxy.enabled:
            username, password, _ = self._upstream_proxy_credential()
            self.proxy_manager = ProxyManager(
                cache_enabled=self.config.proxy.cache_enabled,
                cache_size_mb=self.config.proxy.cache_size_mb,
                upstream_proxy=self.config.proxy.upstream_proxy,
                upstream_proxy_tls=self.config.proxy.upstream_proxy_tls,
                upstream_dns="127.0.0.11",  # Docker's embedded DNS; squid runs inside the gateway, so it needs no filtering
                upstream_proxy_username=username,
                upstream_proxy_password=password,
                # #178: Squid resolves names itself, so the DNS filter's refusals do not reach
                # it. It has to be told the same ranges, or it becomes the way around them.
                denied_destinations=self.config.resolve_deny_cidrs,
                # The gateway's own network is RFC1918, so it has to be an exception or the
                # deny below would refuse Squid's own side of the house
                allowed_destinations=list(self.config.resolve_allow_cidrs)
                + list(detected_lan_subnets or []),
            )

        # Proxy monitor, tailing the Squid access log
        self.proxy_monitor: ProxyMonitor | None = None
        if self.config.proxy.enabled:
            self.proxy_monitor = ProxyMonitor(db_path=self.config.database_path)

        # 0.2.13: whether a save is applied (see ReloadWindow)
        self.reload_window = ReloadWindow(
            "windowed" if self.config.reload_is_windowed() else self.config.reload,
            self.config.reload_window_seconds(),
        )
        self._unapplied_changes = 0

        # File watcher that reloads automatically when config.yml changes
        self.config_observer: Observer | None = None  # type: ignore[valid-type]
        # Task checking that the relay is listening (only when git-relay is configured)
        self._relay_check_task: asyncio.Task[bool] | None = None
        # 0.2.22 (#53): waits for the secret store to open, then puts the upstream proxy
        # credential into Squid's config. Kept so shutdown can cancel it.
        self._proxy_credential_task: asyncio.Task[bool] | None = None
        # The loop reload_config runs on. Set when start() is running; the watcher thread reads it
        self._main_loop: asyncio.AbstractEventLoop | None = None
        if self.config_path:
            # Watch the directory containing the configuration file
            config_dir = Path(self.config_path).parent
            event_handler = ConfigFileEventHandler(self, Path(self.config_path))
            self.config_observer = Observer()
            self.config_observer.schedule(event_handler, str(config_dir), recursive=False)

    def _match_allowed_domain(self, domain: str) -> bool:
        """Whether a domain is on the allow list.

        Defers to the DNS server's matcher. This used to be a third implementation, with its
        own reading of a wildcard — it accepted `*.x` where DNS did not, and rejected what
        DNS accepted. Nothing called it, so the disagreement was invisible; the next caller
        would have inherited it.
        """
        return domain_matches(domain, self.config.allow_domains)

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

        # A domain the relay answers for keeps its real address out of the allow ipset,
        # whichever path got here. Reachable by address, it would bypass the relay entirely.
        if domain.lower().rstrip(".") in {
            d.lower().rstrip(".") for d in self.config.relay_domains()
        }:
            log_system_event("Domain rule refused: the relay answers for it", domain=domain)
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

    def _upstream_proxy_credential(self) -> tuple[str | None, str | None, bool]:
        """The upstream proxy's username and password, and whether they came from the store.

        The third value matters to the caller that runs after an unlock: rewriting Squid's config
        with the values it already has from `config.yml` is pointless work, and worse, it would
        report "applied after unlock" when nothing was applied.

        0.2.22 (#53): the secret store first. The two documented alternatives put the credential
        where the agent can read it — `.devcontainer/.env` becomes an environment variable in the
        agent's own process, and `config.yml` sits in the worktree. Both still work, because
        removing them strands every deployment behind a corporate proxy, and because the store
        cannot bootstrap itself where the proxy is what makes the network reachable.

        A locked store is the normal answer at start-up, not a failure: nobody has typed a
        passphrase yet. Squid comes up without upstream authentication and
        `_apply_proxy_credential_when_unlocked` redoes this once someone unlocks.
        """
        configured = (
            self.config.proxy.upstream_proxy_username,
            self.config.proxy.upstream_proxy_password,
            False,
        )
        try:
            secret = get_secret(PROXY_NAMESPACE, PROXY_NAME)
        except SecretStoreError as e:
            # Either there is no relay at all — `config.yml` need not declare a git-relay handler,
            # and then there is no store and never will be — or the relay has not finished
            # starting. entrypoint.sh launches it and the Python side together, so at this point
            # the socket may simply not be bound yet. The two are indistinguishable from here, so
            # whether to come back and look again is decided by the config, not by this error.
            log_system_event(f"Secret store not reachable ({e}); using the configured credential")
            self._proxy_credential_pending = bool(_relay_ports_of(self.config))
            return configured
        if isinstance(secret, str):
            try:
                parsed = json.loads(secret)
                username, password = parsed["username"], parsed["password"]
            except (ValueError, KeyError, TypeError) as e:
                log_error(
                    ComponentType.PROXY,
                    f"the stored upstream proxy credential is not usable ({e}); "
                    "re-run `sekimore-relay proxy-credential set`",
                )
                return configured
            log_system_event("Upstream proxy credential read from the secret store")
            return username, password, True

        if isinstance(secret, Locked):
            if any(configured):
                # Configured both ways. The store is the one that will win once it opens, so say
                # which is in force now rather than let the swap look like a change nobody made.
                log_system_event(
                    "Secret store locked; using the configured upstream proxy credential for now"
                )
            self._proxy_credential_pending = True
        elif isinstance(secret, NotFound):
            # Nothing stored. Only worth a word when the alternative is the readable one.
            if self.config.proxy.upstream_proxy_password:
                log_system_event(
                    "The upstream proxy password comes from config.yml, which the dev container "
                    "can read. `sekimore-relay proxy-credential set` moves it into the store"
                )
        return configured

    async def _apply_proxy_credential_when_unlocked(
        self, poll_seconds: float = 30.0, give_up_after: float = 86400.0
    ) -> bool:
        """Wait for the store to open, then put the credential into Squid's config.

        The gateway starts before anyone unlocks, so at start-up the credential is unreadable and
        Squid runs without upstream authentication. Polling rather than being told: the control
        socket answers questions, it does not push, and a person unlocking is not a frequent
        event — thirty seconds of latency on something that happens once per gateway is cheap
        next to a notification path that would have to exist on both sides.

        Gives up after a day so a gateway nobody intends to unlock does not poll forever.
        """
        waited = 0.0
        while waited < give_up_after:
            await asyncio.sleep(poll_seconds)
            waited += poll_seconds
            if not is_unlocked():
                continue
            username, password, from_store = self._upstream_proxy_credential()
            if not from_store:
                # Unlocked and the store holds nothing: whatever Squid already has is all there
                # is, and rewriting the same values would report an apply that did not happen.
                log_system_event(
                    "Secret store unlocked but holds no upstream proxy credential; "
                    "Squid keeps what it started with"
                )
                return False
            if not (username and password):
                return False
            if self.proxy_manager is None:
                return False
            self.proxy_manager.upstream_proxy_username = username
            self.proxy_manager.upstream_proxy_password = password
            if not self.proxy_manager.generate_config(
                self.config.proxy_allow_domains(), self.config.proxy_denied_domains()
            ):
                log_error(ComponentType.PROXY, "could not regenerate Squid's config after unlock")
                return False
            if not self.proxy_manager.reload_config():
                log_error(ComponentType.PROXY, "Squid did not reload after unlock")
                return False
            log_system_event("Upstream proxy credential applied after the store was unlocked")
            return True
        log_system_event(
            "Gave up waiting for the secret store; Squid keeps running without upstream "
            "authentication"
        )
        return False

    def _warn_if_upstream_proxy_is_shadowed(self) -> str | None:
        """Warn when proxy.upstream_proxy sits inside one of our own Docker subnets.

        Docker picks the bridge subnets, and it can land on a range the site already uses —
        192.168.0.0/20 here. An upstream proxy inside that range then looks to the container
        like a neighbour on the same link: it ARPs, nothing answers, and the connection times
        out. Nothing is dropped by a rule, the proxy logs nothing because no packet reaches
        it, and the docker host can talk to the same address perfectly well.

        That combination reads as a firewall problem and sends people to widen allow_ips or
        allowed_ports, which hands the agent a route to the proxy and does not fix anything.
        Returns the warning text, so a caller can show it too.
        """
        upstream = getattr(self.config.proxy, "upstream_proxy", None)
        if not upstream:
            return None
        host = str(upstream).rsplit(":", 1)[0].strip("[]")
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            try:
                addr = ipaddress.ip_address(socket.gethostbyname(host))
            except (OSError, ValueError):
                return None

        for iface, cidr in self._own_subnets():
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr in net:
                msg = (
                    f"proxy.upstream_proxy ({upstream}) resolves to {addr}, which is inside "
                    f"this container's own {iface} subnet {net}. Connections to it will time "
                    "out: the address looks like a neighbour on the bridge, so nothing is "
                    "routed and the proxy never sees a packet. This is not a firewall rule "
                    "and widening allow_ips or network.allowed_ports will not help — point "
                    "docker at a range that does not overlap the site's, with "
                    "`default-address-pools` in the daemon's /etc/docker/daemon.json, e.g. "
                    '[{"base": "172.31.0.0/16", "size": 24}]. Naming a subnet per network '
                    "works too but leaves you allocating addresses by hand."
                )
                log_error(ComponentType.ORCHESTRATOR, msg)
                return msg
        return None

    def _own_subnets(self) -> list[tuple[str, str]]:
        """This container's interface subnets, as (interface, cidr)."""
        out: list[tuple[str, str]] = []
        try:
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return out
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != "inet":
                continue
            iface, cidr = parts[1], parts[3]
            if iface == "lo":
                continue
            out.append((iface, cidr))
        return out

    async def initialize(self) -> bool:
        """Initialize the security gateway.

        Returns:
            True on success
        """
        log_system_event("Initializing Security Gateway...")

        # Before anything else: an upstream proxy inside our own bridge subnet fails in a way
        # that looks like a firewall problem and is not one.
        self._warn_if_upstream_proxy_is_shadowed()

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
        relayed = {d.lower().rstrip(".") for d in self.config.relay_domains()}
        for domain in self.config.allow_domains:
            # Wildcards starting with "." are skipped at startup and handled
            # dynamically when a DNS query arrives
            if domain.startswith("."):
                continue
            # A domain the relay answers for must not have its real address in the allow
            # ipset. DNS hands out the gateway's address for these and deliberately skips
            # setup_domain; seeding the upstream's address here would undo that, and the
            # agent could reach it by address and miss the relay altogether.
            if domain.lower().rstrip(".") in relayed:
                log_system_event(
                    "Domain rule skipped: the relay answers for it",
                    domain=domain,
                )
                continue
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
            if not self.proxy_manager.generate_config(
                self.config.proxy_allow_domains(), self.config.proxy_denied_domains()
            ):
                log_error(ComponentType.ORCHESTRATOR, "Failed to generate Squid config")
                # Carry on if the proxy config fails; DNS and the firewall still work
            else:
                log_system_event("Squid proxy config generated")

        # 6b. 0.2.22 (#53): the upstream proxy credential lives in the secret store, which is
        # locked at start-up, so Squid came up without upstream authentication. Redo it when
        # someone unlocks rather than making them restart the gateway.
        if self._proxy_credential_pending and self.proxy_manager:
            self._proxy_credential_task = asyncio.create_task(
                self._apply_proxy_credential_when_unlocked()
            )

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

        # Start watching the file, to reload automatically when config.yml changes.
        # 0.2.15: the handler runs on a watchdog thread and needs this loop to hand the reload
        # back to, so it is captured before the observer can deliver anything.
        self._main_loop = asyncio.get_running_loop()
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

        # It sleeps for up to a day waiting for the store, so shutdown has to cancel it or the
        # process hangs on a task that is doing nothing.
        if self._proxy_credential_task:
            self._proxy_credential_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._proxy_credential_task

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

    def note_unapplied_change(self) -> None:
        """Record that config.yml changed while the window was closed.

        The count is what `check` reports; the audit line is written by the caller. A change
        nobody applied is still worth seeing — it is how an attempt to widen the rules shows up.
        """
        self._unapplied_changes += 1

    def has_unapplied_changes(self) -> bool:
        return self._unapplied_changes > 0

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

            # Generate the new Squid configuration before changing anything. It is the step
            # most likely to be refused — Squid has constraints of its own — and the updates
            # below are not undoable, so a failure here used to leave DNS and the firewall on
            # the new config while Squid and self.config stayed on the old one, with the next
            # reload's diff computed from a state that never existed.
            if self.proxy_manager:
                # domain_handlers changes need a restart, so the relay may still be running with
                # the old set. Take both: a domain either side relays must not be served here.
                denied = sorted(
                    set(self.config.proxy_denied_domains()) | set(new_config.proxy_denied_domains())
                )
                allowed = [
                    d for d in new_config.allow_domains if d.lower().rstrip(".") not in set(denied)
                ]
                if not self.proxy_manager.generate_config(allowed, denied):
                    log_error(ComponentType.ORCHESTRATOR, "Failed to regenerate Squid config")
                    return False

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

            # Re-apply allow_ips / block_ips. These used to be read only at start-up, so
            # adding an address to block_ips did nothing until the container was restarted —
            # and nothing said so, which is the wrong way round for a blocklist.
            if not self.ip_manager.setup_static_ips(
                allow_ips=new_config.allow_ips,
                block_ips=new_config.block_ips,
            ):
                log_error(ComponentType.ORCHESTRATOR, "Static IP reload failed")
                return False

            # Tell Squid to read what was written above.
            if self.proxy_manager and not self.proxy_manager.reload_config():
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
                if not self.proxy_manager.generate_config(
                    self.config.proxy_allow_domains(), self.config.proxy_denied_domains()
                ):
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
