"""Configuration management - loads and validates config.yml."""

import ipaddress
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class DNSConfig(BaseModel):
    """DNS settings.

    Every value is hard-coded and cannot be changed from the config file:
    - upstream: 127.0.0.11 (Docker's embedded DNS)
    - port: 53 (standard DNS port)
    - min_ttl: 60 seconds
    - max_ttl: 86400 seconds (24 hours)

    This prevents misconfiguration; pointing upstream at 127.0.0.1, for example, breaks
    the Squid proxy.
    """

    pass  # no settings; everything is fixed


class ProxyConfig(BaseModel):
    """Proxy settings."""

    enabled: bool = Field(default=False, description="Enable the proxy")
    port: int = Field(default=3128, description="Proxy port")
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_size_mb: int = Field(default=1000, description="Cache size in MB")
    upstream_proxy: str | None = Field(default=None, description="Upstream proxy (host:port)")
    upstream_proxy_tls: bool = Field(
        default=False, description="Use TLS to reach the upstream proxy"
    )
    upstream_proxy_username: str | None = Field(
        default=None,
        description="Username for the upstream proxy (overridden by SEKIMORE_UPSTREAM_PROXY_USERNAME)",
    )
    upstream_proxy_password: str | None = Field(
        default=None,
        description="Password for the upstream proxy (overridden by SEKIMORE_UPSTREAM_PROXY_PASSWORD)",
    )

    def model_post_init(self, __context) -> None:
        """Read credentials from the environment."""
        # Upstream proxy credentials from the environment take precedence over
        # config.yml. The SEKIMORE_ prefix keeps the namespace separate.
        if os.getenv("SEKIMORE_UPSTREAM_PROXY_USERNAME"):
            self.upstream_proxy_username = os.getenv("SEKIMORE_UPSTREAM_PROXY_USERNAME")
        if os.getenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD"):
            self.upstream_proxy_password = os.getenv("SEKIMORE_UPSTREAM_PROXY_PASSWORD")


class NetworkConfig(BaseModel):
    """Network settings."""

    lan_subnets: list[str] = Field(
        default_factory=lambda: ["10.100.0.0/16"],
        description="LAN-side subnets (must match the lan network in docker-compose.yml)",
    )
    # 0.2.2: destination TCP ports allowed towards allowed domains / IPs. Empty means
    # every port, as before. Restricting it (e.g. [80, 443]) closes routes that bypass
    # the relay over another protocol, such as SSH to a raw IP. Applied on restart.
    allowed_ports: list[int] = Field(
        default_factory=list,
        description="Destination TCP ports allowed to the allowed domains and IPs (empty = every port), e.g. [80, 443]",
    )

    @field_validator("allowed_ports")
    @classmethod
    def validate_allowed_ports(cls, v: list[int]) -> list[int]:
        """Integers in 1-65535, deduplicated."""
        out: list[int] = []
        for p in v:
            if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
                raise ValueError(f"network.allowed_ports: {p!r} is not a TCP port (1-65535)")
            if p not in out:
                out.append(p)
        return out


class DomainHandlerConfig(BaseModel):
    """A single domain_handlers entry (the relay)."""

    handler: Literal["splice", "github", "https-relay", "deny"] = Field(
        default="splice",
        description=(
            "splice = as before / github = taken by the relay's SSH and API (DNS answers the relay's IP) / "
            "https-relay = only 443 goes through the relay's passthrough, under an upload cap (0.2.2) / deny = refused"
        ),
    )

    # 0.2.6: `git-relay` was the original spelling and still works; it normalizes to `github`.
    # The SSH git half is not GitHub-specific, but the API half is, so the handler carries the
    # forge's name. Nobody has to rewrite a working config.
    @field_validator("handler", mode="before")
    @classmethod
    def accept_the_original_handler_name(cls, v: Any) -> Any:
        return "github" if v == "git-relay" else v

    # 0.2.2: upload cap in bytes for the 443 passthrough. Omitted falls back to
    # relay.https_max_upload_bytes; -1 means unlimited. Read by the relay.
    max_upload_bytes: int | None = Field(
        default=None,
        description="Per-connection cap in bytes on what dev may send upstream over the 443 passthrough. -1 for unlimited; omit to use the relay default",
    )

    @field_validator("max_upload_bytes")
    @classmethod
    def validate_max_upload_bytes(cls, v: int | None) -> int | None:
        if v is not None and (v == 0 or v < -1):
            raise ValueError(
                "max_upload_bytes must be -1 (unlimited) or a positive number of bytes; "
                "0 would block every HTTPS request"
            )
        return v

    # 0.2.0: multiple git-relay domains are separated by port, because an SSH exec
    # request carries only the repository path.
    ssh_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="git-relay: the relay-side SSH port. Omit it to use the port of relay.ssh_listen (the default upstream)",
    )
    upstream: str | None = Field(
        default=None,
        description="git-relay: the upstream host. Omit it to use the domain name (the relay reads the rest)",
    )


class RelayConfig(BaseModel):
    """The part of the relay section that Python reads.

    The remaining keys belong to the relay binary (Rust); Pydantic's default of ignoring
    unknown keys lets them pass through untouched.
    """

    ssh_listen: str = Field(default="0.0.0.0:22", description="Listen address of the relay's SSH")
    api_listen: str = Field(
        default="0.0.0.0:8420", description="Listen address of the relay's HTTP API"
    )
    https_listen: str = Field(
        default="0.0.0.0:443", description="Address that takes port 443 of the same domain"
    )
    https: Literal["passthrough", "reject"] = Field(
        default="passthrough",
        description="What to do with 443 (passthrough = pass it to the real upstream unchanged / reject = drop it immediately)",
    )


def _port_of(listen: str, default: int) -> int:
    """Extract the port from a 'host:port' string."""
    try:
        return int(str(listen).rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return default


class UIConfig(BaseModel):
    """Web UI settings (0.2.4)."""

    language: Literal["auto", "en", "ja"] = Field(
        default="auto",
        description="Web UI language. auto = the browser's Accept-Language (a choice made in the UI wins via a cookie) / en / ja",
    )


class Config(BaseModel):
    """AI Security Gateway configuration."""

    # Gateway metadata
    name: str | None = Field(default=None, description="Gateway name")
    description: str | None = Field(default=None, description="Gateway description")

    # Domain filtering
    allow_domains: list[str] = Field(default_factory=list, description="Allowed domains")
    block_domains: list[str] = Field(default_factory=list, description="Blocked domains")
    ignore_domains: list[str] = Field(
        default_factory=list, description="Ignored domains (hidden from the UI)"
    )

    # IP filtering
    allow_ips: list[str] = Field(default_factory=list, description="Allowed IPs")
    block_ips: list[str] = Field(default_factory=list, description="Blocked IPs")

    # Component settings
    dns: DNSConfig = Field(default_factory=DNSConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)

    # Database
    database_path: str = Field(
        default="/data/security_gateway.db", description="Path of the SQLite database"
    )

    # The relay. Absent, behaviour is unchanged (see relay/README.md).
    domain_handlers: dict[str, DomainHandlerConfig] = Field(
        default_factory=dict,
        description="Per-domain handler (git-relay / deny / splice). An exact FQDN",
    )
    relay: RelayConfig = Field(default_factory=RelayConfig)
    ui: UIConfig = Field(default_factory=UIConfig)

    @field_validator("domain_handlers", mode="before")
    @classmethod
    def normalize_domain_handlers(cls, v: Any) -> Any:
        """Normalize keys (lowercase, strip trailing dot); reject wildcards, empties and duplicates."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("domain_handlers must be a mapping of domain -> {handler: ...}")
        out: dict[str, Any] = {}
        for key, val in v.items():
            norm = str(key).strip().rstrip(".").lower()
            if not norm:
                raise ValueError("domain_handlers: empty domain key")
            if norm.startswith(".") or "*" in norm:
                raise ValueError(
                    f"domain_handlers: {key!r} must be an exact FQDN "
                    "(a wildcard would redirect every subdomain, e.g. api.github.com)"
                )
            if norm in out:
                raise ValueError(f"domain_handlers: duplicate domain {norm!r}")
            out[norm] = val if val is not None else {}
        return out

    @model_validator(mode="after")
    def validate_git_relay_ports(self) -> "Config":
        """Every git-relay domain listens on its own SSH port (0.2.0).

        An SSH exec request carries only the repository path, so upstreams are told apart
        by port. An entry without ssh_port falls back to the relay.ssh_listen port (the
        default upstream), and only one entry may do so.
        """
        if self.https_relay_domains() and not self.git_relay_domains():
            raise ValueError(
                "domain_handlers: https-relay needs at least one git-relay domain in this version "
                "(the relay's 443 passthrough is started with it)"
            )
        seen: dict[int, str] = {}
        for domain, port in self.git_relay_ssh_ports().items():
            if port in seen:
                raise ValueError(
                    f"domain_handlers: git-relay domains {seen[port]!r} and {domain!r} would both "
                    f"listen on ssh port {port}; every git-relay domain but the default one needs "
                    "its own ssh_port because the SSH exec request carries only the repository path"
                )
            seen[port] = domain
        return self

    def git_relay_ssh_ports(self) -> dict[str, int]:
        """Map each git-relay domain to its relay SSH port (relay.ssh_listen when ssh_port is omitted)."""
        default_port = _port_of(self.relay.ssh_listen, 22)
        return {
            d: (h.ssh_port if h.ssh_port is not None else default_port)
            for d, h in self.domain_handlers.items()
            if h.handler == "github"
        }

    def git_relay_domains(self) -> list[str]:
        """Domains whose handler is git-relay."""
        return [d for d, h in self.domain_handlers.items() if h.handler == "github"]

    def https_relay_domains(self) -> list[str]:
        """Domains whose handler is https-relay (0.2.2; only 443 goes through the relay)."""
        return [d for d, h in self.domain_handlers.items() if h.handler == "https-relay"]

    def relay_domains(self) -> list[str]:
        """Domains for which DNS answers with the relay IP (git-relay + https-relay)."""
        return self.git_relay_domains() + self.https_relay_domains()

    def has_git_relay(self) -> bool:
        return bool(self.git_relay_domains())

    def relay_input_ports(self) -> list[int]:
        """Ports opened in INPUT on lan_if for the relay; empty when git-relay is unused.

        443 is opened regardless of the https setting: even in reject mode the relay
        accepts the connection and closes it immediately, whereas dropping it in INPUT
        would leave the client hanging until it times out.
        """
        if not self.has_git_relay():
            return []
        ssh_ports: list[int] = [_port_of(self.relay.ssh_listen, 22)]
        for port in self.git_relay_ssh_ports().values():
            if port not in ssh_ports:
                ssh_ports.append(port)
        return [
            *ssh_ports,
            _port_of(self.relay.api_listen, 8420),
            _port_of(self.relay.https_listen, 443),
        ]

    @field_validator("allow_ips", "block_ips")
    @classmethod
    def validate_ip_entries(cls, v: list[str]) -> list[str]:
        """Validate IP entries (single IP, CIDR or range)."""
        for entry in v:
            if "-" in entry:
                # IP range form: 192.168.1.1-192.168.1.10
                start_ip_str, end_ip_str = entry.split("-", 1)
                try:
                    ipaddress.ip_address(start_ip_str.strip())
                    ipaddress.ip_address(end_ip_str.strip())
                except ValueError as e:
                    raise ValueError(f"Invalid IP range: {entry}") from e
            elif "/" in entry:
                # CIDR form: 192.168.1.0/24
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR notation: {entry}") from e
            else:
                # Single IP: 192.168.1.1
                try:
                    ipaddress.ip_address(entry)
                except ValueError as e:
                    raise ValueError(f"Invalid IP address: {entry}") from e
        return v

    @classmethod
    def from_yaml(cls, path: Path) -> "Config":
        """Load the configuration from a YAML file."""
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)

        if data is None:
            data = {}

        return cls(**data)

    def to_yaml(self, path: Path) -> None:
        """Write the configuration to a YAML file."""
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, allow_unicode=True)


def load_config(config_path: Path | None = None) -> Config:
    """Load the configuration file.

    Args:
        config_path: Path to the config file (falls back to the default path)

    Returns:
        Config: The loaded configuration
    """
    if config_path is None:
        config_path = Path("/etc/sekimore/config.yml")

    if not config_path.exists():
        # Fall back to the defaults
        return Config()

    return Config.from_yaml(config_path)
