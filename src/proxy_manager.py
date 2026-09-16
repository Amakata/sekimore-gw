"""Proxy management - generates and manages the Squid configuration."""

import subprocess
from pathlib import Path

from . import constants
from .logger import ComponentType, log_error, log_system_event


class ProxyManager:
    """Manages the Squid proxy server."""

    def __init__(
        self,
        config_template_path: str | None = None,
        config_output_path: str | None = None,
        cache_enabled: bool = True,
        cache_size_mb: int = 10000,
        upstream_proxy: str | None = None,
        upstream_proxy_tls: bool = False,
        upstream_dns: str = "127.0.0.11",
        upstream_proxy_username: str | None = None,
        upstream_proxy_password: str | None = None,
    ):
        """Initialize the manager.

        Args:
            config_template_path: Path to the Squid config template
            config_output_path: Path to write the generated config to
            cache_enabled: Whether caching is enabled
            cache_size_mb: Cache size in MB
            upstream_proxy: Upstream proxy (host:port)
            upstream_proxy_tls: Use TLS when connecting to the upstream proxy
            upstream_dns: Upstream DNS server (default: Docker's built-in DNS, 127.0.0.11)
            upstream_proxy_username: Username for upstream proxy authentication
            upstream_proxy_password: Password for upstream proxy authentication
        """
        self.template_path = Path(config_template_path or constants.SQUID_TEMPLATE_PATH)
        self.output_path = Path(config_output_path or constants.SQUID_CONFIG_PATH)
        self.cache_enabled = cache_enabled
        self.cache_size_mb = cache_size_mb
        self.upstream_proxy = upstream_proxy
        self.upstream_proxy_tls = upstream_proxy_tls
        self.upstream_dns = upstream_dns
        self.upstream_proxy_username = upstream_proxy_username
        self.upstream_proxy_password = upstream_proxy_password

    def generate_config(self, allowed_domains: list[str]) -> bool:
        """Generate the Squid configuration file.

        Args:
            allowed_domains: Domain allowlist

        Returns:
            True on success
        """
        try:
            # Load the template
            if not self.template_path.exists():
                log_error(
                    ComponentType.PROXY,
                    f"Template not found: {self.template_path}",
                )
                return False

            with open(self.template_path) as f:
                template = f.read()

            # Build the allowlist ACLs
            domain_acls = self._generate_domain_acls(allowed_domains)

            # Cache settings
            cache_config = self._generate_cache_config()

            # Upstream proxy settings
            upstream_config = self._generate_upstream_proxy_config()

            # Fill in the template
            config = template.format(
                ALLOWED_DOMAINS_ACL=domain_acls,
                CACHE_CONFIG=cache_config,
                UPSTREAM_PROXY_CONFIG=upstream_config,
                DNS_NAMESERVERS=self.upstream_dns,
            )

            # Write out the config file
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w") as f:
                f.write(config)

            log_system_event(
                "Squid config generated",
                output_path=str(self.output_path),
                domains_count=str(len(allowed_domains)),
            )

            return True

        except Exception as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to generate Squid config: {e}",
            )
            return False

    def _generate_domain_acls(self, domains: list[str]) -> str:
        """Build the domain ACLs.

        Args:
            domains: Domain allowlist

        Returns:
            ACL configuration snippet
        """
        acl_lines = []

        # Define one ACL entry per domain
        for domain in domains:
            if domain.startswith("*."):
                # Wildcard: *.example.com -> .example.com
                acl_lines.append(f"acl allowed_domains dstdomain {domain[1:]}")
            else:
                # Plain domain
                acl_lines.append(f"acl allowed_domains dstdomain {domain}")

        return "\n".join(acl_lines)

    def _generate_cache_config(self) -> str:
        """Build the cache configuration.

        Returns:
            Cache configuration snippet
        """
        if not self.cache_enabled:
            return "cache deny all"

        # Cache directory and sizing
        return f"""cache_dir ufs /var/spool/squid {self.cache_size_mb} 16 256
maximum_object_size 100 MB
cache_mem 256 MB"""

    def _generate_upstream_proxy_config(self) -> str:
        """Build the upstream proxy configuration.

        Returns:
            Upstream proxy configuration snippet
        """
        if not self.upstream_proxy:
            return "# No upstream proxy configured"

        # Parse the host:port form
        parts = self.upstream_proxy.split(":")
        if len(parts) != 2:
            log_error(
                ComponentType.PROXY,
                f"Invalid upstream proxy format: {self.upstream_proxy}",
            )
            return "# Invalid upstream proxy configuration"

        host, port = parts

        # Build up the cache_peer options
        options = ""
        if self.upstream_proxy_tls:
            options += " tls"
        if self.upstream_proxy_username and self.upstream_proxy_password:
            options += f" login={self.upstream_proxy_username}:{self.upstream_proxy_password}"
            log_system_event(
                "Upstream proxy configured with Basic authentication",
                host=host,
                port=port,
                username=self.upstream_proxy_username,
                tls=str(self.upstream_proxy_tls),
            )
        else:
            log_system_event(
                "Upstream proxy configured without authentication",
                host=host,
                port=port,
                tls=str(self.upstream_proxy_tls),
            )

        return f"""# Upstream proxy configuration
cache_peer {host} parent {port} 0 no-query default{options}
never_direct allow all"""

    def reload_config(self) -> bool:
        """Reload the Squid configuration.

        Returns:
            True on success
        """
        try:
            # squid -k reconfigure
            subprocess.run(
                ["squid", "-k", "reconfigure"],
                check=True,
                capture_output=True,
                text=True,
            )

            log_system_event("Squid config reloaded")
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to reload Squid: {e.stderr}",
            )
            return False
        except FileNotFoundError:
            log_error(ComponentType.PROXY, "squid command not found")
            return False

    def start(self) -> bool:
        """Start Squid.

        Returns:
            True on success
        """
        try:
            # Initialize the cache directories
            log_system_event("Initializing Squid cache directories")
            result = subprocess.run(
                ["squid", "-z"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                log_error(
                    ComponentType.PROXY,
                    f"Squid cache initialization failed: {result.stderr}",
                )
                # Still try to start Squid even if this fails (e.g. caching disabled)

            # squid -N (foreground mode)
            subprocess.Popen(
                ["squid", "-N"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            log_system_event("Squid proxy started")
            return True

        except FileNotFoundError:
            log_error(ComponentType.PROXY, "squid command not found")
            return False

    def stop(self) -> bool:
        """Stop Squid.

        Returns:
            True on success
        """
        try:
            subprocess.run(
                ["squid", "-k", "shutdown"],
                check=True,
                capture_output=True,
                text=True,
            )

            log_system_event("Squid proxy stopped")
            return True

        except subprocess.CalledProcessError as e:
            log_error(
                ComponentType.PROXY,
                f"Failed to stop Squid: {e.stderr}",
            )
            return False
