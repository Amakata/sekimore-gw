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
        port: int = 3128,
        cache_enabled: bool = True,
        cache_size_mb: int = 10000,
        upstream_proxy: str | None = None,
        upstream_proxy_tls: bool = False,
        upstream_dns: str = "127.0.0.11",
        upstream_proxy_username: str | None = None,
        upstream_proxy_password: str | None = None,
        denied_destinations: list[str] | None = None,
        allowed_destinations: list[str] | None = None,
    ):
        """Initialize the manager.

        Args:
            config_template_path: Path to the Squid config template
            config_output_path: Path to write the generated config to
            port: Port Squid listens on (proxy.port)
            cache_enabled: Whether caching is enabled
            cache_size_mb: Cache size in MB
            upstream_proxy: Upstream proxy (host:port)
            upstream_proxy_tls: Use TLS when connecting to the upstream proxy
            upstream_dns: Upstream DNS server (default: Docker's built-in DNS, 127.0.0.11)
            upstream_proxy_username: Username for upstream proxy authentication
            upstream_proxy_password: Password for upstream proxy authentication
            denied_destinations: Address ranges refused whatever a name resolves to (#178)
            allowed_destinations: Exceptions to denied_destinations
        """
        self.template_path = Path(config_template_path or constants.SQUID_TEMPLATE_PATH)
        self.output_path = Path(config_output_path or constants.SQUID_CONFIG_PATH)
        self.port = port
        self.cache_enabled = cache_enabled
        self.cache_size_mb = cache_size_mb
        self.upstream_proxy = upstream_proxy
        self.upstream_proxy_tls = upstream_proxy_tls
        self.upstream_dns = upstream_dns
        self.upstream_proxy_username = upstream_proxy_username
        self.upstream_proxy_password = upstream_proxy_password
        # #178: destinations refused whatever an allowlisted name resolves to, and the
        # exceptions to that (the gateway's own network, an internal mirror a project names)
        self.denied_destinations: list[str] = list(denied_destinations or [])
        self.allowed_destinations: list[str] = list(allowed_destinations or [])

    def generate_config(
        self, allowed_domains: list[str], relayed_domains: list[str] | None = None
    ) -> bool:
        """Generate the Squid configuration file.

        Args:
            allowed_domains: Domain allowlist
            relayed_domains: Domains another component owns (the relay's github / https-relay,
                and deny). Squid resolves through Docker's DNS and never sees the DNS filter's
                answers, so these get an explicit deny placed before the allow rule. Denying
                rather than dropping them from the allowlist keeps a wildcard like
                `.github.com` serving api. and codeload. while withholding github.com itself

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

            # ... and the deny that has to precede them
            relayed_acls, relayed_rule = self._generate_relayed_denial(relayed_domains or [])

            # Cache settings
            cache_config = self._generate_cache_config()

            # Upstream proxy settings
            upstream_config = self._generate_upstream_proxy_config()

            # The template is bind-mounted from the deployment, not baked into the image, so a
            # gateway can run new code against a template that predates the relayed-domain
            # placeholders. str.format would drop the deny rule silently and leave the relay
            # reachable through the proxy, so put it in ourselves when the template lacks it.
            template = self._ensure_relay_placeholders(template)
            # Before the destination backfill: that one inserts above the relay's allow when
            # the allow is already there, which is how #178 keeps outranking it (#205).
            template = self._ensure_relay_localhost_placeholders(template)
            template = self._ensure_destination_placeholders(template)

            denied_acls, denied_rule = self._generate_denied_destinations()

            # #205: the relay's own way out through Squid, when an upstream proxy is configured
            localhost_acl, localhost_rule = self._generate_relay_localhost_allow()

            # Fill in the template
            config = template.format(
                PROXY_PORT=str(self.port),
                ALLOWED_DOMAINS_ACL=domain_acls,
                RELAYED_DOMAINS_ACL=relayed_acls,
                RELAYED_DOMAINS_RULE=relayed_rule,
                RELAY_LOCALHOST_ACL=localhost_acl,
                RELAY_LOCALHOST_RULE=localhost_rule,
                DENIED_DESTINATIONS_ACL=denied_acls,
                DENIED_DESTINATIONS_RULE=denied_rule,
                CACHE_CONFIG=cache_config,
                UPSTREAM_PROXY_CONFIG=upstream_config,
                DNS_NAMESERVERS=self.upstream_dns,
            )

            # #205: an allow below the deny is one Squid never reaches, so a config with it in
            # the wrong place would look right and leave the relay's HTTPS dead — and one that
            # outranks #178 would let the relay reach IMDS through the proxy. Refuse either.
            if localhost_rule and not self._relay_localhost_allow_is_placed(config):
                log_error(
                    ComponentType.PROXY,
                    "Squid config would not let the relay out (the localhost allow is missing "
                    "or misplaced); refusing to write it",
                )
                return False

            # Belt and braces: never write a config that serves what the relay owns.
            if relayed_domains and "http_access deny relayed_domains" not in config:
                log_error(
                    ComponentType.PROXY,
                    "Squid config would not refuse the relayed domains; refusing to write it",
                )
                return False

            # The same, for the destinations no name may reach (#178). A config written without
            # this rule serves IMDS through the proxy to anything that asks.
            if self.denied_destinations and "http_access deny denied_destinations" not in config:
                log_error(
                    ComponentType.PROXY,
                    "Squid config would not refuse the denied destinations; refusing to write it",
                )
                return False

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

    @staticmethod
    def _ensure_relay_placeholders(template: str) -> str:
        """Add the relayed-domain placeholders to a template written before they existed.

        The template is bind-mounted by each deployment (see docker-compose.yml), so upgrading
        the gateway image does not upgrade it. Without this, `str.format` would quietly discard
        the deny rule and the generated config would serve the domains the relay owns — the
        failure is silent and reopens the hole the rule exists to close.

        A template that already carries the placeholders is returned untouched.
        """
        if "{RELAYED_DOMAINS_RULE}" in template:
            return template

        allow_rule = "http_access allow allowed_domains"
        if allow_rule not in template:
            # Not a shape we recognise. generate_config's check below catches this.
            log_error(
                ComponentType.PROXY,
                "Squid template has neither the relayed-domain placeholders nor the expected "
                "allow rule; cannot place the deny rule",
            )
            return template

        log_system_event(
            "Squid template predates the relayed-domain rule; inserting it",
        )
        template = template.replace(allow_rule, "{RELAYED_DOMAINS_RULE}\n\n" + allow_rule, 1)
        # The ACL definitions have to precede the rule that uses them.
        return template.replace(
            "{ALLOWED_DOMAINS_ACL}", "{ALLOWED_DOMAINS_ACL}\n{RELAYED_DOMAINS_ACL}", 1
        )

    @staticmethod
    def _ensure_destination_placeholders(template: str) -> str:
        """Add the destination placeholders to a template written before they existed (#178).

        Same reasoning as `_ensure_relay_placeholders`: the template is bind-mounted by the
        deployment, so a gateway can run this code against a template from an older release.
        `str.format` would drop the deny silently and serve IMDS through the proxy.

        A template that already carries the placeholders is returned untouched.
        """
        if "{DENIED_DESTINATIONS_RULE}" in template:
            return template

        allow_rule = "http_access allow allowed_domains"
        if allow_rule not in template:
            log_error(
                ComponentType.PROXY,
                "Squid template has neither the destination placeholders nor the expected "
                "allow rule; cannot place the deny rule",
            )
            return template

        log_system_event(
            "Squid template predates the denied-destination rule; inserting it",
        )
        block = "{DENIED_DESTINATIONS_ACL}\n{DENIED_DESTINATIONS_RULE}\n\n"
        # #205: above the relay's allow when that is present. The relay hands the *name* to the
        # proxy and never resolves it, so Squid's `dst` deny is the only thing that sees the
        # address the request would reach; an allow above it would serve IMDS to the relay.
        relay_acl = "{RELAY_LOCALHOST_ACL}"
        if relay_acl in template:
            return template.replace(relay_acl, block + relay_acl, 1)
        # Both go in above the allowlist: Squid takes the first rule that matches
        return template.replace(allow_rule, block + allow_rule, 1)

    def _generate_domain_acls(self, domains: list[str]) -> str:
        """Build the domain ACLs.

        Entries a wildcard already covers are left out. Squid treats a name listed beside a
        wildcard that contains it as a fatal configuration error, not a warning, so writing
        both `deb.debian.org` and `.debian.org` stops the proxy from starting at all. The
        allowlist is hand-edited and that pairing is a natural thing to write, so drop the
        redundant one here rather than refuse the config.

        Args:
            domains: Domain allowlist

        Returns:
            ACL configuration snippet
        """
        # `*.example.com` and `.example.com` are the same thing to Squid
        normalized = [(d, d[1:] if d.startswith("*.") else d) for d in domains]
        # A wildcard covers the bare name too: `.x.com` and `x.com` together are also fatal.
        covered = {n.lstrip(".") for _, n in normalized if n.startswith(".")}

        acl_lines = []
        seen: set[str] = set()
        for original, name in normalized:
            if name in seen:
                continue
            if not name.startswith("."):
                parent: str | None = name
                while parent:
                    if parent in covered:
                        log_system_event(
                            "Squid ACL: domain omitted, a wildcard already covers it",
                            domain=original,
                            covered_by=f".{parent}",
                        )
                        break
                    parent = parent.partition(".")[2]
                else:
                    seen.add(name)
                    acl_lines.append(f"acl allowed_domains dstdomain {name}")
                continue
            seen.add(name)
            acl_lines.append(f"acl allowed_domains dstdomain {name}")

        return "\n".join(acl_lines)

    def _generate_relayed_denial(self, relayed_domains: list[str]) -> tuple[str, str]:
        """Build the ACL and the access rule that withhold the relayed domains.

        Returns a (acl, rule) pair; both are empty when nothing is relayed, leaving the
        generated file byte-identical to what it was before this existed.

        `dstdomain github.com` matches that exact name only, so a wildcard entry in the
        allowlist keeps working for everything under it. That matters: `.github.com` is how
        api.github.com and codeload.github.com are usually allowed, and they are not the
        relay's to own.
        """
        if not relayed_domains:
            return "", ""
        acl = "\n".join(f"acl relayed_domains dstdomain {d}" for d in sorted(relayed_domains))
        rule = (
            "# Domains the relay owns. Squid must not serve them: it resolves through Docker's\n"
            "# DNS and never sees the DNS filter, so serving one here would reach the real\n"
            "# upstream with none of the project's policy applied\n"
            "http_access deny relayed_domains"
        )
        return acl, rule

    @staticmethod
    def _ensure_relay_localhost_placeholders(template: str) -> str:
        """Add the #205 placeholders to a template written before they existed.

        Same reasoning as the two above: the template is bind-mounted by the deployment, so a
        gateway can run this code against a template from an older release. The failure here is
        the opposite one — not a hole, but the relay's HTTPS staying dead with
        `upstream_proxy_tls: true`, and `str.format` raising KeyError rather than dropping it
        quietly, which would leave Squid unconfigured altogether.

        The allow goes directly above `{RELAYED_DOMAINS_RULE}`, because those domains are
        exactly what the relay asks for. `_ensure_destination_placeholders` runs after this and
        puts #178's block above it, so the allow ends up below the one deny it must not outrank.

        A template that already carries the placeholders is returned untouched.
        """
        if "{RELAY_LOCALHOST_RULE}" in template:
            return template

        relayed_rule = "{RELAYED_DOMAINS_RULE}"
        if relayed_rule not in template:
            # `_ensure_relay_placeholders` runs first and puts it there, so this is a template
            # of a shape we do not recognise. generate_config's check below catches it.
            log_error(
                ComponentType.PROXY,
                "Squid template has neither the localhost placeholders nor the relayed-domain "
                "rule; cannot place the relay's allow",
            )
            return template

        log_system_event(
            "Squid template predates the relay's localhost allow; inserting it",
        )
        return template.replace(
            relayed_rule,
            "{RELAY_LOCALHOST_ACL}\n{RELAY_LOCALHOST_RULE}\n\n" + relayed_rule,
            1,
        )

    def _generate_relay_localhost_allow(self) -> tuple[str, str]:
        """Build the ACL and the rule that let the relay out through Squid (#205).

        Returns a (acl, rule) pair, both empty when there is no upstream proxy: with none there
        is nothing for the relay to go through Squid for, and the generated file stays what it
        was before this existed.

        The relay's TLS is rustls, which implements no RSA key exchange. An upstream proxy
        offering only TLS 1.2 with RSA — a Squid `https_port` without `tls-dh=`, which is the
        default — shares no cipher suite with it, so every relayed HTTPS path dies in the
        handshake. Squid is in the same container, speaks OpenSSL and already reaches that proxy
        with `cache_peer ... tls`, so the relay sends its CONNECT here instead.

        This sits above the relayed-domain deny, because the relayed domains are exactly what
        the relay asks for, and below #178's destination deny, which is the only thing that sees
        the address a name resolves to on this path. It widens nothing for the agent: the source
        is 127.0.0.1, the gateway's INPUT policy is DROP with accepts on lan_if only
        (src/firewall.py), and loopback is not routable from dev. The only thing that can match
        it is a process in the gateway container.
        """
        if not self.upstream_proxy:
            return "", ""
        acl = "acl relay_localhost src 127.0.0.1/32"
        rule = (
            "# The relay's own requests (#205). It reaches the upstream proxy through Squid\n"
            "# when that proxy speaks TLS, because Squid's OpenSSL has key exchanges rustls\n"
            "# has not. Above the deny below: the relayed domains are what the relay asks for.\n"
            "# Nothing in dev can match this -- INPUT is DROP except on lan_if, and 127.0.0.1\n"
            "# is not routable from there -- and the relay asks only for hosts its own policy\n"
            "# already allowed\n"
            "http_access allow relay_localhost"
        )
        return acl, rule

    @staticmethod
    def _relay_localhost_allow_is_placed(config: str) -> bool:
        """True when the relay's allow is present and ordered correctly (#205).

        Squid takes the first `http_access` rule that matches, so the allow has to be above
        every deny it must outrank (the relayed domains, and the catch-all) and below the one it
        must not (#178's destinations: the relay never resolves the name on the proxy path, so
        that rule is the only thing that sees where the request goes).
        """
        allow = config.find("http_access allow relay_localhost")
        if allow < 0:
            return False
        for deny in ("http_access deny relayed_domains", "http_access deny all"):
            at = config.find(deny)
            if 0 <= at < allow:
                return False
        # `find` gives -1 when there is no destination deny at all, which is below `allow`
        # and so passes, as it should.
        return config.find("http_access deny denied_destinations") < allow

    def _generate_denied_destinations(self) -> tuple[str, str]:
        """Build the ACL and the access rule that refuse a destination by address (#178).

        Returns a (acl, rule) pair, both empty when nothing is denied.

        The DNS path already refuses these, but Squid resolves the name itself and never sees
        that answer — the same gap that made the relayed-domain deny necessary above. Without
        this, an allowlisted domain pointed at 169.254.169.254 is refused to anything going
        direct and served to anything going through the proxy.

        `dst` matches on the address Squid resolved, so it holds whatever the name says.
        """
        if not self.denied_destinations:
            return "", ""
        acl = "\n".join(
            f"acl denied_destinations dst {c}" for c in sorted(self.denied_destinations)
        )
        # An exception is written as its own ACL and allowed first: Squid takes the first rule
        # that matches, so the project's own network survives the deny below it
        if self.allowed_destinations:
            acl += "\n" + "\n".join(
                f"acl allowed_destinations dst {c}" for c in sorted(self.allowed_destinations)
            )
        rule_lines = []
        if self.allowed_destinations:
            rule_lines.append("http_access allow allowed_destinations")
        rule_lines.append(
            "# An allowed name is not an allowed destination: refuse IMDS, loopback and the\n"
            "# private ranges whatever an allowlisted domain resolves to (#178)"
        )
        rule_lines.append("http_access deny denied_destinations")
        return acl, "\n".join(rule_lines)

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
