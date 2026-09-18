"""Unit tests for proxy_manager module."""

from pathlib import Path
from unittest.mock import Mock, patch

from src.proxy_manager import ProxyManager


def describe_proxy_manager():
    """ProxyManager unit tests."""

    def it_initializes_with_default_paths():
        """Test ProxyManager initializes with default paths."""
        pm = ProxyManager()

        assert pm.template_path == Path("/etc/squid/squid.conf.template")
        assert pm.output_path == Path("/etc/squid/squid.conf")
        assert pm.cache_enabled is True
        assert pm.cache_size_mb == 10000
        assert pm.upstream_proxy is None
        assert pm.upstream_proxy_tls is False
        assert pm.upstream_dns == "127.0.0.11"

    def it_initializes_with_custom_paths():
        """Test ProxyManager initializes with custom paths."""
        pm = ProxyManager(
            config_template_path="/custom/template.conf",
            config_output_path="/custom/output.conf",
            cache_enabled=False,
            cache_size_mb=5000,
            upstream_proxy="proxy.example.com:8080",
        )

        assert pm.template_path == Path("/custom/template.conf")
        assert pm.output_path == Path("/custom/output.conf")
        assert pm.cache_enabled is False
        assert pm.cache_size_mb == 5000
        assert pm.upstream_proxy == "proxy.example.com:8080"

    def it_generates_domain_acls():
        """Test _generate_domain_acls method."""
        pm = ProxyManager()
        domains = ["example.com", "test.org", "*.subdomain.com"]

        result = pm._generate_domain_acls(domains)

        assert "example.com" in result
        assert "test.org" in result
        # ACL format check
        assert "acl" in result.lower() or "dstdomain" in result.lower()

    def it_generates_cache_config_when_enabled():
        """Test _generate_cache_config when cache is enabled."""
        pm = ProxyManager(cache_enabled=True, cache_size_mb=1000)

        result = pm._generate_cache_config()

        # Should contain cache directives
        assert len(result) > 0

    def it_generates_cache_config_when_disabled():
        """Test _generate_cache_config when cache is disabled."""
        pm = ProxyManager(cache_enabled=False)

        result = pm._generate_cache_config()

        # Should contain no-cache directives or be empty
        assert isinstance(result, str)

    def it_generates_upstream_proxy_config_when_set():
        """Test _generate_upstream_proxy_config when upstream is set."""
        pm = ProxyManager(upstream_proxy="proxy.example.com:8080")

        result = pm._generate_upstream_proxy_config()

        assert "cache_peer" in result
        assert "proxy.example.com" in result
        assert "8080" in result
        assert "tls" not in result

    def it_generates_upstream_proxy_config_with_tls():
        """Test _generate_upstream_proxy_config with TLS enabled."""
        pm = ProxyManager(
            upstream_proxy="proxy.example.com:8080",
            upstream_proxy_tls=True,
        )

        result = pm._generate_upstream_proxy_config()

        assert "cache_peer" in result
        assert "proxy.example.com" in result
        assert "tls" in result

    def it_generates_upstream_proxy_config_with_tls_and_auth():
        """Test _generate_upstream_proxy_config with TLS and authentication."""
        pm = ProxyManager(
            upstream_proxy="proxy.example.com:3129",
            upstream_proxy_tls=True,
            upstream_proxy_username="user",
            upstream_proxy_password="pass",
        )

        result = pm._generate_upstream_proxy_config()

        assert (
            "cache_peer proxy.example.com parent 3129 0 no-query default tls login=user:pass"
            in result
        )
        assert "never_direct allow all" in result

    def it_generates_upstream_proxy_config_without_tls():
        """Test _generate_upstream_proxy_config with TLS explicitly disabled."""
        pm = ProxyManager(
            upstream_proxy="proxy.example.com:8080",
            upstream_proxy_tls=False,
            upstream_proxy_username="user",
            upstream_proxy_password="pass",
        )

        result = pm._generate_upstream_proxy_config()

        assert "tls" not in result
        assert "login=user:pass" in result

    def it_generates_upstream_proxy_config_when_not_set():
        """Test _generate_upstream_proxy_config when upstream is not set."""
        pm = ProxyManager(upstream_proxy=None)

        result = pm._generate_upstream_proxy_config()

        # Should return some comment or empty string
        assert isinstance(result, str)

    @patch("pathlib.Path.exists", return_value=False)
    def it_handles_missing_template(mock_exists):
        """Test generate_config handles missing template."""
        pm = ProxyManager()

        result = pm.generate_config(allowed_domains=["example.com"])

        assert result is False

    @patch("subprocess.run")
    def it_starts_squid_process(mock_run):
        """Test start method launches Squid."""
        mock_run.return_value = Mock(returncode=0)
        ProxyManager()

        # Assuming start() method exists
        # result = pm.start()
        # assert result is True
        pass

    def it_supports_upstream_proxy_authentication():
        """Test upstream proxy authentication configuration."""
        pm = ProxyManager(
            upstream_proxy="proxy.example.com:8080",
            upstream_proxy_username="user",
            upstream_proxy_password="pass",
        )

        assert pm.upstream_proxy_username == "user"
        assert pm.upstream_proxy_password == "pass"

    @patch("subprocess.run")
    def it_reloads_config_successfully(mock_run):
        """Test reload_config reloads Squid configuration."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        pm = ProxyManager()

        result = pm.reload_config()

        assert result is True
        # Verify squid -k reconfigure was called
        assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def it_handles_reload_config_failure(mock_run):
        """Test reload_config handles failure."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["squid"], stderr="error")
        pm = ProxyManager()

        result = pm.reload_config()

        assert result is False

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def it_starts_squid_successfully(mock_run, mock_popen):
        """Test start launches Squid daemon."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_popen.return_value = Mock()
        pm = ProxyManager()

        result = pm.start()

        assert result is True
        # Verify squid -z was called for cache init
        assert mock_run.call_count >= 1
        # Verify squid -N was called to start daemon
        assert mock_popen.call_count >= 1

    @patch("subprocess.run")
    def it_handles_start_failure(mock_run):
        """Test start handles Squid launch failure."""
        # Simulate squid command not found
        mock_run.side_effect = FileNotFoundError("squid command not found")
        pm = ProxyManager()

        result = pm.start()

        assert result is False

    @patch("subprocess.run")
    def it_stops_squid_successfully(mock_run):
        """Test stop terminates Squid daemon."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        pm = ProxyManager()

        result = pm.stop()

        assert result is True
        # Verify squid -k shutdown was called
        assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def it_handles_stop_failure(mock_run):
        """Test stop handles Squid termination failure."""
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["squid"], stderr="error")
        pm = ProxyManager()

        result = pm.stop()

        assert result is False

    def it_generates_wildcard_domain_acls():
        """Test _generate_domain_acls handles wildcard domains."""
        pm = ProxyManager()
        domains = ["*.example.com", "test.org"]

        result = pm._generate_domain_acls(domains)

        # Wildcard domain should have * removed
        assert ".example.com" in result
        assert "test.org" in result

    def it_generates_cache_config_with_custom_size():
        """Test _generate_cache_config with custom cache size."""
        pm = ProxyManager(cache_enabled=True, cache_size_mb=5000)

        result = pm._generate_cache_config()

        assert "5000" in result
        assert "cache_dir" in result

    def it_generates_config_successfully(tmp_path):
        """Test generate_config creates squid configuration file.

        FIXED: Previous version used mock_open but didn't mock Path.exists(),
        causing the template existence check to fail. Now using real files
        with tmp_path for proper integration testing.
        """
        # Create template file
        template_path = tmp_path / "squid.conf.template"
        template_path.write_text(
            "{ALLOWED_DOMAINS_ACL}\n{CACHE_CONFIG}\n{UPSTREAM_PROXY_CONFIG}\n{DNS_NAMESERVERS}"
        )

        # Create output path
        output_path = tmp_path / "squid.conf"

        pm = ProxyManager(
            config_template_path=str(template_path),
            config_output_path=str(output_path),
        )
        domains = ["example.com", "test.org"]

        result = pm.generate_config(domains)

        assert result is True
        # Verify output file was created
        assert output_path.exists()
        # Verify content has placeholders replaced
        content = output_path.read_text()
        assert "example.com" in content
        assert "test.org" in content
        assert "{ALLOWED_DOMAINS_ACL}" not in content  # Placeholder should be replaced

    @patch("builtins.open", side_effect=FileNotFoundError("Template not found"))
    def it_handles_missing_template_file(mock_file):
        """Test generate_config handles missing template file."""
        pm = ProxyManager()
        domains = ["example.com"]

        result = pm.generate_config(domains)

        assert result is False


def describe_relayed_domains_are_denied_before_the_allowlist():
    """Squid resolves names through Docker's DNS and never sees the DNS filter's answers,
    so a domain the relay owns must be refused here or `https_proxy=<gateway>:3128` reaches
    the real upstream with none of the project's policy applied."""

    template = Path("config/squid/squid.conf.template")

    def _generate(tmp_path, allowed, relayed):
        out = tmp_path / "squid.conf"
        pm = ProxyManager(
            config_template_path=str(template),
            config_output_path=str(out),
            cache_enabled=False,
        )
        assert pm.generate_config(allowed, relayed) is True
        return out.read_text()

    def the_deny_rule_precedes_the_allow_rule(tmp_path):
        content = _generate(tmp_path, ["pypi.org"], ["github.com"])
        assert "acl relayed_domains dstdomain github.com" in content
        # Order is the whole point: Squid takes the first matching http_access line.
        assert content.index("http_access deny relayed_domains") < content.index(
            "http_access allow allowed_domains"
        )

    def a_wildcard_keeps_serving_the_subdomains(tmp_path):
        # `.github.com` covers github.com too, which is why the exact name needs its own deny.
        # api. and codeload. are not the relay's, and the wildcard must keep serving them —
        # they need no ACL line of their own, and Squid would reject one beside the wildcard.
        content = _generate(tmp_path, [".github.com", "codeload.github.com"], ["github.com"])
        assert "acl allowed_domains dstdomain .github.com" in content
        assert "acl relayed_domains dstdomain github.com" in content
        # Only github.com is refused; the wildcard covering its subdomains is untouched.
        assert "acl relayed_domains dstdomain codeload.github.com" not in content

    def only_the_relayed_name_is_refused_when_listed_alongside_siblings(tmp_path):
        # The shape the live config actually has: siblings listed one by one, no wildcard.
        content = _generate(
            tmp_path,
            ["codeload.github.com", "api.github.com", "pypi.org"],
            ["github.com"],
        )
        for kept in ("codeload.github.com", "api.github.com", "pypi.org"):
            assert f"acl allowed_domains dstdomain {kept}" in content
        assert "acl relayed_domains dstdomain github.com" in content

    def nothing_relayed_leaves_the_file_as_it_was(tmp_path):
        # An existing deployment without domain_handlers must get the same file as before.
        with_none = _generate(tmp_path / "a", ["pypi.org"], [])
        assert "relayed_domains" not in with_none
        assert "http_access allow allowed_domains" in with_none

    def the_default_argument_relays_nothing(tmp_path):
        out = tmp_path / "squid.conf"
        pm = ProxyManager(
            config_template_path=str(template),
            config_output_path=str(out),
            cache_enabled=False,
        )
        assert pm.generate_config(["pypi.org"]) is True
        assert "relayed_domains" not in out.read_text()

    def every_relayed_domain_gets_an_entry(tmp_path):
        content = _generate(tmp_path, ["pypi.org"], ["github.com", "ghcr.io", "evil.example.com"])
        for d in ("github.com", "ghcr.io", "evil.example.com"):
            assert f"acl relayed_domains dstdomain {d}" in content


def describe_redundant_allowlist_entries_are_dropped():
    """Squid treats a name listed beside a wildcard that contains it as a FATAL config error,
    not a warning, so `deb.debian.org` next to `.debian.org` stops the proxy from starting.
    The allowlist is hand-edited and that pairing is a natural thing to write."""

    def _acls(domains):
        pm = ProxyManager(cache_enabled=False)
        return [line.split()[-1] for line in pm._generate_domain_acls(domains).splitlines()]

    def a_subdomain_of_a_listed_wildcard_is_dropped():
        assert _acls(["deb.debian.org", ".debian.org"]) == [".debian.org"]

    def the_order_they_are_written_in_does_not_matter():
        assert _acls([".debian.org", "deb.debian.org"]) == [".debian.org"]

    def a_wildcard_also_covers_the_bare_name():
        # Squid reads `.x.com` as x.com and everything under it, so the pair is fatal too.
        assert _acls(["x.com", "*.x.com"]) == [".x.com"]
        assert _acls(["*.x.com", "x.com"]) == [".x.com"]

    def several_subdomains_collapse_into_the_one_wildcard():
        assert _acls(
            ["production.cloudflare.docker.com", "download.docker.com", ".docker.com"]
        ) == [".docker.com"]

    def a_deeper_subdomain_is_covered_as_well():
        assert _acls(["a.b.example.com", ".example.com"]) == [".example.com"]

    def siblings_and_unrelated_names_are_kept():
        assert _acls(["github.com", "api.github.com"]) == ["github.com", "api.github.com"]
        assert _acls(["pypi.org", ".pythonhosted.org"]) == ["pypi.org", ".pythonhosted.org"]

    def an_exact_duplicate_appears_once():
        assert _acls(["dup.com", "dup.com"]) == ["dup.com"]


def describe_an_outdated_template_still_gets_the_deny_rule():
    """The template is bind-mounted by each deployment, so upgrading the gateway image does
    not upgrade it. Without a backfill, str.format would discard the deny rule with no error
    and the generated config would serve exactly what the relay owns."""

    old_template = """# Squid Proxy Configuration
acl CONNECT method CONNECT

# Allowed domains (dynamically generated)
{ALLOWED_DOMAINS_ACL}

http_access deny manager

# Allow whitelisted domains
http_access allow allowed_domains

# Deny all other access
http_access deny all

{CACHE_CONFIG}
{UPSTREAM_PROXY_CONFIG}
dns_nameservers {DNS_NAMESERVERS}
"""

    def _generate(tmp_path, template, relayed):
        tpl = tmp_path / "squid.conf.template"
        tpl.write_text(template)
        out = tmp_path / "squid.conf"
        pm = ProxyManager(
            config_template_path=str(tpl),
            config_output_path=str(out),
            cache_enabled=False,
        )
        ok = pm.generate_config(["pypi.org", ".github.com"], relayed)
        return ok, (out.read_text() if out.exists() else "")

    def the_rule_is_inserted_before_the_allow(tmp_path):
        ok, content = _generate(tmp_path, old_template, ["github.com"])
        assert ok is True
        assert "acl relayed_domains dstdomain github.com" in content
        assert content.index("http_access deny relayed_domains") < content.index(
            "http_access allow allowed_domains"
        )
        # and the ACL is defined before the rule that uses it
        assert content.index("acl relayed_domains") < content.index(
            "http_access deny relayed_domains"
        )

    def an_up_to_date_template_is_left_alone(tmp_path):
        current = Path("config/squid/squid.conf.template").read_text()
        ok, content = _generate(tmp_path, current, ["github.com"])
        assert ok is True
        assert content.count("http_access deny relayed_domains") == 1

    def nothing_is_inserted_when_nothing_is_relayed(tmp_path):
        ok, content = _generate(tmp_path, old_template, [])
        assert ok is True
        assert "relayed_domains" not in content

    def an_unrecognisable_template_fails_instead_of_writing_a_leaky_config(tmp_path):
        # Better to leave Squid on its previous config than to serve the relayed domains.
        broken = "{ALLOWED_DOMAINS_ACL}\n{CACHE_CONFIG}\n{UPSTREAM_PROXY_CONFIG}\n{DNS_NAMESERVERS}"
        ok, _ = _generate(tmp_path, broken, ["github.com"])
        assert ok is False
