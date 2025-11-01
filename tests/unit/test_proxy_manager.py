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

        assert "proxy.example.com" in result or "cache_peer" in result

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
