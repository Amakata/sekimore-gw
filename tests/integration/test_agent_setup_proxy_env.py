"""The proxy environment agent-setup.sh writes for the dev container (#212).

`agent-setup.sh` cannot be sourced whole -- it discovers the gateway and rewrites
/etc/resolv.conf at the top level -- so these tests cut out the proxy functions and run them
against a temp root (`SEKIMORE_PROXY_ENV_ROOT`) with the JSON the gateway would have answered.
"""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent.parent.parent / "agent-setup.sh"

CONFIGURED = (
    '{"configured":true,"port":3128,'
    '"no_proxy":["api.github.com","registry.npmjs.org",".test","localhost","127.0.0.1",'
    '"sekimore-gw"],"direct_egress":"deny"}'
)
UNCONFIGURED = (
    '{"configured":false,"port":3128,'
    '"no_proxy":["localhost","127.0.0.1","sekimore-gw"],"direct_egress":"allow"}'
)


def _functions(tmp_path: Path) -> Path:
    """The proxy functions, cut from the script at the markers that bracket them."""
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("SEKIMORE_PROXY_MARK_BEGIN='")
    end = text.index("sekimore_relay_setup() {")
    out = tmp_path / "fn.sh"
    out.write_text(text[start:end], encoding="utf-8")
    return out


def _run(tmp_path: Path, *calls: str) -> subprocess.CompletedProcess:
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    script = "\n".join(
        [
            "set -e",
            f". {_functions(tmp_path)}",
            f'export SEKIMORE_PROXY_ENV_ROOT="{root}"',
            *calls,
        ]
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True, timeout=30
    )


def describe_proxy_env_block():
    """What lands in /etc/profile.d and /etc/environment."""

    def it_writes_both_files_when_a_proxy_is_configured(tmp_path):
        _run(tmp_path, f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2")
        profile = (tmp_path / "root/etc/profile.d/sekimore-proxy.sh").read_text()
        env = (tmp_path / "root/etc/environment").read_text()

        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            assert f'export {var}="http://10.100.0.2:3128"' in profile
            assert f'{var}="http://10.100.0.2:3128"' in env
        # Squid refuses CONNECT to the handler targets, so NO_PROXY has to carry them or the
        # GitHub API and npm break with a 403 from the proxy.
        for var in ("NO_PROXY", "no_proxy"):
            assert (
                f'{var}="api.github.com,registry.npmjs.org,.test,localhost,127.0.0.1,sekimore-gw"'
                in profile
            )
            assert (
                f'{var}="api.github.com,registry.npmjs.org,.test,localhost,127.0.0.1,sekimore-gw"'
                in env
            )

    def it_brackets_the_environment_block_with_markers(tmp_path):
        _run(tmp_path, f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2")
        env = (tmp_path / "root/etc/environment").read_text()
        assert env.count("# sekimore-proxy begin") == 1
        assert env.count("# sekimore-proxy end") == 1

    def it_replaces_instead_of_appending_on_every_start(tmp_path):
        # postStartCommand runs on every start; appending would grow the file without bound
        # and leave a stale gateway address above the current one.
        _run(
            tmp_path,
            f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2",
            f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.9",
        )
        env = (tmp_path / "root/etc/environment").read_text()
        assert env.count('HTTP_PROXY="') == 1
        assert "10.100.0.9" in env
        assert "10.100.0.2" not in env

    def it_keeps_what_was_already_in_the_environment_file(tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "etc").mkdir()
        (root / "etc/environment").write_text('PATH="/usr/bin"\n')
        _run(tmp_path, f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2")
        env = (root / "etc/environment").read_text()
        assert 'PATH="/usr/bin"' in env
        assert "HTTP_PROXY" in env

    def it_removes_both_when_no_proxy_is_configured(tmp_path):
        # A container that had a proxy and no longer does must stop sending traffic at it.
        _run(
            tmp_path,
            f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2",
            f"sekimore_proxy_env_apply '{UNCONFIGURED}' 10.100.0.2",
        )
        assert not (tmp_path / "root/etc/profile.d/sekimore-proxy.sh").exists()
        assert "HTTP_PROXY" not in (tmp_path / "root/etc/environment").read_text()

    def it_says_what_it_set(tmp_path):
        out = _run(tmp_path, f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2").stdout
        assert "HTTP_PROXY=http://10.100.0.2:3128" in out
        assert "direct_egress: deny" in out

    def it_says_when_there_is_nothing_to_set(tmp_path):
        out = _run(tmp_path, f"sekimore_proxy_env_apply '{UNCONFIGURED}' 10.100.0.2").stdout
        assert "no upstream proxy configured" in out

    def the_profile_file_is_valid_shell(tmp_path):
        _run(tmp_path, f"sekimore_proxy_env_apply '{CONFIGURED}' 10.100.0.2")
        profile = tmp_path / "root/etc/profile.d/sekimore-proxy.sh"
        subprocess.run(["bash", "-n", str(profile)], check=True, timeout=30)


def describe_proxy_env_parsing():
    """The JSON is read without jq: the agent image may not have it."""

    def it_reads_a_string_field(tmp_path):
        out = _run(tmp_path, f"sekimore_json_field '{CONFIGURED}' direct_egress").stdout
        assert out.strip() == "deny"

    def it_reads_a_boolean_and_a_number(tmp_path):
        out = _run(
            tmp_path,
            f"sekimore_json_field '{CONFIGURED}' configured",
            f"sekimore_json_field '{CONFIGURED}' port",
        ).stdout
        assert out.split() == ["true", "3128"]

    def it_joins_the_no_proxy_array_with_commas(tmp_path):
        out = _run(tmp_path, f"sekimore_json_no_proxy '{CONFIGURED}'").stdout
        assert out.strip() == (
            "api.github.com,registry.npmjs.org,.test,localhost,127.0.0.1,sekimore-gw"
        )

    def it_handles_an_empty_no_proxy_array(tmp_path):
        out = _run(tmp_path, "sekimore_json_no_proxy '{\"no_proxy\":[]}'").stdout
        assert out.strip() == ""
