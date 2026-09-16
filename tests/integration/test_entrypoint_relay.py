"""The startup decision in scripts/start-relay.sh (the needs-relay exit code contract)."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "start-relay.sh"


def _run(
    tmp_path: Path, needs_relay_rc: int | None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    marker = tmp_path / "serve.marker"
    fake = tmp_path / "bin" / "sekimore-relay"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SEKIMORE_RELAY_BIN": str(fake),
        "SEKIMORE_CONFIG_PATH": str(tmp_path / "config.yml"),
        "FAKE_MARKER": str(marker),
    }
    if needs_relay_rc is not None:
        fake.parent.mkdir(parents=True, exist_ok=True)
        fake.write_text(
            "#!/bin/bash\n"
            'case "$*" in\n'
            f"  *needs-relay*) exit {needs_relay_rc} ;;\n"
            '  *serve*) echo serve-called > "$FAKE_MARKER"; exit 0 ;;\n'
            "  *) exit 99 ;;\n"
            "esac\n"
        )
        fake.chmod(0o755)
    proc = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=10, check=False
    )
    return proc, marker


def describe_start_relay_script():
    def it_starts_serve_when_needs_relay_is_true(tmp_path):
        proc, marker = _run(tmp_path, 0)
        assert proc.returncode == 0, proc.stderr
        assert marker.exists()
        assert "starting" in proc.stdout

    def it_does_not_start_when_not_needed(tmp_path):
        proc, marker = _run(tmp_path, 1)
        assert proc.returncode == 0
        assert not marker.exists()
        assert "not starting" in proc.stdout

    def it_keeps_gateway_alive_on_config_error(tmp_path):
        proc, marker = _run(tmp_path, 2)
        assert proc.returncode == 0, "relay config errors must not kill the gateway"
        assert not marker.exists()
        assert "ERROR" in proc.stderr

    def it_skips_when_binary_is_missing(tmp_path):
        proc, marker = _run(tmp_path, None)
        assert proc.returncode == 0
        assert not marker.exists()
        assert "skipping" in proc.stdout
