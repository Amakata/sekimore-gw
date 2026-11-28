"""`python -m src.maint` hands its command line to `sekimore-relay maint` (0.3.0-alpha.5).

What the commands do is tested in Rust (relay/src/gateway/maint.rs, and the `maint` comparison of
relay/tests/equivalence/). This holds the hand-over an `sgw` from before 0.3.0-alpha.5 relies on.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def describe_the_shim():
    def it_runs_the_relay_with_the_same_arguments_and_exit_code(tmp_path):
        relay = tmp_path / "sekimore-relay"
        relay.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@"\nexit 3\n')
        relay.chmod(0o755)
        env = {**os.environ, "SEKIMORE_RELAY_BIN": str(relay)}
        r = subprocess.run(
            [sys.executable, "-m", "src.maint", "--db", "/x y.db", "db-prune", "--yes"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 3
        assert r.stdout.splitlines() == [
            str(relay),
            "maint",
            "--db",
            "/x y.db",
            "db-prune",
            "--yes",
        ]
