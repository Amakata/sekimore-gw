"""`python -m src.maint …` runs `sekimore-relay maint …` (0.3.0-alpha.5).

The reload window and the log database commands moved to the relay's binary
(relay/src/gateway/maint.rs), with the same output, exit codes and command line. This module stays
so that an `sgw` from before 0.3.0-alpha.5, which runs `python -m src.maint <command>` in the
gateway, keeps working against a newer gateway; it goes with the rest of the Python in
0.3.0-alpha.7, when UPGRADING.md asks for `sgw update` first.

    python -m src.maint db-stats [--json]
    python -m src.maint db-prune --before-days 90 --yes [--vacuum]
    python -m src.maint db-reset --yes
    python -m src.maint db-vacuum
    python -m src.maint reload-status | reload-follow [30m] | reload-freeze
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    relay = os.environ.get("SEKIMORE_RELAY_BIN", "/usr/local/bin/sekimore-relay")
    os.execv(relay, [relay, "maint", *sys.argv[1:]])


if __name__ == "__main__":
    main()
