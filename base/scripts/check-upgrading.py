#!/usr/bin/env python3
"""UPGRADING has to have been looked at for the gateway this image takes.

Most releases ask nothing of a user, so "there is a section per version" would be the wrong
check — it would force an empty entry for every quiet release and teach people to write filler.
What has to happen every time is the *decision*: does this release make someone edit a file they
own? The marker records that the decision was made, and this fails when it has not been.

It went wrong without one. The published sample went four releases without `gw:unlock`, and from
gateway 0.2.19 that leaves a user unable to reach the GitHub API and unable to add a task that
works — because `sgw.sh` is missing `gw-tty` too (sgw-devcontainer-base#27).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# UPGRADING sits at the repository root since the move into sekimore-gw (#235)
FILES = [ROOT.parent / "UPGRADING.md", ROOT.parent / "UPGRADING.ja.md"]
DOCKERFILE = ROOT / "Dockerfile"

_MARKER = re.compile(r"^<!-- reviewed-up-to: (\d+(?:\.\d+)*) -->")
_PINNED = re.compile(r"^ARG SEKIMORE_GW_IMAGE=\S+:(\d+(?:\.\d+)*)\s*$", re.M)


def version(s: str) -> tuple[int, ...]:
    return tuple(int(n) for n in s.split("."))


def main() -> int:
    m = _PINNED.search(DOCKERFILE.read_text(encoding="utf-8"))
    if not m:
        print("FAIL: no ARG SEKIMORE_GW_IMAGE=<image>:<version> in Dockerfile", file=sys.stderr)
        return 1
    pinned = m.group(1)

    failed = False
    for path in FILES:
        head = path.read_text(encoding="utf-8").splitlines()[:1]
        got = _MARKER.match(head[0]) if head else None
        if not got:
            print(
                f"FAIL: {path.name} must start with `<!-- reviewed-up-to: X.Y.Z -->`",
                file=sys.stderr,
            )
            failed = True
            continue
        if version(got.group(1)) < version(pinned):
            print(
                f"FAIL: {path.name} was reviewed up to {got.group(1)}, but this image takes "
                f"gateway {pinned}.\n"
                f"      Read what changed between them. If a release makes someone edit a file "
                f"they own\n"
                f"      (config.yml / mise.toml / sgw.sh / docker-compose.yml), add a section. "
                f"If none does,\n"
                f"      just move the marker to {pinned} — that is the point of it.",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"ok    {path.name} reviewed up to {got.group(1)} (image takes {pinned})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
