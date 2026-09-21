"""Actions and base images are pinned by digest, and a digest is easy to drop back to a tag.

`cargo audit` reads `relay/Cargo.lock` and nothing else, so for a long time nothing in CI looked at
the workflows or the Dockerfiles at all (#75). Pinning them by digest closes that, but only while
the pins stay: one `uses: foo/bar@v1` added later and that step is floating again, silently, because
a floating tag is not an error anywhere. These tests are the check.

The trailing `# v1.2.3` comment is not decoration. It is the only place the human-readable version
survives once the ref is a digest, and it is what Dependabot reads to know what to bump the pin to.
A pin without one is a number nobody can update.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
# Every file that names an image pulled from a registry at build or test time.
IMAGE_FILES = [
    ROOT / "Dockerfile",
    ROOT / "Dockerfile.agent",
    ROOT / "tests" / "docker-compose.test.yml",
    # No `image:` of its own today — both services build. Listed so that one added later is
    # covered from the start rather than whenever someone remembers this file exists.
    ROOT / "docker-compose.yml",
]

# `uses: owner/repo@<40 hex> # v1.2.3`. The version after the `#` is free-form because the actions
# do not agree on a shape: most tag `v6.1.0`, dtolnay/rust-toolchain names branches `1.89.0`.
_PINNED_USES = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40} # \S+")
_USES = re.compile(r"^\s*(?:- )?uses:\s+(.+?)\s*$")

# `python:3.13-slim@sha256:…`, with the tag kept so the digest is readable
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}(?:\s|$)")
_FROM = re.compile(r"^FROM\s+(?:--\S+\s+)*(\S+)")
_SYNTAX = re.compile(r"^#\s*syntax=(\S+)")
_COMPOSE_IMAGE = re.compile(r"^\s*image:\s*(\S+)")

# Only the Dockerfiles install Debian packages; the compose files just name images.
DOCKERFILES = [p for p in IMAGE_FILES if p.name.startswith("Dockerfile")]
# The sources have to point at the snapshot archive — literally, or through the ARG that carries
# the timestamp so bumping it is one line.
_SNAPSHOT_URI = re.compile(r"https://snapshot\.debian\.org/archive/debian/(\S+)")
# `ARG DEBIAN_SNAPSHOT=20260920T000000Z`, or the timestamp written straight into the URI.
_SNAPSHOT_STAMP = re.compile(r"(?:ARG\s+DEBIAN_SNAPSHOT=|/debian/)(\d{8}T\d{6}Z)")
# How long the image may go without a security update before CI says so. Short enough that a
# forgotten pin is caught in the same quarter, long enough not to fire on every release.
MAX_SNAPSHOT_AGE_DAYS = 90
# `\` line continuations mean one `apt-get install` spans many lines; a package is a bare token on
# one of them. `-y`, `--no-install-recommends` and the `&&` that ends the run are not packages.
_APT_INSTALL = re.compile(r"apt-get\s+install\b")
_APT_PACKAGE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9.+-]*(?:=\S+)?)\s*\\?\s*$")


def _apt_packages(path: Path) -> list[tuple[int, str]]:
    """Every package named by an `apt-get install`, with its line number."""
    out: list[tuple[int, str]] = []
    inside = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _APT_INSTALL.search(line):
            inside = True
            continue
        if not inside:
            continue
        # The run ends at the first line that is not a bare package: `&& rm -rf …`, or no `\`
        m = _APT_PACKAGE.match(line)
        if not m:
            inside = line.rstrip().endswith("\\") and line.strip().startswith("-")
            continue
        out.append((n, m.group(1)))
    return out


def _uses_lines(path: Path) -> list[tuple[int, str]]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = _USES.match(line)
        if m:
            out.append((n, m.group(1)))
    return out


def _image_refs(path: Path) -> list[tuple[int, str]]:
    """Every registry reference in the file: FROM, the syntax directive, and compose images."""
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for pattern in (_FROM, _SYNTAX, _COMPOSE_IMAGE):
            m = pattern.match(line)
            if m:
                out.append((n, m.group(1)))
                break
    return out


def describe_supply_chain_pins():
    def it_has_workflows_to_check():
        # A rename or a move would otherwise turn every test below green by having nothing to look at
        assert WORKFLOWS, "no workflows found; this test is looking in the wrong place"
        assert [p for p in IMAGE_FILES if p.exists()] == IMAGE_FILES

    @pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
    def it_pins_every_action_to_a_commit(path):
        floating = [
            f"{path.name}:{n} {ref}"
            for n, ref in _uses_lines(path)
            # `./…` is an action from this repository; there is no third party to pin
            if not ref.startswith("./") and not _PINNED_USES.match(ref)
        ]
        assert floating == [], (
            "a tag moves under the workflow that uses it, so an action is pinned to the commit and "
            "the version kept as a trailing comment — `uses: owner/repo@<sha40> # v1.2.3`. "
            f"Resolve with `git ls-remote https://github.com/owner/repo refs/tags/<tag>^{{}}` "
            f"(the peeled sha, for an annotated tag). Not pinned: {floating}"
        )

    @pytest.mark.parametrize("path", IMAGE_FILES, ids=lambda p: p.name)
    def it_pins_every_image_to_a_digest(path):
        floating = [
            f"{path.name}:{n} {ref}"
            for n, ref in _image_refs(path)
            # A later stage building on an earlier one by name, e.g. `FROM relay-builder`
            if "/" in ref or ":" in ref
            if not _DIGEST.search(ref)
        ]
        assert floating == [], (
            "a base image tag is re-pushed in place, so it is pinned by digest with the tag kept "
            "for readability — `python:3.13-slim@sha256:…`. Not pinned: " + str(floating)
        )

    @pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
    def it_keeps_a_version_comment_a_human_can_read(path):
        # The digest alone says nothing about how old it is. Dependabot reads this comment to know
        # what the pin was, and a person reads it to know whether the pin is three years stale.
        bare = [
            f"{path.name}:{n} {ref}"
            for n, ref in _uses_lines(path)
            if re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref)
        ]
        assert bare == [], f"pinned, but with no `# <version>` comment saying what it is: {bare}"

    @pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
    def it_pins_the_debian_archive_to_a_snapshot(path):
        # Naming package versions is not enough on its own: their ~100 transitive dependencies
        # still resolve against whatever Debian is serving today, and a named version is gone from
        # the archive within weeks of being superseded. The snapshot is what makes both hold.
        body = path.read_text(encoding="utf-8")
        if "apt-get install" not in body:
            pytest.skip(f"{path.name} installs no Debian packages")
        assert _SNAPSHOT_URI.search(body), (
            f"{path.name}: `apt-get` reads whatever Debian serves today, so the layer gets a new "
            "digest on essentially every build. Point the sources at "
            "`https://snapshot.debian.org/archive/debian/<YYYYMMDDTHHMMSSZ>`."
        )

    @pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
    def it_pins_every_apt_package_to_a_version(path):
        # The snapshot already fixes what gets installed. These make a change *loud*: bumping the
        # snapshot without noticing that squid moved is the failure this catches.
        floating = [f"{path.name}:{n} {pkg}" for n, pkg in _apt_packages(path) if "=" not in pkg]
        assert floating == [], (
            f"{path.name}: name the version — `squid=6.13-2+deb13u3`. Read them out of the "
            "snapshot itself, not out of a running container. Not pinned: " + str(floating)
        )

    @pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
    def it_does_not_let_the_snapshot_go_stale(path):
        # A pinned archive means no security update reaches the image until someone moves the pin.
        # That turns the bump from housekeeping into an obligation, so it is checked rather than
        # remembered. Widen MAX_SNAPSHOT_AGE_DAYS if the cadence is deliberately slower.
        body = path.read_text(encoding="utf-8")
        m = _SNAPSHOT_URI.search(body)
        if not m:
            pytest.skip(f"{path.name} pins no Debian snapshot")
        stamp = _SNAPSHOT_STAMP.search(body)
        assert stamp, (
            f"{path.name}: the snapshot URI is there but no timestamp is — write it as "
            "`ARG DEBIAN_SNAPSHOT=YYYYMMDDTHHMMSSZ`, so bumping it is one line"
        )
        stamped = datetime.strptime(stamp.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        age = (datetime.now(UTC) - stamped).days
        assert age <= MAX_SNAPSHOT_AGE_DAYS, (
            f"{path.name}: the Debian snapshot is {age} days old, and nothing has reached this "
            f"image since. Bump DEBIAN_SNAPSHOT and re-read the package versions out of the new "
            f"one (limit {MAX_SNAPSHOT_AGE_DAYS} days)."
        )
