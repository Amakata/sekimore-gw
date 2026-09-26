"""One version number for the gateway, the relay and the base image (#235).

The base image lived in a repository of its own until 0.2.45, with a number of its own and a
`take` step that copied the gateway's number into its Dockerfile, its sample, its READMEs and its
UPGRADING marker; four shell tests guarded those copies. Since the move into this repository the
number is `pyproject.toml`'s, and this test is what remains of those four: every place under base/
that writes a version writes that one.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "base"
SAMPLE = BASE / "examples" / "sgw-sample" / ".devcontainer"

_GW_IMAGE = re.compile(r"ghcr\.io/amakata/sekimore-gw:(\d+(?:\.\d+)*)")
_BASE_IMAGE = re.compile(r"ghcr\.io/amakata/sgw-devcontainer-base:(\d+(?:\.\d+)*)")


def _version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def describe_the_base_image_carries_the_gateways_version():
    def it_takes_the_gateway_of_this_very_version():
        m = re.search(
            r"^ARG SEKIMORE_GW_IMAGE=ghcr\.io/amakata/sekimore-gw:(\S+)$",
            _text(BASE / "Dockerfile"),
            re.M,
        )
        assert m, (
            "base/Dockerfile has no ARG SEKIMORE_GW_IMAGE=ghcr.io/amakata/sekimore-gw:<version>"
        )
        assert m.group(1) == _version(), (
            f"base/Dockerfile takes gateway {m.group(1)} but pyproject.toml says {_version()}; "
            "the image and the gateway are released from one tag, so the ARG names that tag"
        )

    def it_pins_the_sample_to_this_version_of_both_images():
        compose = _GW_IMAGE.findall(_text(SAMPLE / "docker-compose.yml"))
        dockerfile = _BASE_IMAGE.findall(_text(SAMPLE / "Dockerfile"))
        assert compose == [_version()], (
            f"the sample's compose pins gateway {compose}, not {_version()}"
        )
        assert dockerfile == [_version()], (
            f"the sample's Dockerfile pins base {dockerfile}, not {_version()}"
        )

    def it_quotes_this_version_in_the_readmes():
        for name in ("README.md", "README.ja.md"):
            text = _text(BASE / name)
            quoted = set(_GW_IMAGE.findall(text)) | set(_BASE_IMAGE.findall(text))
            assert quoted, (
                f"base/{name} no longer quotes an image; drop it from this test if that is deliberate"
            )
            assert quoted == {_version()}, (
                f"base/{name} quotes {sorted(quoted)}, the version is {_version()}"
            )

    def it_has_had_upgrading_reviewed_for_this_version():
        # Most releases ask nothing of a user; what has to happen every time is the decision. The
        # marker records that it was made (base/scripts/check-upgrading.py fails when it was not).
        for name in ("UPGRADING.md", "UPGRADING.ja.md"):
            first = _text(ROOT / name).splitlines()[0]
            m = re.match(r"^<!-- reviewed-up-to: (\d+(?:\.\d+)*) -->", first)
            assert m, f"{name} has no reviewed-up-to marker on its first line"
            assert m.group(1) == _version(), (
                f"{name} is reviewed up to {m.group(1)}; decide whether {_version()} asks anything of the reader, then move the marker"
            )

    def it_writes_the_sample_manifest_for_this_version():
        manifest = _text(SAMPLE / "sgw" / "MANIFEST")
        pins = dict(re.findall(r"^(base|gateway) (\S+)$", manifest, re.M))
        assert pins == {"base": _version(), "gateway": _version()}, (
            f"the sample's MANIFEST pins {pins}; run base/scripts/sync-sample-sgw.sh"
        )

    def it_writes_this_version_up_in_the_changelog():
        # One changelog for the gateway, the relay, the base and sgw (#253). base/CHANGELOG.md
        # is the base's own history up to 0.2.45 and gets nothing new.
        for name in ("CHANGELOG.md", "CHANGELOG.ja.md"):
            heads = re.findall(r"^## (\d+(?:\.\d+)*)", _text(ROOT / name), re.M)
            assert heads and heads[0] == _version(), (
                f"{name} leads with {heads[:1]}, not {_version()}"
            )
