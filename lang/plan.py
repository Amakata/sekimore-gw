"""Which language images to build (#376).

lang/versions.yml lists each language's versions with a revision, the way a Debian package has
one: `8.3.33: 1` is published as `sgw-lang-php:8.3.33-1-bookworm`, and `8.3.33-bookworm` moves to
the newest revision. A published revision never changes; rebuilding means raising the revision.
So nothing already published is built again:

- publish: every version whose `<version>-<revision>-bookworm` is not on the registry yet. A
  revision 1 whose image was published before revisions existed (`8.3.26-bookworm` alone) is
  adopted — tagged, not rebuilt.
- pr: the versions the pull request adds or re-revisions, and — when a recipe changed — the newest
  version of each language that recipe builds, to check it still builds.

`track` (#378) names minor lines (`php: ["8.3"]`) whose newest patch, asked of the base image's
mise, is published as revision 1 without being written into the file: the registry's tags are the
record. A daily run picks each new patch up; on most days it finds nothing to build.

Prints a JSON object: `build` (each `{lang, version, revision}`) and `adopt` (the same shape).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

SUFFIX = "bookworm"
REPO = "ghcr.io/amakata/sgw-lang-{lang}"
# a change here is a change to every language's build
COMMON = ("lang/Dockerfile", "lang/runtime-packages.sh")
_VERSION = re.compile(r"^\d+(\.\d+){1,3}$")


def entries(text: str, *, before_revisions: bool = False) -> list[dict]:
    """`pin: {lang: {version: revision}}` as a list, checked. `before_revisions` also reads the
    list form the file had before (`php: ["8.3.26"]`), each as revision 1: a pull request's base
    branch may still have it."""
    data = yaml.safe_load(text) or {}
    out = []
    for lang, versions in (data.get("pin") or {}).items():
        if before_revisions and isinstance(versions, list):
            versions = {str(v): 1 for v in versions}
        if not isinstance(versions, dict):
            raise ValueError(f'{lang}: write each version with its revision, `"8.3.33": 1`')
        for version, revision in versions.items():
            version = str(version)
            if not _VERSION.match(version):
                raise ValueError(f"{lang} {version}: a version is x.y.z")
            if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
                raise ValueError(f"{lang} {version}: the revision is a whole number from 1")
            out.append({"lang": lang, "version": version, "revision": revision})
    return out


_LINE = re.compile(r"^\d+\.\d+$")


def tracks(text: str) -> list[tuple[str, str]]:
    """`track: {lang: [line, …]}` (#378): the minor lines whose newest patch is built."""
    data = yaml.safe_load(text) or {}
    out = []
    for lang, lines in (data.get("track") or {}).items():
        if not isinstance(lines, list):
            raise ValueError(f'{lang}: track lists minor lines, `["8.3"]`')
        for line in lines:
            line = str(line)
            if not _LINE.match(line):
                raise ValueError(f"{lang} {line}: a tracked line is x.y")
            out.append((lang, line))
    return out


def resolve(pinned: list[dict], lines: list[tuple[str, str]], latest) -> list[dict]:
    """Each tracked line's newest patch, as revision 1 — unless a pin already names that version
    (a pin can raise its revision; the track never does)."""
    have = {(e["lang"], e["version"]) for e in pinned}
    out = []
    for lang, line in lines:
        version = latest(lang, line)
        if not version.startswith(line + ".") or not _VERSION.match(version):
            raise ValueError(f"{lang} {line}: the newest patch came back as {version!r}")
        if (lang, version) not in have and {
            "lang": lang,
            "version": version,
            "revision": 1,
        } not in out:
            out.append({"lang": lang, "version": version, "revision": 1})
    return out


def base_image(dockerfile: str = "lang/Dockerfile") -> str:
    """The base the images are built on, from lang/Dockerfile's `ARG BASE=`."""
    for line in Path(dockerfile).read_text(encoding="utf-8").splitlines():
        if line.startswith("ARG BASE="):
            return line.split("=", 1)[1].strip()
    raise ValueError(f"{dockerfile} has no ARG BASE=")


def latest_from_mise(lang: str, line: str) -> str:
    """Ask the base image's mise, the one that will build it, for the line's newest patch."""
    out = subprocess.run(
        ["docker", "run", "--rm", base_image(), "mise", "latest", f"{lang}@{line}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return out.strip().splitlines()[-1].strip()


def tag(e: dict) -> str:
    return f"{e['version']}-{e['revision']}-{SUFFIX}"


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def plan_pr(head: list[dict], base: list[dict], changed: list[str]) -> list[dict]:
    """What a pull request has to check."""
    before = {(e["lang"], e["version"], e["revision"]) for e in base}
    out = [e for e in head if (e["lang"], e["version"], e["revision"]) not in before]
    langs = {e["lang"] for e in head}
    if any(f in COMMON for f in changed):
        touched = langs
    else:
        touched = {f.split("/")[1] for f in changed if f.startswith("lang/") and f.count("/") >= 2}
    for lang in sorted(touched & langs):
        newest = max((e for e in head if e["lang"] == lang), key=lambda e: _key(e["version"]))
        if newest not in out:
            out.append(newest)
    return out


def plan_publish(head: list[dict], exists) -> dict[str, list[dict]]:
    """What a publish has to build, and what it only has to tag."""
    build, adopt = [], []
    for e in head:
        repo = REPO.format(lang=e["lang"])
        if exists(f"{repo}:{tag(e)}"):
            continue
        if e["revision"] == 1 and exists(f"{repo}:{e['version']}-{SUFFIX}"):
            adopt.append(e)
        else:
            build.append(e)
    return {"build": build, "adopt": adopt}


def on_registry(ref: str) -> bool:
    return (
        subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("mode", choices=["publish", "pr"])
    p.add_argument("--versions", default="lang/versions.yml")
    p.add_argument("--base", help="pr: the base branch's versions.yml")
    p.add_argument("--changed", help="pr: a file listing the changed paths, one per line")
    p.add_argument("--lang", default="", help="publish: only this language")
    p.add_argument("--version", default="", help="publish: only this version")
    a = p.parse_args(argv)
    text = Path(a.versions).read_text(encoding="utf-8")
    head = entries(text)
    lines = tracks(text)
    if a.mode == "pr":
        base_text = Path(a.base).read_text(encoding="utf-8") if a.base else ""
        base = entries(base_text, before_revisions=True)
        changed = Path(a.changed).read_text(encoding="utf-8").split() if a.changed else []
        build = plan_pr(head, base, changed)
        # a line the pull request starts tracking: check its newest patch builds
        new_lines = [t for t in lines if t not in tracks(base_text)]
        build += [e for e in resolve(head, new_lines, latest_from_mise) if e not in build]
        result = {"build": build, "adopt": []}
    else:
        head = head + resolve(head, lines, latest_from_mise)
        chosen = [
            e
            for e in head
            if (not a.lang or e["lang"] == a.lang) and (not a.version or e["version"] == a.version)
        ]
        if (a.lang or a.version) and not chosen:
            print(f"{a.lang} {a.version} is not in {a.versions}", file=sys.stderr)
            return 1
        result = plan_publish(chosen, on_registry)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
