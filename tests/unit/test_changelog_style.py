"""The changelogs are written to a shape, and that shape is easy to drift out of.

An entry is meant to say what changed, not to argue the case for it. Three releases in a row grew
to 450-720 character bullets before anyone noticed, because nothing checked. These tests are the
check: they enforce the shape the 0.1.x entries already had, and keep the two languages aligned.

The shape, since 0.2.18:

    ## 0.2.17 (2026-09-21)

    ### Security

    - sealed the set of records with a MAC, checked at unlock (#77)

A release groups its bullets under `### Security`, `### Fix`, `### Enhancement` — heaviest first,
each one optional — and every bullet ends with the pull request that changed it. The reader who
wants the reasoning follows the number; the entry itself stays one scannable line.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EN = ROOT / "relay" / "CHANGELOG.md"
JA = ROOT / "relay" / "CHANGELOG.ja.md"

# A bullet longer than this is a paragraph wearing a bullet's clothes. Entries sit between 60 and
# 210; the cap leaves room for one that genuinely needs a clause about scope.
MAX_BULLET = 250
# A release with more bullets than this is usually several releases, or one entry split too fine.
MAX_BULLETS_PER_RELEASE = 12
# Heaviest first. A release uses the ones it needs and keeps them in this order.
CATEGORIES = ["Security", "Fix", "Enhancement"]
# `(#77)` at the end of the line. One pull request per entry; an entry spanning two is two entries.
_REF = re.compile(r" \(#\d+\)$")


def _releases(path: Path) -> dict[str, list[str]]:
    """Map each release heading to its bullets, in file order."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        head = re.match(r"^## (\S+?)[ （(]", line)
        if head:
            current = head.group(1)
            out[current] = []
        elif current and line.startswith("- "):
            out[current].append(line)
    return out


def _categories(path: Path) -> dict[str, list[str]]:
    """Map each release heading to the `### ` categories under it, in file order."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        head = re.match(r"^## (\S+?)[ （(]", line)
        if head:
            current = head.group(1)
            out[current] = []
        elif current and line.startswith("### "):
            out[current].append(line[4:].strip())
    return out


def _orphan_bullets(path: Path) -> list[str]:
    """Bullets sitting under a release but not under any category of it."""
    out: list[str] = []
    in_release = False
    in_category = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^## (\S+?)[ （(]", line):
            in_release, in_category = True, False
        elif line.startswith("### "):
            in_category = True
        elif in_release and not in_category and line.startswith("- "):
            out.append(line)
    return out


# `## 0.2.8 (2026-09-17)`, or the Japanese `## 0.2.8（2026-09-17）` with no space before the
# bracket. A range like `## 0.1.0 – 0.1.2 (2026-09-08 – 13)` covers the entries written in one go.
_V = r"\d+(?:\.\d+)*"
_VER = _V + r"(?: [–〜] " + _V + r")?"
# A date, or a range whose second half may be shortened: `2026-09-08 – 13`
_DATE = r"\d{4}-\d{2}-\d{2}(?: [–〜] [\d-]+)?"
_HEADING = re.compile("## " + _VER + r"(?: \(" + _DATE + r"\)|（" + _DATE + "）)")


def _heading_lines(path: Path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.startswith("## ")]


def describe_changelog_style():
    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_keeps_bullets_short_enough_to_scan(path):
        long_ones = [
            (rel, len(b), b[:80])
            for rel, bullets in _releases(path).items()
            for b in bullets
            if len(b) > MAX_BULLET
        ]
        assert long_ones == [], (
            f"{path.name}: a changelog entry states what changed; the reasoning belongs in the "
            f"commit or the pull request. Split or shorten these (limit {MAX_BULLET}): {long_ones}"
        )

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_names_the_pull_request_that_changed_it(path):
        # The number is how a reader gets from "what" to "why" without the entry carrying the why.
        missing = [
            (rel, b)
            for rel, bullets in _releases(path).items()
            for b in bullets
            if not _REF.search(b)
        ]
        assert missing == [], (
            f"{path.name}: every entry ends with the pull request that changed it, as ` (#77)`. "
            f"Missing: {missing}"
        )

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_files_every_entry_under_a_category(path):
        orphans = _orphan_bullets(path)
        assert orphans == [], (
            f"{path.name}: an entry belongs under one of {CATEGORIES}, not directly under the "
            f"release heading: {orphans}"
        )

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_orders_the_categories_heaviest_first(path):
        rank = {name: i for i, name in enumerate(CATEGORIES)}
        wrong = {
            rel: cats
            for rel, cats in _categories(path).items()
            if [c for c in cats if c not in rank]
            or [rank[c] for c in cats] != sorted(rank[c] for c in cats)
            or len(cats) != len(set(cats))
        }
        assert wrong == {}, (
            f"{path.name}: categories are {CATEGORIES}, heaviest first, at most one of each: {wrong}"
        )

    def it_files_an_entry_under_the_same_category_in_both_languages():
        en, ja = _categories(EN), _categories(JA)
        uneven = {rel: (en[rel], ja.get(rel)) for rel in en if en[rel] != ja.get(rel)}
        assert uneven == {}, f"the two changelogs categorise differently (en, ja): {uneven}"

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_keeps_a_release_to_a_readable_number_of_entries(path):
        crowded = {
            rel: len(bullets)
            for rel, bullets in _releases(path).items()
            if len(bullets) > MAX_BULLETS_PER_RELEASE
        }
        assert crowded == {}, f"{path.name}: too many entries in one release: {crowded}"

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_heads_a_release_with_a_version_and_a_date_only(path):
        # `## 0.2.8 (2026-09-17)` — a heading that also summarises the release duplicates the
        # entries below it and goes stale on its own.
        bad = [
            h
            for h in _heading_lines(path)
            if not _HEADING.fullmatch(h) and not h.startswith("## Unreleased")
        ]
        assert bad == [], f"{path.name}: heading should be `## X.Y.Z (YYYY-MM-DD)`: {bad}"

    def it_describes_the_same_releases_in_both_languages():
        en, ja = _releases(EN), _releases(JA)
        assert list(en) == list(ja), (
            "the two changelogs have drifted apart: "
            f"en-only {sorted(set(en) - set(ja))}, ja-only {sorted(set(ja) - set(en))}"
        )
        # Not a translation check — just that neither side quietly lost an entry
        uneven = {rel: (len(en[rel]), len(ja[rel])) for rel in en if len(en[rel]) != len(ja[rel])}
        assert uneven == {}, f"different number of entries (en, ja): {uneven}"

    def it_leads_with_the_newest_release():
        versions = [
            tuple(int(n) for n in v.split("."))
            for v in _releases(EN)
            if re.fullmatch(r"\d+\.\d+\.\d+", v)
        ]
        assert versions == sorted(versions, reverse=True), (
            f"releases should be newest first: {versions}"
        )

    @pytest.mark.parametrize("path", [EN, JA], ids=["en", "ja"])
    def it_matches_the_version_the_code_declares(path):
        cargo = (ROOT / "relay" / "Cargo.toml").read_text(encoding="utf-8")
        version = re.search(r'^version = "([^"]+)"', cargo, re.M).group(1)
        newest = next(iter(_releases(path)))
        assert newest == version, (
            f"{path.name} leads with {newest} but relay/Cargo.toml says {version}; "
            "the release entry and the version bump belong in the same change"
        )
