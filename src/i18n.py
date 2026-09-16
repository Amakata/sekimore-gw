"""Language resources (0.2.4).

Strings live in `src/locales/<lang>.json` under flat keys. The default is English
(`en`); missing keys fall back to English. Adding a language means adding one file.

- Web UI: `/api/i18n` resolves the language and returns the dictionary; the dashboard
  applies it via `data-i18n` and `tr()`
  (order: `?lang=` -> cookie `sekimore_lang` -> `ui.language` in `config.yml` (pinned
  unless `auto`) -> `Accept-Language` -> en)
- CLI (`python -m src.maint`): `SEKIMORE_LANG` -> `LC_ALL` -> `LC_MESSAGES` -> `LANG` -> en

Denial reasons (the `sekimore: ...` lines the relay writes to stderr) and audit logs
stay in English, so they remain machine-matchable and readable to AI agents.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

SUPPORTED: tuple[str, ...] = ("en", "ja")
DEFAULT = "en"
LOCALES_DIR = Path(__file__).parent / "locales"
COOKIE_NAME = "sekimore_lang"

_TAG_RE = re.compile(r"^\s*([A-Za-z]{2,3})(?:[-_]([A-Za-z]{2,4}))?")


def normalize(tag: str | None) -> str | None:
    """Map `ja` / `ja-JP` / `ja_JP.UTF-8` to `ja`; None if empty or unsupported."""
    if not tag:
        return None
    m = _TAG_RE.match(str(tag))
    if not m:
        return None
    lang = m.group(1).lower()
    return lang if lang in SUPPORTED else None


def from_accept_language(header: str | None) -> str | None:
    """Return the first supported language in Accept-Language, highest q first."""
    if not header:
        return None
    items: list[tuple[float, int, str]] = []
    for i, part in enumerate(header.split(",")):
        piece = part.strip()
        if not piece:
            continue
        tag, _, params = piece.partition(";")
        q = 1.0
        for p in params.split(";"):
            p = p.strip()
            if p.startswith("q="):
                try:
                    q = float(p[2:])
                except ValueError:
                    q = 0.0
        items.append((-q, i, tag.strip()))
    for _, _, tag in sorted(items):
        lang = normalize(tag)
        if lang:
            return lang
    return None


def resolve_lang(
    explicit: str | None = None,
    cookie: str | None = None,
    accept_language: str | None = None,
    configured: str | None = "auto",
) -> str:
    """Resolve the Web UI language (see the module docstring for the order)."""
    for candidate in (explicit, cookie):
        lang = normalize(candidate)
        if lang:
            return lang
    if configured and configured != "auto":
        lang = normalize(configured)
        if lang:
            return lang
    return from_accept_language(accept_language) or DEFAULT


def env_lang(environ: dict[str, str] | None = None) -> str:
    """Resolve the CLI language from environment variables."""
    env = os.environ if environ is None else environ
    for var in ("SEKIMORE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = env.get(var)
        if value and value != "C" and value != "POSIX":
            lang = normalize(value)
            if lang:
                return lang
    return DEFAULT


@lru_cache(maxsize=8)
def _load(lang: str) -> dict[str, str]:
    path = LOCALES_DIR / f"{lang}.json"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def strings(lang: str | None) -> dict[str, str]:
    """Return the dictionary for `lang`, layered over the English base."""
    lang = normalize(lang) or DEFAULT
    merged = dict(_load(DEFAULT))
    if lang != DEFAULT:
        merged.update(_load(lang))
    return merged


def t(key: str, lang: str | None = None, **vars: Any) -> str:
    """Return a string; an unknown key returns itself. `{name}` is filled from vars."""
    text = strings(lang).get(key, key)
    for name, value in vars.items():
        text = text.replace("{" + name + "}", str(value))
    return text
