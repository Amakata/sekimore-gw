"""Language resources of the Python CLI (`python -m src.maint`, 0.2.4).

Strings live in `src/locales/<lang>.json` under flat keys. The default is English (`en`); missing
keys fall back to English. The language: `SEKIMORE_LANG` -> `LC_ALL` -> `LC_MESSAGES` -> `LANG` -> en.

The dashboard's strings, and `/api/i18n` that serves them, moved to the relay in 0.3.0-alpha.4
(`relay/src/webui/locales/`). That copy holds these `maint.*` keys too, so `/api/i18n` answers
what it did; `relay/src/webui/tests.rs` keeps the two in step until `maint` moves (alpha.5).

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
