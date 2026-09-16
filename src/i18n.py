"""言語リソース（0.2.4）.

`src/locales/<lang>.json` にフラットなキーで文言を持つ。既定は英語（`en`）。
足りないキーは英語に落ちる。追加言語はファイルを 1 つ足すだけ。

- Web UI: `/api/i18n` が言語を決めて辞書を返し、dashboard が `data-i18n` と `tr()` で当てる
  （順序: `?lang=` → cookie `sekimore_lang` → `config.yml` の `ui.language`（`auto` 以外なら固定）→ `Accept-Language` → en）
- CLI（`python -m src.maint`）: `SEKIMORE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG` → en

拒否理由（relay が stderr に出す `sekimore: …`）と監査ログは英語のまま固定する（機械照合と AI の可読性のため）。
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
    """`ja` / `ja-JP` / `ja_JP.UTF-8` → `ja`。対応外や空なら None."""
    if not tag:
        return None
    m = _TAG_RE.match(str(tag))
    if not m:
        return None
    lang = m.group(1).lower()
    return lang if lang in SUPPORTED else None


def from_accept_language(header: str | None) -> str | None:
    """Accept-Language を q 値の高い順に見て、最初に対応している言語."""
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
    """Web UI の言語を決める（順序は module docstring）."""
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
    """CLI の言語（環境変数から）."""
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
    """`lang` の辞書（英語をベースに上書き）."""
    lang = normalize(lang) or DEFAULT
    merged = dict(_load(DEFAULT))
    if lang != DEFAULT:
        merged.update(_load(lang))
    return merged


def t(key: str, lang: str | None = None, **vars: Any) -> str:
    """文言を返す。無いキーはキーそのまま。`{name}` を vars で埋める."""
    text = strings(lang).get(key, key)
    for name, value in vars.items():
        text = text.replace("{" + name + "}", str(value))
    return text
