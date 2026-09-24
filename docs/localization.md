# Localization

*[日本語版](localization.ja.md)*

This document describes how sekimore-gw selects a language for the Web UI, the command-line
tools and the documentation.

English is the primary language. Japanese is available wherever a person reads text, and text
that machines read stays in English.

## Web UI

The dashboard text comes from `src/locales/<lang>.json` (`en`, `ja`). `/api/i18n` resolves the
language and returns the dictionary, and the page applies it through `data-i18n` attributes. The
language selector in the header sets a `sekimore_lang` cookie (one year, `SameSite=Lax`) and
reloads the page.

The Web UI resolves the language in the following order, and the first match wins:

| Order | Source | Notes |
|-------|--------|-------|
| 1 | `?lang=en` / `?lang=ja` query parameter | One-off override, useful for links and screenshots |
| 2 | `sekimore_lang` cookie | Set by the language selector; per viewer |
| 3 | `ui.language` in `config.yml` | Applies only when the value is not `auto`; sets the language for every viewer |
| 4 | `Accept-Language` | The browser's preference |
| 5 | English | Default |

To keep the language from following the browser, set it in `config/config.yml`:

```yaml
ui:
  language: auto   # auto | en | ja  (default: auto)
```

An unsupported language tag falls back to English, and a key that is missing from a translation
falls back to the English string. A partial translation therefore never leaves a blank in the UI.

## CLI

Command-line tools read the environment instead of the configuration file. They check
`SEKIMORE_LANG`, `LC_ALL`, `LC_MESSAGES` and `LANG` in that order, and default to English. This
applies to `python -m src.maint` in the gateway container and to the Rust `sekimore-relay` binary.

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

For the relay's dictionaries and for `sekimore guide --lang`, see
[Display language in relay/README.md](../relay/README.md#display-language-024).

## What stays in English

Denial messages (the `sekimore: ...` lines that the relay writes to stderr) and the audit log are
always in English, regardless of the locale. Scripts, CI and AI agents match on this text, so it
must not change with the operator's language.

## Documentation

The documentation is written in English, with a Japanese translation (`*.ja.md`) next to each
file: [README.md](../README.md) and [README.ja.md](../README.ja.md),
[relay/README.md](../relay/README.md) and [relay/README.ja.md](../relay/README.ja.md), and this
file and [localization.ja.md](localization.ja.md).
