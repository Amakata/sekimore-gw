"""ローカライズ（0.2.4）: 言語の決め方、辞書のフォールバック、dashboard のキー整合、/api/i18n、src.maint の言語."""

import re
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src import i18n

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "src" / "web_ui" / "templates" / "dashboard.html"


def describe_language_resolution():
    def it_normalizes_tags():
        assert i18n.normalize("ja") == "ja"
        assert i18n.normalize("ja-JP") == "ja"
        assert i18n.normalize("ja_JP.UTF-8") == "ja"
        assert i18n.normalize("en-US") == "en"
        assert i18n.normalize("fr") is None
        assert i18n.normalize("") is None and i18n.normalize(None) is None

    def it_picks_the_best_supported_accept_language():
        assert i18n.from_accept_language("fr-FR,fr;q=0.9,ja;q=0.8,en;q=0.7") == "ja"
        assert i18n.from_accept_language("en-US,en;q=0.9,ja;q=0.8") == "en"
        assert i18n.from_accept_language("de") is None
        assert i18n.from_accept_language(None) is None

    def it_resolves_in_order_query_cookie_config_header_default():
        assert i18n.resolve_lang() == "en"
        assert i18n.resolve_lang(accept_language="ja,en;q=0.5") == "ja"
        assert (
            i18n.resolve_lang(accept_language="ja", configured="en") == "en"
        )  # config が固定なら header より優先
        assert (
            i18n.resolve_lang(cookie="en", configured="ja") == "en"
        )  # 利用者の切替 (cookie) は config より優先
        assert i18n.resolve_lang(explicit="ja", cookie="en") == "ja"
        assert i18n.resolve_lang(explicit="xx", cookie="yy", accept_language="zz") == "en"

    def it_reads_the_cli_language_from_the_environment():
        assert i18n.env_lang({}) == "en"
        assert i18n.env_lang({"LANG": "ja_JP.UTF-8"}) == "ja"
        assert i18n.env_lang({"LANG": "C", "LC_ALL": "C"}) == "en"
        assert i18n.env_lang({"LANG": "ja_JP.UTF-8", "SEKIMORE_LANG": "en"}) == "en"
        assert i18n.env_lang({"LANG": "en_US.UTF-8", "LC_MESSAGES": "ja_JP"}) == "ja"


def describe_dictionaries():
    def it_has_the_same_keys_in_every_language():
        en = i18n._load("en")
        ja = i18n._load("ja")
        assert en and ja
        assert set(en) == set(ja), set(en) ^ set(ja)

    def it_falls_back_to_english_and_interpolates():
        assert i18n.t("loading", "ja") == "読み込み中..."
        assert i18n.t("loading", "en") == "Loading..."
        assert i18n.t("loading", "fr") == "Loading..."  # 未対応言語は英語
        assert i18n.t("more_items", "en", n=3) == "...3 more"
        assert i18n.t("no.such.key", "ja") == "no.such.key"

    def it_covers_every_key_the_dashboard_uses():
        html = DASHBOARD.read_text(encoding="utf-8")
        used = set(re.findall(r'data-i18n(?:-html)?="([^"]+)"', html))
        used |= set(re.findall(r"tr\('([^']+)'", html))
        assert used, "dashboard should use i18n keys"
        missing = sorted(k for k in used if k not in i18n._load("en"))
        assert missing == [], missing

    def it_leaves_no_hard_coded_japanese_in_the_dashboard():
        jp = re.compile(r"[぀-ヿ一-鿿]")
        offenders = []
        for line in DASHBOARD.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*", "<!--")) or "日本語" in stripped:
                continue  # コメントと言語切替の表示名は対象外
            code = re.sub(r"\s//.*$", "", line)  # 行末コメントも対象外
            if jp.search(code):
                offenders.append(stripped[:100])
        assert offenders == [], offenders


def describe_i18n_api():
    import contextlib

    @contextlib.contextmanager
    def _client(tmp_path, ui_language=None):
        cfg = tmp_path / "config.yml"
        cfg.write_text(
            "allow_domains: [example.com]\n"
            + (f"ui:\n  language: {ui_language}\n" if ui_language else "")
        )
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            yield TestClient(app)

    def it_defaults_to_english_and_follows_accept_language(tmp_path):
        with _client(tmp_path) as client:
            data = client.get("/api/i18n").json()
            assert data["lang"] == "en" and data["supported"] == ["en", "ja"]
            assert data["strings"]["loading"] == "Loading..."
            data = client.get("/api/i18n", headers={"Accept-Language": "ja,en;q=0.8"}).json()
            assert data["lang"] == "ja" and data["strings"]["loading"] == "読み込み中..."

    def it_prefers_query_then_cookie_then_config(tmp_path):
        with _client(tmp_path, ui_language="en") as client:
            # config が en 固定なら header の ja は無視
            assert client.get("/api/i18n", headers={"Accept-Language": "ja"}).json()["lang"] == "en"
            # 利用者の切替 (cookie) は config より優先
            client.cookies.set("sekimore_lang", "ja")
            assert client.get("/api/i18n").json()["lang"] == "ja"
            # ?lang= が最優先
            assert client.get("/api/i18n?lang=en").json()["lang"] == "en"
            assert (
                client.get("/api/i18n?lang=xx").json()["lang"] == "ja"
            )  # 不正な指定は無視して次へ (cookie)

    def it_serves_the_dashboard_in_english_by_default(tmp_path):
        with _client(tmp_path) as client:
            html = client.get("/").text
        assert '<html lang="en">' in html
        assert 'data-i18n="tab.dashboard"' in html and 'id="lang-select"' in html


def describe_maint_language():
    def it_prints_help_and_messages_in_the_selected_language(tmp_path, capsys):
        from src import maint

        db = tmp_path / "gw.db"
        assert maint.main(["--db", str(db), "db-stats"], lang="en") == 0
        assert "(not found)" in capsys.readouterr().out
        assert maint.main(["--db", str(db), "db-stats"], lang="ja") == 0
        assert "(見つかりません)" in capsys.readouterr().out
        assert maint.main(["--db", str(db), "db-reset", "--yes"], lang="ja") == 1
        assert "DB が見つかりません" in capsys.readouterr().err

    def it_uses_the_environment_by_default(tmp_path, capsys, monkeypatch):
        from src import maint

        monkeypatch.setenv("SEKIMORE_LANG", "ja")
        assert maint.main(["--db", str(tmp_path / "none.db"), "db-stats"]) == 0
        assert "(見つかりません)" in capsys.readouterr().out
