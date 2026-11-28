"""Localization of the Python CLI (0.2.4): language from the environment, dictionary fallback, and src.maint.

The dashboard's localization (`/api/i18n`, the language order, the dashboard's keys) moved to the
relay in 0.3.0-alpha.4 and is tested there (`relay/src/webui/i18n.rs`, `relay/src/webui/tests.rs`).
"""

from src import i18n


def describe_language_resolution():
    def it_normalizes_tags():
        assert i18n.normalize("ja") == "ja"
        assert i18n.normalize("ja-JP") == "ja"
        assert i18n.normalize("ja_JP.UTF-8") == "ja"
        assert i18n.normalize("en-US") == "en"
        assert i18n.normalize("fr") is None
        assert i18n.normalize("") is None and i18n.normalize(None) is None

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

    def it_holds_only_the_cli_strings():
        assert all(k.startswith("maint.") for k in i18n._load("en"))

    def it_falls_back_to_english_and_interpolates():
        assert i18n.t("maint.json", "ja") != i18n.t("maint.json", "en")
        assert i18n.t("maint.json", "fr") == i18n.t("maint.json", "en")
        assert "/x.db" in i18n.t("maint.not_found", "en", db="/x.db")
        assert i18n.t("no.such.key", "ja") == "no.such.key"


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
