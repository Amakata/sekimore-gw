# ローカライズ

*[English](localization.md)*

この文書は、sekimore-gw が Web UI、コマンドラインツール、ドキュメントの言語をどう選ぶかを説明します。

第一言語は英語です。人が読むテキストには日本語も用意し、機械が読むテキストは英語のままにしています。

## Web UI

ダッシュボードの文言は `src/locales/<lang>.json`（`en`、`ja`）から読み込みます。`/api/i18n` が言語を決定して辞書を返し、
画面は `data-i18n` 属性を通じてそれを適用します。ヘッダの言語セレクタは `sekimore_lang` cookie（有効期間 1 年、`SameSite=Lax`）を設定し、
ページを再読み込みします。

Web UI は次の順序で言語を決定し、最初に一致したものを採用します。

| 順序 | 参照元 | 補足 |
|------|--------|------|
| 1 | `?lang=en` / `?lang=ja` クエリパラメータ | その場限りの上書き。リンクやスクリーンショット向き |
| 2 | `sekimore_lang` cookie | 言語セレクタが設定する。閲覧者ごと |
| 3 | `config.yml` の `ui.language` | 値が `auto` 以外のときだけ有効。全閲覧者の言語を固定する |
| 4 | `Accept-Language` | ブラウザの設定 |
| 5 | 英語 | 既定 |

言語をブラウザに追従させたくない場合は、`config/config.yml` で設定します。

```yaml
ui:
  language: auto   # auto | en | ja  (default: auto)
```

未対応の言語タグは英語にフォールバックし、翻訳にないキーは英語の文言にフォールバックします。そのため、翻訳が途中でも UI に空欄はできません。

## CLI

コマンドラインツールは、設定ファイルではなく環境変数に従います。`SEKIMORE_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG` の順に参照し、
どれもなければ英語を使います。対象は、ゲートウェイのコンテナ内の `python -m src.maint` と、Rust 製の `sekimore-relay` バイナリです。

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

関所の辞書と `sekimore guide --lang` については、[relay/README.ja.md の表示言語](../relay/README.ja.md#表示言語024)を参照してください。

## 英語のままにしているもの

拒否メッセージ（関所が標準エラー出力に書く `sekimore: ...` の行）と監査ログは、ロケールにかかわらず常に英語です。
スクリプト、CI、AI エージェントがこの文字列で判定するため、運用者の言語によって変わってはいけません。

## ドキュメント

ドキュメントは英語で書き、各ファイルの隣に日本語訳（`*.ja.md`）を置きます。[README.md](../README.md) と [README.ja.md](../README.ja.md)、
[relay/README.md](../relay/README.md) と [relay/README.ja.md](../relay/README.ja.md)、この文書と [localization.md](localization.md) が該当します。
