# sekimore-relay 変更履歴

*[English](CHANGELOG.md)*

## 0.2.10（2026-09-17）

- `SEKIMORE_WEB_HOST`、`SEKIMORE_WEB_PORT`、`SEKIMORE_ULOG_PATH` は定数に読み込まれるだけで誰も使っておらず、設定しても効かなかった。効くようにした。`ULOG_FILE_PATH` の既定も `syslogemu.log` だったが実際に読むのは `firewall.log` で、ulogd が書くファイル名に合わせた
- `login` が `proxy.upstream_proxy` 経由だったか直接だったかを示すようになった。到達できないプロキシと到達できない上流が同じタイムアウトになり、直す場所が違うのに区別できなかった
- 未使用の依存を 5 つ削除。Rust の `thiserror` と `http`（`http::` は同名のローカルモジュールを指していた）、Python の `pydantic-settings`、`python-json-logger`、`jinja2`
- 呼び出しの無い Rust の関数 7 つ、`bootstrap` エージェントサブコマンドと `bootstrap status`、Python の定義 4 つを削除。`agent-setup.sh` は `POST /bootstrap` を HTTP で叩くので、エンドポイントは残す

## 0.2.9（2026-09-17）

- `sekimore pr merge` に `--method merge|squash|rebase`、`--title`、`--message`、`--delete-branch` を追加。squash 専用の repo は従来の空ボディを 405 で拒否していた
- `--delete-branch` はマージしたブランチだけを消し、repo 側の `delete_merged_branch` が要る。git レベルの `delete` とは別の権限
- `sekimore pr reopen` / `issue reopen`、`issue unlabel`、`issue unassign`、`pr update --title/--body/--base`。base を変えるときは base の検査をやり直す
- `sekimore release edit` で draft を公開・修正できる。draft を false にするには新しい `release:publish` が要る
- `sekimore ci rerun --run-id N [--all]` と `ci cancel`。新しい権限 `ci:rerun`。再実行は Actions の分数を消費し、秘密情報を持つジョブを走らせ直すので `ci:read` とは分ける
- `sekimore repo vocabulary` でラベル・担当者に指定できる人・開いているマイルストーンを一覧する。`repo:read` は宣言されているだけでどこも検査していなかった
- CHANGELOG の書式を CI で検査する。項目の長さ、見出しは版と日付だけ、2 言語が同じ版を記述しているか

## 0.2.8（2026-09-17）

- `sekimore pr view` / `pr comments` / `pr list`、`issue view` / `issue comments` / `issue list`。Issue を作れるのに読めず、レビューされても内容を見られなかった
- `pr comments` は会話・レビューの可否・行への指摘を 1 つの時系列にまとめる（古い順）
- `sekimore search "is:open label:bug"` で案件を横断して検索する。クエリを `repo:` で絞り、返ってきた結果も案件内かで濾す
- 権限 `issue:read` と `search:read` を追加。`pr view` / `comments` / `list` は既存の `pr:read`
- コメントの文面は指示ではなくデータである、とガイドに明記した

## 0.2.7（2026-09-17）

- セキュリティ: 細工したタグと CI の ref がリポジトリのパスの外へ出て、operator のトークンで別のリポジトリを読めた。パス部品では `/` と `.` も符号化する（クエリ値は従来どおり）。`ci runs --ref` は 0.1.7 から、`release view --tag` は 0.2.6 から到達できた
- セキュリティ: Projects v2 のボードが node ID だけで到達でき、案件に属するかを誰も見ていなかった。`relay.project.boards` に `{ org, number }` で宣言し、起動時に解決する。**破壊的変更**: 空なら Projects の操作を全て拒否する
- `dns_server.py` が `git-relay` としか比較しておらず、`github` と書いたドメインが実アドレスに解決されて関所を通らなかった
- `sekimore pr request-review --reviewers alice,bob [--teams t]`。新しい権限 `pr:request_review`
- `sekimore project fields` でボードのフィールドと single-select の option id を一覧する（`update-item` に必要）
- `find_pull_request` が読み取りに `pr:create` を要求していた。`pr:read` でも通るようにした
- ガイドは force push を拒否すると書いていたが、関所が見るのは ref 名であって早送りかどうかではない。拒否するのは上流のブランチ保護

## 0.2.6（2026-09-16）

- `sekimore release create --tag vX.Y.Z [--title T] [--notes … | --notes-file F] [--draft] [--prerelease]`、`release view`、`release list`。本文を渡さなければ前のタグからの PR を元に GitHub が書く
- タグが上流に無いと作れないので、`git push origin vX.Y.Z` の後に実行する
- 権限 `release:create` と `release:read` を追加。device flow のトークンは既に `repo` スコープを持つ
- `handler: git-relay` を `handler: github` と書くようにした。SSH の git は forge 非依存だが API は GitHub 固有で、0.3.0 の `gitlab` / `gitea` に道を残す
- `git-relay` は Rust と Python の両方で別名として有効。設定を書き換える必要はない

## 0.2.5（2026-09-16）

- Docker: `relay/locales` をビルダー段にコピーする。0.2.4 の辞書は `include_str!` で取り込むのにコピーしていたのは `relay/share` だけで、v0.2.4 のイメージが公開されなかった
- relay 本体の変更は無く、0.2.4 と 0.2.5 は同じコード

## 0.2.4（2026-09-16）

- Web UI: 文言を `src/locales/{en,ja}.json` に移し、既定を英語に。言語は `?lang=` → cookie（画面の切替）→ `config.yml` の `ui.language`（`auto` / `en` / `ja`）→ ブラウザの `Accept-Language` → 英語の順で決める。`/api/i18n`
- `python -m src.maint`: `--help` とメッセージを `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` で切替（既定は英語）
- Rust CLI: `--help` と操作者向けの出力を `relay/locales/{en,ja}.json` に移し、実行時に `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` で選ぶ（既定は英語）。未収録キーは英語 → キー名にフォールバック
- `sekimore guide --lang en|ja`: ガイドを `relay/share/agent-guide.en.md` と `agent-guide.ja.md` に分割（英語版は要約ではなく全文）。agent-setup が skill と `AGENTS.md` に置くのは既定で英語（`SEKIMORE_GUIDE_LANG`）
- README と CHANGELOG を英語主体に。日本語版は `README.ja.md` / `CHANGELOG.ja.md`
- 拒否理由（`sekimore: …`）と監査ログは英語のまま固定

## 0.2.3（2026-09-16）

- Web UI: 1 本のポーラが rowid をカーソルに増分だけ読み、1 メッセージで送る。1 件なら即時、多ければまとめて。接続時と非表示タブの復帰時は最新 50 件のスナップショット
- `/api/stats` はログ 1 件ごとではなく、新着後に最短 3 秒に 1 回
- SQLite: `journal_mode=WAL`、`synchronous=NORMAL`、`busy_timeout`、`dns_queries(timestamp)` と `(status, timestamp)` の索引
- 記録は削除しない。`python -m src.maint db-stats | db-prune | db-reset | db-vacuum` を操作者が明示的に実行する（Dev Containers なら `mise run gw:db-*`）
- Relay タブ: 上流が 1 つでも送信上限を表示する
- relay 本体の変更は無し

## 0.2.2（2026-09-16）

- 持ち出し対策: 443 passthrough に dev → 上流の送信上限（`relay.https_max_upload_bytes`、既定 1 MiB、`-1` で無制限）。超えた接続は切断して監査 `https_upload_capped`
- `handler: https-relay`: 443 だけを関所の passthrough で通し、宛先ごとに `max_upload_bytes` を掛ける（自分で image を push する宛先は `-1`）
- `network.allowed_ports`（sekimore-gw 本体）: 許可ドメイン / 許可 IP へ通す宛先ポートを絞る。未設定は従来どおり全ポート
- Web UI: 宛先ごとの上限、1 MiB 以上を送った passthrough 接続に LARGE UPLOAD、24 時間の件数（大きな送信 / 上限超過）
- `sekimore guide`: AI エージェント向けの使い方（CLI に埋め込み）。agent-setup が Claude Code の skill と Codex CLI の `AGENTS.md` ブロックとして置く（`SEKIMORE_AGENT_INSTRUCTIONS`）

## 0.2.1（2026-09-16）

- `project.upstreams.<domain>`: 案件既定と repo の間に上流ごとの層（`permissions` の差分、`push` / `tags` / `delete` の既定、`repos`）
- `domain_handlers.<domain>.ssh_options` / `relay.ssh_options`: 上流 ssh に `-o` で渡す（踏み台の `ProxyJump=` など）。関所が強制するオプションは上書き不可
- `domain_handlers.<domain>.api_base` / `graphql_base`: 上流ごとの API の宛先
- `sekimore-relay keyscan`: 上流や踏み台のホスト鍵を fingerprint 表示付きで known_hosts に追加
- Web UI: 上流ごとの `ssh_options` と `api_base`。orchestrator は `ssh_port` の変更も再起動要と判定

## 0.2.0（2026-09-16）

- 複数上流: `domain_handlers` に git-relay を複数書ける。上流ごとに別ポートで listen し、接続を受けたポートで上流を決める
- `repos[].name` に `host/Org/Repo`。SSH 経路は接続を受けた上流の repo だけを探す
- 443 passthrough は TLS の SNI で上流を選ぶ
- `login` / `logout` / `whoami --upstream`。既定以外の上流の state は `/data/relay/upstreams/<host>/`
- `/bootstrap` が `git_domains` を返し、agent-setup が上流ごとに `Host` ブロックと known_hosts を書く
- Web UI Relay タブに上流の一覧

## 0.1.9（2026-09-16）

- 権限を `project` 配下に集約: `permissions` は `[…]` か `{allow, deny}`（deny が勝つ）、`push` / `tags`（glob）/ `delete`
- `repos[]` で `tags` / `delete` / `permissions`（差分）を上書き
- 旧 `relay.allow_tags` / `relay.allow_delete` は非推奨（読めば既定に畳み込んで警告）

## 0.1.8（2026-09-16）

- `ci jobs --number` が PR の全 workflow run を集約
- Docker Publish の `provenance: false`

## 0.1.7（2026-09-16）

- `ci runs --ref <tag|branch|sha>`、`ci jobs` / `ci log` の `--run-id`
- Docker Publish をアーキごとの native runner で並列化（0.1.6 は公開に失敗し欠番）

## 0.1.5（2026-09-15）

- `relay.allow_tags`
- `ci:read`: `ci jobs` / `ci log`（GitHub Actions の失敗ログを末尾から）

## 0.1.4（2026-09-15）

- Web UI Relay タブの API が実プロセスで 404 になる問題を修正

## 0.1.3（2026-09-15）

- `proxy.enabled` を見る。認証バナーの廃止。拒否した push を report-status の `ng` で返す
- 監査の抜け（tcpip-forward、Authorization 無し、不正 body）を記録
- 同じ鍵での再 bootstrap は前のトークンを失効。期限切れ 7 日後にレコードを掃除
- Web UI Relay タブ。署名鍵のコメントに案件名と利用者名
- `pr status`（`pr:read`）。HTTPS git の credential helper と GIT_ASKPASS を dev 側で無効化（依頼者の認証の迂回を防ぐ）

## 0.1.0 〜 0.1.2（2026-09-08 〜 13）

- 初版。SSH（git）と GitHub API の中継、案件ポリシー、`refs/for/<base>` から PR 作成、bootstrap、443 passthrough、devcontainer base への同梱
