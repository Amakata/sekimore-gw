# sekimore-relay 変更履歴

*[English](CHANGELOG.md)*

## 0.2.7（2026-09-17。セキュリティ: タグと ref が案件の外へ到達できた。レビュー依頼、Project のフィールド一覧、DNS 転送）

- セキュリティ、および Projects を使っている場合の破壊的変更: Projects v2 の node ID は不透明で、どのボードの所有者かを何も示さない。そのため 1 つの repo に対する `project:add_item` があれば、案件の内外を問わず上流トークンから見える**任意の**ボードに到達できた。触れてよいボードを `relay.project.boards` に宣言する形にした。書き方は URL のとおりで、`github.com/orgs/acme/projects/3` なら `{ org: acme, number: 3 }`、個人のボードなら `user:`。関所が起動時に node ID へ解決し、それ以外は受け付けない。省略または空なら Projects の操作を全て拒否する。宣言の無い設定で穴を開けたままにするより、使っている案件に一覧を書いてもらう方を選んだ
- `sekimore pr request-review --number N --reviewers alice,bob [--teams platform]` でレビューを依頼できる。権限は `pr:review` ではなく専用の `pr:request_review`。意見を出すことと人に通知することは別の権限だから
- `sekimore project fields --project-id PVT_…` でボードのフィールドと single-select の option id を一覧できる。`project update-item` は `field_id` を、single-select では名前ではなく option の id を要求するため、これまでその id は人間から渡すしかなく、コマンド単体では使えなかった。権限は既存の `project:read`
- ガイドは force push が既定で拒否されると書いていたが、実際には拒否していない。関所が見るのは ref 名であって早送りかどうかではないので、自分の `sekimore/*` の中では force push は通り、必要な場所では上流のブランチ保護が拒否する。関所側で forge と同じ検査を持つのではなく、ガイドの記述を実態に合わせた
- セキュリティ: エージェントが渡すタグと CI の ref が、自分のリポジトリの外へ出られた。どちらもリクエストのパスに入り、URL を組み立てるときにパーサが `..` を解決するため、`release view --tag '../../../Other/Secret/releases'` が案件に無いリポジトリへ operator のトークンで認証付きの読み取りを飛ばしていた。エスケープが `/` と `.` を通していたのが原因で、クエリ値としては正しいがパス部品では誤り。パス部品では両方を符号化するようにした。監査ログには実際に触れたリポジトリではなく案件内のリポジトリが記録されるので、`ci:read`（`--ref` の経路は 0.1.7 から）や `release:read`（0.2.6 から）を許可していた gateway ではログを確認すること
- `find_pull_request` が読み取りに `pr:create` を要求していた。到達経路は `refs/for` だけでその証明を持っているため悪用はできなかったが、本来必要な `pr:read` でも通るようにした
- DNS: `handler: github` でも関所へ転送するようにした。`git-relay` では従来どおり動いていたが、0.2.6 は handler を改名して設定層だけを追従させたため、`dns_server.py` が旧名としか比較しておらず、新しい書き方のドメインが実アドレスに解決されて関所を通らなかった。両方の綴りを受け、同じ結果になることをテストで固定した。`git-relay` のままだった場合は影響なし

## 0.2.6（2026-09-16。エージェントからの Release 作成と、handler 名を上流サービス名に）

- `sekimore release create --tag vX.Y.Z [--title T] [--notes "…" | --notes-file F] [--generate-notes] [--draft] [--prerelease]`、`sekimore release view --tag vX.Y.Z`、`sekimore release list [--limit N]`。エンドポイントは `/release/create`、`/release/view`、`/release/list`
- タグが上流に無いと GitHub が 422 を返すので、`release create` は `git push origin vX.Y.Z` の後に実行する。本文を渡さないと関所が `generate_release_notes` を立て、前のタグ以降にマージされた PR から GitHub が本文を書く（これが通常の使い方）。`--notes` / `--notes-file` を渡すとそれが本文になり、さらに `--generate-notes` を付けると生成した本文が後ろに追記される。`--title` の既定はタグ名、`--draft` は公開を人間に任せる（既定は公開済み）
- 権限に `release:create` と `release:read` を追加。他と同じく既定で拒否。device flow トークンは `repo` スコープを持つので、認証のやり直しは不要
- `handler: git-relay` の書き方を `handler: github` に変更。SSH の git 側（refs/for、ポリシー、receive-pack）はただの git でどの forge でも動くが、API 側（pulls、check-runs、Projects v2）は GitHub 固有なので、handler に上流サービスの名前を持たせた。0.3.0 で API 層を差し替え可能にしたときの `gitlab` / `gitea` の余地にもなる
- `git-relay` はそのまま動く。Rust 側も Python 側も別名として受け付けるので、設定を書き換える必要は今も今後も無い

## 0.2.5（2026-09-16。0.2.4 のイメージビルドの修正）

- Docker: `relay/locales` をビルダー段にコピーする。0.2.4 の CLI 辞書は `include_str!` で取り込むが、コピーしていたのは `relay/share` だけだったため、リリースビルドが `locales/ja.json` を読めず v0.2.4 のイメージが公開されなかった。relay 本体の変更は無く、0.2.4 と 0.2.5 は同じコード。

## 0.2.4（2026-09-16。ローカライズ。英語を正本に、日本語は言語ファイル）

- Web UI: 文言を `src/locales/{en,ja}.json` に移し、既定を英語に。言語は `?lang=` → cookie（画面の切替）→ `config.yml` の `ui.language`（`auto` / `en` / `ja`）→ ブラウザの `Accept-Language` → 英語の順で決める。`/api/i18n`
- `python -m src.maint`: `--help` とメッセージを `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` で切替（既定は英語）
- Rust CLI: `--help` と操作者向けの出力を `relay/locales/{en,ja}.json` に移し、実行時に `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` で選ぶ（既定は英語）。未収録キーは英語 → キー名にフォールバック
- `sekimore guide --lang en|ja`: ガイドを `relay/share/agent-guide.en.md` と `agent-guide.ja.md` に分割（英語版は要約ではなく全文）。agent-setup が skill と `AGENTS.md` に置くのは既定で英語（`SEKIMORE_GUIDE_LANG`）
- README と CHANGELOG を英語主体に。日本語版は `README.ja.md` / `CHANGELOG.ja.md`
- 拒否理由（`sekimore: …`）と監査ログは英語のまま固定

## 0.2.3（2026-09-16。sekimore-gw 本体の性能と運用。relay 本体の変更なし）

- Web UI: WebSocket は接続ごとの全表走査をやめ、1 本のポーラが rowid カーソルで新着だけを読んで 1 メッセージ（配列）で配信。1 件でも即時、多ければまとめて届く。接続時と非表示から戻ったときは最新 50 件の snapshot。ログ 1 件ごとの `/api/stats` 取得をやめ、新着後 3 秒に 1 回に
- SQLite: `journal_mode=WAL` / `synchronous=NORMAL` / `busy_timeout`、`dns_queries(timestamp)` と `(status, timestamp)` の索引。記録は削除しない（永続化）
- `python -m src.maint db-stats | db-prune | db-reset | db-vacuum`（操作者が明示的に実行）。Dev Containers の `mise run gw:db-*`
- Relay タブ: 単一上流でもその上流の送信上限を表示

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
