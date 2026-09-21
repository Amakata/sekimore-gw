# sekimore-relay 変更履歴

*[English](CHANGELOG.md)*

## 0.2.17（2026-09-21）

- Python のテストジョブが、自前のタイムアウトによる kill をそのまま実行結果として扱っていた。失敗を含むスイートもハングするので、緑として報告されていた。判定を要約行に変更。0.2.15 から落ち続けていたテストが、これで2リリース通過していた
- `dashboard.html` が `pr:label` / `pr:assign` / `issue:update` を提示しておらず、関所に足した権限を Web UI で選べなかった
- `pip-audit` をプルリクエストごとに実行（`mise run ci:py-audit`）。`cargo audit` は `relay/Cargo.lock` しか読まず、Python 側6パッケージ29件がロックファイルに残っていた
- 秘密ストアの `export` / `import`。封緘したまま出し入れする。施錠中でもバックアップが取れ、封筒が salt とパラメータを持つのでマシン移動はファイルのコピーで済む
- レコードの集合に MAC を掛けた。レコードごとの AEAD は中身と身元しか守らないので、1つ削る・別ストアのものを混ぜる操作が検出できなかった。import 時ではなく解錠時に検査する
- `relay.store.unlock: file` / `env` で人を介さず解錠できる。**このプロジェクトの開発用**。パスフレーズが保存された状態になる（`prompt` が避けているもの）ので、起動時に警告を出す
- `COPY src/` が `uv pip install` より上にあり、ソースを1行変えるだけで site-packages が作り直され、利用者が毎回 pull し直していた

## 0.2.16（2026-09-21）

- `mise run gw:unlock` が、パスフレーズ未設定のストアに設定できなかった。2回尋ねたうえで `unlock` を送っており、まだ書かれていないパラメータで鍵を解こうとしていた。制御ソケットに `init` が無かった。初回起動というすべての環境が通る経路を、テストだけが通っていなかった
- stdin が端末でないときのメッセージが「端末で実行してください」だった。端末にいる人には手がかりにならないので、「パイプしないでください」に変えた

## 0.2.15（2026-09-21）

- `project list` / `fields` / `add-item` / `update-item` が `--board 2` を取る。`config.yml` と URL と同じ番号。`--project-id` も従来どおりで、ボードが1枚の案件はどちらも省略できる
- `project list` が各アイテムのフィールド値（single-select / text / number / date）を返す。`update-item` で書いた値を読み戻せる
- 番号がプルリクエストを指すとき、`issue` の書き込みが `pr:*` を要求する。GitHub がプルリクエストを issues のエンドポイントで返すため `issue:close` が届いていた。`pr:label` と `pr:assign` を新設
- `issue update --number N [--title …] [--body …]`。`issue:create` ではなく新設の `issue:update` の下
- 設定の reload がゲートウェイ本体のイベントループで走り、firewall の規則変更がロックを取る。交錯すると NFLOG ルールが ACCEPT より前に残るか消えていた
- `domain_handlers` が中継するドメインを `allow_domains` が覆っていない設定を、ドメイン名を挙げて起動時に拒否する。`deny` と `splice` は対象外
- 秘密ストアを追加。専用ファイルの SQLite、値ごとの AES-256-GCM、レコードの身元を AAD に結合。まだ誰も使っていない
- `sekimore-relay unlock` / `lock` / `store-status` / `passphrase`。エージェント向け API ではなく、関所の状態ディレクトリに置いた unix socket 経由。`mise run gw:unlock` ほか
- プルリクエストと `main` への push が `:pr-<n>` と `:main` を arm64 で作る。版番号を使わずにゲートウェイの変更を試せる

## 0.2.14（2026-09-18）

- reload が ipset を `allow_domains` だけから作り直していたので、`allow_ips` と `block_ips` が次の再起動まで消えていた。設定に直接書く IP は、DNS 名で代替できないものだけに使う
- reload が既存の状態を消してから新しい squid.conf を生成していたため、生成に失敗すると新旧どちらの規則も無い状態が残った。先に生成し、関所の持つドメインの拒否を含まない設定は書かずに失敗するようにした
- `ProxyManager` は起動時に一度だけ作られるので、`proxy` 配下のキーは再起動まで固定される。`enabled` も同じで、true にしても何も起こらず、reload も何も言わなかった。手掛かりは Squid が居ないことだけだった。reload の差分検出が proxy も比較する
- `project add-item` は GraphQL の node id を要求するが、それを返すコマンドが無かった。作成と同時にしかボードへ載せられず、既に立っている issue はまったく載せられなかった。`issue view` / `pr view` が `node_id` を返す

## 0.2.13（2026-09-18）

- config は dev から書けて保存で即反映されるので、攻撃的なプロンプトを読んだ AI が自分を縛る設定を書き換えられた。`reload:` に auto（従来）/ manual / 期間を追加した。閉じ忘れの起きない、時間切れで閉じる窓にしてある。開け直せるのは関所の中からだけで、AI には届かない
- `python -m src.maint reload-follow 30m` / `reload-freeze` / `reload-status`。窓が閉じている間の保存は、破棄せず数えて記録する
- PR の head を検査していなかった。GitHub は `owner:branch` を fork として読むので、関所を一度も通っていないコードの PR を案件内リポジトリに作れた。head も直接 push と同じ glob を満たすことを要求する
- 1 回の push で同じ upstream ref を 2 回更新できた。report-status の対応表が 1 対 1 なので、どちらの結果がどちらの ref のものか言えなくなる。書き換え先の名前は AI 自身の commit から決まるので、狙って指定できた
- 起動時に allow_domains から ipset を作る処理が domain_handlers を見ておらず、関所が受け持つドメインの実 IP が入っていた（この環境で 6 件）。IP 直打ちで関所を素通しできた
- ドメイン一致がラベル境界を見ておらず、`.debian.org` が `evildebian.org` を許可していた。誰でも取得できる名前が持ち出し先になる。allow / block / ignore が判定を共有するようにし、ワイルドカードの三者不一致も解消した
- reload の差分検出が 4 キーしか持たないモデル越しに relay を比較していたので、案件へのリポジトリ追加も pr:merge の付与も送信上限の撤廃も「変更なし」と判定されていた
- SNI が無い接続が既定の上限を取っていた。名前を省くだけで最も緩い上限を要求できる。最も厳しいものを使うようにした
- truncate() が str をバイト単位で切っていた。上流のエラー本文は AI が送った値を反射するので、日本語のラベル名だけでタスクが落ちた
- 人を別方向に導いていた 2 つのメッセージ: 操作者向けコマンドに関所の中で動かすことを明記した（`sekimore-relay keyscan` を dev で実行した AI が無関係な原因を報告していた）。上流プロキシへの login のタイムアウトは、プロキシのアドレスが docker のブリッジサブネットに入っているのが原因のことがあり、起動時にその旨を出す（次の一手として自然に出る allow_ips の拡大では直らない）
- 設定から黙って誤ったものが作られていた 2 件: `domain_handlers` のキーのタイポが無視され、しかも緩む方向に効いていた（`max_uploads_bytes` は「上限なし」と読まれ、`check` も unlimited と表示する）。ipset の名前がドメインの 31 文字切り詰めで、先頭 25 文字が同じ 2 つが同じ set を共有し、片方が他方の IP を消していた
- ほか: `merged` 欠落を true と読んでブランチ削除の条件にしていた件、`repo vocabulary` が取得失敗を「ラベル 0 件」と返していた件、idle timeout で送信バイト数が 0 になっていた件、SSH のチャネルが解放されなかった件、glob_match が AI の決める ref 名に対して指数時間になっていた件

## 0.2.12（2026-09-18）

- Squid が関所の持つドメインを通していた。Squid は Docker 内蔵 DNS で自ら名前解決するので DNS フィルタの応答を見ず、`https_proxy=<関所>:3128` を指定したクライアントに `github.com` をそのまま通していた。案件のポリシーを一切通さずに実上流へ到達できる。`proxy.enabled` が true のとき、つまり既定で成立する
- 生成する squid.conf で、`github` / `https-relay` / `deny` のドメインを allowlist より前に拒否するようにした。拒否は完全一致なので `.github.com` は残り、api.github.com と codeload.github.com は通る。どちらも関所の管轄ではなく、ワイルドカードごと落とすとソース tarball の取得が壊れる
- 起動・reload・restart の 3 経路すべてに適用。reload では新旧どちらの handler の分も拒否する（再起動までは旧値で動くため）。handler が無ければ生成されるファイルは従来と完全に同一
- 別件: ワイルドカードとそれに含まれる名前を並べて書くと（`deb.debian.org` と `.debian.org`）、Squid は警告ではなく FATAL にするため proxy がまったく起動しなかった。冗長な方を ACL から落とすようにした
- squid.conf のテンプレートは各環境が bind mount するもので、イメージには入っていない。つまりゲートウェイを上げても古いままになる。古いテンプレートには拒否ルールを自分で挿入し、形が分からないテンプレートは生成を失敗させる。関所の持つドメインを通す設定を黙って書かないため

## 0.2.11（2026-09-17）

- `cli/agent.rs`（948 行）を `cli/agent/` に分割した。clap の定義、dispatch、表示、HTTP クライアント。それぞれが 1 つのことだけを知る形になり、表示はエンドポイントを知らず、クライアントはサブコマンドを知らない
- エンドポイントのパスをフラグの隣で宣言するようにした。両者がずれない。パスの無いサブコマンドはコンパイルが通らない。フィールドの対応付けは明示のまま。38 全部をマクロで覆うには 7 つの機能と 16 の例外が要り、読む負担の方が大きい
- `api/handlers.rs` の繰り返されていた前置きを 3 つのヘルパにまとめ、約 150 行を削った。権限は各呼び出し箇所で引数のまま。セキュリティ境界は読める場所に置く
- コマンド、フラグ、エンドポイント、権限、メッセージはいずれも変更なし。47 のヘルプ画面が両言語で完全に一致することを確認した

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
