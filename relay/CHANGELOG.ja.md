# sekimore-relay 変更履歴

*[English](CHANGELOG.md)*

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

## 0.2.17（2026-09-21）

### Security

- レコード集合を MAC で封じ、解錠時に検査するようにした。抜かれた・他ストアから継がれたレコードに気づける (#77)
- 全 PR で `pip-audit` を走らせ、Python 6 パッケージ 29 件の勧告を解消した (#80)

### Fix

- Python のテストジョブが自前のタイムアウト kill を成功として読むのをやめた。0.2.15 から落ち続けていたテストがあった (#80)
- `dashboard.html` に `pr:label` / `pr:assign` / `issue:update` を追加した (#80)

### Enhancement

- 秘密ストアの `export` / `import` を追加した。封じたまま、施錠中でもバックアップが取れる (#77)
- 無人解錠の `relay.store.unlock: file` / `env` を追加した。どちらもパスフレーズを保存するので起動時に警告する (#78)
- `COPY src/` を `uv pip install` の下へ移した。1行の編集で site-packages を作り直さなくなった (#79)

## 0.2.16（2026-09-21）

### Fix

- 制御ソケットに `init` を追加した。パスフレーズの無いストアに `mise run gw:unlock` で設定できる (#73)
- stdin が端末でないときの文言を「端末で実行せよ」から「パイプするな」に変えた (#73)

## 0.2.15（2026-09-21）

### Security

- 番号が PR を指すとき `issue` の書き込みに `pr:*` を要求するようにした。`pr:label` / `pr:assign` を新設 (#67)

### Fix

- 設定リロードを gateway のイベントループへ載せ、ファイアウォールの規則変更と交錯しないようにした (#66)
- `domain_handlers` が中継するドメインを `allow_domains` が覆っていない設定を、起動時に名指しで拒否するようにした (#65)

### Enhancement

- 秘密ストアを追加した。専用ファイルの SQLite、値ごとに AES-256-GCM、レコードの識別子を AAD に使う (#70)
- `unlock` / `lock` / `store-status` / `passphrase` を、relay の状態の隣の unix ソケット経由で追加した (#71)
- `project` 系に `--board 2` を追加した。`config.yml` と URL が既に使っている番号 (#64)
- `project list` が各 item のフィールド値を返すようにした。`update-item` で書いた値を読み戻せる (#64)
- `issue update --number N [--title …] [--body …]` を新しい `issue:update` の下に追加した (#69)
- PR と `main` への push で `:pr-<n>` / `:main` の arm64 イメージを作るようにした。版を消費せず試せる (#63)

## 0.2.14（2026-09-18）

### Fix

- リロードを跨いで `allow_ips` / `block_ips` を保つようにした。ipset が `allow_domains` だけから作り直されていた (#56)
- 古い状態を流す前に Squid の設定を生成するようにした。生成に失敗して両方失うことがなくなった (#56)
- リロードの判定が `proxy` ブロックも比較するようにした。`proxy.enabled` が再起動まで固定だった (#56)
- `issue view` / `pr view` に `node_id` を追加した。既存の issue もボードに載せられる (#56)

## 0.2.13（2026-09-18）

### Security

- 常時有効だった設定リロードを `reload: auto | manual | <duration>` にした。開け直せるのは gateway の中からだけ (#49)
- PR の head を push と同じ glob で検査するようにした。fork 経由で未検査のコードを持ち込めなくなった (#49)
- 起動時の allow ipset を `domain_handlers` も見て作るようにした。上流の実アドレスへ直接到達できなくなった (#49)
- ドメイン比較をラベル境界で行うようにした。`.debian.org` が `evildebian.org` を覆わなくなった (#49)
- SNI の無い TLS 接続に、既定ではなく最も厳しい送信上限を当てるようにした (#49)

### Fix

- 1回の push が上流の同じ ref を2回更新するとき、report-status がどの ref の結果か言えるようにした (#49)
- リロード判定の relay セクションのモデルを広げた。4キーしか持たず、ほとんどの変更を無変更と読んでいた (#49)
- `truncate()` が `str` を1バイトずつ切っていたのを直した。日本語のラベル名でタスクが panic していた (#49)
- 運用コマンドがどこで走るかを明示し、docker bridge 内のプロキシに対する login のタイムアウトを起動時に名指しするようにした (#49)
- `domain_handlers` の綴り違いを拒否し、31文字に切られた ipset 名の衝突をなくした (#49)
- その他: `merged` 欠落が true と読まれる、`repo vocabulary` が読み取り失敗を「ラベル無し」と答える、アイドルタイムアウトが 0 バイトと記録する、SSH のセッションチャネルが解放されない、`glob_match` が指数的にバックトラックする (#49)

### Enhancement

- `python -m src.maint reload-follow 30m` / `reload-freeze` / `reload-status` を追加した (#49)

## 0.2.12（2026-09-18）

### Security

- 生成する `squid.conf` で relay 自身のドメインを拒否するようにした。Squid は Docker の DNS で解決するため、`https_proxy=<gateway>:3128` を設定した者に `github.com` を出していた (#48)
- 拒否するドメインを1つずつ名指しにした。`.github.com` は api.github.com と codeload.github.com を通し続ける (#48)

### Fix

- 起動・リロード・再起動のすべてで拒否を適用し、リロードでは新旧どちらの handler 集合も拒否するようにした (#48)
- それを含むワイルドカードと並ぶ名前を除いた。`deb.debian.org` と `.debian.org` の併記は Squid には FATAL (#48)
- 拒否規則を、それ以前のテンプレートにも挿入するようにした。置き場所が分からないテンプレートは生成を失敗させる (#48)

## 0.2.11（2026-09-17）

### Enhancement

- `cli/agent.rs`（948行）を `cli/agent/` に分割した。clap の木、ディスパッチ、表示、HTTP クライアント (#47)
- 各エンドポイントのパスをフラグの隣で宣言するようにした。パスの無いサブコマンドはコンパイルが通らない (#47)
- `api/handlers.rs` の繰り返しの前置きを3つのスコープヘルパに畳んだ。約150行 (#47)
- コマンド・フラグ・エンドポイント・権限・メッセージは変えていない。47枚のヘルプは両言語ともバイト一致 (#47)

## 0.2.10（2026-09-17）

### Fix

- `SEKIMORE_WEB_HOST` / `SEKIMORE_WEB_PORT` / `SEKIMORE_ULOG_PATH` を実際に読むようにした。誰も使わない定数に入れていた (#46)
- `ULOG_FILE_PATH` の既定を、ulogd が書く `firewall.log` にした。`syslogemu.log` になっていた (#46)

### Enhancement

- `login` が `proxy.upstream_proxy` 経由か直接かを言うようにした (#46)
- 未使用の依存5件を削除した: `thiserror` / `http` / `pydantic-settings` / `python-json-logger` / `jinja2` (#46)
- 呼び出しの無い Rust 関数7つ、`bootstrap` サブコマンド、`bootstrap status`、Python の定義4つを削除した (#46)

## 0.2.9（2026-09-17）

### Fix

- `pr merge` が本文を送るようにした。squash のみのリポジトリが空の本文を 405 で弾いていた (#45)
- `repo:read` を検査するようにした。宣言だけされてどこでも検査されていなかった (#45)

### Enhancement

- `pr merge` に `--method merge|squash|rebase` / `--title` / `--message` / `--delete-branch` を追加した (#45)
- `pr reopen` / `issue reopen` / `issue unlabel` / `issue unassign` / `pr update --title/--body/--base` を追加した (#45)
- `release edit` を追加した。draft を published にするには新しい `release:publish` が要る (#45)
- `ci rerun --run-id N [--all]` と `ci cancel` を新しい `ci:rerun` の下に追加した。`ci:read` ではない (#45)
- `repo vocabulary` を追加した。ラベル、担当にできる人、open なマイルストーン (#45)
- changelog の形式を CI で検査するようにした。行の長さ、日付のみの見出し、両言語の歩調 (#45)

## 0.2.8（2026-09-17）

### Enhancement

- `pr view` / `pr comments` / `pr list` と `issue view` / `issue comments` / `issue list` を追加した (#43)
- `pr comments` が会話・レビュー判定・行コメントを1つの並びに統合するようにした。古い順 (#43)
- `search "is:open label:bug"` を案件横断で追加した。`repo:` で絞り、結果ごとに再検査する (#43)
- `issue:read` と `search:read` を新設した (#43)
- コメント本文は指示ではなくデータだとガイドに書いた (#43)

## 0.2.7（2026-09-17）

### Security

- パスセグメントで `/` と `.` を percent-encode するようにした。細工した tag や CI ref が運用者のトークンで別リポジトリを読めた。0.1.7 から到達可能 (#40)
- Projects v2 のボードを `relay.project.boards` で宣言し起動時に解決するようにした。**破壊的変更**、空なら全 Projects 呼び出しを拒否 (#42)
- `dns_server.py` が `git-relay` としか比較していなかったのを直した。`github` と書いたドメインが relay に届かなかった (#39)

### Fix

- `find_pull_request` が `pr:read` を受け付けるようにした。読み取りに `pr:create` を要求していた (#41)
- force push を拒否するというガイドの記述を訂正した。拒否するのは上流のブランチ保護 (#41)

### Enhancement

- `pr request-review --reviewers alice,bob [--teams t]` を新しい `pr:request_review` の下に追加した (#41)
- `project fields` を追加した。ボードのフィールドと single-select の option id。`update-item` に要る (#42)

## 0.2.6（2026-09-16）

### Enhancement

- `release create --tag vX.Y.Z [--title T] [--notes … | --notes-file F] [--draft] [--prerelease]` と `release view` / `release list` を追加した (#38)
- 本文を渡さなければ、前のタグ以降の PR から GitHub が書くようにした (#38)
- `release:create` と `release:read` を新設した (#38)
- `handler: git-relay` を `handler: github` に改名した。`gitlab` / `gitea` の余地を残す (#38)
- `git-relay` は Rust 側・Python 側とも別名として残した (#38)

## 0.2.5（2026-09-16）

### Fix

- `relay/locales` を Docker の builder ステージへコピーするようにした。これが無く v0.2.4 のイメージは公開されなかった (#36)
- relay 自体の変更は無い。0.2.4 と 0.2.5 は同じコード (#37)

## 0.2.4（2026-09-16）

### Enhancement

- Web UI の文言を `src/locales/{en,ja}.json` へ移した。`?lang=` → cookie → `ui.language` → `Accept-Language` → 英語 の順で解決 (#33)
- `python -m src.maint` が `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` に従うようにした (#33)
- Rust CLI のヘルプと運用者向け出力を `relay/locales/{en,ja}.json` へ移した。欠けたキーは英語、次にキー名 (#34)
- `guide --lang en|ja` を追加した。`agent-guide.{en,ja}.md`、agent-setup が書くものは `SEKIMORE_GUIDE_LANG` (#34)
- README と CHANGELOG を英語正本にし、`README.ja.md` / `CHANGELOG.ja.md` を置いた (#34)
- 拒否理由（`sekimore: …`）と監査ログは英語のままにした (#34)

## 0.2.3（2026-09-16）

### Enhancement

- Web UI の行ごとの push を、rowid カーソルを進める1つのポーラに置き換えた。新着をまとめて1メッセージで送る (#32)
- `/api/stats` を新着後に最短3秒間隔で取るようにした。ログ行ごとではなくなった (#32)
- SQLite を `journal_mode=WAL` / `synchronous=NORMAL` / `busy_timeout` にし、`dns_queries(timestamp)` と `(status, timestamp)` に索引を張った (#32)
- `python -m src.maint db-stats | db-prune | db-reset | db-vacuum` を追加した。記録は自動では消さない (#32)
- 上流が1つでも Relay タブに送信上限を表示するようにした (#32)
- relay 自体の変更は無い (#32)

## 0.2.2（2026-09-16）

### Security

- 443 passthrough の dev → 上流の送信に上限を付けた（`relay.https_max_upload_bytes`、既定 1 MiB、`-1` で無効）。超えた接続は切る (#30)
- `network.allowed_ports` を追加した。許可ドメイン・IP に届く宛先ポートを絞る (#30)

### Enhancement

- `handler: https-relay` を追加した。443 のみを通し、宛先ごとの `max_upload_bytes` を当てる (#30)
- Web UI に宛先ごとの上限、LARGE UPLOAD の印、24時間の件数を追加した (#30)
- `sekimore guide` を追加した。agent-setup が Claude Code のスキルと Codex CLI の `AGENTS.md` に置く (#31)

## 0.2.1（2026-09-16）

### Enhancement

- `project.upstreams.<domain>` を追加した。案件の既定と repos の間に入る上流ごとの層 (#27)
- `ssh_options` を追加した。上流の ssh に `-o` で渡す。relay が強制する項目は上書きできない (#28)
- 上流ごとの `api_base` / `graphql_base` を追加した (#28)
- `keyscan` を追加した。上流や踏み台のホスト鍵を known_hosts に入れ、指紋を表示する (#28)
- Web UI に上流ごとの `ssh_options` / `api_base` を表示し、`ssh_port` の変更を要再起動と判定するようにした (#28)

## 0.2.0（2026-09-16）

### Enhancement

- `domain_handlers` に git-relay を複数書けるようにした。上流ごとに待ち受けポートを分ける (#24)
- `repos[].name` が `host/Org/Repo` を受けるようにした。接続が来た上流に属する repos だけを見る (#24)
- 443 passthrough が TLS の SNI で上流を選ぶようにした (#25)
- `login` / `logout` / `whoami` に `--upstream` を追加した。状態は `/data/relay/upstreams/<host>/` (#25)
- `/bootstrap` が `git_domains` を返すようにした。agent-setup が上流ごとに `Host` と known_hosts を書く (#25)
- Web UI の Relay タブに上流一覧を出した (#26)

## 0.1.9（2026-09-16）

### Enhancement

- 権限を `project` の下にまとめた。`permissions` は `[…]` か `{allow, deny}`、加えて `push` / `tags` / `delete` (#23)
- `repos[]` が `tags` / `delete` / `permissions` を差分で上書きできるようにした (#23)
- `relay.allow_tags` / `relay.allow_delete` を非推奨にした。読みはするが警告付きで既定に畳む (#23)

## 0.1.8（2026-09-16）

### Enhancement

- `ci jobs --number` が PR の全ワークフロー実行をまとめるようにした (#22)
- Docker Publish を `provenance: false` にした (#22)

## 0.1.7（2026-09-16）

### Enhancement

- `ci runs --ref <tag|branch|sha>` と、`ci jobs` / `ci log` の `--run-id` を追加した (#19)
- Docker Publish をアーキごとのネイティブランナーに並列化した。0.1.6 は公開に失敗し飛ばした (#17)

## 0.1.5（2026-09-15）

### Enhancement

- `relay.allow_tags` を追加した (#16)
- `ci:read` と `ci jobs` / `ci log` を追加した。GitHub Actions の失敗ログを末尾から読む (#16)

## 0.1.4（2026-09-15）

### Fix

- Web UI の Relay タブの API が実プロセスで 404 を返すのを直した (#15)

## 0.1.3（2026-09-15）

### Security

- 監査の漏れを塞いだ: tcpip-forward、Authorization 欠落、不正な本文 (#14)
- 同じ鍵での再 bootstrap で前のトークンを失効させ、期限切れ7日後にトークン記録を掃除するようにした (#14)
- dev 側の HTTPS git で credential helper と GIT_ASKPASS を無効にした。運用者の資格情報で relay を迂回できなくなった (#14)

### Fix

- `proxy.enabled` を尊重し、認証バナーを外し、拒否した push を report-status で `ng` と返すようにした (#14)

### Enhancement

- Web UI の Relay タブ、`pr status`（`pr:read`）、署名鍵のコメントに案件名とユーザ名を追加した (#14)

## 0.1.0 〜 0.1.2（2026-09-08 〜 13）

### Enhancement

- 最初のリリース。SSH（git）と GitHub API の中継、案件ポリシー、`refs/for/<base>` からの PR 作成、bootstrap、443 passthrough、devcontainer base への同梱 (#11)
