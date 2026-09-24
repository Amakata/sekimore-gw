# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**GitHub アカウントを渡さずに、AI エージェントに GitHub 上の作業をさせる。**

エージェントにプルリクエストを作らせるには、通常はトークンを渡します。プルリクエストを作れるトークンは
`repo` スコープを持ち、**あなたのアカウントがアクセスできるすべてのリポジトリへの読み書き権限**を与えます。
鍵の置き場所を変えても解決しません。ターミナルを持つエージェントは `~/.ssh` も `.env` も読めるためです。

sekimore-gw は、この資格情報を**エージェントの外**に置きます。エージェントが持つのは使い捨ての鍵とプロジェクトトークンだけで、
どちらもこのゲートウェイ以外では通用しません。

```console
$ curl -H "Authorization: token $SEKIMORE_TOKEN" https://api.github.com/user
401 Bad credentials          # GitHub はプロジェクトトークンを拒否する

$ sekimore pr create --title "..." --base main    # ゲートウェイ経由では、許可した操作が通る
#42 https://github.com/Org/Repo/pull/42

$ sekimore pr merge --number 42                   # 許可していない操作は、ここで拒否される
sekimore: denied: pr:merge is not allowed by policy
```

この構成では `gh` を使いません。トークンを持つ `gh` はゲートウェイを通らずに GitHub へ直接接続するため、
**ここで設定した権限がどれも適用されません**。ポリシーで `pr:merge` を拒否していても、`gh pr merge` は成功します。
そのため [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) のイメージにも `gh` は含めていません。

**かわりに、運用者は権限を操作ごとに付与します。**

```yaml
# config.yml — プロジェクトごとに設定する
permissions: [pr:create, pr:read, issue:create, issue:comment, ci:read]
repos:
  - { name: Org/Repo, mode: read-write, bases: [main] }
```

指定できる権限は次の 33 種類です。

```
pr:      create  read  comment  comment_update  comment_delete  review  request_review
         label  assign  close  merge
issue:   create  read  update  comment  comment_update  comment_delete  label  assign  close
ci:      read  rerun  dispatch          security: read  dismiss
release: create  read  publish          project:  read  add_item  update_item
repo:    read                           search:   read
```

関所（sekimore-relay）が付与するのは、設定に書かれた権限だけです。`permissions` を設定しなければ、すべての権限が拒否されます。
そのため `pr:merge`、`ci:rerun`、`ci:dispatch`、`security:dismiss` のような影響の大きい権限は、運用者が追加するまで拒否されたままです。リポジトリごとに権限を追加・削除することもできます。

これらの操作はすべて `sekimore` コマンドで行います。`sekimore guide` は、エージェント向けの利用ガイドを表示します。

## クイックスタート

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # 許可するドメインを書く
docker compose up -d                             # http://localhost:8080 で監視画面
```

ゲートウェイには Docker 20.10 以降、Docker Compose 2.0 以降、および iptables が動作する Linux ホストが必要です。
ホストが認証の必要な上流プロキシの内側にある場合は、ゲートウェイを起動する前に `cp .env.example .env` を実行して `.env` を編集します。

**dev コンテナで使う場合は、こちらではなく [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) の
`examples/sgw-sample/` を複製してください。** このサンプルには、ゲートウェイのコンテナ、dev コンテナ、
ホスト側のタスクが、連携するよう設定済みの状態で含まれています。

## 機能

| | |
|---|---|
| **エージェントに鍵を渡さない git 操作** | エージェントが持つのは、このゲートウェイだけが受け付ける使い捨ての鍵です。ゲートウェイは各操作を運用者の鍵で GitHub に転送します。 |
| **GitHub 操作ごとの権限** | たとえば `pr:merge` は拒否し、`issue:create` は許可できます。プロジェクト外のリポジトリには、どのリクエストも届きません。 |
| **宛先の許可リスト** | 許可リストにないドメインは名前解決できません。エージェントが IP アドレスを直接指定して接続しても、ファイアウォールがその接続を破棄します。 |
| **送信量の上限** | ゲートウェイは、ゲートウェイが扱う宛先へ各接続が送ったバイト数を数えます。上限を超えた接続を切断し、監査ログに記録します。 |
| **監査ログ** | 監査ログには、拒否した操作だけでなく許可した操作も記録されます。 |
| **ゲートウェイによるコミット署名** | 署名鍵はゲートウェイが保持します。エージェントは署名を依頼できますが、鍵にはそれ以外の方法でアクセスできません。署名したコミットは GitHub で Verified と表示されます。 |

dev コンテナで使う場合、dev 側の土台は [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) が提供します。

## 向くとき、向かないとき

**sekimore-gw が向くのは**、エージェントに GitHub 上の作業をさせつつ、その範囲を制限したい場合です。
プルリクエストは作らせるがマージはさせない、操作できるのはこのリポジトリだけにする、すべてのコミットに署名する、
送信量に上限をかける、そしてすべての操作を記録する、といった制限です。その間、エージェントは上流の資格情報を一切持ちません。

**sekimore-gw が向かないのは**、次のような場合です。より小さな仕組みや別の仕組みのほうが適しています。

| | |
|---|---|
| GitHub 以外の上流で API を制限したい | SSH の git 中継はどの Git ホストでも動作しますが、**API の変換は GitHub にのみ対応しています**。GitLab や社内の Artifactory は、ドメインとして許可するか、送信量の上限をかけてポート 443 で通すことはできますが、それ以上の制限はできません。これを変える作業は [#50](https://github.com/Amakata/sekimore-gw/issues/50) で扱います。 |
| リクエストの内容で許可を決めたい | ゲートウェイは TLS を終端しないため、宛先とバイト数は分かりますが、リクエストそのもの（たとえば `GET /v1/public/`）は見えません。そのかわり、MITM 証明書が不要です。 |
| ネットワークを制限したいだけ | 4 つの層と関所は、エージェントが GitHub で行える操作を制限するためのものです。宛先を制限するだけなら、より単純な仕組みで足ります。 |
| エージェントが GitHub を使わない | 人が git コマンドを実行するなら、関所の役割はありません。 |

## 仕組み

sekimore-gw は、1 つのファイル（`config.yml`）から 4 つの層を構成します。**1 つの層だけを制限すると、残りの層が迂回路になる**ため、
4 つの層をまとめて設定します。

| 層 | 役割 |
|---|---|
| **DNS**（:53） | 許可リストにあるドメインにだけ実際の IP アドレスを返し、同時にそのアドレスをファイアウォールで許可します。ゲートウェイが扱うドメインは、ゲートウェイ自身のアドレスに解決されます。 |
| **ファイアウォール** | iptables と ipset を使います。DNS が許可した宛先とポートだけを通します。エージェントが IP アドレスを直接指定した接続は、ここで止まります。 |
| **Squid**（:3128） | プロキシ経由の迂回を防ぎます。Squid は自身で名前解決を行うため、DNS フィルタリングだけでは防げません。 |
| **関所**（sekimore-relay） | git（SSH :22）、GitHub API（:8420）、その他の HTTPS（:443）を扱います。**上流の資格情報を持つのは関所だけです。** |

詳しくは [アーキテクチャ](#アーキテクチャ) を、関所については [relay/README.ja.md](relay/README.ja.md) を参照してください。

## そのほかの機能

- **Web UI**（:8080）: 通信をリアルタイムで表示します。英語と日本語に対応し、閲覧者ごとに言語を選べます。
- **パケットログ**: ulogd2 を通じて NFLOG でパケットを記録します。
- **SQLite**: アクセスログと統計を保存します（WAL モード、索引付き）。記録の削除には `mise run gw:db-prune` などの `gw:db-*` タスクを使います。
  関所の監査ログ（`/data/relay/audit.jsonl`）は別のファイルで、これらのタスクの影響を受けません。
- **Squid と企業プロキシ**: ゲートウェイは上流プロキシの内側でも動作します。
- **サブネットの固定が不要**: ゲートウェイは Docker API からネットワーク構成を読み取るため、Docker が別のサブネットを割り当てても動作します。

## 例: AI エージェントのセットアップ

`docker-compose.yml` には、サンプルのエージェントとして `ai-agent` サービスが定義されています。ほかのサービスと一緒に起動します。

```yaml
ai-agent:
  build:
    context: .
    dockerfile: Dockerfile.agent
  cap_add:
    - NET_ADMIN            # the agent sets its own default route
  networks:
    internal-net: {}
  dns:
    - 127.0.0.1            # disables Docker's internal DNS (127.0.0.11), which would bypass the filter
  dns_search: []
  volumes:
    - ./agent-setup.sh:/agent-setup.sh:ro
  command: ["bash", "-c", "/agent-setup.sh && sleep infinity"]
  depends_on:
    sekimore-gw:
      condition: service_healthy
```

エージェントはゲートウェイを自動で見つけ、すべての通信をゲートウェイ経由で送ります。

### 運用者向けのタスク（mise）

運用者がゲートウェイを操作する `gw:*` タスクは、2 つの言語でイメージに同梱しています。
`/usr/local/share/sekimore/gateway.mise.en.toml` と `gateway.mise.ja.toml` です。
プロジェクトはタスクをコピーせず、どちらかのファイルを取り込みます。コピーしたタスクは、関所の変更に伴う更新を受け取れないためです。
sgw-devcontainer-base 0.2.20 以降では、`mise run upgrade:sync`（または `upgrade:apply`）がゲートウェイのリリースタグからこのファイルを取り出し、
`sgw.sh` と同じ場所の `.devcontainer/sgw/gateway.mise.toml` に書き込みます。このファイルは編集しないでください。
手で編集されていると、次のアップグレードは上書きせずに停止します。`gw:*` タスクを変更したいときは、
同じ名前のタスクをプロジェクト自身の `mise.toml` に定義してください。その定義が取り込んだタスクより優先されます。

言語の選択で変わるのは、`mise tasks` が表示する説明文だけです。タスク名と実行するコマンドは両方のファイルで同一で、
テストでそれを検証しています。

```toml
# プロジェクト側の mise.toml
[task_config]
includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
```

`sgw.sh` はプロジェクト側で管理します。このスクリプトはゲートウェイのコンテナを特定する役割を持つため、イメージからは提供できません。
タスクが使うサブコマンドは `gw`、`gw-tty`、`id`、`recreate` の 4 つだけです。`gw-tty` は常に `docker exec -it` を実行します。
`gw:unlock` と `gw:passphrase` は端末からパスフレーズを読むため、`gw-tty` を必要とします。

0.2.29 以降は、ゲートウェイを作り直すたびにパスフレーズを入力する必要はありません。`mise run gw:keychain-set` は、
ホスト自身の秘密ストア（macOS Keychain、`secret-tool` 経由の Secret Service、または `/etc/sekimore` 以下の root 所有ファイル）に
パスフレーズを一度だけ保存します。以後は `gw:recreate` がゲートウェイの秘密ストアを自動で解錠します。
秘密ストアを施錠したままにするには `SGW_NO_AUTO_UNLOCK=1` を設定します。ゲートウェイ自体はこの処理に関与しません。
パスフレーズはこれまでどおり control socket 経由で届き、コンテナの中からホストのパスフレーズを取り出す手段はありません。
`gw:unlock` は変わらず、ホストにパスフレーズが保存されていないときに秘密ストアを解錠する手段として使えます。

## 設定

### 上流プロキシの認証

社内プロキシの資格情報は、`.env` ではなく秘密ストアに保存してください。

```bash
mise run gw:proxy-credential      # ユーザー名とパスワードを尋ね、封をして保存する
```

秘密ストアが解錠されると、Squid と関所（HTTPS の passthrough と GitHub API の呼び出し）はどちらも秘密ストアから資格情報を読み、
変更も再起動なしに反映します。関所がどの資格情報を使っているかは `mise run gw:check` で確認できます。
秘密ストアに資格情報がないときは、ゲートウェイは引き続き `SEKIMORE_UPSTREAM_PROXY_USERNAME` と `SEKIMORE_UPSTREAM_PROXY_PASSWORD` を読みます。
ただし `.devcontainer/.env` は dev コンテナの `env_file` でもあるため、そこに書いた値はエージェントから読めます。

**補足**: Docker Compose は既定でディレクトリ名をプロジェクト名として使います。ゲートウェイは既定のネットワーク名
`internal-net` と `internet` を使います。別の名前を使うには、環境変数 `INTERNAL_NETWORK_NAME` と `INTERNET_NETWORK_NAME` を設定します。

### ドメインフィルタリング

`config/config.yml` を編集します。

```yaml
allow_domains:
  - pypi.org
  - .pythonhosted.org  # Wildcard: *.pythonhosted.org
  - api.openai.com

block_domains:
  - .malicious.com

network:
  allowed_ports: [80, 443]   # Optional (0.2.2): destination TCP ports allowed towards allowlisted
                             # domains/IPs. Empty (default) keeps the previous behavior (all ports).
```

`allowed_ports` を制限すると、許可リストにある IP アドレスへの SSH のような迂回路を塞げます。`allowed_ports` の変更には、コンテナの再起動が必要です。

### プロキシの設定

```yaml
proxy:
  enabled: true
  port: 3128
  cache_enabled: true
  cache_size_mb: 1000
  upstream_proxy: "proxy.company.com:8080"  # Optional
```

## ローカライズ（0.2.4）

第一言語は英語です。人が読むテキストには日本語も用意し、機械が読むテキストは英語のままにしています。

### Web UI

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

### CLI

コマンドラインツールは、設定ファイルではなく環境変数に従います。`SEKIMORE_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG` の順に参照し、
どれもなければ英語を使います。対象は、ゲートウェイのコンテナ内の `python -m src.maint` と、Rust 製の `sekimore-relay` バイナリです。

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

### 英語のままにしているもの

拒否メッセージ（関所が標準エラー出力に書く `sekimore: ...` の行）と監査ログは、ロケールにかかわらず常に英語です。
スクリプト、CI、AI エージェントがこの文字列で判定するため、運用者の言語によって変わってはいけません。

### ドキュメント

ドキュメントは英語で書き、各ファイルの隣に日本語訳（`*.ja.md`）を置きます。このファイルと [README.md](README.md)、
[relay/README.md](relay/README.md) と [relay/README.ja.md](relay/README.ja.md) が該当します。

## アーキテクチャ

```
┌─────────────────┐       ┌──────────────┐       ┌────────────────┐
│ AI エージェント │──────▶│ sekimore-gw  │──────▶│ インターネット │
│ (internal)      │       │ (gateway)    │       │                │
└─────────────────┘       └──────────────┘       └────────────────┘
                                 │
                                 │ Web UI :8080
                                 ▼
                           ┌────────────┐
                           │ ブラウザ   │
                           └────────────┘
```

### ネットワーク設計

- **internal-net**: AI エージェントが接続するネットワーク（サブネットは動的）
- **internet**: ゲートウェイの外向きインターフェース（サブネットは動的）
- **ホスト側ファイアウォール**: 許可されていない通信を遮断する追加の層

### セキュリティの層

1. **DNS フィルタリング**: 許可リストにあるドメインだけを名前解決
2. **コンテナのファイアウォール**: sekimore-gw 内の iptables/ipset ルール
3. **ホストのファイアウォール**: Docker ホスト上の追加の iptables ルール
4. **DNS 経由の持ち出し対策**: ゲートウェイ以外からのポート 53 を遮断

## 開発

### 必要なもの

- Python 3.11 以降
- [uv](https://github.com/astral-sh/uv)（Python のパッケージマネージャ）

### セットアップ

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Run linter
uv run ruff check src/
uv run ruff format src/

# Type check
uv run mypy src/
```

### テスト

```bash
# Unit tests
uv run pytest tests/unit/ -v

# Integration tests (includes timeout tests for infinite loop detection)
uv run pytest tests/integration/ -v

# All tests except E2E (for CI and the dev container)
uv run pytest -m "not e2e" -v

# E2E tests (require docker compose; run on the host machine only)
uv run pytest tests/e2e/ -v

# With coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

**E2E テストの注意:**
- E2E テスト（`tests/e2e/`）は、実際のポートバインドと Docker との連携を検証します。
- `docker compose` が使えるホストマシンで実行してください。CI や dev コンテナでは実行できません。
- 検証する内容:
  - DNS サーバが実際にポート 53 にバインドすること
  - Docker API によるサブネットの自動検出
  - 実際の DNS 応答
- 既存のコンテナを止めてから、`pytest tests/e2e -v` で実行します。

## Docker イメージ

### ローカルでビルドする

```bash
docker build -t sekimore-gw:latest .
```

### GitHub Container Registry から取得する

```bash
docker pull ghcr.io/Amakata/sekimore-gw:latest
```

### プレビューイメージ

プルリクエストと `main` への push で、検証用のイメージがビルドされます。**これらのイメージはリリースではありません。**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # そのプルリクエストのイメージ
docker pull ghcr.io/Amakata/sekimore-gw:main    # main の先端
```

プレビューイメージは `linux/arm64` 向けにのみビルドされます。タグは次の push で上書きされるため、
長期間動かし続けるものから参照してはいけません。バージョンタグ（`:0.2.14`）と `:latest` は、`v*.*.*` の Git タグからのみ作られます。

プレビューイメージは、変更を試すためのデプロイとバージョンの公開を分けるためのものです。
プレビューイメージがなければ、変更を実機で試すためにリリースが必要になります。

## 複数組織での利用

`COMPOSE_PROJECT_NAME` を変えると、組織ごとに分離したインスタンスを動かせます。

```bash
# Organization A
COMPOSE_PROJECT_NAME=sekimore-org-a docker compose up -d

# Organization B
COMPOSE_PROJECT_NAME=sekimore-org-b docker compose up -d
```

各インスタンスのネットワークとサブネットは自動的に分離されます。

## Git / GitHub API の中継関所（sekimore-relay）

関所は任意の機能です。`config.yml` に `domain_handlers: { github.com: { handler: git-relay } }` があると、
ゲートウェイはイメージに同梱された Rust 製のプログラム `sekimore-relay` を起動します。関所を有効にすると、次のように動作します。

- DNS は `github.com` をゲートウェイのアドレスに解決します。
- 関所はポート 22 で SSH 経由の `git` を受け付け、使い捨ての鍵でエージェントを認証します。
- 関所はプロジェクト単位のポリシーを適用します。対象は、許可するリポジトリ、読み取り専用か読み書きか、プルリクエストのベースブランチ、
  `pr:create` や `issue:comment` などの権限です。
- 関所は `git push HEAD:refs/for/main` を、ブランチとプルリクエストに変換します。
- 関所は、運用者の ssh-agent と、エージェントからは見えない device flow のトークンを使って、本物の上流へ転送します。

`domain_handlers` がなければ関所は起動せず、ゲートウェイの動作は変わりません。

セットアップ、エージェント側の手順、日々の使い方、トラブルシューティングは **[relay/README.ja.md](relay/README.ja.md)** を参照してください。

## トラブルシューティング

### エージェントがゲートウェイを見つけられない

- `dns: [127.0.0.1]` が設定されていることを確認します。この設定で Docker の内部 DNS が無効になります。
- サブネットの大きさを確認します。エージェントがサブネット全体を走査するのは、プレフィックス長が 24 以上
  （アドレスが 256 個以下。たとえば /24 や /25）の場合だけです。それより大きいサブネットでは、一部のアドレスだけを確認します。
- エージェントのログを確認します: `docker logs <agent-container>`

### DNS の名前解決に失敗する

- `config/config.yml` に許可するドメインが書かれているか確認します。
- Web UI で、拒否されたリクエストを確認します。
- ファイアウォールのログを確認します: `docker logs sekimore-gw`

### Web UI が遅い、またはデータベースが大きい

- `docker compose exec sekimore-gw python -m src.maint db-stats` で、行数、期間、索引、`journal_mode` を確認できます。0.2.3 以降では `journal_mode` は `wal` です。
- ゲートウェイが記録を自動で削除することはありません。古い記録を削除するには `python -m src.maint db-prune --before-days 90 --yes --vacuum` を、空のデータベースからやり直すには `python -m src.maint db-reset --yes` を実行します。
- どちらのコマンドもゲートウェイの稼働中に実行できます。実行後も、DNS、ファイアウォール、プロキシは記録を続けます。

### ホスト側のファイアウォールが効かない

- docker-compose.yml に `privileged: true` が設定されていることを確認します。
- ホストの iptables ルールを確認します: `sudo iptables -L -n -v`

## コントリビュート

開発の進め方は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## ライセンス

Apache License 2.0 — 詳細は [LICENSE](LICENSE) を参照してください。

## バージョン

ゲートウェイと関所は 1 つのイメージに同梱され、バージョン番号も共通です。

- [CHANGELOG.ja.md](CHANGELOG.ja.md) — ゲートウェイ（DNS、ファイアウォール、Squid、Web UI、ビルド）
- [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) — 関所

どちらの変更履歴も、現在のバージョンを先頭に記載しています。
