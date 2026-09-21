# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**AI エージェント向けセキュリティゲートウェイ** - Docker 用の DNS / ファイアウォール / プロキシ

Docker 上で動く AI エージェント環境のために設計したセキュリティゲートウェイです。DNS によるアクセス制御、iptables/ipset のファイアウォール管理、任意で Squid プロキシとの連携を提供します。

## 機能

### コアのセキュリティ

- **DNS ベースのアクセス制御**: 許可リスト / 拒否リストによる動的なドメインフィルタリング
- **多層ファイアウォール**: コンテナ側とホスト側の iptables ルールによる多重防御
- **DNS 持ち出し対策**: エージェントからの許可されていない DNS 問い合わせを遮断
- **静的 IP フィルタリング**: CIDR と IP レンジによる追加のアクセス制御

### 動的な構成

- **Docker API 連携**: Docker API でネットワーク構成を自動検出
- **サブネット固定なし**: サブネットを動的に割り当てる複数組織の運用に対応
- **自動探索**: AI エージェントは ARP によるサブネット走査でゲートウェイを見つける

### 監視と運用

- **Web UI**: ポート 8080 のリアルタイム監視ダッシュボード
- **パケットログ**: ulogd2 を使った NFLOG ベースのファイアウォールログ
- **SQLite データベース**: アクセスログと統計の永続化（WAL + 索引。記録は操作者が掃除するまで残る）
- **保守用 CLI**（0.2.3）: ゲートウェイコンテナ内で `python -m src.maint db-stats | db-prune --before-days N --yes | db-reset --yes | db-vacuum`。ゲートウェイの稼働中でも安全に実行できる。関所の監査ログ（`/data/relay/audit.jsonl`）は別管理で、これらの操作では触らない。Dev Containers 環境では `mise run gw:db-stats` / `gw:db-prune` / `gw:db-reset` として用意されている
- **ローカライズされた UI**（0.2.4）: Web UI は英語と日本語を備え、閲覧者ごとに切り替わる。[ローカライズ](#ローカライズ-024) を参照

### 任意のコンポーネント

- **Git / GitHub API 中継関所（sekimore-relay）**: 任意で有効化するコンテナ内の関所。AI エージェントが上流の資格情報を一切持たないまま、案件単位のポリシーのもとで `git@github.com:…` と小さな GitHub API CLI を使えるようにする。[relay/README.md](relay/README.md) を参照
- **Squid プロキシ**: 上流プロキシにも対応した HTTP/HTTPS キャッシュプロキシ
- **企業プロキシとの連携**: 企業環境向けの透過的なプロキシチェーン

## クイックスタート

### 前提

- Docker 20.10 以降
- Docker Compose 2.0 以降
- iptables が使える Linux ホスト

### インストール

1. リポジトリを clone する:

```bash
git clone https://github.com/YOUR_USERNAME/sekimore-gw.git
cd sekimore-gw
```

2. サンプル設定をコピーする:

```bash
cp config/config.sample.yml config/config.yml
```

3. （任意）上流プロキシの認証が必要なら `.env` を作る:

```bash
cp .env.example .env
# .env を編集し、プロキシ認証の設定をコメント解除する
```

4. `config/config.yml` を編集して、許可 / 拒否するドメインと IP を設定する。

5. ゲートウェイを起動する:

```bash
docker-compose up -d
```

6. `http://localhost:8080` で Web UI を開く。

### 例: AI エージェントのセットアップ

`docker-compose.yml` の `ai-agent` サービスをコメント解除して起動します:

```yaml
ai-agent:
  image: python:3.11-slim
  cap_add:
    - NET_ADMIN
  networks:
    internal-net: {}
  dns:
    - 127.0.0.1  # Disable Docker internal DNS
  dns_search: []
  volumes:
    - ./agent-setup.sh:/agent-setup.sh:ro
  command: ["/agent-setup.sh"]
  depends_on:
    - sekimore-gw
```

エージェントは自動でゲートウェイを見つけ、すべての通信をそこへ流します。

### 操作者向けの mise タスク

ホストからゲートウェイを操作する `gw:*` タスクはイメージに同梱しています
（`/usr/local/share/sekimore/gateway.mise.toml`）。各プロジェクトはこれを取り込んで使ってください。
タスクをコピーすると、関所の更新から取り残されます:

```bash
docker exec sekimore-gw cat /usr/local/share/sekimore/gateway.mise.toml \
  > .devcontainer/gateway.mise.toml
```

```toml
# プロジェクト側の mise.toml
[task_config]
includes = [".devcontainer/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/scripts/sgw.sh"
```

`sgw.sh` はプロジェクトのものです（コンテナを見つける役なので、イメージからは配れません）。タスクが使うのは
`gw` / `gw-tty` / `id` / `recreate` の 4 つだけです。`gw-tty`（常に `docker exec -it`）は、
端末からパスフレーズを読む `gw:unlock` と `gw:passphrase` に必要です。

## 設定

### 環境変数（任意）

`.env` は任意です。上流プロキシの認証が必要なときだけ作ってください:

```bash
# Optional: Upstream Proxy Authentication
SEKIMORE_UPSTREAM_PROXY_USERNAME=your-username
SEKIMORE_UPSTREAM_PROXY_PASSWORD=your-password
```

**補足**: Docker Compose はディレクトリ名をプロジェクト名として使います。ネットワーク名は既定値（`internal-net` と `internet`）です。必要なら環境変数で上書きしてください。

### ドメインフィルタリング

`config/config.yml` を編集します:

```yaml
allow_domains:
  - pypi.org
  - .pythonhosted.org  # Wildcard: *.pythonhosted.org
  - api.openai.com

block_domains:
  - .malicious.com

network:
  allowed_ports: [80, 443]   # Optional (0.2.2): destination TCP ports allowed towards allow-listed
                             # domains/IPs. Empty (default) keeps the previous behaviour (all ports).
```

`allowed_ports` を絞ると、許可 IP への SSH のような迂回路をふさげます。変更にはコンテナの再起動が必要です。

### プロキシの設定

```yaml
proxy:
  enabled: true
  port: 3128
  cache_enabled: true
  cache_size_mb: 1000
  upstream_proxy: "proxy.company.com:8080"  # Optional
```

## ローカライズ (0.2.4)

第一言語は英語です。人が読むところには日本語も用意し、機械が読むところは英語のままにしています。

### Web UI

ダッシュボードの文言は `src/locales/<lang>.json`（`en`、`ja`）から読み込みます。`/api/i18n` が言語を決めて辞書を返し、画面は `data-i18n` 属性でそれを当てはめます。ヘッダの言語セレクタは `sekimore_lang` cookie（1 年、`SameSite=Lax`）を設定して再読み込みします。

解決の順序（先に一致したものを採用）:

| 順 | 参照元 | 補足 |
|----|--------|------|
| 1 | `?lang=en` / `?lang=ja` クエリ | その場限りの上書き。リンクやスクリーンショット向き |
| 2 | `sekimore_lang` cookie | 言語セレクタが設定するもの。閲覧者ごと |
| 3 | `config.yml` の `ui.language` | `auto` 以外のときだけ有効 - 全員の言語を固定する |
| 4 | `Accept-Language` | ブラウザの設定 |
| 5 | 英語 | 既定 |

ブラウザに追従させたくない場合は `config/config.yml` で固定します:

```yaml
ui:
  language: auto   # auto | en | ja  (default: auto)
```

未対応の言語タグは英語に落ち、翻訳に無いキーは英語の文言に落ちます。翻訳が途中でも UI が空欄になることはありません。

### CLI

コマンドライン側は設定ファイルではなく環境変数に従います。`SEKIMORE_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG` の順に見て、既定は英語です。ゲートウェイコンテナ内の `python -m src.maint` と、Rust の `sekimore-relay` バイナリが対象です。

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

### 英語のままにしているもの

拒否メッセージ（関所が標準エラーに書く `sekimore: ...` の行）と監査ログは、ロケールに関わらず常に英語です。スクリプトや CI、AI エージェントがこの文字列で判定するため、操作者の言語で変わってはいけません。

### ドキュメント

ドキュメントは英語を主とし、`*.ja.md` の翻訳を横に置きます。このファイルと [README.md](README.md)、[relay/README.md](relay/README.md) と [relay/README.ja.md](relay/README.ja.md) がそれにあたります。

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

- **internal-net**: AI エージェントが接続する側（サブネットは動的）
- **internet**: ゲートウェイの外向きインターフェース（サブネットは動的）
- **ホスト側ファイアウォール**: 許可されていない通信を止める追加の層

### セキュリティの層

1. **DNS フィルタリング**: 許可ドメインだけが名前解決できる
2. **コンテナのファイアウォール**: sekimore-gw 内の iptables/ipset ルール
3. **ホストのファイアウォール**: Docker ホスト側の追加 iptables ルール
4. **DNS 持ち出し対策**: ゲートウェイ以外からのポート 53 を遮断

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

# All tests except E2E (for CI/devcontainer)
uv run pytest -m "not e2e" -v

# E2E tests (requires docker-compose, run on host machine only)
uv run pytest tests/e2e/ -v

# With coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

**E2E テストの注意:**
- E2E テスト（`tests/e2e/`）は実際のポートバインドと Docker 連携を検証する
- docker-compose が使えるホストマシンで実行すること（CI や devcontainer では不可）
- 検証内容:
  - DNS サーバが実際にポート 53 を掴むこと
  - Docker API によるサブネットの自動検出
  - 実際の DNS 応答
- 実行方法: `pytest tests/e2e -v`（先に既存のコンテナを止めておくこと）

## Docker イメージ

### ローカルでビルドする

```bash
docker build -t sekimore-gw:latest .
```

### GitHub Container Registry から取得する

```bash
docker pull ghcr.io/Amakata/sekimore-gw:latest
```

### 作業用のイメージ (preview)

プルリクエストと `main` への push で、検証用のイメージが焼かれます。**公式版ではありません。**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # そのプルリクエストの内容
docker pull ghcr.io/Amakata/sekimore-gw:main    # main の先端
```

`linux/arm64` のみです。タグは次の push で書き換わるので、動かし続けるものに指しては
いけません。版番号 (`:0.2.14`) と `:latest` は `v*.*.*` タグからのみ作られます。

これが無いと、変更を実機で試すために公式版を切るしかありません。作業としてのデプロイと
公式版の公開を分けるためのものです。

## 複数組織での利用

`COMPOSE_PROJECT_NAME` を変えれば、組織ごとに独立したインスタンスを動かせます:

```bash
# Organization A
COMPOSE_PROJECT_NAME=sekimore-org-a docker-compose up -d

# Organization B
COMPOSE_PROJECT_NAME=sekimore-org-b docker-compose up -d
```

ネットワークとサブネットは自動的に分離されます。

## Git / GitHub API 中継関所（sekimore-relay）

任意の機能です。`config.yml` に `domain_handlers: { github.com: { handler: git-relay } }` があると、ゲートウェイはイメージに同梱された Rust 製の `sekimore-relay` を起動します。DNS は `github.com` をゲートウェイに向け、関所はポート 22 で使い捨てのエージェント鍵による SSH の `git` を受け、案件単位のポリシー（許可リポジトリ、読み取り専用 / 読み書き、PR のベースブランチ、`pr:create` / `issue:comment` などの権限）を適用し、`git push HEAD:refs/for/main` をブランチ + プルリクエストに変換して、操作者の ssh-agent とエージェントには見えない device flow のトークンで本物の上流へ中継します。`domain_handlers` が無ければ何も変わりません。

セットアップ、エージェント側の手順、日々の使い方、トラブルシュート: **[relay/README.ja.md](relay/README.ja.md)**。

## トラブルシューティング

### エージェントがゲートウェイを見つけられない

- `dns: [127.0.0.1]` が設定されていることを確認する（Docker 内部 DNS を無効化する）
- サブネットの大きさを確認する。/24 以下が最も安定する
- エージェントのログを見る: `docker logs <agent-container>`

### DNS の名前解決に失敗する

- `config/config.yml` に許可ドメインがあるか確認する
- Web UI で拒否されたリクエストを確認する
- ファイアウォールのログを見る: `docker logs sekimore-gw`

### Web UI が遅い、またはデータベースが大きい

- `docker compose exec sekimore-gw python -m src.maint db-stats` で行数、期間、索引、`journal_mode`（0.2.3 以降は `wal` のはず）を確認できる
- 記録が自動で消えることはない。減らすなら `python -m src.maint db-prune --before-days 90 --yes --vacuum`、作り直すなら `python -m src.maint db-reset --yes`
- どちらもゲートウェイの稼働中に実行でき、その後も DNS / ファイアウォール / プロキシは記録を続ける

### ホスト側のファイアウォールが効かない

- docker-compose.yml に `privileged: true` があることを確認する
- ホストの iptables を確認する: `sudo iptables -L -n -v`

## コントリビュート

開発の進め方は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## ライセンス

Apache License 2.0 - 詳細は [LICENSE](LICENSE) を参照してください。

## バージョン

1つのイメージに gateway と関所が入り、版番号は共通です。

- [CHANGELOG.ja.md](CHANGELOG.ja.md) — gateway 側（DNS、ファイアウォール、Squid、Web UI、ビルド）
- [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) — 関所側

どちらも先頭が現在の版です。
