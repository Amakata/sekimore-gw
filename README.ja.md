# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**アカウントを渡さずに、AI エージェントに GitHub 上の作業をさせる。**

sekimore-gw（sgw）は、Docker で動く AI エージェントのためのネットワークゲートウェイです。

- 1 つのコンテナに全部入り:
  - DNS フィルタ
  - IP ファイアウォール
  - HTTP プロキシ
  - git と GitHub API の relay（関所、sekimore-relay）
- 設定は 1 つの `config.yml`
- GitHub の資格情報は関所が持つ。エージェントは持たない
- 権限は操作ごと: `pr:create` は許可、`pr:merge` は拒否
- 許可した通信もブロックした通信も Web UI で見える

## トークンでは足りない理由

- コンテナの中のトークンは、エージェントに読める
- トークンはリポジトリを絞れても、操作は絞れない
- 何をしたかの記録が残らない

## はじめかた

必要なもの:

- Docker（macOS は Docker Desktop、Linux は Docker Engine）
- VS Code と Dev Containers 拡張

1. `sgw` を入れる:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. 雛形を書く:
   ```bash
   sgw init --devcontainer my-project
   cd my-project
   ```
3. `.devcontainer/.env` と `.devcontainer/config/config.yml` を埋める
4. VS Code を完全に終了してから開き直し、「Reopen in Container」を選ぶ:
   ```bash
   sgw open
   ```
   ⚠️ VS Code は必ず `sgw open` で起動する
5. 秘密ストアを解錠する:
   ```bash
   sgw unlock
   ```
   ⚠️ 初回に決めたパスフレーズで、以後も解錠する
6. GitHub にログインする:
   ```bash
   sgw login
   ```
   ⚠️ 初回だけ。結果は秘密ストアに入る
7. 確認する:
   ```bash
   sgw verify
   ```

## 何を設定すると何が起きるか

設定は `.devcontainer/config/config.yml`。全キーの説明は [config.sample.yml](config/config.sample.yml)。

| 設定 | 効果 |
|---|---|
| `allow_domains` | エージェントが届いてよい宛先 |
| `domain_handlers` | 関所を通すドメイン: git、GitHub API、HTTPS |
| `relay.project.repos` | エージェントが触ってよいリポジトリ |
| `relay.project.permissions` | 許す操作 |
| `network.allowed_ports` | 届いてよいポート |

| したいこと | コマンド |
|---|---|
| 秘密ストアを解錠する（ゲートウェイのコンテナを作り直したあとは施錠されている） | `sgw unlock` |
| 解錠を自動にする | `sgw keychain-set` |
| GitHub にログインする | `sgw login` |
| 構成を確認する | `sgw verify` |
| `config.yml` の変更を反映する | `sgw restart` |
| 新しい版に上げる | `sgw update --apply` |
| 許可・ブロックされた通信を Web UI で見る | `sgw web` |
| エージェントの操作記録を見る | `sgw audit` |

ほかは `sgw --help`。

## オプション

| したいこと | 設定 |
|---|---|
| 企業プロキシを通す | `proxy.upstream_proxy`。パスワードは `sgw proxy-credential set` |
| 踏み台越しに GitHub に届く | `domain_handlers.<host>.ssh_options: [ProxyJump=…]` |
| GitHub Enterprise を使う | `domain_handlers` にそのホストを足す（`ssh_port`、`api_base`） |
| エージェントのコミットを GitHub で Verified にする | `sgw signing-key` が表示する鍵を Signing Key として登録する |

## 向くとき、向かないとき

エージェントに次をさせたいときに向きます。

- プルリクエストは作るが、マージはしない
- このリポジトリにだけ到達する
- すべてのコミットに署名する
- HTTPS の通過に送信量の上限をかける
- すべての操作を記録する
- 上流の資格情報を持たない

エージェントに次をさせたいときには向きません。

- GitHub 以外の API に規則を課す
- リクエストの内容で判断される（TLS を終端しない）
- 宛先の制限だけを受ける（許可リストで足りる）
- GitHub に触らない

## ドキュメント

- [base/examples/sgw-sample/README.ja.md](base/examples/sgw-sample/README.ja.md) — `sgw init` が書くファイル
- [base/README.ja.md](base/README.ja.md) — dev コンテナのイメージの中身
- [relay/README.ja.md](relay/README.ja.md) — 関所の設定と権限の一覧
- [config/config.sample.yml](config/config.sample.yml) — すべてのキー
- [UPGRADING.ja.md](UPGRADING.ja.md) — 版を上げるときの作業
- [CHANGELOG.ja.md](CHANGELOG.ja.md) — 変更履歴
- [docs/paths.ja.md](docs/paths.ja.md) — 経路台帳
- [docs/localization.ja.md](docs/localization.ja.md) — 英語と日本語
- [CONTRIBUTING.md](CONTRIBUTING.md)、[RELEASING.md](RELEASING.md)

## dev コンテナがうまく上がらないとき

まず `sgw verify`。落ちた項目と打つコマンドを言います。

| 症状 | すること |
|---|---|
| 再起動や更新のあと、エージェントが GitHub に届かない | `sgw unlock` |
| dev の `ssh-add -l` に自分の鍵が並ぶ | VS Code を完全に終了して `sgw open` |
| `config.yml` を変えたのに効かない | `sgw restart` |
| 起動時に「network … already exists」と出る | 前の compose のネットワークが残っている。`sgw down` してから開き直す。まだ出るなら `docker network prune` |
| エージェントに要るドメインが解決されない | `allow_domains` に足す。ブロックされた通信は `sgw web` で見える |
| 版を上げたのにゲートウェイが古い | `sgw recreate` |
| 版を上げたのに dev コンテナが古い | VS Code の Rebuild Container |

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE)。
