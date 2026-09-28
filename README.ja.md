# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**アカウントを渡さずに、AI エージェントに GitHub 上の作業をさせる。**

sekimore-gw（sgw）は、Docker で動く AI エージェントのためのネットワークゲートウェイです。ホストでは `sgw`、
dev コンテナの中でエージェントが使うのは `sgw-agent`（使い方は `sgw-agent guide` が出す）。

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

## 仕組み

dev コンテナから外に出る道はゲートウェイだけです。

1. `allow_domains` に無いドメインは解決されない
2. IP への直接接続はファイアウォールが落とす
3. HTTP プロキシも同じ一覧を見るので、`http_proxy` は抜け道にならない
4. `github.com` は関所に解決される。関所はホストの ssh-agent と device flow のトークンで上流に git と
   GitHub API を話す。どちらもゲートウェイから出ない
5. 関所は操作のたびにプロジェクトのリポジトリと権限を確かめ、記録する

エージェントに見えるのは ssh のホスト 1 つと API のエンドポイント 1 つで、どちらの資格情報も持ちません。

## はじめかた

対応しているのは macOS と Linux の VS Code Dev Containers です。Windows は試していません。

必要なもの:

- Docker（macOS は Docker Desktop、Linux は Docker Engine）。ゲートウェイは `privileged` と `pid: host` で動く。
  dev コンテナをゲートウェイに縛る規則はホストのファイアウォールにあるため
- VS Code と Dev Containers 拡張

1. `sgw` を入れる。`~/.local/bin/sgw` にバイナリ 1 つ（そのディレクトリを PATH に通す）。スクリプトはリリースが公開する sha256 を照合する。
   手で入れるなら [Releases](https://github.com/Amakata/sekimore-gw/releases) に同じアーカイブがある:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. 自分のリポジトリに雛形を書く（新しいディレクトリなら `sgw init --devcontainer my-project`）:
   ```bash
   cd your-project
   sgw init --devcontainer
   ```
3. 最小限を埋める。`.devcontainer/.env`: `GIT_AUTHOR_NAME`、`GIT_AUTHOR_EMAIL`（COMMITTER も同じ）、
   `DEVCONTAINER_ID`（このホストで一意な名前）。`.devcontainer/config/config.yml`: `allow_domains`、`relay.project.name`、
   `relay.project.repos`、`relay.project.permissions`。残りのキーは [config.sample.yml](config/config.sample.yml)
4. VS Code を完全に終了してから `sgw open` で起動し、「Reopen in Container」を選ぶ:
   ```bash
   sgw open
   ```
   ⚠️ 必ず `sgw open` で。自分の ssh-agent をコンテナに渡さないため
5. 秘密ストアを解錠する。VS Code は起動したまま、ホストのターミナルで。初回がパスフレーズを決め、
   以後は同じものを聞かれる（`sgw keychain-set` で聞かれなくなる）:
   ```bash
   sgw unlock
   ```
6. GitHub にログインする。初回だけ。トークンは秘密ストアに入る:
   ```bash
   sgw login
   ```
7. 確認する:
   ```bash
   sgw verify
   ```
8. 試す。dev コンテナのターミナルで:
   ```bash
   sgw-agent whoami            # 権限: pr:create … があり pr:merge が無い
   sgw-agent pr merge --number 1
   # sgw-agent: denied: pr:merge is not allowed by policy
   ```

## 設定

設定は `.devcontainer/config/config.yml`。全キーの説明は [config.sample.yml](config/config.sample.yml)。

| 設定 | 効果 |
|---|---|
| `allow_domains` | エージェントが届いてよい宛先 |
| `relay.project.name` | プロジェクトの名前。エージェントのトークンはこれに対して発行され、監査の見出しになる |
| `domain_handlers` | 関所を通すドメイン: git、GitHub API、HTTPS |
| `relay.project.repos` | エージェントが触ってよいリポジトリ |
| `relay.project.permissions` | 許す操作 |
| `network.allowed_ports` | 届いてよいポート |

## コマンド

| したいこと | コマンド |
|---|---|
| 秘密ストアを解錠する（ゲートウェイのコンテナを作り直したあとは施錠されている） | `sgw unlock` |
| 解錠を自動にする | `sgw keychain-set` |
| GitHub にログインする | `sgw login` |
| 構成を確認する | `sgw verify` |
| `config.yml` の変更を反映する | `sgw restart`。上流を足した・変えたときは続けて `sgw refresh`（エージェントの ssh 設定を書き直す） |
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
| Remote-SSH で繋ぐ Linux VM の上で dev コンテナを動かす | [docs/remote-ssh.ja.md](docs/remote-ssh.ja.md) |

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

- [docs/template.ja.md](docs/template.ja.md) — `sgw init` が書くファイル
- [docs/remote-ssh.ja.md](docs/remote-ssh.ja.md) — Remote-SSH で繋ぐ Linux VM の上で dev コンテナを動かす
- [base/README.ja.md](base/README.ja.md) — dev コンテナのイメージの中身
- [relay/README.ja.md](relay/README.ja.md) — 関所の設定と権限の一覧
- [config/config.sample.yml](config/config.sample.yml) — すべてのキー
- [UPGRADING.ja.md](UPGRADING.ja.md) — 版を上げるときの作業
- [CHANGELOG.ja.md](CHANGELOG.ja.md) — 変更履歴
- [docs/paths.ja.md](docs/paths.ja.md) — 通信が通りうる経路の一覧。誰が確かめ、`sgw verify` が何を見るか
- [docs/localization.ja.md](docs/localization.ja.md) — 英語と日本語
- [CONTRIBUTING.md](CONTRIBUTING.md)、[RELEASING.md](RELEASING.md)

## トラブルシューティング

まず `sgw verify`。落ちた項目と打つコマンドを言います。

| 症状 | すること |
|---|---|
| 再起動や更新のあと、エージェントが GitHub に届かない | `sgw unlock` |
| dev の `ssh-add -l` に自分の鍵が並ぶ | VS Code を完全に終了して `sgw open` |
| `config.yml` を変えたのに効かない | `sgw restart` |
| エージェントに要るドメインが解決されない | `allow_domains` に足す。ブロックされた通信は `sgw web` で見える |
| 版を上げたのにゲートウェイが古い | `sgw recreate` |
| 起動時に「network … already exists」と出る | 前の dev コンテナとゲートウェイが残っている。`sgw down` で丸ごと消して開き直す |
| 起動直後に HTTP 503「the secret store is locked」が返る | 上流 proxy のパスワードが locked のストアにある。`sgw unlock` |
| 版を上げたのに dev コンテナが古い | VS Code の Rebuild Container |

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE)。
