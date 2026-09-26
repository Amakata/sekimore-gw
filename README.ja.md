# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**アカウントを渡さずに、AI エージェントに GitHub 上の作業をさせる。**

sekimore-gw（sgw）は、Docker で動く AI エージェントのためのネットワークゲートウェイです。

- 1 つのコンテナに 4 つの層: DNS、ファイアウォール、Squid、関所。設定は 1 つの `config.yml`
- 運用者の GitHub の資格情報は関所（sekimore-relay）が持つ。エージェントはゲートウェイの外で通用するものを持たない
- 権限は操作ごとに付与する: `pr:create` は許可、`pr:merge` は拒否

## トークンでは足りない理由

- エージェントのコンテナにあるトークンは読み出せる。`~/.ssh` も `.env` も同じ
- classic の `repo` トークン: アカウントが到達できるすべてのリポジトリに読み書きできる
- fine-grained トークン: リポジトリは絞れるが、操作は絞れない。「Pull requests: write」は作成もマージもできる
- どちらもエージェントの操作を記録しない。送信量の上限もない


## はじめかた

Docker（macOS は Docker Desktop、Linux は Docker Engine）と、Dev Containers 拡張の入った VS Code が要ります。

1. 運用者の道具 `sgw` を入れる:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. プロジェクトの雛形をディレクトリに書く:
   ```bash
   sgw init --devcontainer my-project
   ```
3. 続きは [base/README.ja.md](base/README.ja.md): `config.yml`、dev コンテナ、`sgw unlock` / `sgw login` / `sgw verify`。

## 何を設定すると何が起きるか

設定は `.devcontainer/config/config.yml` に全部あります。[config.sample.yml](config/config.sample.yml) に全キーがコメント付きで載っています。

| 設定 | 効果 |
|---|---|
| `allow_domains` | エージェントの普段の通信が届いてよい宛先。DNS・ファイアウォール・Squid が同じこの一覧に従う |
| `domain_handlers`、`relay` | このドメインは関所を通る: SSH の git、GitHub API、上限付きの HTTPS。上流の資格情報は関所が持ち、エージェントは持たない |
| `relay.project.repos`、`permissions` | どのリポジトリを、読み取り専用か読み書きか、33 種類の操作のどれを許すか: `pr:create` は許可、`pr:merge` は拒否 |
| `proxy.upstream_proxy`、`proxy.direct_egress` | 外に出る通信すべてに企業プロキシを通す。`deny` でプロキシを迂回する道を塞ぐ。パスワードは秘密ストアに入れる（`sgw proxy-credential set`）。エージェントが読めるファイルには書かない |
| `network.allowed_ports` | エージェントが届いてよいポート。未設定は全ポート。ふつうは `[80, 443]` |

| 操作 | コマンド |
|---|---|
| 秘密ストアを解錠する（作り直すたびに。`sgw keychain-set` を一度やれば自動） | `sgw unlock` |
| GitHub にログインする（一度だけ） | `sgw login` |
| 構成全体を確認する | `sgw verify` |
| `domain_handlers` や `relay` を変えたあと | `sgw restart` |
| 新しい版に上げる | `sgw update --apply` |
| エージェントがしたこと・拒否されたことを見る | `sgw audit` |

ほかのコマンドは `sgw --help`。

## 向くとき、向かないとき

エージェントに次をさせたいときに向きます。

- プルリクエストは作るが、マージはしない
- このリポジトリにだけ到達する
- すべてのコミットに署名する
- HTTPS の通過に送信量の上限をかける
- すべての操作を記録する
- 上流の資格情報を持たない

向かないとき:

- 上流が GitHub ではなく、その API に規則が要る: SSH の git はどのホストでも動くが、API の変換は GitHub だけ（[#50](https://github.com/Amakata/sekimore-gw/issues/50)）
- リクエストの内容で判断したい: TLS を終端しないので、分かるのは宛先とバイト数だけ
- 宛先を制限したいだけ: 許可リストだけなら、もっと小さな仕組みで足りる
- エージェントが GitHub を使わない: 関所の役割がない

## ドキュメント

- [relay/README.ja.md](relay/README.ja.md) — 関所の設定、エージェント側の手順、日々の使い方、設定リファレンス、権限の一覧
- [config/config.sample.yml](config/config.sample.yml) — すべてのキー。既定値とコメント付き
- [docs/localization.ja.md](docs/localization.ja.md) — Web UI と CLI の言語（英語・日本語）
- [docs/paths.ja.md](docs/paths.ja.md) — 経路台帳: すべての接続の辺をグラフとして検査
- [CONTRIBUTING.md](CONTRIBUTING.md) — 開発、テスト、イメージ
- [CHANGELOG.ja.md](CHANGELOG.ja.md)、[relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md)、[base/CHANGELOG.ja.md](base/CHANGELOG.ja.md) — イメージは 2 つ、版は 1 つ
- [UPGRADING.ja.md](UPGRADING.ja.md) — 版を上げるときにプロジェクト側で要る作業
- [base/README.ja.md](base/README.ja.md) — dev コンテナ側: イメージとプロジェクトのテンプレート
- [RELEASING.md](RELEASING.md) — リリースの手順

## dev コンテナがうまく上がらないとき

`sgw verify` が、落ちた項目と打つコマンドを言います。よくあるもの:

| 症状 | すること |
|---|---|
| 再起動や更新のあと、エージェントが GitHub に届かない | 秘密ストアが施錠されている: `sgw unlock`（一度 `sgw keychain-set` しておけば `sgw recreate` が自分で解錠する） |
| dev の `sekimore whoami` がトークンが無いと言う | `sgw login`、そのあと `sgw verify` |
| dev の `ssh-add -l` に自分の鍵が並ぶ | VS Code が `SSH_AUTH_SOCK` 付きで起動している。完全に終了して `sgw open` で起動する |
| `config.yml` の `domain_handlers` や `relay` を変えたのに効かない | `sgw restart`。`allow_domains` だけの変更は reload の窓が開いていれば反映される（`sgw reload-status`） |
| エージェントに要るドメインが解決されない | `allow_domains` に足す。拒否の記録は Web UI（`sgw web`）と `sgw logs` にある |
| `sgw update --apply` のあともゲートウェイのイメージが古い | `sgw recreate` が pull する。`docker restart` では古いまま。base の変更は VS Code の Rebuild Container が要る |

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE)。
