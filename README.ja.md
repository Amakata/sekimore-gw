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

```console
# どこからでも: プロジェクトトークンは GitHub には通用しない
$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token skm_..." https://api.github.com/user
401

# dev コンテナの中: ポリシーが許可した操作
$ sekimore pr create --head sekimore/topic --base main --title "..."
#42 https://github.com/Org/Repo/pull/42

# dev コンテナの中: 許可していない操作
$ sekimore pr merge --number 42
sekimore: denied: pr:merge is not allowed by policy
```

この構成に `gh` は含まれません。トークンを持った `gh` は、ここで設定した権限をすべて通り過ぎます。dev コンテナのイメージにも入っていません。

## はじめかた

[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) の `examples/sgw-sample/` テンプレートを使います。
その README が clone から関所の動作確認までを案内します。

認証の必要なプロキシの内側では、パスワードを秘密ストアに入れます（`.devcontainer/.env` はエージェントが読めるため）:

```bash
mise run gw:proxy-credential -- set
```

## 仕組み

4 つの層を 1 つの `config.yml` から構成します。1 つだけ制限すると、残りが迂回路になります。

| 層 | 役割 |
|---|---|
| **DNS**（:53） | 許可リストのドメインだけを解決する。返したアドレスをファイアウォールで開ける。関所のドメインはゲートウェイ自身に解決する |
| **ファイアウォール**（iptables、ipset） | DNS が許可したアドレスとポートにだけ転送する。IP 直指定の接続は破棄する。`network.allowed_ports` でポートを絞る。未設定なら全ポート |
| **Squid**（:3128） | エージェントの HTTP プロキシ。自分で名前を解決するため、同じ許可リストを持つ。関所のドメインは拒否する |
| **関所**（sekimore-relay） | SSH の git（:22）、GitHub API（:8420）、HTTPS の通過（:443）。上流の資格情報を持つ唯一の部品 |

関所がすること:

- プロジェクト単位のポリシーを適用する: リポジトリ、読み取り専用か読み書きか、33 種類の権限、プルリクエストのベースブランチ
- `git push HEAD:refs/for/main` をブランチとプルリクエストに変換する
- エージェントが使えるが読み出せない鍵でコミットに署名する
- 443 の通過に送信量の上限をかける
- 許可した操作と拒否した操作を監査ログに記録する

詳細は [relay/README.ja.md](relay/README.ja.md) を参照してください。

`proxy.upstream_proxy` を設定しても、上流を通るのは関所自身の経路と、Squid を明示したクライアントだけです。
それ以外はゲートウェイから直接出ていきます。`proxy.direct_egress: deny` でその経路を塞ぐと、出口は Squid だけになります。
dev コンテナは起動時にゲートウェイから `HTTP_PROXY` と `NO_PROXY` を受け取ります（`GET /api/proxy-env`。
`NO_PROXY` は `domain_handlers` と `proxy.no_proxy` から組み立てられます）。

## 向くとき、向かないとき

エージェントに次をさせたいときに向きます。

- プルリクエストは作るが、マージはしない
- このリポジトリにだけ到達する
- すべてのコミットに署名する
- HTTPS の通過に送信量の上限をかける
- すべての操作を記録する
- 上流の資格情報を持たない

向かないとき:

| 場合 | 理由 |
|---|---|
| GitHub 以外の上流の API を制限したい | SSH の git はどのホストでも動く。API の変換は GitHub のみ。GitLab や Artifactory は、許可リストか、上限付きの 443 通過まで。[#50](https://github.com/Amakata/sekimore-gw/issues/50) |
| リクエストの内容で判断したい | TLS を終端しない。分かるのは宛先とバイト数だけ。そのかわり MITM 証明書が不要 |
| 宛先を制限したいだけ | 許可リストだけなら、もっと小さな仕組みで足りる |
| エージェントが GitHub を使わない | 関所の役割がない |

## 動作要件

- Docker 20.10 以降、Docker Compose 2.0 以降
- Linux ホスト、または macOS の Docker Desktop（各層は Docker の VM の中で動く）
- ゲートウェイは `NET_ADMIN`、`privileged: true`、`pid: host` で動く。`pid: host` は、エージェントを閉じ込める FORWARD 規則をホストの DOCKER-USER チェーンに置くために要る。テンプレートの `docker-compose.yml` が 3 つとも設定する
- エージェントのコンテナは `dns: [127.0.0.1]` で動き、起動時に `agent-setup.sh` がゲートウェイを見つけてデフォルトルートを設定する。dev コンテナのイメージが両方を行う
- `network.allowed_ports` は既定で未設定 = 全ポート。必要がなければ `[80, 443]` に絞る。変更には再起動が必要

## 名前

| 名前 | 何か |
|---|---|
| sekimore-gw、sgw | このゲートウェイ。`sgw` は sgw-devcontainer-base、`sgw.sh`、`.devcontainer/sgw/` に出てくる |
| sekimore-relay | ゲートウェイの中の関所デーモンと、dev コンテナにある同名の CLI |
| `sekimore` | dev コンテナのラッパー。`sekimore-relay agent …` を実行する。`sekimore guide` でエージェント向けガイドを表示 |
| sgw-devcontainer-base | dev コンテナのイメージ。`examples/sgw-sample/` がプロジェクトのテンプレート |
| `.devcontainer/sgw/`、`gw:*` | ホスト側のスクリプトと mise タスク。イメージと一緒に配布され、`mise run upgrade:apply` が入れ替える |

## ドキュメント

- [relay/README.ja.md](relay/README.ja.md) — 関所の設定、エージェント側の手順、日々の使い方、設定リファレンス、権限の一覧
- [config/config.sample.yml](config/config.sample.yml) — すべてのキー。既定値とコメント付き
- [docs/localization.ja.md](docs/localization.ja.md) — Web UI と CLI の言語（英語・日本語）
- [docs/paths.ja.md](docs/paths.ja.md) — 経路台帳: すべての接続の辺をグラフとして検査
- [CONTRIBUTING.md](CONTRIBUTING.md) — 開発、テスト、イメージ
- [CHANGELOG.ja.md](CHANGELOG.ja.md)、[relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) — 1 つのイメージ、1 つの版番号
- [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) — dev コンテナ側

## トラブルシューティング

**エージェントがゲートウェイを見つけられない**

- エージェントのコンテナの `dns: [127.0.0.1]` を確認する
- エージェントのログを見る: `docker logs <agent-container>`
- `agent-setup.sh` がサブネット全体を走査するのは、プレフィックス長が 24 以上のときだけ

**ドメインが解決されない**

- `config/config.yml` の `allow_domains` を確認する
- 拒否の記録: Web UI、または `docker logs sekimore-gw`

**データベースが大きい**

ゲートウェイのコンテナで実行します（mise の `gw:db-*` タスクはこれらを呼びます）。

```bash
python -m src.maint db-stats                                   # サイズと件数
python -m src.maint db-prune --before-days 90 --yes --vacuum   # 古い記録を削除
```

関所の監査ログ（`/data/relay/audit.jsonl`）は別のファイルで、これらのコマンドでは変わりません。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE)。
