# sekimore-gw

*[English](README.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**アカウントを渡さずに、AI エージェントに GitHub 上の作業をさせる。**

sekimore-gw（略称: sgw）は、Docker で動く AI エージェントのためのネットワークゲートウェイです。
1 つのコンテナに 4 つの層（DNS、ファイアウォール、Squid、関所）が入り、1 つのファイルで設定します。
GitHub に関わるのは関所（sekimore-relay）です。運用者の資格情報は関所が持ち、エージェントはゲートウェイの外で通用するものを何も持ちません。

## トークンでは足りない理由

エージェントが持つトークンは、どれも読み出せます。ターミナルを持つエージェントは `~/.ssh` も `.env` も読めるためです。
classic トークンの `repo` スコープは、アカウントが到達できるすべてのリポジトリへの読み書き権限を与えます。
fine-grained トークンはリポジトリを絞れますが、操作は絞れません。「Pull requests: write」はプルリクエストの作成とマージの両方を含みます。
どちらも、エージェントが何をしたかを記録せず、送信量に上限もかけません。

sekimore-gw は、資格情報をゲートウェイの中に置きます。エージェントが持つのは使い捨ての SSH 鍵とプロジェクトトークンだけで、
どちらもゲートウェイ以外では通用しません。運用者は権限を操作ごとに付与します。たとえば `pr:create` は許可し、`pr:merge` は拒否する、という形です。

```console
# コンテナの外を含むどこからでも: プロジェクトトークンは GitHub には通用しない
$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token skm_..." https://api.github.com/user
401

# dev コンテナの中: ポリシーが許可した操作はゲートウェイを通る
$ sekimore pr create --head sekimore/topic --base main --title "..."
#42 https://github.com/Org/Repo/pull/42

# ポリシーが許可していない操作はゲートウェイで止まる
$ sekimore pr merge --number 42
sekimore: denied: pr:merge is not allowed by policy
```

この構成に `gh` は含まれません。トークンを持った `gh` は GitHub に直接接続し、ここで設定した権限をすべて通り過ぎるためです。
dev コンテナのイメージにも `gh` は入っていません。

## はじめかた

**A. dev コンテナ（推奨）。** ゲートウェイ、dev コンテナ、関所、ホスト側のタスクをまとめた構成が、
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) の `examples/sgw-sample/` テンプレートです。
その README が、clone から関所の動作確認までを案内します。

**B. ゲートウェイだけ。** Linux ホストで次の 3 コマンドを実行すると、DNS の許可リスト、ファイアウォール、Squid、ダッシュボードが動きます。

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # allow_domains: エージェントに許可するドメイン
docker compose up -d                             # ダッシュボード: http://localhost:8080
```

この方法には関所が含まれません。関所を足すには、[relay/README.ja.md](relay/README.ja.md) にしたがって `config.yml` に
`domain_handlers` と `relay` を設定し（`config.sample.yml` の末尾がテンプレートです）、エージェントのコンテナに
dev コンテナのテンプレートが提供する部品（`agent-setup.sh`、`sekimore-relay` CLI、`sekimore` ラッパー）を入れます。
`docker-compose.yml` の `ai-agent` サービスが、最小のエージェントコンテナです。

ホストが認証の必要なプロキシの内側にある場合、ゲートウェイ単体では `cp .env.example .env` を実行して
`SEKIMORE_UPSTREAM_PROXY_USERNAME` と `_PASSWORD` を書きます。dev コンテナの構成では、かわりに
`mise run gw:proxy-credential -- set` でゲートウェイの秘密ストアに保存します。`.devcontainer/.env` は dev コンテナの
`env_file` でもあり、エージェントが読めるためです。

## 仕組み

4 つの層は 1 つの `config.yml` から構成します。1 つの層だけを制限すると、残りの層が迂回路になるためです。

| 層 | 役割 |
|---|---|
| **DNS**（:53） | 許可リストにあるドメインだけを解決し、返したアドレスをファイアウォールで開けます。関所が扱うドメインは、ゲートウェイ自身のアドレスに解決されます。 |
| **ファイアウォール**（iptables、ipset） | DNS が許可したアドレスとポートにだけ転送し、IP アドレスを直接指定した接続は破棄します。エージェントはゲートウェイの DNS に問い合わせできますが、DNS が許可するまで、それ以外には到達できません。`network.allowed_ports` は宛先ポートを絞ります。未設定なら、許可したアドレスのすべてのポートが開きます。 |
| **Squid**（:3128） | エージェントのツールが使うプロキシです。Squid は自分で名前を解決するため、DNS の層では止められません。Squid は同じ許可リストを適用し、関所が扱うドメインは拒否します。 |
| **関所**（sekimore-relay） | SSH の git（:22）、GitHub API（:8420）、その他の HTTPS の通過（:443）を扱います。上流の資格情報を持つ唯一の部品です。プロジェクト単位のポリシー（リポジトリ、読み取り専用か読み書きか、33 種類の権限、プルリクエストのベースブランチ）を適用し、`git push HEAD:refs/for/main` をブランチとプルリクエストに変換し、エージェントが使えるが読み出せない鍵でコミットに署名し、443 の通過で 1 接続が送れる量に上限をかけ、許可した操作と拒否した操作を監査ログに書きます。 |

関所は任意の機能です。`domain_handlers` がなければ、最初の 3 層だけが動きます。
設定、エージェント側の手順、ポリシーは [relay/README.ja.md](relay/README.ja.md) を参照してください。

## 向くとき、向かないとき

**sekimore-gw が向くのは**、エージェントに範囲を限って GitHub 上の作業をさせたい場合です。
プルリクエストは作らせるがマージはさせない、このリポジトリだけに到達させる、すべてのコミットに署名する、
HTTPS の通過に送信量の上限をかける、すべての操作を記録する。その間、エージェントは上流の資格情報を持ちません。

**sekimore-gw が向かないのは**、次の場合です。より小さな仕組みや別の仕組みのほうが適しています。

| | |
|---|---|
| GitHub 以外の上流の API を制限したい | SSH の git 中継はどの Git ホストでも動きますが、API の変換は GitHub にのみ対応しています。GitLab や社内の Artifactory は、ドメインとして許可するか、送信量の上限をかけてポート 443 で通すことはできますが、それ以上の制限はできません。変更は [#50](https://github.com/Amakata/sekimore-gw/issues/50) で扱います。 |
| リクエストの内容で判断したい | ゲートウェイは TLS を終端しません。宛先とバイト数は分かりますが、`GET /v1/public/` は見えません。そのかわり、MITM 証明書が不要です。 |
| 宛先を制限したいだけ | 4 つの層は、エージェントが GitHub で行える操作を制限するためのものです。許可リストだけなら、より単純な仕組みで足ります。 |
| エージェントが GitHub を使わない | 人が git コマンドを実行するなら、関所の役割はありません。 |

## 動作要件

- Docker 20.10 以降と Docker Compose 2.0 以降。
- Linux ホスト、または macOS の Docker Desktop。各層は Docker の VM の中で動きます。macOS では dev コンテナのテンプレートを使います。
- `docker-compose.yml` は、ゲートウェイを `NET_ADMIN` と `privileged: true` で起動します。
- エージェントのコンテナは Docker 内蔵の DNS を無効にし（`dns: [127.0.0.1]`）、`agent-setup.sh` を実行します。
  このスクリプトがゲートウェイを見つけ、デフォルトルートを設定します。
- `network.allowed_ports` は既定で未設定のため、許可したアドレスのすべてのポートが開きます。
  エージェントに必要がなければ `[80, 443]` に絞ってください。変更にはコンテナの再起動が必要です。

## 名前

| 名前 | 何か |
|---|---|
| sekimore-gw、sgw | このゲートウェイ。`sgw` は sgw-devcontainer-base、`sgw.sh`、`.devcontainer/sgw/` で使う略称です。 |
| sekimore-relay | ゲートウェイの中で動く関所のデーモンと、dev コンテナに入っている同名の CLI バイナリ。 |
| `sekimore` | dev コンテナで `sekimore-relay agent …` を実行するラッパー。`sekimore guide` はエージェント向けのガイドを表示します。 |
| sgw-devcontainer-base | dev コンテナのイメージ。その中の `examples/sgw-sample/` がプロジェクトのテンプレートです。 |
| `.devcontainer/sgw/`、`gw:*` | ホスト側のスクリプトと mise タスク。イメージと一緒に配布され、`mise run upgrade:apply` が入れ替えます。 |

## ドキュメント

- [relay/README.ja.md](relay/README.ja.md) — 関所の設定、エージェント側の手順、日々の使い方、設定リファレンス、権限の一覧
- [config/config.sample.yml](config/config.sample.yml) — ゲートウェイが読むすべてのキー。既定値とコメント付き
- [docs/localization.ja.md](docs/localization.ja.md) — Web UI と CLI の言語（英語・日本語）
- [CONTRIBUTING.md](CONTRIBUTING.md) — 開発、テスト、ビルド、プレビューイメージ
- [CHANGELOG.ja.md](CHANGELOG.ja.md) と [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) — 1 つのイメージにゲートウェイと関所が入り、版番号は共通
- [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) — dev コンテナ側

## トラブルシューティング

- **エージェントがゲートウェイを見つけられない。** エージェントのコンテナの `dns: [127.0.0.1]` と、ログ（`docker logs <agent-container>`）を確認してください。
  `agent-setup.sh` がサブネット全体を走査するのは、プレフィックス長が 24 以上（256 アドレス以下）のときだけです。
- **ドメインが解決されない。** `config/config.yml` の `allow_domains` と、Web UI または `docker logs sekimore-gw` の拒否記録を確認してください。
- **データベースが大きい。** ゲートウェイのコンテナで `python -m src.maint db-stats` を実行するとサイズが分かります。
  `python -m src.maint db-prune --before-days 90 --yes --vacuum` は古い記録を削除します。mise の `gw:db-*` タスクはこれらのコマンドを実行します。
  関所の監査ログ（`/data/relay/audit.jsonl`）は別のファイルで、これらの操作では変わりません。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE) を参照してください。
