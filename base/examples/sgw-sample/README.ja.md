# sgw-sample

*[English](README.md)*

`sgw init --devcontainer` が書くプロジェクトの雛形。`sekimore-gw` の内側に `sgw-devcontainer-base` で作る dev コンテナ。中身は次のとおり。

- すべての通信が `sekimore-gw` を通る隔離されたネットワーク
- git と GitHub API を中継する関所 `sekimore-relay` の設定（`docker-compose.relay.yml`）。AI エージェントは
  `git@github.com:Org/Repo.git` をそのまま使う。鍵は使い捨てで、上流への接続はゲートウェイの中で運用者の
  ssh-agent が認証する。関所は案件外のリポジトリと許可していない操作を拒否する
- base イメージを `FROM` するだけの最小の `Dockerfile`。`mise` で言語の版を入れる例つき

このディレクトリは読むための写しです。`sgw` が同じファイルを持っていて、それを書きます。手でコピーしないでください。
`sgw init` が、自分の版の pin で書きます。

## 使いかた

手順は [base/README.ja.md](../../README.ja.md) にあります: `sgw init`、`.env`、`config.yml`、`sgw open`、`sgw unlock`、
`sgw login`、`sgw signing-key`、`sgw verify`。その裏で知っておくとよいこと:

- **VS Code は `SSH_AUTH_SOCK` なしで起動しなければならない**（`sgw open`）。Dev Containers 拡張は運用者の ssh-agent を
  必ず dev コンテナに転送し、止める設定がない。macOS の `code` CLI は `open` 経由でアプリを起動するので
  `env -u SSH_AUTH_SOCK code` では変わらない。`sgw open` は launchd から変数を外し、アプリを直接起動し、環境を確かめる
  （`sgw open --check`）。Docker Desktop を再起動する前に `sgw open --restore-agent-env`。ふつうに開くと post-create が
  **ERROR で止まり**、そう言う。
- **秘密ストアは作り直すたびに施錠される**（`sgw unlock`。一度 `sgw keychain-set` すれば `sgw recreate` が解錠する）。
  上流 API のトークンはこの中にあり、施錠中は関所が GitHub API を使えない（git の push / pull は SSH なので動く）。
- 署名鍵のコメント（GitHub での題名になる）は `sekimore-agent-signing: <project> / <name> <email>`。`.env` の
  `SEKIMORE_SIGNING_KEY_COMMENT` で変えられる。
- `config.yml` に上流を足したり変えたりしたら: `sgw restart`、そのあと `sgw refresh`（dev の `~/.ssh/config` の Host ブロックと
  proxy 環境を Rebuild Container なしで作り直す）。
- 日常: `sgw check`、`sgw tokens`、`sgw audit`、`sgw revoke-project`（案件の終わりに）、
  `sgw relay <sekimore-relay の任意のサブコマンド>`。

関所なしで使うには、`devcontainer.json` の `dockerComposeFile` から `docker-compose.relay.yml` を外し、
`config/config.yml` から `domain_handlers:` と `relay:` を消す。

`.devcontainer/sgw/` の mise タスク（`mise run gw:unlock`、`mise run relay:verify` …）は `sgw` のコマンドと同じことをする。
`mise tasks` に一覧がある。

## ファイル

```
sgw-sample/
├── README.md
├── mise.toml                       # あなたのもの: .devcontainer/sgw/ を include し、自分のタスクを書く
└── .devcontainer/
    ├── devcontainer.json
    ├── docker-compose.yml          # dev と sekimore-gw の 2 サービス
    ├── docker-compose.relay.yml    # sekimore-relay 用の overlay（agent ソケットのマウント、鍵のボリューム）
    ├── Dockerfile                  # FROM sgw-devcontainer-base に、mise で入れる言語の版
    ├── .env.sample                 # sgw init が .env に写す
    ├── .gitignore
    ├── config/
    │   ├── config.yml              # sekimore-gw のドメイン許可リストと、関所のプロジェクトポリシー
    │   └── squid/
    │       └── squid.conf.template
    ├── scripts/
    │   └── post-create.sh          # zsh rc.d を展開し、agent 転送を検出する（ERROR で止まる）
    ├── sgw/                        # 配布物: sgw update --apply が丸ごと入れ替える。編集しない
    │   ├── tasks.mise.toml         # ホスト側の mise タスク（vscode / web / relay:verify / upgrade …）
    │   ├── gateway.mise.toml       # ゲートウェイの mise タスク（gw:*）
    │   ├── sgw.sh                  # compose のラベルで gateway / dev コンテナを見つけ docker exec する
    │   ├── vscode.sh               # sgw open が実行するもの
    │   ├── upgrade.sh              # mise run upgrade
    │   ├── post-start.sh           # postStartCommand が実行: agent-setup（SEKIMORE_* を全部渡す）、docker-init、post-create
    │   └── MANIFEST                # sgw update / upgrade が最後に書いたもの。手の編集を見分ける
    └── zsh-config/
        └── rc.d/                   # プロジェクト自身の zsh 設定
```
