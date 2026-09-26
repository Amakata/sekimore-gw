# sgw-sample

*[English](README.md)*

`sgw-devcontainer-base` を使った最小構成の dev コンテナ。次のものを含む。

- すべての通信が `sekimore-gw` を経由する、分離されたネットワーク
- git と GitHub API の通信を中継する関所 (sekimore-relay) を使う構成 (`docker-compose.relay.yml`)。
  AI エージェントは `git@github.com:Org/Repo.git` をそのまま使えるが、その鍵は使い捨てで、
  上流への接続はゲートウェイ内にある運用者の ssh-agent で認証する。プロジェクト外のリポジトリと
  許可されていない操作は関所が拒否する
- base イメージを `FROM` するだけの最小限の `Dockerfile`
- 特定バージョンの Python、Node.js、Ruby、Rust を `mise` でインストールする例
  (PHP は Dockerfile でコメントアウトしてあり、必要に応じて有効にできる)

## 使い方

ホスト (Mac と Docker Desktop) 側の操作は mise のタスクにまとめてある。`mise tasks` で一覧を表示できる。
タスクの定義は `.devcontainer/sgw/` にあり、`mise run upgrade:apply` が最新に保つ。
`mise.toml` はプロジェクトのもので、それらのタスクファイルを include しているだけである。

1. `.devcontainer/.env.sample` を `.devcontainer/.env` にコピーして値を埋める。
   `SEKIMORE_AGENT_SOCK` は運用者の ssh-agent のソケットで、Docker Desktop なら既定値のままでよい。
2. `config/config.yml` の `relay.project.repos` と `permissions` を、このプロジェクトの値に書き換える。
3. ssh-agent を使える状態で Docker Desktop を起動し、**VS Code を完全に終了 (Cmd+Q) してから**、
   Terminal.app で **`mise run vscode`** を実行し、"Reopen in Container" を選ぶ。
   macOS の `code` CLI は `open` 経由でアプリケーションを起動するため、`env -u SSH_AUTH_SOCK code`
   ではアプリケーションの環境に反映されない。このタスクは launchd から `SSH_AUTH_SOCK` を外し、
   アプリケーションを直接起動し、起動後にアプリケーションの環境を確認する (`mise run vscode:check`)。
   Docker Desktop を再起動する前には `mise run vscode:restore-agent-env` を実行する。
   `SSH_AUTH_SOCK` なしで VS Code を起動する必要があるのは、Dev Containers 拡張機能が運用者の
   ssh-agent を常に dev コンテナへ転送し、それを無効にする設定がないためである。通常の方法で
   VS Code を開くと、post-create が **ERROR で停止し**、この手順を案内する。
4. **`mise run gw:unlock`** で秘密ストアを解錠する。**ゲートウェイを作り直すたびに必要である。**
   0.2.19 以降、上流の API トークンはこのストアに保存されており、ストアが施錠されている間、関所は
   GitHub API をまったく使えない (git の push と pull は SSH を使うので動作する)。鍵はメモリ上にしか
   保持されないため、ゲートウェイが再起動したら再びストアを解錠する。
5. 初回だけ、ゲートウェイに対して **`mise run gw:login`** を実行する (device flow。上流のトークンと
   `known_hosts` を保存する)。保存先のストアがまだ開いていないため、解錠より先には実行できない。
6. **`mise run dev:signing-key`** が表示する署名用の公開鍵を、GitHub の Settings → SSH and GPG keys に
   "Signing Key" として登録する。AI エージェントのコミットは、あなたの鍵ではなくこの鍵で署名される。
   鍵のコメントは GitHub 上の Title になり、「sekimore-agent-signing: \<プロジェクト名\> / \<あなたの名前\> \<メール\>」
   である。変更するには `.env` で `SEKIMORE_SIGNING_KEY_COMMENT` を設定する。
7. **`mise run relay:verify`** で構成全体を確認する。ゲートウェイの状態、dev コンテナに ssh-agent が
   届いていないこと、関所を経由した git、プロジェクト外のリポジトリの拒否を確認する。

日常の操作: `mise run gw:check` (状態)、`mise run gw:tokens`、`mise run gw:audit` (監査ログ)、
`mise run relay:refresh` (`config.yml` に上流を追加・変更して `mise run gw:restart` した後に。
Rebuild Container なしで dev の `~/.ssh/config` の Host ブロックとプロキシの環境を作り直す)、
`mise run gw:revoke-project` (プロジェクトの終了時)、`mise run gw -- <sekimore-relay の任意のサブコマンド>`。

関所を使わずにサンプルを使う場合は、`devcontainer.json` の `dockerComposeFile` から
`docker-compose.relay.yml` を外し、`config/config.yml` から `domain_handlers:` と `relay:` を削除する。
その場合、gw:* と relay:* のタスクも不要になる。

新しいプロジェクトにサンプルを使う場合は、`.devcontainer/` と `mise.toml` をコピーする。以後は
`mise run upgrade` が新しい版があるかどうかを表示し、`mise run upgrade:apply` がその版に更新する。

## ファイル構成

```
sgw-sample/
├── README.md
├── mise.toml                       # あなたのもの: .devcontainer/sgw/ の include と、自分のタスク
└── .devcontainer/
    ├── devcontainer.json
    ├── docker-compose.yml          # dev と sekimore-gw の 2 サービス
    ├── docker-compose.relay.yml    # sekimore-relay 用の overlay (agent socket のマウント、鍵の volume)
    ├── Dockerfile                  # FROM sgw-devcontainer-base と、mise による特定バージョンのインストール
    ├── .env.sample
    ├── .gitignore
    ├── config/
    │   ├── config.yml              # sekimore-gw のドメインの許可リストと、関所のプロジェクトポリシー
    │   └── squid/
    │       └── squid.conf.template
    ├── scripts/
    │   └── post-create.sh          # zsh rc.d の展開、agent 転送の検知 (検知したら ERROR で止める)
    ├── sgw/                        # 配布物: mise run upgrade:apply がまるごと入れ替える。編集しない
    │   ├── tasks.mise.toml         # ホスト側のタスク (vscode / web / relay:verify / upgrade ...)
    │   ├── gateway.mise.toml       # ゲートウェイのタスク (gw:*)。動かしているゲートウェイの版に対応する
    │   ├── sgw.sh                  # compose のラベルでゲートウェイ / dev コンテナを見つけて docker exec する
    │   ├── vscode.sh               # mise run vscode
    │   ├── upgrade.sh              # mise run upgrade
    │   ├── post-start.sh           # postStartCommand が実行する: agent-setup (SEKIMORE_* をすべて渡す)、docker-init、post-create
    │   └── MANIFEST                # upgrade が最後に書いた記録。手で書き換えたかどうかの判定に使う
    └── zsh-config/
        └── rc.d/                   # プロジェクト固有の zsh 設定
```
