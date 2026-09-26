# sgw-sample

*[English](README.md)*

`sgw init --devcontainer` が書くファイル。`sekimore-gw` の内側に `sgw-devcontainer-base` で作る dev コンテナ。
このディレクトリは読むための写しで、`sgw` が同じファイルを持っている。手でコピーしない。

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

## 知っておくこと

- VS Code は `SSH_AUTH_SOCK` なしで起動する必要がある。`sgw open` がそうする。ふつうに開くと post-create が ERROR で止まる
- 秘密ストアは作り直すたびに施錠される。施錠中は関所が GitHub API を使えない。SSH の git は動く
- `config.yml` に上流を足したり変えたりしたら: `sgw restart`、そのあと `sgw refresh`
- 署名鍵の GitHub での題名は `sekimore-agent-signing: <project> / <name> <email>`。`.env` の `SEKIMORE_SIGNING_KEY_COMMENT` で変えられる
- 案件が終わったら: `sgw revoke-project`
- `.devcontainer/sgw/` の mise タスクは `sgw` のコマンドと同じことをする（`mise tasks` に一覧）

## 最新への追従

`.devcontainer/sgw/` は配布物で、`sgw update --apply` が入れ替える。編集しない。タスクを変えたければ、
`mise.toml` に同じ名前のタスクを書く。

```bash
sgw update            # 何が新しいか、どのファイルが変わるか、UPGRADING が何を求めるか。何も変更しない
sgw update --apply    # 更新する
```

`sgw update --apply` がすること:

1. ゲートウェイの `image:` タグと `FROM` タグを `sgw` 自身の版に上げる
2. `.devcontainer/sgw/` を入れ替える
3. 確認のうえ、ゲートウェイを作り直す
4. パスフレーズが保存されていれば解錠する
5. 運用者にしかできない作業を表示する: Rebuild Container、またぐ [UPGRADING.ja.md](../../../UPGRADING.ja.md) の節（`sgw update --notes`）、コミット

`.devcontainer/sgw/` のファイルが手で書き換えられていれば止まる（`--force` で上書き）。
