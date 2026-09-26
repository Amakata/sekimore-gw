# sgw-sample

*[English](README.md)*

`sgw init --devcontainer` が書くファイル。`sekimore-gw` の内側に `sgw-devcontainer-base` で作る dev コンテナ。
このディレクトリは読むための写しで、`sgw` が同じファイルを持っている。手でコピーしない。

## ファイル

```
sgw-sample/
├── README.md
├── sgw.toml                        # sgw の記録: 各ファイルを書いたときの sha（編集しない）
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
    └── zsh-config/
        └── rc.d/                   # プロジェクト自身の zsh 設定
```

## 知っておくこと

- VS Code は `SSH_AUTH_SOCK` なしで起動する必要がある。`sgw open` がそうする。ふつうに開くと post-create が ERROR で止まる
- 秘密ストアは作り直すたびに施錠される。施錠中は関所が GitHub API を使えない。SSH の git は動く
- `config.yml` に上流を足したり変えたりしたら: `sgw restart`、そのあと `sgw refresh`
- 署名鍵の GitHub での題名は `sekimore-agent-signing: <project> / <name> <email>`。`.env` の `SEKIMORE_SIGNING_KEY_COMMENT` で変えられる
- 案件が終わったら: `sgw revoke-project`

## 最新への追従

`sgw init` が書いたものはすべてあなたのもので、編集してよい。`sgw.toml` は sgw が書いたものの記録
（各ファイルの sha）で、`sgw update` はこれで「あなたが編集したファイル」と「新しい版が変えるファイル」を見分ける。

```bash
sgw update            # 何が新しいか、どのファイルが変わるか、UPGRADING が何を求めるか。何も変更しない
sgw update --apply    # 更新する
```

`sgw update --apply` がすること:

1. ゲートウェイの `image:` タグと `FROM` タグを `sgw` 自身の版に上げる
2. sgw が書いたままの雛形ファイルをこの版が変えるなら上書きする。あなたが編集したものは触らない。
   両方なら、この版のファイルを `<file>.sgw-new` として隣に書く（取り込んだら消す。`--force` で上書き）
3. 確認のうえ、ゲートウェイを作り直す
4. パスフレーズが保存されていれば解錠する
5. 運用者にしかできない作業を表示する: Rebuild Container、またぐ [UPGRADING.ja.md](../../../UPGRADING.ja.md) の節（`sgw update --notes`）、コミット

0.2.52 より前のプロジェクトには `.devcontainer/sgw/`（mise の層）と、それを include する `mise.toml` がある。
`sgw update --apply` がそのディレクトリと行を消し、自分のタスクは残す。
