# sgw-devcontainer-base

*[English](README.md)*

sekimore-gw（略して sgw）の dev コンテナ側で、ゲートウェイのリポジトリのこのディレクトリにある。
単体では使わない。この構成がなぜ必要かは[最上位の README](../README.ja.md) で説明している。
0.2.45 までは独立したリポジトリだった（`Amakata/sgw-devcontainer-base`、archive 済み）。

- 配布先: `ghcr.io/amakata/sgw-devcontainer-base`。ゲートウェイと同じ版番号で、同じタグから出す
- 対応プラットフォーム: `linux/amd64`, `linux/arm64`

## プロジェクトを始める

プロジェクトは [`examples/sgw-sample/`](examples/sgw-sample/) の複製から始める。中身は次のとおり。

- ゲートウェイと dev のコンテナ
- ホスト側の mise タスク

次の手順をホストで順に実行する。
各手順の詳細は [`examples/sgw-sample/README.ja.md`](examples/sgw-sample/README.ja.md) に書いてある。

1. リポジトリを複製する:
   ```
   git clone https://github.com/Amakata/sekimore-gw.git
   ```
2. 次のものをプロジェクトにコピーする:
   - `base/examples/sgw-sample/.devcontainer/`
   - `base/examples/sgw-sample/mise.toml`
3. `.devcontainer/.env.sample` を `.devcontainer/.env` にコピーする:
   ```
   cp .devcontainer/.env.sample .devcontainer/.env
   ```
   プロジェクト名、ユーザー名、メールアドレスを埋める。
4. `.devcontainer/config/config.yml` を編集する:
   - `relay.project.repos` と `permissions` を設定する。
   - このファイルにはゲートウェイが読むキーがすべて載っている。
   - 影響の大きい権限はコメントアウトしてある。
5. VS Code を完全に終了し、次を実行して「Reopen in Container」を選ぶ:
   ```
   mise run vscode
   ```
   このタスクは `SSH_AUTH_SOCK` なしで VS Code を開く。
   運用者の ssh-agent は dev コンテナに届かない。
6. 秘密ストアを解錠する:
   ```
   mise run gw:unlock
   ```
   - 初回の実行でパスフレーズを設定する。
   - ゲートウェイを作り直すたびに解錠し直す必要がある。
   - これを省くには、次を一度実行する:
     ```
     mise run gw:keychain-set
     ```
     パスフレーズがホストに保存される。保存先は macOS のキーチェーン、Secret Service、root 所有のファイルのいずれかである。
     以後は `gw:recreate` がストアを自動で解錠する。
7. GitHub にログインする (初回だけ):
   ```
   mise run gw:login
   ```
   - デバイスフローを使う。
   - 上流のトークンと `known_hosts` を保存する。
   - 解錠済みのストアが必要である。
8. 署名鍵を表示する:
   ```
   mise run dev:signing-key
   ```
   表示された公開鍵を、GitHub に Signing Key として登録する。
   エージェントのコミットはこの鍵で署名される。
9. 構成全体を確認する:
   ```
   mise run relay:verify
   ```
   これが通れば設定は完了である。

## プロジェクトの Dockerfile

プロジェクトの `.devcontainer/Dockerfile` に必要なのは次の内容だけである。

```dockerfile
# latest ではなく版を書く。`mise run upgrade:apply` がこれを上げる
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.46

# プロジェクト固有の追加だけを書く
# 例: mise use -g python@3.13.0 && mise reshim
```

サンプルの [Dockerfile](examples/sgw-sample/.devcontainer/Dockerfile) に、次の方法を示してある。

- 言語のバージョンをプリインストールする
- mise のデータディレクトリに volume をマウントしても残す

## イメージの内容

| | |
|---|---|
| ベース | `mcr.microsoft.com/devcontainers/base:bookworm` (`vscode` ユーザー、uid=1000) |
| シェル | zsh、oh-my-zsh とプラグイン、`fzf`, `jq`, `vim`, `nano`, `curl`, `wget`, `unzip`, `rsync`, `pv`, `gnupg`, `sudo` |
| ネットワーク | `iptables`, `iproute2`, `iputils-ping`, `dnsutils` |
| Git | `git-delta` |
| DB ヘッダ | `libpq-dev`, `default-libmysqlclient-dev` |
| 言語 | `mise` (Python、Node.js、Ruby、PHP、Rust、Go を管理)。言語のバージョンは含まない |
| AI | Claude Code CLI、OpenAI Codex CLI |
| クラウド | AWS CLI v2、Docker CE (buildx と compose を含む) |
| ゲートウェイ | `sekimore-agent-setup.sh`、`sekimore-relay` CLI、`sekimore` ラッパー |
| zsh の既定設定 | `/etc/skel/zsh-rc.d/`: XDG、上流プロキシの環境変数、mise の activate、エイリアス、プラグイン。post-create が `~/.config/zsh/rc.d/` に複製する |

- `sekimore-agent-setup.sh` と関所（sekimore-relay）の CLI `sekimore-relay` は、同じ sekimore-gw イメージから取り込む。
  両者の版はずれない。
- このイメージにプロジェクト固有のものは含まれない。
  次のものは、サンプルと同様にプロジェクト側で用意する:
  - 言語のビルド依存
  - 設定
  - Docker デーモンに必要な権限

## 所有と最新への追従

サンプルから複製したものはすべてプロジェクトのものになる。`.devcontainer/sgw/` だけは例外である。

- `.devcontainer/sgw/` にはホスト側のスクリプトとタスクが入っている。
- `mise run upgrade:apply` がこれを入れ替える。手で編集しない。
- 配布タスクを変えるには、プロジェクトの `mise.toml` に同じ名前のタスクを定義する。
  そちらが優先される。
- `.devcontainer/sgw/gateway.mise.toml` には `gw:*` タスクが入っている。
  ゲートウェイイメージが英語版と日本語版を同梱している。
  `mise run upgrade:sync` が現在の言語のものを取得する。
  言語は `SEKIMORE_LANG`、次に `LC_ALL`、`LC_MESSAGES`、`LANG` で決まる。
- 保存したパスフレーズで `gw:recreate` がストアを解錠しないようにするには、`SGW_NO_AUTO_UNLOCK=1` を設定する。
- `config.yml` に `proxy.upstream_proxy` があると、ゲートウェイが `HTTP_PROXY`・`HTTPS_PROXY`・
  `NO_PROXY` を dev に書き、`10-sekimore-proxy.zsh` がすべてのシェルに渡す。
  プロジェクトが独自に設定している場合は外すか値を揃える。dev の通常の通信が本当に上流を通るかは
  `mise run relay:verify` が確認する（UPGRADING: base 0.2.40）。

```bash
mise run upgrade          # 何が新しいか、どのファイルが変わるか、UPGRADING が何を求めるか。何も変更しない
mise run upgrade:apply    # 更新する
```

`upgrade:apply` は次のことを行う。

1. ゲートウェイの `image:` タグと `FROM` タグを、GHCR の最新の版に上げる。
2. `.devcontainer/sgw/` を入れ替える。
3. 確認を求めたうえで、ゲートウェイを作り直す。
4. パスフレーズが保存されていれば解錠する。
5. 運用者にしかできない作業を表示する:
   - base が変わった場合の Rebuild Container
   - 更新でまたぐ [UPGRADING.ja.md](../UPGRADING.ja.md) の節
   - コミット

`.devcontainer/sgw/` のファイルが手で書き換えられている場合は、何も書き込まずに止まる。

3 つの部分は互いに依存している。
1 つのコマンドですべてを更新するのはそのためである。

```
sekimore-gw (ゲートウェイ)  ── このイメージが関所のバイナリを取り込む
        ↓
sgw-devcontainer-base  ── あなたの .devcontainer/Dockerfile が FROM する
        ↓
.devcontainer/sgw/     ── 両方に合わせたホスト側のスクリプトとタスク
```

- このイメージの `sekimore-relay` CLI と `sekimore-agent-setup.sh` は、ゲートウェイ `ghcr.io/amakata/sekimore-gw:0.2.46` (`ARG SEKIMORE_GW_IMAGE`) から取り込む。
  base とゲートウェイは別々の 0.2.x 系列である。
- プロジェクトが動かすゲートウェイは、compose ファイルの `image:` タグで決まる。
  `mise run upgrade:apply` が両方を上げる。

## リンク

- [UPGRADING.ja.md](../UPGRADING.ja.md) — 各リリースがプロジェクトに求める変更。次を含む:
  - ゲートウェイ 0.0.x からの移行
  - base 0.2.20 より前に作ったプロジェクトの、`.devcontainer/sgw/` への一度きりの移行
- [CHANGELOG.ja.md](CHANGELOG.ja.md) — このイメージの変更履歴。各リリースが使ったゲートウェイの版も記録している。関連:
  - [ゲートウェイの CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/CHANGELOG.ja.md)
  - [関所の CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/relay/CHANGELOG.ja.md)
- [RELEASING.md](RELEASING.md) — リリースの順序、ローカルビルド、GHCR に push するタグ (保守者向け、英語)
- ライセンス: Apache-2.0（[LICENSE](../LICENSE)。ゲートウェイと同じ）
