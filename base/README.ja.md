# sgw-devcontainer-base

*[English](README.md)*

sekimore-gw（略して sgw）の dev コンテナ側で、ゲートウェイのリポジトリのこのディレクトリにある。
単体では使わない。この構成がなぜ必要かは[最上位の README](../README.ja.md) で説明している。
0.2.45 までは独立したリポジトリだった（`Amakata/sgw-devcontainer-base`、archive 済み）。

- 配布先: `ghcr.io/amakata/sgw-devcontainer-base`。ゲートウェイと同じ版番号で、同じタグから出す
- 対応プラットフォーム: `linux/amd64`, `linux/arm64`

## プロジェクトを始める

運用者の道具 `sgw` が、プロジェクトを書き、ホストからゲートウェイを動かす。次の手順をホストで順に実行する。
`sgw init` が書く雛形の中身は [`examples/sgw-sample/README.ja.md`](examples/sgw-sample/README.ja.md) にある。

1. `sgw` を入れる:
   ```
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. 雛形を書く:
   ```
   sgw init --devcontainer my-project
   cd my-project
   ```
   `.devcontainer/`（ゲートウェイと dev のコンテナ、`config.yml`、ホスト側のファイル）と `mise.toml`、
   `.env.sample` から作った `.devcontainer/.env` が書かれる。
   `.devcontainer/.env` にプロジェクト名、ユーザー名、メールアドレスを埋める。
3. `.devcontainer/config/config.yml` を編集する:
   - `relay.project.repos` と `permissions` を設定する。
   - このファイルにはゲートウェイが読むキーがすべて載っている。
   - 影響の大きい権限はコメントアウトしてある。
4. VS Code を完全に終了し、次を実行して「Reopen in Container」を選ぶ:
   ```
   sgw open
   ```
   `SSH_AUTH_SOCK` なしで VS Code を開く。運用者の ssh-agent は dev コンテナに届かない。
5. 秘密ストアを解錠する:
   ```
   sgw unlock
   ```
   - 初回の実行でパスフレーズを設定する。
   - ゲートウェイを作り直すたびに解錠し直す必要がある。
   - これを省くには、次を一度実行する:
     ```
     sgw keychain-set
     ```
     パスフレーズがホストに保存される。保存先は macOS のキーチェーン、Secret Service、root 所有のファイルのいずれかである。
     以後は `sgw recreate` がストアを自動で解錠する。
6. GitHub にログインする（初回だけ）:
   ```
   sgw login
   ```
   - デバイスフローを使う。
   - 上流のトークンと `known_hosts` を保存する。ホスト鍵は保存する前に確認を求める。
   - 解錠済みのストアが必要である。
7. 署名鍵を表示する:
   ```
   sgw signing-key
   ```
   表示された公開鍵を、GitHub に Signing Key として登録する。
   エージェントのコミットはこの鍵で署名される。
8. 構成全体を確認する:
   ```
   sgw verify
   ```
   これが通れば設定は完了である。

`.devcontainer/sgw/` の mise タスクも同じことをする（`mise run gw:unlock`、`mise run relay:verify` …）。`mise tasks` に一覧がある。

## プロジェクトの Dockerfile

プロジェクトの `.devcontainer/Dockerfile` に必要なのは次の内容だけである。

```dockerfile
# 版を書く。latest ではなく: `sgw update --apply` が上げる
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.47

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

`sgw init` が書いたものはすべてプロジェクトのものになる。`.devcontainer/sgw/` だけは例外である。

- `.devcontainer/sgw/` には `sgw` より前のやり方のホスト側スクリプトと mise タスクが入っている。
  `sgw update --apply`（または `mise run upgrade:apply`）がこれを入れ替える。手で編集しない。
- 配布タスクを変えるには、プロジェクトの `mise.toml` に同じ名前のタスクを定義する。
  そちらが優先される。
- タスクファイルは英語版と日本語版がある。`sgw update --sync` が現在の言語のものを書く。
  言語は `SEKIMORE_LANG`、次に `LC_ALL`、`LC_MESSAGES`、`LANG` で決まる。
- 保存したパスフレーズで解錠させないには、`sgw recreate --no-unlock`（または `SGW_NO_AUTO_UNLOCK=1`）。
- `config.yml` に `proxy.upstream_proxy` があると、ゲートウェイが `HTTP_PROXY`・`HTTPS_PROXY`・
  `NO_PROXY` を dev に書き、`10-sekimore-proxy.zsh` がすべてのシェルに渡す。
  プロジェクトが独自に設定している場合は外すか値を揃える。dev の通常の通信が本当に上流を通るかは
  `sgw verify` が確認する（UPGRADING: base 0.2.40）。

```bash
sgw update            # 何が新しいか、どのファイルが変わるか、UPGRADING が何を求めるか。何も変更しない
sgw update --apply    # 更新する
```

`sgw update --apply` は次のことを行う。

1. ゲートウェイの `image:` タグと `FROM` タグを、`sgw` 自身の版に上げる。GHCR に `sgw` より新しい版が
   あるときはそう言い、代わりに `install.sh` を示す。
2. `.devcontainer/sgw/` をその版のファイル（バイナリが持っている）で入れ替える。
3. 確認を求めたうえで、ゲートウェイを作り直す。
4. パスフレーズが保存されていれば解錠する。
5. 運用者にしかできない作業を表示する:
   - base が変わった場合の Rebuild Container
   - 更新でまたぐ [UPGRADING.ja.md](../UPGRADING.ja.md) の節（`sgw update --notes`）
   - コミット

`.devcontainer/sgw/` のファイルが手で書き換えられている場合は、何も書き込まずに止まる（`--force` で上書き）。

各部分は互いに依存しており、1 つの版番号がそれらを覆う。

```
sekimore-gw (ゲートウェイ)   ── このイメージが関所のバイナリを取り込む
        ↓
sgw-devcontainer-base    ── あなたの .devcontainer/Dockerfile が FROM する
        ↓
sgw / .devcontainer/sgw/ ── 運用者の道具とホスト側のファイル。同じ版
```

- このイメージの `sekimore-relay` CLI と `sekimore-agent-setup.sh` は、ゲートウェイ `ghcr.io/amakata/sekimore-gw:0.2.47` (`ARG SEKIMORE_GW_IMAGE`) から取り込む。
  base はゲートウェイと同じ版番号を持ち、1 つのタグから出る。
- プロジェクトが動かすゲートウェイは、compose ファイルの `image:` タグで決まる。
  `sgw update --apply` が両方を上げる。

## リンク

- [UPGRADING.ja.md](../UPGRADING.ja.md) — 各リリースがプロジェクトに求める変更。次を含む:
  - ゲートウェイ 0.0.x からの移行
  - base 0.2.20 より前に作ったプロジェクトの、`.devcontainer/sgw/` への一度きりの移行
- [CHANGELOG.ja.md](CHANGELOG.ja.md) — このイメージの変更履歴。各リリースが使ったゲートウェイの版も記録している。関連:
  - [ゲートウェイの CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/CHANGELOG.ja.md)
  - [関所の CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/relay/CHANGELOG.ja.md)
- [RELEASING.md](../RELEASING.md) — リリースの手順、ローカルビルド、GHCR に push するタグ（保守者向け、英語）
- ライセンス: Apache-2.0（[LICENSE](../LICENSE)。ゲートウェイと同じ）
