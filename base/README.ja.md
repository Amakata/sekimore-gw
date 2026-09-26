# sgw-devcontainer-base

*[English](README.md)*

dev コンテナの元になるイメージ。使い方は[最上位の README](../README.ja.md) にある。
このページは、イメージに何が入っているかと、base 自体を変えるならどこを触るか。

- `ghcr.io/amakata/sgw-devcontainer-base`。ゲートウェイと同じ版番号、同じタグ
- `linux/amd64`, `linux/arm64`

## プロジェクトの Dockerfile

```dockerfile
# 版を書く。latest ではなく: sgw update --apply が上げる
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.51

# プロジェクト固有の追加だけ。例: mise use -g python@3.13.0 && mise reshim
```

言語のバージョンをプリインストールする例は、雛形の [Dockerfile](../relay/templates/devcontainer/.devcontainer/Dockerfile) にある。

## イメージの中身

| | |
|---|---|
| ベース | `mcr.microsoft.com/devcontainers/base:bookworm`（`vscode`、uid 1000） |
| シェル | zsh、oh-my-zsh、`fzf`, `jq`, `vim`, `nano`, `curl`, `wget`, `unzip`, `rsync`, `pv`, `gnupg`, `sudo` |
| ネットワーク | `iptables`, `iproute2`, `iputils-ping`, `dnsutils` |
| Git | `git-delta` |
| DB ヘッダ | `libpq-dev`, `default-libmysqlclient-dev` |
| 言語 | `mise`。言語のバージョンは含まない |
| AI | Claude Code CLI、OpenAI Codex CLI、Anthropic 公式の skills |
| クラウド | AWS CLI v2、Docker CE（buildx、compose） |
| ゲートウェイ | `sgw-agent`（AI のコマンド。起動のたびに `sgw-agent setup`）、`sekimore-relay`、`sekimore`（旧名）、`sgw-post-start`（`postStartCommand` が実行する）。`ghcr.io/amakata/sekimore-gw:0.2.51` から取り込む |
| zsh の既定設定 | `/etc/skel/zsh-rc.d/`。post-create が `~/.config/zsh/rc.d/` に複製する |

入れていないもの:

- GitHub CLI: dev にトークンがあると、関所の権限を素通りして GitHub を操作できる
- プロジェクト固有のもの: 言語のバージョン、ビルド依存、`config.yml`

## どこを変えると何が変わるか

| 変えたいもの | 触る場所 |
|---|---|
| apt パッケージ | [Dockerfile](Dockerfile) の `Base apt packages` ブロック |
| git-delta、AWS CLI、Docker CE、Claude Code、Codex、skills | [Dockerfile](Dockerfile) のその名前の節 |
| すべての zsh が最初に読むもの | [zsh-config/rc.d/](zsh-config/rc.d/) |
| Claude Code の managed settings | [managed-settings.json](managed-settings.json) |
| `sekimore` ラッパー、`docker-init.sh`、Docker のインストール | [scripts/](scripts/) |
| 関所のツールをどのゲートウェイから取るか | `ARG SEKIMORE_GW_IMAGE`。リリースが合わせる |

手元でビルドして確かめる:

```sh
docker build -t sgw-devcontainer-base:dev base
base/tests/test_image.sh sgw-devcontainer-base:dev
```

## リンク

- [docs/template.ja.md](../docs/template.ja.md) — `sgw init` が書く雛形
- [UPGRADING.ja.md](../UPGRADING.ja.md) — 版を上げるときの作業
- [CHANGELOG.ja.md](../CHANGELOG.ja.md) — ゲートウェイ、relay、base、sgw で 1 つ。[base/CHANGELOG.ja.md](CHANGELOG.ja.md) は 0.2.45 までの base 独自の履歴
- [RELEASING.md](../RELEASING.md)
