# dev コンテナの言語

base イメージに入っている言語は、mise と、codex が動く node だけです。プロジェクトは次の 3 通りのどれかで言語を足します。

| 誰が | 方法 | 置き場 |
|---|---|---|
| プロジェクト（ビルド済みのイメージがある言語） | 言語イメージを `COPY --from=` で取り込む | `/opt/mise`（読み取り専用） |
| プロジェクト（それ以外の言語） | Dockerfile で `mise install --system` | `/opt/mise`（読み取り専用） |
| 各自 | コンテナの中で `mise use -g <言語>@<版>` | mise-store の volume |

- `/opt/mise` は mise の system ディレクトリ（`MISE_SYSTEM_DATA_DIR`）です。root が所有し、ユーザーの mise は読むだけで書きません。起動時に chown もしません。
- 同じ版が mise-store の volume と `/opt/mise` の両方にあると、volume 側が優先されます。
- 版は `x.y.z` で書きます。`node@24` や `latest` はその時点の最新に解決されます。イメージの版と食い違うと、mise が volume に別の版を入れます。

## プロジェクト: Dockerfile で入れる

root で system ディレクトリに入れ、shim を作り、書き込みを塞ぎます。

```dockerfile
USER root
RUN umask 022 \
 && HOME=/root mise install --system python@3.13.7 node@22.21.1 uv@0.8.22 \
 && HOME=/root mise reshim --system \
 && chmod -R a-w /opt/mise
USER vscode
RUN mise use -g python@3.13.7 node@22.21.1 uv@0.8.22
```

- `mise reshim --system` は省けません。省くと、ユーザーの mise が system の shim を自分で作ろうとして失敗します（`refusing to publish outside the system installs or shims directories`）。
- ユーザーで実行する `mise use -g` は版を記録するだけです。ダウンロードもコピーもしません。

### ビルド済みの言語イメージから取り込む

ソースからビルドする言語（PHP、Python 2.7）は、ビルドに数分かかります。ビルド済みのイメージ（#376、公開後）は、それを `/opt/mise` の下に持っています。

```dockerfile
FROM ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm AS php
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.67
USER root
RUN apt-get update && apt-get install -y --no-install-recommends <イメージが示す実行時のパッケージ> \
 && rm -rf /var/lib/apt/lists/*
COPY --from=php /opt/mise/installs/php/ /opt/mise/installs/php/
COPY --from=php --chown=vscode:vscode /home/ /home/
RUN HOME=/root mise reshim --system && chmod -R a-w /opt/mise
USER vscode
RUN mise use -g php@8.3.26
```

- タグ: `<版>-<リビジョン>-bookworm`（`8.3.33-1-bookworm`）は中身が変わりません。同じ版を作り直すと、リビジョンが上がった新しいタグになります。`<版>-bookworm` は最新のリビジョンを指します。イメージを完全に固定したいときはリビジョンまで書きます。
- 追う系列: `lang/versions.yml` の `track` にある系列（PHP 8.3）は、新しいパッチ版が出た日に公開されます。それ以外の版は、そこに固定した版を一度だけ作ります。プロジェクトの Dockerfile にある追う系列の版は、`sgw update` が新しいパッチ版を知らせ、`--apply` で書き換えます（タグを直接書いた行だけで、ARG を通した行は対象外）。別の系列へは上げず、それ以外の版は触りません。
- `/opt/mise/installs/<言語>/` はディレクトリごとコピーします。版のほかに、mise のバックエンドの記録と版の別名（`8.3`、`latest`）があります。
- `/home/` には、実行時に要る mise のプラグインがあります（PHP なら vfox-php）。mise には system 側のプラグイン置き場が無いので、ユーザーの mise が見る場所に置きます。プラグインの要らない言語（Python）では `/home/` は空です。
- `/opt/mise/installs/<言語>/<版>/.sgw-runtime-packages` に、実行時に要る apt のパッケージの一覧があります。

### npm のグローバルな道具

system 側の node は読み取り専用なので、`npm install -g` は EACCES で失敗します。CLI は mise の道具として入れます: `HOME=/root mise install --system npm:<パッケージ>@<版>`（または `pnpm@<版>`）。

## 各自: コンテナの中で入れる

```sh
mise use -g node@24.21.0
```

`~/.local/share/mise/installs`（mise-store の volume）にダウンロードされるので、リビルドしても残ります。ダウンロードは gateway を通るので、配布元のホストが `allow_domains` に要ります。

| 言語 | ホスト |
|---|---|
| node | `nodejs.org` |
| python（ビルド済み）、uv | `github.com`、`objects.githubusercontent.com`、`release-assets.githubusercontent.com` |
| そのほか多く（aqua、GitHub のリリース） | `github.com`、`objects.githubusercontent.com`、`release-assets.githubusercontent.com`、`api.github.com` |

拒否されたダウンロードは、`sgw web` や `sgw audit` にホスト名が出ます。

## 0.3 への移行

0.3 では、0.2 がしていた 2 つのことをやめます（#377）。

- `/usr/local/share` をユーザーに渡さない（`chown -R vscode` をしない）。post-start も chown しない。
- template は `~/.local/share/mise/installs` を `installs-default` にコピーしない。post-create もそれを mise-store の volume にコピーしない。

プロジェクトの Dockerfile で変えること:

| 今していること | 変え方 |
|---|---|
| vscode で `mise use -g <言語>@<版>` し、`cp -a … installs-default` | root で `mise install --system`、`mise reshim --system`、`chmod -R a-w /opt/mise`、そのあと vscode で `mise use -g`（[上](#プロジェクト-dockerfile-で入れる)）。`cp -a` は消す |
| `ENV MISE_DATA_DIR=/usr/local/share/mise` | 消す |
| `/usr/local/share/mise/installs/…` のパスを直接使う（`ls -d node/24.*`、symlink、`cp -a`） | `mise where <言語>@<版>` |
| `node@24`、`php@8.3`、`latest` | `x.y.z`。あいまいな指定はイメージと違う版に解決され、mise がその版を volume に入れる（PHP ならソースビルドが始まる） |
| `npm install -g <CLI>` | `HOME=/root mise install --system npm:<CLI>@<版>`（または `pnpm@<版>`） |
| `/usr/local/share` の下に書き込む前提 | 専用のディレクトリを Dockerfile で作り、chown する |
| Dockerfile で rust を入れている | 各自が `mise use -g rust@<版>`（rustup は system ディレクトリでは動かない） |

mise-store の volume には、以前のやり方でコピーされた版が残っていることがあります。volume 側の版は、イメージの同じ版より優先されます。一度だけ空にしてください。dev コンテナを止めて volume を消す（`docker volume rm mise-store-<id>`）か、docker-compose.yml で volume の名前を変えます。
