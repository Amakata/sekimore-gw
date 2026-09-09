# sekimore-relay

AI エージェントの **git 操作（SSH）と GitHub API 操作を案件単位のポリシーで中継する関所**。
sekimore-gw のイメージに同梱され、`config.yml` に `domain_handlers` の `git-relay` があるときだけ起動する。

- 要件: `doc/sekimore-gw/requirements/04-relay.md`
- 設計: `doc/sekimore-gw/design/relay.md`（状態機械、エラー分類、brief からの逸脱一覧）

## 何をするか

| 経路 | 方式 | 関所の受け口 |
|---|---|---|
| git | DNS が `github.com` → 関所 IP、known_hosts 1 行。`git@github.com:Org/Repo.git` がそのまま通る | `:22`（SSH、公開鍵認証、`git-upload-pack` / `git-receive-pack` のみ） |
| GitHub API | 専用 CLI `sekimore-relay agent …` が平文 HTTP で叩く | `:8420` |
| 同じドメインの 443 | 既定は実 upstream への TCP 素通し（`relay.https: reject` で即切断） | `:443` |

- 案件外リポジトリ / read-only / 許可外 base は **上流に到達する前に**拒否（`Authorized` 型で検査漏れをコンパイルエラーに）
- `git push origin HEAD:refs/for/main` → `refs/heads/sekimore/main-<sha7>` に書き換えて push し、PR を作る
- 直接 push は既定で `refs/heads/sekimore/*` のみ。tag / 削除は拒否
- 上流 git は `ssh git@<host> git-<verb> 'Org/Repo.git'`（依頼者の ssh-agent。鍵は Mac から出ない）
- 上流 API は device flow トークン（`repo project`）。エージェントには案件トークン `skm_…` だけ渡す
- 監査ログ `/data/relay/audit.jsonl`（全ての拒否に `reason`、`actor: agent-via-gateway`）

## 設定（`/etc/sekimore/config.yml`、Python と共有）

```yaml
domain_handlers:
  github.com: { handler: git-relay }      # 完全一致 FQDN。1 つのみ
relay:
  https: passthrough                      # passthrough | reject
  bootstrap: auto                         # auto | manual
  token_ttl: 12h
  project:
    name: case-a
    repos:
      - { name: Org/Repo, mode: read-write, bases: [main] }   # push: ["sekimore/*"] が既定
    permissions: [pr:create, issue:create]
```

`relay:` 配下の未知キーはエラー（typo で権限が緩まない）。全キーは `src/config.rs`。

## 操作者コマンド（gateway コンテナ内）

```bash
docker compose exec sekimore-gw sekimore-relay check          # ポリシーと状態（agent / known_hosts / token / keys）
docker compose exec sekimore-gw sekimore-relay login          # device flow → /data/relay/upstream_token + known_hosts
docker compose exec sekimore-gw sekimore-relay token          # 案件トークン発行（bootstrap: manual のとき）
docker compose exec sekimore-gw sekimore-relay tokens | revoke --label L | revoke-project
docker compose exec sekimore-gw sekimore-relay add-key "ssh-ed25519 AAAA…"   # 手動登録
docker compose exec sekimore-gw sekimore-relay bootstrap disable|enable|status
```

## エージェント側（devcontainer 内）

```bash
export SEKIMORE_ENDPOINT=http://<gateway-ip>:8420 SEKIMORE_TOKEN=skm_… SEKIMORE_REPO=Org/Repo
sekimore-relay agent whoami
sekimore-relay agent pr create --head sekimore/main-abc1234 --base main --title T
sekimore-relay agent issue create --title T --labels bug
git push origin HEAD:refs/for/main
```

## 開発

```bash
mise use rust@1.89                                  # または rustup
cargo test --features test-hooks                    # e2e は git / ssh が必要（無ければ skip。CI では SEKIMORE_E2E_REQUIRED=1）
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo audit                                         # .cargo/audit.toml の ignore は理由付き
cargo tree -i aws-lc-rs; cargo tree -i openssl-sys  # どちらも無いこと
```

`test-hooks` feature は `LocalGitUpstream`（ローカル bare repo に `git receive-pack`）を有効にする。イメージビルドには含めない。

## ビルド（イメージ）

`rust:1.89-slim-bookworm` + `musl-tools` で各アーキ native の静的 musl バイナリ（`sekimore-gw/Dockerfile` の `relay-builder` 段）。
glibc 世代に依存しないので、devcontainer base イメージへ `COPY --from` してそのまま動く。
