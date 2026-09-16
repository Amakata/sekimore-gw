# sekimore-relay

AI エージェントの git 操作（SSH）と GitHub API 操作を、案件単位のポリシーで中継する関所です。
sekimore-gw のイメージに同梱され、`config.yml` に `handler: git-relay` があるときだけ起動します。
無ければ何も変わりません。

- 変更履歴: [CHANGELOG.md](CHANGELOG.md)
- 要件と設計（workspace リポジトリ）: [requirements/04-relay.md](https://github.com/Amakata/sgw-devcontainer/blob/main/doc/sekimore-gw/requirements/04-relay.md)、[design/relay.md](https://github.com/Amakata/sgw-devcontainer/blob/main/doc/sekimore-gw/design/relay.md)
- エージェント側の自動化（agent-setup / devcontainer base）: [design/sekimore-relay-agent.md](https://github.com/Amakata/sgw-devcontainer/blob/main/doc/sgw-devcontainer-base/design/sekimore-relay-agent.md)

## 全体像

```
dev (AI)                          sekimore-gw                              上流
────────                          ───────────                              ────
git@github.com:Org/Repo.git ─DNS→ 関所 IP:22 (SSH, 使い捨て鍵) ─┐
                                    案件リポジトリ検証            ├─ ssh git@github.com (依頼者の ssh-agent) → GitHub
                                    refs/for/<base> → PR 作成    ┘   POST /repos/…/pulls (device flow トークン)
sekimore … ─HTTP→ 関所 IP:8420 (skm_ トークン) ──────────────── リソース×アクション判定 → GitHub API
https://github.com/…  ─DNS→ 関所 IP:443 ─────────────────────── TCP 素通し（既定。TLS は終端しない）
```

エージェントが持つのは次の 3 つだけです。どれも上流ではそのまま使えません。

- 使い捨て SSH 鍵（関所への認証）
- AI 専用の署名鍵（コミット署名）
- 案件トークン `skm_…`（関所の API）

上流の資格情報（依頼者の ssh-agent、device flow トークン）は sekimore-gw の中にしかありません。

## 導入手順（操作者）

### 1. 関所を有効にする

`config.yml`（`/etc/sekimore/config.yml` にマウント）に追記します。最小構成は次のとおりです。

```yaml
domain_handlers:
  github.com: { handler: git-relay }

relay:
  project:
    name: case-a
    permissions: [pr:create, pr:read, ci:read]
    repos:
      - { name: Org/Repo, mode: read-write, bases: [main] }
```

キーの意味と全体の例は「設定リファレンス」を見てください。
`relay:` 配下の未知キーはエラーになります（typo で権限が緩まないため）。

### 2. 依頼者の ssh-agent を関所に渡す

関所は上流 git に依頼者の ssh-agent で認証します。鍵はホストから出ません。

```yaml
# docker-compose.yml の sekimore-gw
    volumes:
      - ${SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}:/ssh-agent/agent.sock:ro
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

- Docker Desktop（Mac）: 既定値のままで動きます。Mac 側の `ssh-add -l` に鍵が出ていることを確認してください。
- Vagrant VM: 固定パスに socket を用意し、`SEKIMORE_AGENT_SOCK` に書きます。
  例: `ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>`

### 3. 再起動して確認する

`domain_handlers` と `relay` の変更はコンテナの再作成で反映されます。hot reload は警告を出して旧値を維持します。

```bash
docker compose up -d --force-recreate sekimore-gw      # Dev Containers 構成なら: mise run gw:recreate
docker compose exec sekimore-gw sekimore-relay check   # ポリシーと状態（agent / known_hosts / token / 鍵）
```

### 4. 上流に認証する（初回のみ）

```bash
docker compose exec sekimore-gw sekimore-relay login   # Dev Containers 構成なら: mise run gw:login
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← ブラウザで承認
```

- トークンは `/data/relay/upstream_token`（0600）に保存されます。上流の SSH ホスト鍵も同時に known_hosts に入ります。
- 上流が複数あるときは `--upstream <domain>` で上流ごとに実行します（`logout` / `whoami` も同じ）。
- `sekimore-relay whoami` で、関所がどの GitHub identity として動くかを確認できます。

device flow トークンは `repo` スコープです。GitHub 側の認可には頼れず、`repos` と `permissions` が唯一の防壁になります。
GitHub の監査ログではエージェントと人間の操作を区別できないので、関所の `/data/relay/audit.jsonl` が区別できる唯一の記録です。

## エージェント側の準備（dev コンテナ内）

`agent-setup.sh`（sgw-devcontainer-base では `/usr/local/bin/sekimore-agent-setup.sh`、postStartCommand で毎起動）が、関所を見つけたら自動で行います。

- 使い捨て認証鍵 `~/.ssh/sekimore/id_ed25519` と署名鍵 `~/.ssh/sekimore/signing_ed25519` を生成します（あれば再利用）。
- `POST /bootstrap` で公開鍵を登録し、案件トークンを受け取ります。有効なトークンがあれば再発行しません。
- `/etc/sekimore-agent/env`（0600）に接続情報を書きます。`sekimore` ラッパーはこのファイルを読み、期限切れなら自動で取り直します。
- 上流ごとに `~/.ssh/config` の `Host` ブロックと known_hosts を書きます。
- コミット署名を AI 専用鍵に設定します。署名鍵の公開鍵は GitHub に「Signing Key」として手で登録してください（ログに表示されます）。

調整用の環境変数:

| 変数 | 意味 |
|---|---|
| `SEKIMORE_BOOTSTRAP=manual` | 鍵登録とトークン発行を操作者が行う（`add-key` と `token`） |
| `SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT` | 署名鍵のコメント（GitHub 登録時の Title） |
| `SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE` | 対象ユーザーと保存先 |

## 日常の使い方（エージェント）

```bash
git clone git@github.com:Org/Repo.git           # URL はそのまま。関所が透過的に中継する
git push origin HEAD:refs/for/main              # sekimore/main-<sha7> に push され、PR（base=main）が作られる
git push origin HEAD:refs/heads/sekimore/x      # 自分の名前空間 sekimore/* への直接 push

sekimore whoami                                 # 自分の権限と repo
sekimore pr create --head sekimore/x --base main --title T --body="…"
sekimore pr status --number 12                  # PR の CI チェック（--json で機械可読）
sekimore pr merge --number 12
sekimore ci runs --ref v0.2.0                   # タグ / ブランチ / SHA に紐づく workflow run
sekimore ci jobs --number 12                    # PR の全 run のジョブ一覧（失敗と job_id が分かる）
sekimore ci log --number 12                     # 失敗ジョブのログを末尾から。--before / --window で前へ
sekimore issue create --title T --labels bug    # ラベル付きは issue:label も要る
```

`sekimore` は `sekimore-relay agent` のラッパーです。repo は `--repo Org/Repo` で指定し、上流が複数あるときは `host/Org/Repo` と書けます。
`--body` の値が `-` で始まるときは `--body="…"` の形にしてください。

既定で拒否されるもの: 案件外のリポジトリ、read-only への push、`bases` に無い base への `refs/for`、`sekimore/*` 以外への直接 push、タグ、削除、許可していない API 操作。理由は stderr に `sekimore: …` で出ます。

## 設定リファレンス

### `domain_handlers.<domain>`

キーは完全一致の FQDN です。`git-relay` を複数書くと上流が複数になります。

| キー | 既定 | 意味 |
|---|---|---|
| `handler` | `splice` | `git-relay` で関所が受ける。`deny` は拒否、`splice` は従来どおり |
| `ssh_port` | `relay.ssh_listen` のポート | 関所側の SSH ポート。2 つ目以降の上流では必須 |
| `upstream` | ドメイン名 | 実際の上流ホスト |
| `upstream_ssh_port` | `relay.upstream_ssh_port` | 上流の SSH ポート |
| `ssh_options` | `[]` | 上流 ssh に `-o` で渡す（`ProxyJump=bastion` など）。強制オプションは上書き不可 |
| `api_base` / `graphql_base` | 上流から派生 | GitHub API の宛先。`upstream` を転送先にしたときに使う |
| `oauth_client_id` | `relay.oauth_client_id` | device flow の OAuth app（GHES では別） |
| `default` | `false` | 既定上流にする。省略時は `ssh_port` を省いた 1 つが既定 |

### `relay`

| キー | 既定 | 意味 |
|---|---|---|
| `ssh_listen` / `api_listen` / `https_listen` | `0.0.0.0:22` / `0.0.0.0:8420` / `0.0.0.0:443` | listen アドレス |
| `https` | `passthrough` | 443 の扱い。`reject` で即切断 |
| `state_dir` | `/data/relay` | 状態ファイルの置き場 |
| `token_ttl` | `12h` | 案件トークンの寿命 |
| `bootstrap` | `auto` | `POST /bootstrap` を許すか。`manual` なら操作者が登録する |
| `ssh_options` | `[]` | 全上流共通の `-o` |
| `ssh_config` | 無し | 上流 ssh に `-F` で渡すファイル（上級者向け） |
| `upstream` / `upstream_ssh_port` / `api_base` / `graphql_base` / `oauth_client_id` | | 既定上流用。handler 側に書くのが新しい書き方 |
| `limits` | | セッション数やタイムアウト |
| `project` | 必須 | 案件（下記） |

### `relay.project`

| キー | 既定 | 意味 |
|---|---|---|
| `name` | 必須 | 案件名。トークンとログに出る |
| `permissions` | `[]` | 案件の既定権限。`[…]` か `{allow, deny}` |
| `push` | `["sekimore/*"]` | 直接 push を許すブランチ glob |
| `tags` | `[]` | push を許すタグ glob。空は拒否 |
| `delete` | `false` | ブランチとタグの削除 |
| `repos` | `[]` | リポジトリ。`Org/Repo` は既定上流、`host/Org/Repo` で上流を明示 |
| `upstreams.<domain>` | | 上流ごとの層。`permissions`（差分）、`push` / `tags` / `delete`（その上流の既定）、`repos` |

### `repos[]`

| キー | 既定 | 意味 |
|---|---|---|
| `name` | 必須 | `Org/Repo`（`upstreams.<domain>.repos` の中では host 不要） |
| `mode` | 必須 | `read-only` か `read-write`。read-only は書き込み系を全て止める |
| `bases` | 全て | `refs/for/<base>` と PR の base に許すブランチ |
| `push` / `tags` / `delete` | 上位の既定 | この repo だけ上書き |
| `permissions` | 差分なし | `{allow, deny}` で足す / 消す。list は allow の追加 |

### 権限の決まり方

- 実効権限 = (案件 allow ∪ 上流 allow ∪ repo allow) − (案件 deny ∪ 上流 deny ∪ repo deny)。deny はどの層に書いても勝ちます。
- `push` / `tags` / `delete` は 案件 → 上流 → repo の順で上書きされます。glob は `*` と `?` が使えます。
- 権限キーは 16 個: `pr:create` `pr:read` `pr:comment` `pr:review` `pr:merge` `pr:close`、`issue:create` `issue:comment` `issue:close` `issue:label` `issue:assign`、`project:read` `project:add_item` `project:update_item`、`repo:read`、`ci:read`。
- 実効値は `sekimore-relay check` と Web UI の Relay タブで確認できます。

### 例: github.com と GHES を同時に扱う

```yaml
domain_handlers:
  github.com: { handler: git-relay }                    # 既定上流（ssh_port 省略）
  ghe.example.com:
    handler: git-relay
    ssh_port: 2222                                      # 2 つ目以降は別ポート
    ssh_options: [ProxyJump=bastion.example.com]        # 踏み台経由なら

relay:
  project:
    name: case-a
    permissions: [pr:read, ci:read]                     # 全上流に共通
    upstreams:
      github.com:
        permissions: { allow: [pr:create, pr:merge] }
        tags: ["v*"]
        repos:
          - { name: Org/App, mode: read-write, bases: [main] }
      ghe.example.com:
        permissions: { allow: [pr:create], deny: [pr:merge] }   # GHES ではマージさせない
        repos:
          - { name: Corp/Internal, mode: read-write, bases: [main] }
```

複数上流の仕組み: SSH の exec にはホスト名が無いので、関所は上流ごとに別ポートで listen し、接続を受けたポートで上流を決めます。
agent-setup が `~/.ssh/config` に上流ごとの `Host` と `Port` を書くので、エージェントの URL は変わりません。
443 は TLS の SNI で上流を選びます。関所の ssh はホスト側の `~/.ssh/config` を読まないので、踏み台やプロキシは `ssh_options` に書きます。
踏み台のホスト鍵は `sekimore-relay keyscan bastion.example.com --upstream ghe.example.com` で入れます。

## 運用（操作者）

Web UI（ホストの http://localhost:8090）の Relay タブで、設定・権限・トークン・アクセス履歴・ブロック履歴を閲覧できます（閲覧のみ）。
Dev Containers 構成では `mise run gw:tokens` / `gw:revoke-project` / `gw:audit` / `gw -- <args>` が用意されています。

| コマンド | 用途 |
|---|---|
| `sekimore-relay check` | ポリシーと状態の一覧 |
| `sekimore-relay tokens` | 発行済みトークン（ラベル / 期限 / 使用回数 / 状態） |
| `sekimore-relay revoke --label skm_xxxxxxxx` | 1 つ失効 |
| `sekimore-relay revoke-project` | 案件の全トークンを失効（案件終了時） |
| `sekimore-relay bootstrap disable` / `enable` | 自動登録の kill-switch |
| `sekimore-relay add-key "ssh-ed25519 AAAA…"` | 公開鍵の手動登録 |
| `sekimore-relay keyscan <host> [--port N] [--upstream <domain>]` | 上流や踏み台のホスト鍵を known_hosts に追加（fingerprint を表示） |
| `sekimore-relay login` / `logout` / `whoami` `[--upstream <domain>]` | 上流トークン |
| `tail -f /data/relay/audit.jsonl` | 全ての操作と拒否の記録 |

`/data/relay` は gateway のボリューム（0700）で、AI コンテナからは見えません。
同じ鍵からの再 bootstrap は前のトークンを失効させるので、鍵 1 本につき有効トークンは 1 つです。
期限切れから 7 日過ぎたトークンの記録は自動で消えます。恒久的な記録は `audit.jsonl` です。

## 困ったとき

| 症状 | 意味 | 対処 |
|---|---|---|
| `SSH_AUTH_SOCK is not set in the gateway container` | agent socket が関所に渡っていない | 手順 2 のマウントと環境変数。Mac 側の `ssh-add -l` |
| `ssh-agent socket … does not exist` / `cannot connect` | 転送が切れた、または権限 | 転送を張り直す。EACCES なら socket の所有者 |
| `known_hosts … has no entry for <host>` | 上流のホスト鍵が無い | `sekimore-relay login` か `sekimore-relay keyscan <host>` |
| `repository "X" is not in project "P"` | 案件外 | `repos` に追加する。意図した拒否なら何もしない |
| `push to refs/heads/main is not allowed` | 名前空間外への直接 push | `refs/for/main` で PR にする。必要なら `push` に glob を足す |
| `tag is not allowed for this repository` | タグの push は既定拒否 | その repo か上流の `tags` に glob を足す |
| `Permission denied (publickey)`（関所から） | エージェントの鍵が未登録 | `sekimore bootstrap …` か操作者の `add-key`。`bootstrap.disabled` の有無 |
| `! [remote rejected] … (sekimore: …)` | ポリシーで拒否した push | メッセージの案内どおり |
| `denied: token expired at …` | 案件トークンの期限切れ | `sekimore` ラッパーが自動で取り直す。古い環境は `sudo sekimore-agent-setup.sh` |
| `no upstream token … run sekimore-relay login` | device flow 未実施、または logout 後 | `sekimore-relay login` |
| `git ls-remote` が無言で止まる | DNS は関所を向いたが INPUT で落ちている | `iptables-legacy -S INPUT` に `--dport 22` があるか。無ければ relay 未起動 |
| `https://github.com/…` が失敗 | `https: reject`、または上流に届かない | 既定の `passthrough` に戻す。audit の `https_failed` |
| HTTPS git で `could not read Username` | HTTPS 認証を意図的に塞いでいる（依頼者の認証が関所を迂回しないため） | `git@github.com:` の SSH を使う |
| post-create の「ssh-agent が転送されています」が消えない | macOS の `code` は launchd の環境を継ぐ | VS Code を完全終了して `mise run vscode` |

## 開発

```bash
mise use rust@1.89                                  # または rustup
cargo test --features test-hooks                    # e2e は git / ssh が必要（CI では SEKIMORE_E2E_REQUIRED=1）
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo audit                                         # .cargo/audit.toml の ignore は理由付き
cargo tree -i aws-lc-rs; cargo tree -i openssl-sys  # どちらも無いこと
```

sekimore-gw のルートで `mise run ci` を実行すると、Rust と Python の lint・テストが並列で走ります。
`test-hooks` feature は `LocalGitUpstream`（ローカル bare repo への `git receive-pack`）を有効にします。イメージビルドには含めません。

## ビルド（イメージ）

`sekimore-gw/Dockerfile` の `relay-builder` 段が、`cargo-zigbuild` で静的 musl バイナリを作ります（CI はアーキごとの native runner）。
glibc 世代に依存しないので、devcontainer base イメージへ `COPY --from` してそのまま動きます。

## 変更履歴

[CHANGELOG.md](CHANGELOG.md) にあります。設計判断の詳細は workspace リポジトリの
[design/relay.md](https://github.com/Amakata/sgw-devcontainer/blob/main/doc/sekimore-gw/design/relay.md) を参照してください。
