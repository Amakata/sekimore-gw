# sekimore-relay

AI エージェントの **git 操作（SSH）と GitHub API 操作を案件単位のポリシーで中継する関所**。
sekimore-gw のイメージに同梱され、`config.yml` に `domain_handlers` の `git-relay` があるときだけ起動する。
無ければ何も変わらない（既存利用者への影響なし）。

- 要件: `doc/sekimore-gw/requirements/04-relay.md`（workspace リポジトリ）
- 設計: `doc/sekimore-gw/design/relay.md`（状態機械、エラー分類、brief からの逸脱一覧）
- エージェント側の自動化（Phase 4、`agent-setup.sh` / devcontainer base）: `doc/sgw-devcontainer-base/design/sekimore-relay-agent.md`

## 全体像

```
dev (AI)                          sekimore-gw                              上流
────────                          ───────────                              ────
git@github.com:Org/Repo.git ─DNS→ 関所 IP:22 (SSH, 使い捨て鍵) ─┐
                                    案件リポジトリ検証            ├─ ssh git@github.com (依頼者の ssh-agent) → GitHub
                                    refs/for/<base> → PR 作成    ┘   POST /repos/…/pulls (device flow トークン)
sekimore-relay agent … ─HTTP→ 関所 IP:8420 (skm_ トークン) ────── リソース×アクション判定 → GitHub API
https://github.com/…  ─DNS→ 関所 IP:443 ─────────────────────── TCP 素通し（既定。TLS は終端しない）
```

エージェントが持つのは **使い捨て SSH 鍵 / AI 専用署名鍵 / 案件トークン `skm_…`** の 3 つだけ。どれも上流では無効。
上流の資格情報（依頼者の ssh-agent、device flow トークン）は sekimore-gw の中にしか無い。

## 導入手順（操作者）

### 1. 関所を有効にする

`config.yml`（`./config/config.yml`、`/etc/sekimore/config.yml` にマウントされる）に追記する。

```yaml
domain_handlers:
  github.com: { handler: git-relay }      # 完全一致 FQDN。git-relay は 1 つのみ（GHES ならそのホスト名）

relay:
  https: passthrough                      # 同一ドメインの 443: passthrough（既定）| reject
  bootstrap: auto                         # 使い捨て鍵の登録 + トークン発行を POST /bootstrap で自動化: auto | manual
  token_ttl: 12h
  project:
    name: case-a
    repos:
      - { name: Org/Repo, mode: read-write, bases: [main] }      # bases = PR の base に許可するブランチ
      - { name: VendorOrg/reference-impl, mode: read-only }
    permissions: [pr:create, issue:create, project:read]         # 書かないものは全て拒否
```

`relay:` 配下の未知キーはエラー（typo で権限が緩まない）。全キーは `src/config.rs`。

### 2. 依頼者の ssh-agent を関所に渡す

relay は上流 git に **依頼者の ssh-agent** で認証する（鍵は Mac から出ない）。socket のパスはセッション毎に変わるので、
socket を置いた **ディレクトリ** を固定パスでマウントする。

```yaml
# docker-compose.yml の sekimore-gw
    volumes:
      - ${SEKIMORE_AGENT_SOCK_DIR}:/ssh-agent:ro     # 例: /home/vagrant/.ssh-agent（中に agent.sock）
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

VM 側で固定パスに socket を用意する例（Mac から）:

```bash
ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>
```

### 3. 再起動して確認する

`domain_handlers` / `relay` の変更は **コンテナ再起動で反映**（hot reload は警告を出して旧値を維持する）。

```bash
docker compose up -d --force-recreate sekimore-gw
docker compose exec sekimore-gw pgrep -af "sekimore-relay serve"     # relay が居る
docker compose exec sekimore-gw ss -tln | grep -E ':(22|8420|443) '  # 3 ポートが listen
docker compose exec sekimore-gw sekimore-relay check                 # ポリシーと状態（agent / known_hosts / token / 鍵）
```

### 4. 上流に認証する（初回のみ）

```bash
docker compose exec sekimore-gw sekimore-relay login
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← ブラウザで承認（組織の承認申請は発生しない）
```

`/data/relay/upstream_token`（0600）に保存され、`GET /meta` の SSH ホスト鍵で `/data/relay/known_hosts` も作られる。
`sekimore-relay whoami` で「関所がどの GitHub identity として動くか」を確認できる。

> device flow トークンは `repo` スコープ = アクセス可能な全リポジトリの読み書き。GitHub の認可には頼れず、
> `repos` と `permissions` が唯一の防壁。GitHub 側の監査ログではエージェントと人間の操作が区別できないので、
> 関所の `/data/relay/audit.jsonl` が唯一の区別可能な記録になる。

## エージェント側の準備（dev コンテナ内）

Phase 4 で `agent-setup.sh` が全て自動で行う予定。現時点では手作業。

```bash
# 使い捨て認証鍵を作り、関所に登録して案件トークンを受け取る（bootstrap: auto のとき）
ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/sekimore_ed25519
export SEKIMORE_ENDPOINT=http://<関所の internal-net IP>:8420
sekimore-relay agent bootstrap --pubkey-file ~/.ssh/sekimore_ed25519.pub   # JSON で token が返る
export SEKIMORE_TOKEN=skm_...  SEKIMORE_REPO=Org/Repo

# DNS は既に関所を向いているので、github.com として関所のホスト鍵を受け入れる
ssh-keyscan github.com >> ~/.ssh/known_hosts
printf 'Host github.com\n  User git\n  IdentityFile ~/.ssh/sekimore_ed25519\n  IdentitiesOnly yes\n' >> ~/.ssh/config

# AI 専用の署名鍵（依頼者の鍵でコミットに署名しない）。公開鍵は GitHub に「Signing Key」として登録する
ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/sekimore_signing_ed25519
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/sekimore_signing_ed25519.pub
git config --global commit.gpgsign true
```

`bootstrap: manual` のときは操作者が gateway 内で `sekimore-relay add-key "<公開鍵行>"` と `sekimore-relay token` を実行し、
トークンをエージェントに渡す。

## 日常の使い方（エージェント）

```bash
git clone git@github.com:Org/Repo.git           # URL はそのまま。関所が透過的に中継する
git push origin HEAD:refs/for/main              # refs/heads/sekimore/main-<sha7> に push され、PR（base=main）が作られる
git push origin HEAD:refs/heads/sekimore/x      # 自分の名前空間 sekimore/* への直接 push は可（PR ブランチの更新）

sekimore-relay agent whoami                     # 案件・権限・リポジトリ（既定拒否の内容が分かる）
sekimore-relay agent pr create --head sekimore/main-abc1234 --base main --title T
sekimore-relay agent issue create --title T --labels bug     # ラベル付きは issue:label も要る
sekimore-relay agent project add-item --project-id P --content-id C
```

拒否されるもの（既定）: 案件外リポジトリ、read-only への push、`bases` に無い base への `refs/for`、
`main` など `sekimore/*` 以外への直接 push、tag、削除、許可していない API 操作。理由は stderr に `sekimore: …` で出る。

## 運用（操作者）

```bash
docker compose exec sekimore-gw sekimore-relay tokens                    # 発行済みトークン（ラベル / 期限 / 使用回数 / 状態）
docker compose exec sekimore-gw sekimore-relay revoke --label skm_xxxxxxxx
docker compose exec sekimore-gw sekimore-relay revoke-project            # 案件終了時に全部失効
docker compose exec sekimore-gw sekimore-relay bootstrap disable|enable  # 自動登録の kill-switch（失効を最終手段にするなら disable）
docker compose exec sekimore-gw sekimore-relay add-key "ssh-ed25519 AAAA…"   # 手動登録
docker compose exec sekimore-gw sekimore-relay logout                    # 上流トークンを削除
docker compose exec sekimore-gw tail -f /data/relay/audit.jsonl          # 全ての拒否（reason 付き）と操作の記録
```

`/data/relay`（gateway-data ボリューム、0700）: `host_key` `authorized_keys` `known_hosts` `tokens.json`（ハッシュのみ）
`upstream_token` `audit.jsonl` `bootstrap.disabled`。AI コンテナからは見えない。

## 困ったとき

| 症状 | 意味 | 対処 |
|---|---|---|
| `sekimore: SSH_AUTH_SOCK is not set in the gateway container` | 関所に agent socket が渡っていない | 手順 2 のマウントと環境変数。`sekimore-relay check` の ssh-agent 行 |
| `sekimore: ssh-agent socket … does not exist` / `cannot connect` | 転送セッションが切れた / 権限 | Mac からの転送を張り直す。EACCES なら socket の所有者と userns-remap |
| `sekimore: known_hosts … has no entry for github.com` | 上流のホスト鍵が無い | `sekimore-relay login`（`/meta` から生成）か `ssh-keyscan` |
| `sekimore: repository "X" is not in project "P"` | 案件外 | `relay.project.repos` に追加する（意図した拒否なら何もしない） |
| `sekimore: push to refs/heads/main is not allowed` | 名前空間外への直接 push | `refs/for/main` で PR にする。必要なら `repos[].push` に glob を足す |
| `Permission denied (publickey)`（関所から） | エージェントの鍵が未登録 | `agent bootstrap` または操作者の `add-key`。`bootstrap.disabled` の有無 |
| `no upstream token … run sekimore-relay login` | device flow 未実施 / logout 後 | `sekimore-relay login` |
| `git ls-remote` が無言で止まる | DNS は関所を向いたが INPUT で落ちている | `iptables-legacy -S INPUT` に `--dport 22` があるか。無ければ relay 未起動（`[relay]` の起動ログと `needs-relay` の終了コード） |
| `https://github.com/…` が失敗 | `relay.https: reject`、または上流到達不可 | 既定の `passthrough` に戻す。audit の `https_failed` の reason |

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
