| post-create の「依頼者の ssh-agent が転送されています」が `env -u SSH_AUTH_SOCK code` でも消えない | macOS の `code` は `open` 経由で本体を起動するので launchd の `SSH_AUTH_SOCK` を継ぐ（VS Code が起動中なら既存インスタンスが開く） | VS Code を Cmd+Q で完全終了してから `mise run vscode`（launchd の変数を外して本体を直接起動する）。`mise run vscode:check` で確認 |
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

relay は上流 git に **依頼者の ssh-agent** で認証する（鍵は Mac から出ない）。

```yaml
# docker-compose.yml の sekimore-gw
    volumes:
      - ${SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}:/ssh-agent/agent.sock:ro
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

- **Docker Desktop（Mac）**: 既定値のままでよい。Docker Desktop がホストの agent を VM 内の `/run/host-services/ssh-auth.sock` に転送している
  （Mac 側で `ssh-add -l` に鍵が出ていること）
- **Vagrant VM**: 固定パスに socket を用意して `SEKIMORE_AGENT_SOCK` に書く。例（Mac から）:
  `ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>`。
  転送を張り直したら `docker compose up -d --force-recreate sekimore-gw`

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
# (sgw-devcontainer-base の sample / Dev Containers 構成なら: mise run gw:login)
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← ブラウザで承認（組織の承認申請は発生しない）
```

`/data/relay/upstream_token`（0600）に保存され、`GET /meta` の SSH ホスト鍵で `/data/relay/known_hosts` も作られる。
`sekimore-relay whoami` で「関所がどの GitHub identity として動くか」を確認できる。

> device flow トークンは `repo` スコープ = アクセス可能な全リポジトリの読み書き。GitHub の認可には頼れず、
> `repos` と `permissions` が唯一の防壁。GitHub 側の監査ログではエージェントと人間の操作が区別できないので、
> 関所の `/data/relay/audit.jsonl` が唯一の区別可能な記録になる。

## エージェント側の準備（dev コンテナ内）

`agent-setup.sh`（sgw-devcontainer-base では `/usr/local/bin/sekimore-agent-setup.sh`、postStartCommand で毎起動）が
**関所を見つけたら自動で**行う。gateway に relay が居なければ何もしない。

- 使い捨て認証鍵 `~/.ssh/sekimore/id_ed25519` と AI 専用署名鍵 `~/.ssh/sekimore/signing_ed25519` を生成（既にあれば再利用）
- `POST /bootstrap` で公開鍵を登録し案件トークンを受け取る（既存トークンが有効なら再発行しない）
- `/etc/sekimore-agent/env` に `SEKIMORE_IP` `SEKIMORE_ENDPOINT` `SEKIMORE_TOKEN` `SEKIMORE_TOKEN_EXPIRES` `SEKIMORE_AGENT_KEY` `SEKIMORE_REPO` `SEKIMORE_GIT_DOMAIN`（0600、vscode 所有）。
  `sekimore` ラッパー（base）はこのファイルを環境変数より優先して読み、期限切れなら `agent bootstrap` で取り直して書き換える
- `~/.ssh/known_hosts` に関所のホスト鍵を `github.com` として登録、`~/.ssh/config` に `Host github.com → 使い捨て鍵`
- `git config --global gpg.format ssh / user.signingkey / commit.gpgsign true`。**署名鍵の公開鍵は GitHub に「Signing Key」として手で登録する**（ログに表示される）
  署名鍵のコメント（GitHub 登録時の Title になる）は既定で `sekimore-agent-signing: <案件名> / <git user.name> <user.email>`。`SEKIMORE_PROJECT` と `SEKIMORE_SIGNING_KEY_COMMENT` で調整でき、旧形式 `…@<hostname>` の既存鍵は名前入りに更新される（鍵は不変）

環境変数で調整: `SEKIMORE_BOOTSTRAP=manual`（登録・発行を操作者に任せる）、`SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE`、`SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT`（署名鍵のコメント）。

`bootstrap: manual` のときは操作者が gateway 内で `sekimore-relay add-key "<公開鍵行>"` と `sekimore-relay token` を実行し、
トークンを `/etc/sekimore-agent/env` の `SEKIMORE_TOKEN` に入れる。

手作業で同じことをする場合:

```bash
ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/sekimore_ed25519
export SEKIMORE_ENDPOINT=http://<関所の internal-net IP>:8420
sekimore-relay agent bootstrap --pubkey-file ~/.ssh/sekimore_ed25519.pub   # JSON で token / repos / git_domain が返る
export SEKIMORE_TOKEN=skm_...  SEKIMORE_REPO=Org/Repo
ssh-keyscan github.com >> ~/.ssh/known_hosts          # DNS は既に関所を向いている
printf 'Host github.com\n  User git\n  IdentityFile ~/.ssh/sekimore_ed25519\n  IdentitiesOnly yes\n' >> ~/.ssh/config
```

## 日常の使い方（エージェント）

```bash
git clone git@github.com:Org/Repo.git           # URL はそのまま。関所が透過的に中継する
git push origin HEAD:refs/for/main              # refs/heads/sekimore/main-<sha7> に push され、PR（base=main）が作られる
git push origin HEAD:refs/heads/sekimore/x      # 自分の名前空間 sekimore/* への直接 push は可（PR ブランチの更新）

sekimore whoami                                 # = sekimore-relay agent whoami（ラッパーが /etc/sekimore-agent/env を読む）
sekimore-relay agent pr create --head sekimore/main-abc1234 --base main --title T
sekimore-relay agent issue create --title T --labels bug     # ラベル付きは issue:label も要る
sekimore pr status --number 12                   # PR の CI チェックが通ったか（pr:read）。--json で機械可読
sekimore-relay agent project add-item --project-id P --content-id C
```

拒否されるもの（既定）: 案件外リポジトリ、read-only への push、`bases` に無い base への `refs/for`、
`main` など `sekimore/*` 以外への直接 push、tag、削除、許可していない API 操作。理由は stderr に `sekimore: …` で出る。

## 運用（操作者）

sekimore-gw の Web UI（host の http://localhost:8090）の **Relay タブ**で、設定・権限・トークン・アクセス履歴・ブロック履歴を閲覧できる（閲覧のみ。変更は下の CLI）。

Dev Containers 構成（sgw-devcontainer-base の sample）ではこれらは `mise run gw:tokens` / `gw:revoke-project` / `gw:audit` / `gw -- <args>` として用意してある。

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

トークンの回転と掃除（0.1.3）: 同じ agent 鍵からの再 bootstrap（コンテナ再作成、期限切れ後の自動更新）は、その鍵に発行済みの
有効トークンを失効させてから新しく発行する（鍵 1 本につき有効トークンは 1 つ。監査 `bootstrap_ok` の `revoked_previous`）。
期限切れから 7 日過ぎたレコードは書き込み時に落とすので `tokens.json` は肥大化しない（恒久的な記録は `audit.jsonl`）。

## 困ったとき

| 症状 | 意味 | 対処 |
|---|---|---|
| `sekimore: SSH_AUTH_SOCK is not set in the gateway container` | 関所に agent socket が渡っていない | 手順 2 のマウントと環境変数。`sekimore-relay check` の ssh-agent 行。Docker Desktop なら Mac 側の `ssh-add -l` に鍵があるか |
| `sekimore: ssh-agent socket … does not exist` / `cannot connect` | 転送セッションが切れた / 権限 | Mac からの転送を張り直す。EACCES なら socket の所有者と userns-remap |
| `sekimore: known_hosts … has no entry for github.com` | 上流のホスト鍵が無い | `sekimore-relay login`（`/meta` から生成）か `ssh-keyscan` |
| `sekimore: repository "X" is not in project "P"` | 案件外 | `relay.project.repos` に追加する（意図した拒否なら何もしない） |
| `sekimore: push to refs/heads/main is not allowed` | 名前空間外への直接 push | `refs/for/main` で PR にする。必要なら `repos[].push` に glob を足す |
| `Permission denied (publickey)`（関所から） | エージェントの鍵が未登録（0.1.3 からバナーは出さない。理由は監査の `ssh_auth_denied`） | `agent bootstrap` または操作者の `add-key`。`bootstrap.disabled` の有無 |
| `! [remote rejected] … (sekimore: push to … is not allowed)` | ポリシーで拒否した push（0.1.3 から report-status の `ng` で返す。以前は切断して "remote end hung up" だった） | メッセージの案内どおり（`refs/for/<base>`、`repos[].push`、`allow_delete`） |
| `sekimore: denied: token expired at …` | 案件トークンの期限切れ（`token_ttl`、既定 12h） | `sekimore` ラッパー（base 0.2.1）が自動で bootstrap をやり直す。古い環境は `sudo sekimore-agent-setup.sh` |
| `no upstream token … run sekimore-relay login` | device flow 未実施 / logout 後 | `sekimore-relay login` |
| `git ls-remote` が無言で止まる | DNS は関所を向いたが INPUT で落ちている | `iptables-legacy -S INPUT` に `--dport 22` があるか。無ければ relay 未起動（`[relay]` の起動ログと `needs-relay` の終了コード） |
| `https://github.com/…` が失敗 | `relay.https: reject`、上流到達不可、または HTTPS 認証を塞いでいる（下記） | 既定の `passthrough` に戻す。audit の `https_failed` の reason |
| `https://github.com/…` の push/clone で `could not read Username … terminal prompts disabled` | relay 構成が HTTPS 経由の認証を塞いでいる（依頼者の GitHub 認証が関所を迂回するのを防ぐため。VS Code の credential helper と GIT_ASKPASS を無効化）。意図した挙動 | `git@github.com:` の SSH（関所経由）を使う。どうしても HTTPS が要るなら `SEKIMORE_ALLOW_CREDENTIAL_HELPER=1`（非推奨） |

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

`sekimore-gw/Dockerfile` の `relay-builder` 段が `ghcr.io/rust-cross/cargo-zigbuild` を `--platform=$BUILDPLATFORM` で使い、
`TARGETARCH` 向けの静的 musl バイナリを **クロスコンパイル**する（arm64 を QEMU で回すと 45 分かかるため。クロスなら両アーキで数分）。
glibc 世代に依存しないので、devcontainer base イメージへ `COPY --from` してそのまま動く。

手元で両ターゲットを作る例:

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e CARGO_TARGET_DIR=/target -v relay-target:/target ghcr.io/rust-cross/cargo-zigbuild:0.20.1 \
  sh -c 'rustup toolchain install 1.89.0 --profile minimal && rustup target add --toolchain 1.89.0 x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
         && cargo zigbuild --release --locked --target x86_64-unknown-linux-musl && cargo zigbuild --release --locked --target aarch64-unknown-linux-musl'
```
