# sekimore-relay

*[English](README.md)*

AI エージェントの git 操作（SSH）と GitHub API 操作を、案件単位のポリシーで中継する関所です。
sekimore-gw のイメージに同梱され、`config.yml` に `handler: github` があるときだけ起動します。
無ければ何も変わりません。

- 変更履歴: [CHANGELOG.md](CHANGELOG.md)

## 全体像

```
  dev (AI)                      sekimore-gw                      上流
  ========                      ===========                      ====

  git clone / push       ─DNS→  :22  SSH                  ─ssh→   GitHub
  git@github.com:Org/Repo        ・使い捨て鍵を認証する
                                 ・この repo は案件に入っているか
                                 ・refs/for/<base> をブランチ + PR にする
                                                    使う資格情報: 操作者の ssh-agent

  sekimore pr create     ─HTTP→  :8420  REST API          ─API→   GitHub
  sekimore ci log                ・案件トークン skm_ を検証する
                                 ・このリソース × アクションは許可されているか
                                                    使う資格情報: device flow のトークン

  https://github.com/…   ─DNS→   :443  TCP passthrough    ─TCP→   GitHub
                                 ・TLS は終端しない。バイト数だけ数える
                                 ・送信上限を掛ける
```

関所が経路に入るのは DNS のおかげです。ゲートウェイがそれらのドメインに自分のアドレスを返し、
本当のアドレスはファイアウォールの許可リストに入りません。だから上流へ出る道は、上の 3 本だけです。

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
  github.com: { handler: github }

relay:
  project:
    name: case-a
    permissions: [pr:create, pr:read, ci:read]
    repos:
      - { name: Org/Repo, mode: read-write, bases: [main] }
```

`git-relay` はこの handler の元の名前で、今も受け付けます。動いている設定を書き換える必要はありません。

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

- トークンは秘密ストアに封じて保存されます（0.2.18）。ログインの前に `mise run gw:unlock` で解錠しておく必要があります。以前の版が残した `/data/relay/upstream_token` は、最初に読んだときにストアへ移して削除します。上流の SSH ホスト鍵も同時に known_hosts に入ります。
- 上流が複数あるときは `--upstream <domain>` で上流ごとに実行します（`logout` / `whoami` も同じ）。
- `sekimore-relay whoami` で、関所がどの GitHub identity として動くかを確認できます。

device flow トークンは `repo` スコープです。GitHub 側の認可には頼れず、`repos` と `permissions` が唯一の防壁になります。
GitHub の監査ログではエージェントと人間の操作を区別できないので、関所の `/data/relay/audit.jsonl` が区別できる唯一の記録です。

## エージェント側の準備（dev コンテナ内）

`agent-setup.sh`（sgw-devcontainer-base では `/usr/local/bin/sekimore-agent-setup.sh`、postStartCommand で毎起動）が、関所を見つけたら自動で行います。

- 使い捨て認証鍵 `~/.ssh/sekimore/id_ed25519` を生成します（あれば再利用）。
- `POST /bootstrap` で公開鍵を登録し、案件トークンを受け取ります。有効なトークンがあれば再発行しません。
- `/etc/sekimore-agent/env`（0600）に接続情報を書きます。`sekimore` ラッパーはこのファイルを読み、期限切れなら自動で取り直します。
- 上流ごとに `~/.ssh/config` の `Host` ブロックと known_hosts を書きます。
- コミット署名を設定します。どの鍵を使うかは `relay.signing_key`（下記）で決まります。
- AI エージェント向けの使い方（`sekimore guide`）を Claude Code の skill と Codex の `AGENTS.md` に置きます。

調整用の環境変数:

| 変数 | 意味 |
|---|---|
| `SEKIMORE_BOOTSTRAP=manual` | 鍵登録とトークン発行を操作者が行う（`add-key` と `token`） |
| `SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT` | 署名鍵のコメント（GitHub 登録時の Title） |
| `SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE` | 対象ユーザーと保存先 |

### 署名鍵（0.2.29、#59）

上の認証鍵が使い捨てなのは正しい。アクセスを与える鍵だから、寿命が短いこと自体が安全側に働く。
署名鍵は逆である。何の権限も与えず、GitHub には人が手で登録し、消すとその鍵が署名した全ての
コミットから Verified が外れる。つまり失うことは「作り直し」ではなく喪失である。コンテナごとに
生成すると、volume を消すたびに新しい鍵が生まれ、そのたびに手で登録が要り、しかも古い鍵は
消せないまま溜まっていく。

`relay.signing_key` を書くと、**人につき 1 本**になる。鍵はすでに gateway にマウントされている
ホストの ssh-agent にあり、GitHub には一度だけ登録する。relay は共有 volume 上に**絞り込んだ**
agent socket を作って dev に渡す。

| 要求 | 応答 |
|---|---|
| `REQUEST_IDENTITIES` | 設定した fingerprint の 1 本だけ |
| `SIGN_REQUEST` | fingerprint が一致し、**かつ** データが namespace `git` の SSHSIG blob のときだけ転送 |
| add / remove / lock / extension | `SSH_AGENT_FAILURE` |

git の署名は `"SSHSIG" ++ namespace ++ …` を覆う。SSH の**認証**署名が覆うのは長さ前置きの
session id で始まる別の構造で、`SSHSIG` の 6 バイトで始まることはない。だからこの socket は
どこに対しても認証に使えない（relay 自身の sshd を含む）。同じ鍵が認証鍵としても登録されていても
同じである。依頼者の他の鍵は同じ agent にあっても fingerprint で隠れる。拒否は
`signing_agent_refused`、成功した署名は `signing_agent_signed` として監査に残る。

dev 側に sekimore 専用のコマンドは要らない。素の `git commit` でよい。`agent-setup.sh` が公開鍵を
`~/.ssh/sekimore/signing.pub` に書き、`user.signingkey` をそこに向け、`SSH_AUTH_SOCK` を
`/etc/sekimore-agent/env` に書く。

```yaml
# config.yml
relay:
  signing_key:
    fingerprint: "SHA256:…"    # ssh-keygen -lf <key>.pub。依頼者自身の署名鍵とは別の鍵にする
```

```yaml
# docker-compose: socket の volume を両方のサービスに
services:
  sekimore-gw:
    volumes: [sekimore-signing:/run/sekimore]
  dev:
    volumes: [sekimore-signing:/run/sekimore]
```

`sekimore-relay check` は fingerprint と、それがホストの agent に実際にあるかを表示する。無い
ときは `agent-setup.sh` が `commit.gpgsign false` にしてそう言う。誰も登録していない鍵で代用は
しない。

`relay.signing_key` を書かなければ従来どおり。`~/.ssh/sekimore/signing_ed25519` をここで生成し、
その公開鍵を GitHub に「Signing Key」として手で登録する（ログに表示される）。

## 日常の使い方（エージェント）

```bash
git clone git@github.com:Org/Repo.git           # URL はそのまま。関所が透過的に中継する
git push origin HEAD:refs/for/main              # sekimore/main-<sha7> に push され、PR（base=main）が作られる
git push origin HEAD:refs/heads/sekimore/x      # 自分の名前空間 sekimore/* への直接 push

sekimore whoami                                 # 自分の権限と repo
sekimore pr create --head sekimore/x --base main --title T --body="…"
sekimore pr status --number 12                  # PR の CI チェック（--json で機械可読）
sekimore pr merge --number 12 --method squash --delete-branch
sekimore pr update --number 12 --title T         # --base は bases に対して再検査される
sekimore pr reopen --number 12                   # issue reopen も同じ。閉じるのと同じ権限
sekimore ci runs --ref v0.2.0                   # タグ / ブランチ / SHA に紐づく workflow run
sekimore ci jobs --number 12                    # PR の全 run のジョブ一覧（失敗と job_id が分かる）
sekimore ci log --number 12                     # 失敗ジョブのログを末尾から。--before / --window で前へ
sekimore issue create --title T --labels bug    # ラベル付きは issue:label も要る
sekimore release create --tag v0.2.6            # タグを push した後に。本文は GitHub が書く
sekimore release view --tag v0.2.6              # タグに対応する Release
sekimore release list --limit 10                # 新しい順に Release 一覧
sekimore release edit --tag v0.2.6 --draft false # draft を公開する（release:publish が要る）
sekimore issue unlabel --number 5 --labels bug  # issue unassign も同じ形
sekimore ci rerun --run-id 123 [--all]          # ci cancel --run-id 123。どちらも ci:rerun
```

AI エージェント向けの使い方は `sekimore guide` で表示できます（CLI に埋め込み。正本は `relay/share/agent-guide.en.md` と `agent-guide.ja.md`）。
agent-setup が同じ内容を Claude Code の skill（`~/.claude/skills/sekimore-relay/SKILL.md`）と Codex CLI の `~/.codex/AGENTS.md`（マーカー付きブロック）に置くので、
これらのツールは自動で読みます。他のツールは `sekimore guide` の出力をそのツールの規約の場所に置いてください。`SEKIMORE_AGENT_INSTRUCTIONS=none` で無効、`claude` や `codex` だけの指定も可能です。

`sekimore` は `sekimore-relay agent` のラッパーです。repo は `--repo Org/Repo` で指定し、上流が複数あるときは `host/Org/Repo` と書けます。
`--body` の値が `-` で始まるときは `--body="…"` の形にしてください。

既定で拒否されるもの: 案件外のリポジトリ、read-only への push、`bases` に無い base への `refs/for`、`sekimore/*` 以外への直接 push、タグ、削除、許可していない API 操作。理由は stderr に `sekimore: …` で出ます。

## 設定リファレンス

### `domain_handlers.<domain>`

キーは完全一致の FQDN です。`github` を複数書くと上流が複数になります。
`git-relay` は `github` handler の元の名前で、今も受け付けます。既存の設定はそのまま動きます。

| キー | 既定 | 意味 |
|---|---|---|
| `handler` | `splice` | `github` で関所が受ける（SSH の git と GitHub API）。`https-relay` は 443 だけを関所の passthrough で通す（送信上限を掛けたい宛先用）。`deny` は拒否、`splice` は従来どおり |
| `ssh_port` | `relay.ssh_listen` のポート | 関所側の SSH ポート。2 つ目以降の上流では必須 |
| `upstream` | ドメイン名 | 実際の上流ホスト |
| `upstream_ssh_port` | `relay.upstream_ssh_port` | 上流の SSH ポート |
| `ssh_options` | `[]` | 上流 ssh に `-o` で渡す（`ProxyJump=bastion` など）。強制オプションは上書き不可 |
| `api_base` / `graphql_base` | 上流から派生 | GitHub API の宛先。`upstream` を転送先にしたときに使う |
| `oauth_client_id` | `relay.oauth_client_id` | device flow の OAuth app（GHES では別） |
| `default` | `false` | 既定上流にする。省略時は `ssh_port` を省いた 1 つが既定 |
| `max_upload_bytes` | `relay.https_max_upload_bytes` | 443 passthrough で dev から上流へ送れる 1 接続あたりの上限。`-1` で無制限、`0` は不可 |

### `relay`

| キー | 既定 | 意味 |
|---|---|---|
| `ssh_listen` / `api_listen` / `https_listen` | `0.0.0.0:22` / `0.0.0.0:8420` / `0.0.0.0:443` | listen アドレス |
| `https` | `passthrough` | 443 の扱い。`reject` で即切断 |
| `https_max_upload_bytes` | `1048576` | 443 passthrough の送信上限の既定（バイト）。`-1` で無制限。超えた接続は切断して監査 `https_upload_capped` |
| `state_dir` | `/data/relay` | 状態ファイルの置き場 |
| `token_ttl` | `12h` | 案件トークンの寿命 |
| `bootstrap` | `auto` | `POST /bootstrap` を許すか。`manual` なら操作者が登録する |
| `ssh_options` | `[]` | 全上流共通の `-o` |
| `ssh_config` | 無し | 上流 ssh に `-F` で渡すファイル（上級者向け） |
| `upstream` / `upstream_ssh_port` / `api_base` / `graphql_base` / `oauth_client_id` | | 既定上流用。handler 側に書くのが新しい書き方 |
| `limits` | | セッション数やタイムアウト |
| `signing_key` | 無し | 0.2.29（#59）dev がコミット署名に使う鍵。絞り込んだ agent socket 経由で渡す。キーは `source`（`agent`）、`fingerprint`（`SHA256:…`）、`namespace`（`git`）、`timeout`（`15s`）、`socket`（`/run/sekimore/signing-agent.sock`）、`socket_uid`（`1000`）。書かなければ dev が自分で鍵を生成する（下記） |
| `project` | 必須 | 案件（下記） |

### `relay.project`

| キー | 既定 | 意味 |
|---|---|---|
| `name` | 必須 | 案件名。トークンとログに出る |
| `permissions` | `[]` | 案件の既定権限。`[…]` か `{allow, deny}` |
| `push` | `["sekimore/*"]` | 直接 push を許すブランチ glob |
| `tags` | `[]` | push を許すタグ glob。空は拒否 |
| `delete` | `false` | ブランチとタグの削除、および既に upstream にあるタグを動かすこと。削除して作り直すのと強制更新は同じ結果なので、権限も同じ。まだ無いタグを作るだけなら `tags` で足りる |
| `delete_merged_branch` | `false` | `pr merge --delete-branch` がマージしたブランチを消してよいか。そのブランチだけなので `delete` とは別の権限。forge 側で自動削除している場合は不要 |
| `boards` | `[]` | この案件が触れてよい Projects v2 のボード。URL のとおりに書く: `github.com/orgs/acme/projects/3` なら `{ org: acme, number: 3 }`、`{ user: someone, number: 1 }` も可。空なら Projects の操作を全て拒否 |
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
- 権限キーは 23 個: `pr:create` `pr:read` `pr:comment` `pr:review` `pr:request_review` `pr:merge` `pr:close`、`issue:create` `issue:read` `issue:comment` `issue:close` `issue:label` `issue:assign`、`project:read` `project:add_item` `project:update_item`、`repo:read`、`ci:read` `ci:rerun`、`release:create` `release:read` `release:publish`、`search:read`。
- `pr:read` は状態・CI チェックに加えて本文とコメントも含む。`issue:read` は別にしてあるので、非公開のトラッカーを読ませずに bug を登録させられる。`search:read` は 1 つのリポジトリに宛てた操作ではないので独立した資源。
- `pr:review` はレビューを出す権限、`pr:request_review` は誰かに依頼する権限。意見を記録することと人に通知することは別なので分けてある。
- `ci:rerun` は workflow run の再実行と中止。`ci:read` には含めていない。再実行は Actions の時間を消費し、リポジトリの secret を持つ workflow のコードを実行するため。
- `release:publish` は Release を draft から公開状態にする権限。`release create --draft` は公開を人間に委ねるためにあるので、`release:create` に畳み込むとその線が消える。draft のまま編集するだけなら `release:create` で足りる。
- 閉じると開き直すは同じ権限（`pr:close` / `issue:close`）。開き直すのは閉じたことの取り消しであって、新しい力ではない。ラベルと担当者の付け外しも同様に 1 つ（`issue:label` / `issue:assign`）。PR のタイトルや本文の編集は `pr:create`。ただし base の変更だけは、そのリポジトリの `bases` に対して改めて検査する。
- `repo:read` は `repo vocabulary`（そのリポジトリのラベル・担当者に指定できる人・マイルストーンの一覧）で使う。
- 実効値は `sekimore-relay check` と Web UI の Relay タブで確認できます。

### 例: github.com と GHES を同時に扱う

```yaml
domain_handlers:
  github.com: { handler: github }                       # 既定上流（ssh_port 省略）
  ghe.example.com:
    handler: github
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

### Release（0.2.6）

`release:create` と `release:read` は他の権限と同じく既定で拒否です。使う案件では `permissions` に書いてください。
device flow トークンは `repo` スコープを持っているので、認証をやり直す必要はありません。

```bash
git push origin v0.2.6                                   # タグが先に上流へ入っている必要がある
sekimore release create --tag v0.2.6                     # 本文はマージ済み PR から GitHub が書く
sekimore release create --tag v0.2.6 --notes-file NOTES.md --draft
sekimore release view --tag v0.2.6
sekimore release list --limit 10
```

- タグが上流に無いと GitHub が 422 を返すので、これはタグを push した後に実行します。
- 本文を渡さないと関所が `generate_release_notes` を立て、前のタグ以降にマージされた PR から GitHub が本文を作ります。
  これが通常の使い方で、自分で書く必要はありません。
- `--notes` か `--notes-file` を渡すとそれが本文になります。さらに `--generate-notes` を付けると、書いた本文の後ろに
  GitHub の生成した本文が追記されます。
- `--title` の既定はタグ名なので、無題の Release はできません。`--prerelease` で prerelease になります。
- `--draft` は未公開で作り、公開は人間に任せます。既定は公開済みです。

### 持ち出し対策: 443 の送信上限と `https-relay`

関所は依頼者の資格情報を AI に使わせませんが、プロンプトに埋め込まれた他人の資格情報で HTTPS push する持ち出しは TLS の中身を見ない限り区別できません。
そのため 443 passthrough には dev から上流へ送れるバイト数の上限があります（既定 1 MiB、ダウンロードは数えません）。
通常の GET や API 呼び出しの送信量はこれよりはるかに小さく、`git push` などの大きな送信だけが止まります。

```yaml
domain_handlers:
  github.com: { handler: github, max_upload_bytes: 262144 }      # 256 KiB。HTTPS push は関所経由の SSH を使うので不要
  ghcr.io:    { handler: https-relay, max_upload_bytes: -1 }     # 自分で image を push する宛先は無制限
  registry-1.docker.io: { handler: https-relay }                 # 既定 (relay.https_max_upload_bytes) を使う
relay:
  https_max_upload_bytes: 1048576
network:
  allowed_ports: [80, 443]      # 許可ドメインへ通す宛先ポート（sekimore-gw 本体の設定。IP 直指定の SSH などを止める）
```

- `https-relay` のドメインは DNS で関所に向き、443 だけが関所の passthrough を通ります。他のポートは届きません。
- 上限を超えた接続は切断され、監査に `https_upload_capped` が残ります。Relay タブでは 1 MiB 以上を送った接続に LARGE UPLOAD の印が付き、24 時間の件数が出ます。
- `allow_domains` に残したドメインは関所を通らず上限も掛かりません。上限を掛けたいものだけ handler に移します。

複数上流の仕組み: SSH の exec にはホスト名が無いので、関所は上流ごとに別ポートで listen し、接続を受けたポートで上流を決めます。
agent-setup が `~/.ssh/config` に上流ごとの `Host` と `Port` を書くので、エージェントの URL は変わりません。
443 は TLS の SNI で上流を選びます。関所の ssh はホスト側の `~/.ssh/config` を読まないので、踏み台やプロキシは `ssh_options` に書きます。
踏み台のホスト鍵は `sekimore-relay keyscan bastion.example.com --upstream ghe.example.com` で入れます。

## 表示言語（0.2.4）

CLI の文言は `relay/locales/en.json` と `relay/locales/ja.json` にあり、バイナリに埋め込まれます。
言語は `SEKIMORE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG` の順で見て、`ja*` なら日本語、それ以外は英語です（既定は英語）。
辞書に無いキーは英語に、英語にも無ければキー名にフォールバックします。

```bash
sekimore-relay check                     # 英語（既定）
SEKIMORE_LANG=ja sekimore-relay check    # 日本語
sekimore guide --lang ja                 # ガイドだけ日本語で表示
```

対象は `--help` と操作者向けの出力、そして `sekimore guide` です。
ガイドは `--lang en|ja` で選べ、正本は `relay/share/agent-guide.en.md` と `relay/share/agent-guide.ja.md` です。
拒否理由（`sekimore: …`）と監査ログ `audit.jsonl` は意図的に英語のまま固定しています。ツールやエージェントが文字列で照合できるようにするためです。

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
| `Permission denied (publickey)`（関所から） | エージェントの鍵が未登録 | `sudo sekimore-agent-setup.sh` か操作者の `add-key`。`bootstrap.disabled` の有無 |
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

[CHANGELOG.ja.md](CHANGELOG.ja.md) にあります。
