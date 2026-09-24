# sekimore-relay

*[English](README.md)*

関所（sekimore-relay）は、AI エージェントの git 操作（SSH）と GitHub API 操作を、プロジェクト単位のポリシーに従って中継します。
sekimore-gw のイメージに同梱されており、`config.yml` に `handler: github` があるときだけ起動します。
この設定が無ければ、ゲートウェイは関所が無いときと同じように動作します。

- 変更履歴: [CHANGELOG.ja.md](CHANGELOG.ja.md)

## 全体像

```
  dev (AI)                      sekimore-gw                      上流
  ========                      ===========                      ====

  git clone / push       ─DNS→  :22  SSH                  ─ssh→   GitHub
  git@github.com:Org/Repo        ・使い捨て鍵を認証する
                                 ・この repo はプロジェクトに入っているか
                                 ・refs/for/<base> と refs/pr/<branch> をブランチと PR にする
                                                    使う資格情報: 運用者の ssh-agent

  sekimore pr create     ─HTTP→  :8420  REST API          ─API→   GitHub
  sekimore ci log                ・プロジェクトトークン skm_ を検証する
                                 ・このリソース × アクションは許可されているか
                                                    使う資格情報: device flow のトークン

  https://github.com/…   ─DNS→   :443  TCP passthrough    ─TCP→   GitHub
                                 ・TLS は終端しない。バイト数を数える
                                 ・送信上限を適用する
```

関所が経路に入るのは DNS によるものです。ゲートウェイは中継対象のドメインに対して自分のアドレスを返し、
上流の本当のアドレスはファイアウォールの許可リストに入りません。そのため、上流に届く通信は上の 3 つの経路のいずれかを通るものだけです。

エージェントが持つ資格情報は次の 3 つだけで、どれも上流に対しては有効ではありません。

- 使い捨て SSH 鍵（関所への認証用）
- AI 専用のコミット署名手段（`relay.signing_key` を設定した場合は絞り込んだ agent socket、設定しない場合は dev コンテナ内で生成した署名鍵）
- プロジェクトトークン `skm_…`（関所の API 用）

上流の資格情報（運用者の ssh-agent と device flow トークン）は sekimore-gw の外に出ません。

## 導入手順（運用者）

### 1. 関所を有効にする

`config.yml`（`/etc/sekimore/config.yml` にマウント）に次の内容を追記します。これが最小構成です。

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

`git-relay` はこの handler の元の名前で、現在も受け付けます。そのため、動作している既存の設定を書き換える必要はありません。

各キーの意味と、より完全な例は[設定リファレンス](#設定リファレンス)を参照してください。
`relay:` 配下の未知のキーはエラーになります。これにより、typo で権限が緩むことはありません。

### 2. 運用者の ssh-agent を関所に渡す

関所は、運用者の ssh-agent を使って上流の git サーバーに認証します。鍵がホストの外に出ることはありません。

```yaml
# docker-compose.yml の sekimore-gw サービス
    volumes:
      - ${SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}:/ssh-agent/agent.sock:ro
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

- Docker Desktop（Mac）: 既定値のままで動作します。Mac 側の `ssh-add -l` に鍵が表示されることを確認してください。
- Vagrant VM: 固定パスに socket を作成し、`SEKIMORE_AGENT_SOCK` にそのパスを設定します。
  例: `ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>`

### 3. 再起動して確認する

`domain_handlers` と `relay` の変更は、コンテナを再作成したときにだけ反映されます。hot reload では警告を出し、変更前の値を維持します。

```bash
docker compose up -d --force-recreate sekimore-gw      # Dev Containers 構成なら: mise run gw:recreate
docker compose exec sekimore-gw sekimore-relay check   # ポリシーと状態（agent / known_hosts / token / 鍵）
```

### 4. 上流に認証する（初回のみ）

```bash
docker compose exec sekimore-gw sekimore-relay login   # Dev Containers 構成なら: mise run gw:login
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← ブラウザでコードを承認する
```

- トークンは秘密ストアに封じて保存されます（0.2.18）。そのため、ログインでトークンを保存するには、先に `mise run gw:unlock` でゲートウェイを解錠しておく必要があります。以前の版が残した `/data/relay/upstream_token` があれば、関所は最初にトークンを読むときにトークンをストアへ移し、ファイルを削除します。ログインでは、上流の SSH ホスト鍵も known_hosts に追加されます。
- 上流が複数あるときは、`--upstream <domain>` を付けて上流ごとに実行します。`logout` と `whoami` も同様です。
- `sekimore-relay whoami` で、関所がどの GitHub identity として動作するかを確認できます。

device flow トークンは `repo` スコープを持ちます。そのため GitHub 側の認可による制限は無く、`repos` と `permissions` が唯一の防壁です。
GitHub の監査ログではエージェントの操作と人間の操作を区別できないので、両者を区別できる記録は関所の `/data/relay/audit.jsonl` だけです。

## エージェント側の準備（dev コンテナ内）

`agent-setup.sh`（sgw-devcontainer-base では `/usr/local/bin/sekimore-agent-setup.sh` として配置され、postStartCommand で起動のたびに実行されます）は、関所を検出すると次の処理を自動で行います。

- 使い捨て認証鍵 `~/.ssh/sekimore/id_ed25519` を生成します（既にあれば再利用します）。
- `POST /bootstrap` で公開鍵を登録し、プロジェクトトークンを受け取ります。有効なトークンがある間は再発行を求めません。
- `/etc/sekimore-agent/env`（0600）に接続情報を書き込みます。`sekimore` ラッパーはこのファイルを読み、トークンの期限が切れると自動で取り直します。
- 上流ごとに、`~/.ssh/config` の `Host` ブロックと known_hosts のエントリを書き込みます。
- コミット署名を設定します。どの鍵を使うかは `relay.signing_key`（後述）で決まります。
- AI エージェント向けの使い方（`sekimore guide`）を、Claude Code の skill と Codex の `AGENTS.md` に配置します。

調整用の環境変数:

| 変数 | 意味 |
|---|---|
| `SEKIMORE_BOOTSTRAP=manual` | 鍵の登録とトークンの発行を運用者が行います（`add-key` と `token`）。 |
| `SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT` | 署名鍵のコメント（GitHub に登録するときの Title） |
| `SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE` | 対象ユーザーと保存先 |

### 署名鍵（0.2.29、#59）

上の認証鍵は、意図して使い捨てにしています。アクセス権を与える鍵なので、寿命が短いことが安全策になります。
署名鍵は逆です。署名鍵はアクセス権を与えず、人が手で GitHub に登録します。また、署名鍵を削除すると、その鍵で署名した
すべてのコミットから Verified 表示が外れます。そのため、署名鍵を失うことは「作り直せば済む」ことではなく、データの喪失です。
コンテナごとに署名鍵を生成していたときは、volume を消すたびに新しい鍵ができました。新しい鍵はそのたびに手で登録する必要があり、
古い鍵はどれも削除できませんでした。

`relay.signing_key` を設定すると、署名鍵は**人につき 1 本**になります。鍵は、既にゲートウェイにマウントされているホストの
ssh-agent に置かれ、GitHub には一度だけ登録します。関所は、共有 volume 上に**絞り込んだ** agent socket を作成し、dev コンテナに提供します。

| 要求 | 応答 |
|---|---|
| `REQUEST_IDENTITIES` | 設定した fingerprint の鍵 1 本だけ |
| `SIGN_REQUEST` | fingerprint が一致し、**かつ**データが namespace `git` の SSHSIG blob であるときだけ転送 |
| add / remove / lock / extension | `SSH_AGENT_FAILURE` |

git の署名が対象とするのは `"SSHSIG" ++ namespace ++ …` です。SSH の*認証*署名が対象とするのは、長さを前置した session ID で始まる
別の構造で、6 バイトの `SSHSIG` で始まることはありません。そのため、同じ鍵が認証鍵としても登録されている場合でも、この socket は
どのサーバーへの認証にも使えません（関所自身の sshd も含みます）。運用者の他の鍵が同じ agent にあっても、fingerprint による
絞り込みで見えなくなります。関所は、拒否を `signing_agent_refused`、成功した署名を `signing_agent_signed` として監査ログに記録します。

socket はモード 0600 で作成され、`socket_uid` が所有します。関所はどちらもパスではなくファイルディスクリプタ経由で設定します。
volume は共有されており dev コンテナには sudo があるので、パスを解決し直す `chmod` は、ゲートウェイ側のファイルに向け直されるおそれがあるためです。

dev コンテナ側に sekimore 専用のコマンドは不要で、通常の `git commit` で署名されます。`agent-setup.sh` が公開鍵を
`~/.ssh/sekimore/signing.pub` に書き込み、`user.signingkey` をそのファイルに設定し、`SSH_AUTH_SOCK` を
`/etc/sekimore-agent/env` に書き込みます。

```yaml
# config.yml
relay:
  signing_key:
    fingerprint: "SHA256:…"    # ssh-keygen -lf <key>.pub。運用者自身の署名鍵とは別の鍵にする
```

```yaml
# docker-compose.yml: socket の volume を両方のサービスにマウントする
services:
  sekimore-gw:
    volumes: [sekimore-signing:/run/sekimore]
  dev:
    volumes: [sekimore-signing:/run/sekimore]
```

`sekimore-relay check` は、fingerprint と、その鍵がホストの agent に実際にあるかを表示します。鍵が無いときは、
`agent-setup.sh` が `commit.gpgsign false` を設定し、その旨を表示します。誰も登録していない鍵で代用することはしません。

### `signing: required` は上流 API に 1 回問い合わせる

pack には、上流が持っていないオブジェクトだけが入ります。そのため、push の履歴が pack の外に出る地点は、本来は上流が既に持っている
履歴のはずです。しかし、上流にあるオブジェクトを base とする delta の裏に隠れたコミットも、pack の中からはまったく同じに見えます。
その形の pack を手で作ると、署名の無いコミットが検査を通過してしまいます。`git push` はそのような pack を作りません
（`pack-objects` が thin pack の base にするのは tree と blob だけです）が、ここでのクライアントは AI エージェントです。

そこで関所は、その境界で `GET /repos/{repo}/git/commits/{sha}` を送ります。pack に blob delta がいくつあっても、呼び出しは
1 push あたり 1〜2 回で、その範囲はその push が既に通過した認可の内側に収まります。関所は、答えを得られなければ push を拒否します。
そのため **`required` では、ゲートウェイの解錠（`mise run gw:unlock`）と login が必要です**。どちらかが欠けているときは、拒否メッセージがその旨を示します。

`relay.signing_key` を設定しなければ、従来の動作になります。`agent-setup.sh` が dev コンテナ内で `~/.ssh/sekimore/signing_ed25519` を生成し、
人がその公開鍵を GitHub に「Signing Key」として手で登録する必要があります。公開鍵はログに表示されます。

## 日常の使い方（エージェント）

```bash
git clone git@github.com:Org/Repo.git           # URL はそのまま。関所が透過的に中継する
git push origin HEAD:refs/pr/feature/login      # 0.3.0: feature/login に push し、PR（base = 既定ブランチ）を作る
git push origin HEAD:refs/for/main              # sekimore/main-<sha7> に push し、PR（base=main）を作る
git push origin HEAD:refs/heads/sekimore/x      # `push` が許すブランチ（既定は sekimore/*）への直接 push

sekimore whoami                                 # 自分の権限と repo
sekimore pr create --head sekimore/x --base main --title T --body="…"
sekimore pr status --number 12                  # PR の CI チェック（--json で機械可読）
sekimore pr merge --number 12 --method squash --delete-branch
sekimore pr update --number 12 --title T         # --base は bases に対して再検査される
sekimore pr reopen --number 12                   # issue reopen も同じ。閉じるのと同じ権限が要る
sekimore ci runs --ref v0.2.0                   # タグ / ブランチ / SHA に紐づく workflow run
sekimore ci jobs --number 12                    # PR の全 run のジョブ一覧（失敗と job_id が分かる）
sekimore ci log --number 12                     # 失敗ジョブのログを末尾から。--before / --window で前へ
sekimore issue create --title T --labels bug    # ラベルを付けるには issue:label も要る
sekimore release create --tag v0.2.6            # タグを push した後に実行する。本文は GitHub が書く
sekimore release view --tag v0.2.6              # タグに対応する Release
sekimore release list --limit 10                # Release の一覧（新しい順）
sekimore release edit --tag v0.2.6 --draft false # draft を公開する（release:publish が要る）
sekimore issue unlabel --number 5 --labels bug   # issue unassign も同じ形
sekimore ci rerun --run-id 123 [--all]           # ci cancel --run-id 123 もある。どちらも ci:rerun が要る
```

AI エージェント向けの使い方は `sekimore guide` で表示できます。ガイドは CLI に埋め込まれており、正本は `relay/share/agent-guide.en.md` と `agent-guide.ja.md` です。
agent-setup が同じ内容を Claude Code の skill（`~/.claude/skills/sekimore-relay/SKILL.md`）と Codex CLI の `~/.codex/AGENTS.md`（マーカー付きブロック）に配置するので、
これらのツールは自動で読み込みます。他のツールでは、`sekimore guide` の出力を、そのツールの規約で決まっている場所に置いてください。`SEKIMORE_AGENT_INSTRUCTIONS=none` で配置を無効にでき、`claude` または `codex` を指定すると一方だけに配置します。

`sekimore` は `sekimore-relay agent` のラッパーです。リポジトリは `--repo Org/Repo` で指定します。上流が複数あるときは `host/Org/Repo` とも書けます。
`--body` の値が `-` で始まるときは、`--body="…"` の形で書いてください。

既定で拒否されるものは、プロジェクト外のリポジトリ、read-only のリポジトリへの push、`bases` に無い base への `refs/for`、`push` の範囲外への直接 push と `refs/pr/` のブランチ名、タグ、削除、設定で許可していない API 操作です。拒否の理由は stderr に `sekimore: …` として出力されます。

`sekimore whoami` は、read-write のリポジトリごとに、受け付けるブランチ名（`push`）、許可する base、各 ref の書き方がどのブランチと base になるかを表示します。そのため、エージェントは最初の push の前にこれらの規則を確認できます。

## 設定リファレンス

### `domain_handlers.<domain>`

キーは FQDN で、完全一致で照合します。`github` を複数のドメインに設定すると、上流が複数になります。
`git-relay` は `github` handler の元の名前で、現在も受け付けます。既存の設定はそのまま動作します。

| キー | 既定 | 意味 |
|---|---|---|
| `handler` | `splice` | `github` はそのドメインを関所で受けます（SSH の git と GitHub API）。`https-relay` は 443 番ポートだけを関所の passthrough に通します（送信上限を掛けたい宛先用）。`deny` は拒否し、`splice` は関所が無いときと同じ動作です。 |
| `ssh_port` | `relay.ssh_listen` のポート | 関所側の SSH ポート。2 つ目以降の上流では必須です。 |
| `upstream` | ドメイン名 | 実際の上流ホスト |
| `upstream_ssh_port` | `relay.upstream_ssh_port` | 上流の SSH ポート |
| `ssh_options` | `[]` | 上流の ssh に `-o` で渡すオプション（例: `ProxyJump=bastion`）。強制オプションは上書きできません。 |
| `api_base` / `graphql_base` | `upstream` から導出 | GitHub API の宛先。`upstream` を別のホストに向けたときに設定します。 |
| `oauth_client_id` | `relay.oauth_client_id` | device flow の OAuth app（GHES では別の app） |
| `default` | `false` | このドメインを既定の上流にします。どのドメインにも指定が無いときは、`ssh_port` の無いものが既定になります。 |
| `max_upload_bytes` | `relay.https_max_upload_bytes` | 443 passthrough で dev コンテナから上流へ送れる、1 接続あたりのバイト数の上限。`-1` で無制限、`0` は指定できません。 |

### `relay`

| キー | 既定 | 意味 |
|---|---|---|
| `ssh_listen` / `api_listen` / `https_listen` | `0.0.0.0:22` / `0.0.0.0:8420` / `0.0.0.0:443` | listen アドレス |
| `https` | `passthrough` | 443 番ポートの扱い。`reject` では接続を即座に切断します。 |
| `https_max_upload_bytes` | `1048576` | 443 passthrough の送信上限の既定値（バイト）。`-1` で無制限です。上限を超えた接続は切断され、監査ログに `https_upload_capped` として記録されます。 |
| `state_dir` | `/data/relay` | 状態ファイルの置き場所 |
| `store.unlock` | `prompt` | 秘密ストアの解錠方法。`prompt` では、再起動のたびに人が `mise run gw:unlock` を実行し、パスフレーズはどこにも保存されません。`file`（`path:`）と `env`（`var:`）は、代わりにファイルまたは環境変数からパスフレーズを読みます。これらは、ゲートウェイを 1 時間に何度も再作成する**sekimore-gw 自体の開発用**です。パスフレーズを保存することになるので、関所は起動時にその旨をログに出します。`env` を `.devcontainer/.env` で設定してはいけません。このファイルはエージェントが書き込めるためです。 |
| `token_ttl` | `12h` | プロジェクトトークンの寿命 |
| `bootstrap` | `auto` | `POST /bootstrap` を許可するか。`manual` では運用者が鍵を登録します。 |
| `ssh_options` | `[]` | 全上流に共通の `-o` オプション |
| `ssh_config` | 無し | 上流の ssh に `-F` で渡すファイル（上級者向け） |
| `upstream` / `upstream_ssh_port` / `api_base` / `graphql_base` / `oauth_client_id` | | 既定の上流の設定。handler 側に書くのが新しい書き方です。 |
| `limits` | | セッション数とタイムアウト |
| `signing_key` | 無し | 0.2.29（#59）: dev コンテナがコミット署名に使う鍵。絞り込んだ agent socket 経由で提供します。キーは `source`（`agent`）、`fingerprint`（`SHA256:…`）、`namespace`（`git`）、`timeout`（`15s`）、`socket`（`/run/sekimore/signing-agent.sock`）、`socket_uid`（`1000`）です。設定しなければ、dev コンテナが自分で鍵を生成します（「署名鍵」を参照）。 |
| `project` | 必須 | プロジェクト（後述） |

### `relay.project`

| キー | 既定 | 意味 |
|---|---|---|
| `name` | 必須 | プロジェクト名。トークンとログに表示されます。 |
| `permissions` | `[]` | プロジェクトの既定の権限。`[…]` または `{allow, deny}` で書きます。 |
| `push` | `["sekimore/*"]` | 直接 push を許すブランチの glob |
| `tags` | `[]` | push を許すタグの glob。空の場合、タグの push はすべて拒否されます。 |
| `delete` | `false` | ブランチとタグの削除、および上流に既にあるタグの移動を許可するか。タグを削除して作り直すことと強制更新は同じ結果になるので、同じ権限にしています。まだ存在しないタグを作るだけなら `tags` で足ります。 |
| `delete_merged_branch` | `false` | `pr merge --delete-branch` が、マージしたそのブランチを削除してよいか。対象はそのブランチだけなので、`delete` とは別の権限です。forge 側でマージ済みブランチを自動削除している場合は不要です。 |
| `signing` | `optional` | 0.2.29（#59）: ブランチへの push が署名の無いコミットを含んでよいか — `required` \| `optional` \| `off`。`required` では、`refs/heads/*`、`refs/for/*`、`refs/pr/*` への push に署名の無いコミットが 1 つでもあれば拒否します。`signed_tags` と同じく、署名の有無だけを確認し、正しさは検証しません。**上流 API を使う**（「`signing: required` は上流 API に 1 回問い合わせる」を参照）ので、ストアの解錠と login が必要です。既定は `optional` なので、既存のプロジェクトの動作は変わりません。上流ごと、リポジトリごとに上書きできます。 |
| `branch` | 後述 | 0.3.0（#158）: `refs/for/<base>` で関所が作るブランチの名前の付け方 |
| `boards` | `[]` | このプロジェクトが操作してよい Projects v2 のボード。URL のとおりに書きます。`github.com/orgs/acme/projects/3` なら `{ org: acme, number: 3 }`、ほかに `{ user: someone, number: 1 }` の形も使えます。空の場合、Projects の操作はすべて拒否されます。 |
| `repos` | `[]` | リポジトリ。`Org/Repo` は既定の上流を指し、`host/Org/Repo` で上流を明示します。 |
| `upstreams.<domain>` | | 上流ごとの層。`permissions`（差分）、`push` / `tags` / `delete`（その上流の既定値）、`repos` |

### `repos[]`

| キー | 既定 | 意味 |
|---|---|---|
| `name` | 必須 | `Org/Repo`（`upstreams.<domain>.repos` の中では host は不要） |
| `mode` | 必須 | `read-only` または `read-write`。`read-only` はすべての書き込み操作を止めます。 |
| `bases` | すべて | `refs/for/<base>` と PR の base に許すブランチ。省略すると、エージェントが base を選べます。`refs/pr/` を使うには省略する必要があります。 |
| `push` / `tags` / `delete` | 上位の層の値 | このリポジトリだけの上書き |
| `permissions` | 差分なし | `{allow, deny}` で権限を追加または削除します。リストで書くと `allow` への追加になります。 |

### ブランチ名（0.3.0、#158）

プロジェクトのブランチは、機能なら `feature/`、バグ修正なら `fix/` のように、命名規約に従うのが普通です。
関所がその規約に従えるかどうかは、次の 2 つの設定で決まります。

**エージェントが付けてよいブランチ名**は、glob のリストである `push` で決まります。関所は、直接 push、
`refs/pr/<branch>`、pull request の head ブランチに対してこれを検査します。

```yaml
repos:
  - name: Org/Repo
    mode: read-write
    push: ["feature/*", "fix/*", "chore/*"]   # 既定の sekimore/* を置き換える
```

**関所が付けるブランチ名**は `project.branch` で決まり、`refs/for/<base>` に適用されます。

```yaml
relay:
  project:
    branch:
      template: "sekimore/{branch}-{sha}"   # 既定値
      on_exists: reject
```

| キー | 既定 | 意味 |
|---|---|---|
| `template` | `sekimore/{branch}-{sha}` | 関所は `{branch}`、`{base}`、`{sha}` を置換します。`{sha}` は短縮 SHA です。`refs/for/<base>` はそれ自体のブランチ名を持たないので、`{branch}` と `{base}` は同じ文字列になります。未知のプレースホルダ、対応の取れない波括弧、プレースホルダを 1 つも含まないテンプレートは、設定ファイルの読み込み時に拒否されます。 |
| `on_exists` | `reject` | その名前のブランチが上流に既にあるときの動作。`reject` または `update` です。`refs/pr/<branch>` にも適用されます。`{sha}` を含むテンプレートは、そのコミットだけが使えるブランチ名になるので、この設定にかかわらず、同じコミットの再 push は冪等です。 |

履歴に `sekimore` という文字列を残したくないプロジェクトは、`template: "agent/{base}-{sha}"` など、任意の形を設定できます。

#### push 先の ref の選び方

| ref | ブランチ | base |
|---|---|---|
| `refs/pr/<branch>` | `<branch>` そのもの | 上流の既定ブランチ（`bases` が未設定であることが必要） |
| `refs/for/<base>` | `template` から生成 | `<base>` |
| `refs/heads/<branch>` | `<branch>` そのもの。pull request は作らない | — |

`refs/pr/` では base を指定できません。base を安全に埋め込む方法が無いためです。git が区切り文字として受け付ける文字は
どれもブランチ名の中でも使え、git がブランチ名で禁止している文字（`:` `^` `~`）は refspec でも拒否されます。
別の base に対して pull request を作るには、pull request を作らずに push してから `sekimore pr create --head <branch> --base <base>` を実行するか、
後から `sekimore pr update --base <base>` で base を変更します。

**`refs/pr/` を使うには、`bases` が未設定である必要があります。** `refs/pr/` の push は既定ブランチに対して pull request を作りますが、
関所が既定ブランチを知るのは API からで、それは push の後です。`bases` を列挙しているリポジトリでは、ブランチが上流に届いた後でしか
base を検査できません。そのため関所は、そのようなリポジトリでは何も送信する前に `refs/pr/` を拒否します。`refs/pr/` を使うには
`bases` を未設定にします。あるいは `refs/for/<base>` を使います。こちらは ref の中で base を指定するので、push を送信する前に検査されます。

### 権限の決まり方

- 実効権限 = (プロジェクト allow ∪ 上流 allow ∪ repo allow) − (プロジェクト deny ∪ 上流 deny ∪ repo deny)。deny はどの層に書いても優先されます。
- `push` / `tags` / `delete` は、プロジェクト → 上流 → repo の順で上書きされます。glob では `*` と `?` が使えます。
- 権限キーは 33 個です: `pr:create` `pr:read` `pr:comment` `pr:review` `pr:request_review` `pr:merge` `pr:close` `pr:label` `pr:assign` `pr:comment_update` `pr:comment_delete`、`issue:create` `issue:read` `issue:comment` `issue:update` `issue:close` `issue:label` `issue:assign` `issue:comment_update` `issue:comment_delete`、`project:read` `project:add_item` `project:update_item`、`repo:read`、`ci:read` `ci:rerun` `ci:dispatch`、`release:create` `release:read` `release:publish`、`search:read`、`security:read` `security:dismiss`。設定が許可している権限は `sekimore-relay check` で表示できます。
- `pr:read` は、状態と CI チェックに加えて、本文とコメントも対象にします。`issue:read` は別の権限なので、非公開のトラッカーを読ませずに bug を登録させることができます。`search:read` は、検索が 1 つのリポジトリに宛てた操作ではないため、独立したリソースです。
- `pr:review` はレビューを提出する権限、`pr:request_review` は他の人にレビューを依頼する権限です。前者は意見を記録し、後者は人に通知するので、分けています。
- `ci:rerun` は workflow run の再実行と中止の権限です。再実行は Actions の時間を消費し、リポジトリの secret にアクセスできる workflow のコードを実行するので、`ci:read` には含めていません。
- `release:publish` は、draft の Release を公開する権限です。`release create --draft` は公開を人間に委ねるためにあるので、公開を `release:create` に含めると、その区別が失われます。draft のまま編集するだけなら `release:create` で足ります。
- 閉じることと開き直すことは同じ権限です（`pr:close` / `issue:close`）。開き直すことは閉じたことの取り消しであり、新しい能力を与えるものではないためです。同様に、ラベルと担当者の追加と削除も、それぞれ 1 つの権限です（`issue:label` / `issue:assign`）。PR のタイトルや本文の編集には `pr:create` が必要です。ただし、新しい base は、そのリポジトリの `bases` に対して改めて検査されます。
- `repo:read` は `repo vocabulary`（そのリポジトリのラベル、担当者に指定できるユーザー、マイルストーンの一覧）に必要です。
- 実効値は、`sekimore-relay check` と Web UI の Relay タブで確認できます。

### 例: github.com と GHES を同時に扱う

```yaml
domain_handlers:
  github.com: { handler: github }                       # 既定の上流（ssh_port を省略）
  ghe.example.com:
    handler: github
    ssh_port: 2222                                      # 2 つ目以降の上流は別のポートが必要
    ssh_options: [ProxyJump=bastion.example.com]        # 踏み台を経由する場合

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

`release:create` と `release:read` は、他の権限と同じく既定で拒否されます。Release を使うプロジェクトでは `permissions` に追加してください。
device flow トークンは既に `repo` スコープを持っているので、認証をやり直す必要はありません。

```bash
git push origin v0.2.6                                   # タグが先に上流に存在している必要がある
sekimore release create --tag v0.2.6                     # 本文はマージ済み PR から GitHub が書く
sekimore release create --tag v0.2.6 --notes-file NOTES.md --draft
sekimore release view --tag v0.2.6
sekimore release list --limit 10
```

- タグが上流に既に存在している必要があるので、このコマンドはタグを push した後に実行します。タグが無いと GitHub は 422 を返します。
- 本文を渡さないと、関所は `generate_release_notes` を指定し、前のタグ以降にマージされた pull request から GitHub が本文を生成します。
  これが通常の使い方で、本文を手で書く必要はありません。
- `--notes` か `--notes-file` を渡すと、その内容が本文になります。さらに `--generate-notes` を付けると、GitHub が生成した本文が
  その後ろに追記されます。
- `--title` の既定値はタグ名なので、Release に必ずタイトルが付きます。`--prerelease` を付けると prerelease になります。
- `--draft` は未公開の状態で Release を作り、公開を人間に委ねます。既定では公開済みの状態で作られます。
- `sekimore release edit --tag v0.2.6 --draft false` はその draft を公開します。これには `release:publish` が必要です。
  draft のまま編集する（`--title`、`--notes`、`--prerelease`）だけなら `release:create` で足ります。

### 持ち出し対策: 443 の送信上限と `https-relay`

関所は運用者の資格情報を AI に使わせません。しかし、プロンプトに埋め込まれた他人の資格情報を使った HTTPS push は、TLS の中身を検査しない限り通常の通信と区別できません。
そのため、443 passthrough には、dev コンテナから上流へ送れるバイト数の上限があります（既定は 1 MiB。ダウンロードは数えません）。
通常の GET リクエストや API 呼び出しの送信量はこの上限よりはるかに小さいので、止まるのは `git push` などの大きな送信だけです。

```yaml
domain_handlers:
  github.com: { handler: github, max_upload_bytes: 262144 }      # 256 KiB。SSH が関所を通るので HTTPS push は不要
  ghcr.io:    { handler: https-relay, max_upload_bytes: -1 }     # 自分で image を push するレジストリは無制限
  registry-1.docker.io: { handler: https-relay }                 # 既定値（relay.https_max_upload_bytes）を使う
relay:
  https_max_upload_bytes: 1048576
network:
  allowed_ports: [80, 443]      # 許可ドメインへ通す宛先ポート（sekimore-gw 本体の設定。IP アドレス直指定の SSH などを止める）
```

- `https-relay` のドメインは DNS で関所に解決され、443 番ポートだけが関所の passthrough を通ります。他のポートはそのドメインに届きません。
- 上限を超えた接続は切断され、監査ログに `https_upload_capped` が記録されます。Relay タブでは、1 MiB 以上を送った接続に LARGE UPLOAD の印が付き、直近 24 時間の件数が表示されます。
- `allow_domains` に残したドメインは関所を通らないので、上限も掛かりません。上限を掛けたいドメインだけを handler に移します。

複数上流の仕組み: SSH の exec 要求にはホスト名が含まれないので、関所は上流ごとに別のポートで listen し、接続を受けたポートで上流を選びます。
agent-setup が `~/.ssh/config` に上流ごとの `Host` と `Port` を書き込むので、エージェントが使う URL は変わりません。
443 番ポートでは、TLS の SNI で上流を選びます。関所の ssh はホスト側の `~/.ssh/config` を読まないので、踏み台やプロキシは `ssh_options` に設定します。
踏み台のホスト鍵は `sekimore-relay keyscan bastion.example.com --upstream ghe.example.com` で追加します。

## 表示言語（0.2.4）

CLI の文言は `relay/locales/en.json` と `relay/locales/ja.json` にあり、バイナリに埋め込まれます。
関所は `SEKIMORE_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG` の順に参照し、値が `ja*` に一致すれば日本語、それ以外は英語を選びます（既定は英語）。
辞書に無いキーは英語にフォールバックし、英語にも無ければキー名にフォールバックします。

```bash
sekimore-relay check                     # 英語（既定）
SEKIMORE_LANG=ja sekimore-relay check    # 日本語
sekimore guide --lang ja                 # ガイドだけを日本語で表示
```

対象は、`--help`、運用者向けの出力、`sekimore guide` です。
ガイドの言語は `--lang en|ja` で選べ、ガイドの正本は `relay/share/agent-guide.en.md` と `relay/share/agent-guide.ja.md` です。
拒否理由（`sekimore: …`）と監査ログ `audit.jsonl` は、意図的に英語のままにしています。ツールやエージェントが文字列で照合できるようにするためです。

## 運用（運用者）

Web UI（ホストの http://localhost:8090）の Relay タブで、設定、権限、トークン、アクセス履歴、ブロック履歴を確認できます。このタブは閲覧専用です。
Dev Containers 構成では、`mise run gw:tokens` / `gw:revoke-project` / `gw:audit` / `gw -- <args>` も使えます。

| コマンド | 用途 |
|---|---|
| `sekimore-relay check` | ポリシーと現在の状態の一覧 |
| `sekimore-relay tokens` | 発行済みトークンの一覧（ラベル / 期限 / 使用回数 / 状態） |
| `sekimore-relay revoke --label skm_xxxxxxxx` | トークンを 1 つ失効 |
| `sekimore-relay revoke-project` | プロジェクトの全トークンを失効（プロジェクト終了時） |
| `sekimore-relay bootstrap disable` / `enable` | 自動登録の停止と再開（kill switch） |
| `sekimore-relay add-key "ssh-ed25519 AAAA…"` | 公開鍵の手動登録 |
| `sekimore-relay keyscan <host> [--port N] [--upstream <domain>]` | 上流または踏み台のホスト鍵を known_hosts に追加（fingerprint を表示） |
| `sekimore-relay login` / `logout` / `whoami` `[--upstream <domain>]` | 上流トークンの管理 |
| `tail -f /data/relay/audit.jsonl` | すべての操作と拒否の記録の追跡 |

`/data/relay` はゲートウェイの volume（0700）で、AI コンテナからは見えません。
同じ鍵で bootstrap をやり直すと前のトークンは失効するので、鍵 1 本あたりの有効なトークンは最大 1 つです。
トークンの記録は、期限切れから 7 日後に自動で削除されます。恒久的な記録は `audit.jsonl` です。

## 困ったとき

| 症状 | 原因 | 対処 |
|---|---|---|
| `SSH_AUTH_SOCK is not set in the gateway container` | agent socket が関所に渡されていません。 | 手順 2 のマウントと環境変数、Mac 側の `ssh-add -l` を確認します。 |
| `ssh-agent socket … does not exist` / `cannot connect` | 転送が切れたか、権限のエラーです。 | 転送を張り直します。EACCES なら socket の所有者を確認します。 |
| `known_hosts … has no entry for <host>` | 上流のホスト鍵がありません。 | `sekimore-relay login` か `sekimore-relay keyscan <host>` を実行します。 |
| `repository "X" is not in project "P"` | リポジトリがプロジェクトの外にあります。 | `repos` に追加します。意図した拒否なら対処は不要です。 |
| `push to refs/heads/main is not allowed` | 直接 push の宛先が、許可された名前空間の外のブランチです。 | `refs/for/main` に push して PR を作ります。必要なら `push` に glob を追加します。 |
| `branch X already exists upstream` | その名前が既に使われており、`on_exists` が `reject` です。 | 別の名前で push するか、`refs/heads/<branch>` への直接 push でブランチを更新します。 |
| `tag is not allowed for this repository` | タグの push は既定で拒否されます。 | そのリポジトリか上流の `tags` に glob を追加します。 |
| `Permission denied (publickey)`（関所から） | エージェントの鍵が登録されていません。 | `sudo sekimore-agent-setup.sh` を実行するか、運用者が `add-key` を実行します。`bootstrap.disabled` の有無も確認します。 |
| `! [remote rejected] … (sekimore: …)` | ポリシーが push を拒否しました。 | メッセージの案内に従います。 |
| `denied: token expired at …` | プロジェクトトークンの期限が切れています。 | `sekimore` ラッパーが自動で取り直します。古い環境では `sudo sekimore-agent-setup.sh` を実行します。 |
| `no upstream token … run sekimore-relay login` | device flow を実行していないか、logout した後です。 | `sekimore-relay login` を実行します。 |
| `git ls-remote` が出力なしで止まる | DNS は関所を向いていますが、INPUT チェインでパケットが破棄されています。 | `iptables-legacy -S INPUT` に `--dport 22` があるかを確認します。無ければ関所が起動していません。 |
| `https://github.com/…` が失敗する | `https` が `reject` に設定されているか、上流に届きません。 | 既定の `passthrough` に戻します。監査ログの `https_failed` を確認します。 |
| HTTPS の git で `could not read Username` | 運用者の資格情報が関所を迂回しないよう、HTTPS 認証を意図的に塞いでいます。 | SSH（`git@github.com:`）を使います。 |
| post-create の「ssh-agent が転送されています」という表示が消えない | macOS の `code` は launchd の環境を引き継ぎます。 | VS Code を完全に終了してから `mise run vscode` を実行します。 |

## 開発

```bash
mise use rust@1.89                                  # または rustup
cargo test --features test-hooks                    # e2e テストには git と ssh が必要（CI では SEKIMORE_E2E_REQUIRED=1）
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo audit                                         # .cargo/audit.toml の ignore にはすべて理由を書いてある
cargo tree -i aws-lc-rs; cargo tree -i openssl-sys  # どちらのクレートも含まれていないこと
```

sekimore-gw のルートで `mise run ci` を実行すると、Rust と Python の lint とテストが並列で実行されます。
`test-hooks` feature は `LocalGitUpstream`（ローカルの bare リポジトリに対する `git receive-pack`）を有効にします。イメージのビルドには含めません。

## イメージのビルド

`sekimore-gw/Dockerfile` の `relay-builder` ステージが、`cargo-zigbuild` で静的な musl バイナリをビルドします（CI ではアーキテクチャごとの native runner を使います）。
このバイナリは特定の glibc のバージョンに依存しないので、dev コンテナの base イメージに `COPY --from` するだけで動作します。

## 変更履歴

[CHANGELOG.ja.md](CHANGELOG.ja.md) を参照してください。
