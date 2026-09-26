# sgw-devcontainer-base 変更履歴

*[English](CHANGELOG.md)*

DevContainer のベースイメージ — Dockerfile と焼き込む道具、同梱する zsh 設定と
スクリプト、`examples/` のサンプル devcontainer。

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

0.2.46 からは sekimore-gw リポジトリの `base/` から作り、同じタグで、ゲートウェイと同じ版番号で出す（#235）。
それより前の項目の PR 番号は旧 `Amakata/sgw-devcontainer-base` リポジトリのもの。各版は取り込んだゲートウェイの版を書いている。

0.2.18 から始める。それ以前のリリースはここに書かない。各 PR とタグが記録。
取り込んだ gateway の版だけは末尾にある。

## 0.2.47（2026-09-26）

### Enhancement

- base イメージ自体の変更は無い。ゲートウェイと一緒に出す (sekimore-gw#238)

## 0.2.46（2026-09-26）

### Enhancement

- sekimore-gw リポジトリの `base/` に移った。イメージはそこから作り、ゲートウェイのタグで、その版番号で出す。base は 0.2.43 → 0.2.46 に飛ぶ (sekimore-gw#236)
- `upgrade.sh` は配布ファイルを sekimore-gw のタグの `base/share/sgw/` から、UPGRADING をその最上位から取る。サンプルの `gateway.mise.toml` は同じコミットの `../share` のもの (sekimore-gw#236)
- 他と同じ Apache-2.0 にした。以前は MIT だった (sekimore-gw#236)

## 0.2.43（2026-09-25）

### Enhancement

- `sgw.sh` が Docker CLI の "What's next" の案内を抑えるようにした。`relay:verify` の出力に紛れ込んでいた (#102)
- sekimore-gw 0.2.45 を取り込む。`gw:login` が端末上で動き、ホスト鍵を保存できなかったときは device flow の前で止まる。監査の各行が経路台帳の辺を示す (sekimore-gw#230, sekimore-gw#228)

## 0.2.42（2026-09-25）

### Enhancement

- sekimore-gw 0.2.44 を取り込む。ProxyJump の踏み台を上流の known_hosts で検証し、keyscan と login は踏み台経由で行く (sekimore-gw#220, sekimore-gw#221)
- `relay:verify` が各項目の確かめる経路台帳の辺を示す。例: `[dev.egress.route_past_gateway]` (#99)
- `relay:refresh` が Rebuild Container なしに dev の Host ブロックとプロキシ環境変数を作り直す (#98)

## 0.2.41（2026-09-25）

### Security

- sekimore-gw 0.2.43 を取り込む。`/api/config` が上流プロキシのパスワードを返さなくなった
- `relay:verify` が確認する。dev から見たゲートウェイの API に上流プロキシのパスワードが載っていてはならない (#95)
- 更新後は上流プロキシのパスワードを入れ替える。古いものは dev コンテナから読めていた

## 0.2.40（2026-09-25）

### Security

- sekimore-gw 0.2.42 を取り込む
- 上流プロキシが設定されているとき、dev はゲートウェイから `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` を受け取る。同梱の zsh rc.d が読み込むので、通常の通信も直接出ずにゲートウェイを通る (#91)
- ゲートウェイが直接出口を拒むとき、`relay:verify` は dev の通常の通信が上流を迂回できないことを確かめる (#91)
- rc.d の追加のため Rebuild Container が要る

## 0.2.39（2026-09-25）

### Fix

- sekimore-gw 0.2.41 を取り込む
- TLS で話す上流プロキシが再び動く。関所は自身の HTTPS をローカルの Squid 経由で送る
- `relay:verify` は関所経由の HTTPS と GitHub API 1 回を試す (#86)
- `relay:verify` と `upgrade.sh` は `store-status` の 1 行目だけを読む (#88)
- あなたのファイルは変わらない

## 0.2.38（2026-09-25）

### Enhancement

- sekimore-gw 0.2.40 を取り込む
- `relay:verify` は端末で OK を緑、FAIL を赤で出す。`gw:*` タスクは関所の `check` と `store-status` に状態語を色付けさせる (#84)
- そうでないときは `NO_COLOR` と `SEKIMORE_COLOR` が決める
- あなたのファイルは変わらない

## 0.2.37（2026-09-25）

### Fix

- sekimore-gw 0.2.39 を取り込む。関所は `https://` の上流プロキシに対し、CONNECT を送る前に TLS で話す。TLS を自分で終端するプロキシでも動く
- Squid は保存済みの上流プロキシ資格情報を、手動の unlock のあとだけでなく、再起動のたびに受け取る。ゲートウェイは動いている間ずっとシークレットストアを見張る
- 資格情報の状態（none / locked / set）が `gw:check` とダッシュボードに出る。直すためのコマンドも添える
- あなたのファイルは変わらない

## 0.2.36（2026-09-25）

### Security

- sekimore-gw 0.2.38 を取り込む。ホスト自身を dev に対して閉じる。ホストに INPUT 規則を 2 本置き、ホストが開いた接続への応答だけを通し、内部ブリッジからのそれ以外は落とす。dev はホスト自身にも、同じマシンの他のコンテナが公開しているポートにも、Docker Desktop の VM のサービスにも届かなくなる (#190)
- `relay:verify` が確かめる。ブリッジの `.1` は dev の ping に応答してはならない
- あなたのファイルは変わらない。ゲートウェイに必要なのは base 0.2.35 の `pid: host` だけ

## 0.2.35（2026-09-25）

### Security

- sekimore-gw 0.2.37 を取り込む。ホストの `DOCKER-USER` チェーンに FORWARD 規則を置き、内部ブリッジからはゲートウェイにしか届かなくする。dev の root プロセスが Docker の NAT でゲートウェイを迂回できなくなる (#189)
- サンプルのゲートウェイのサービスが、この規則に必要な `pid: host` で動く。プロジェクトは自分の `.devcontainer/docker-compose.yml` に追加する必要がある。[UPGRADING](UPGRADING.ja.md#0237-ゲートウェイに-pid-host-が要る) を参照
- `relay:verify` が迂回を確かめる。dev からブリッジ自身のルーター経由でホストルートを張っても、インターネットに届いてはならない

## 0.2.34（2026-09-24）

### Security

- sekimore-gw 0.2.36 を取り込む。許可した名前が link-local (IMDS)、ループバック、RFC1918、carrier-grade NAT に解決したら宛先として拒否するようになる (#178)

## 0.2.33（2026-09-24）

### Enhancement

- sekimore-gw 0.2.35 を取り込む。このイメージの CLI とガイドが `pr files` と `pr diff` を知るようになる。どちらも `pr:read` で PR の差分を読む (#173)

## 0.2.32（2026-09-24）

### Enhancement

- sekimore-gw 0.2.34 を取り込む。このイメージの CLI とガイドが `pr comment-edit` / `comment-delete` と `issue` 側の同じコマンドを知るようになる (#174)

## 0.2.31（2026-09-24）

### Enhancement

- sekimore-gw 0.2.33 を取り込む。このイメージの CLI とガイドが `pr reply`、行への指摘、`ci dispatch`、draft の PR を知るようになる (#165 #167 #168 #169)

## 0.2.30（2026-09-24）

### Fix

- ログインシェルでも mise の shims が PATH に乗る。`codex` / `node` / `npm` が使える。Debian の `/etc/profile` が PATH を追加ではなく代入していて、イメージの `ENV PATH` を捨てていた (#60)

### Enhancement

- README が「はじめかた」から始まる。What's inside は 1 項目 10 行の箇条書きをやめて表にした。README が見せる `FROM` の版はサンプルと照合する (4 版ぶん遅れていた) (#67)

## 0.2.29（2026-09-24）

### Fix

- プロジェクトの `post-create.sh` に `disable_vscode_credential_helper` が残っているとき、`post-start.sh` がそれを知らせる。0.2.26 で不要になった写しは、取り除く helper が無いと偽を返す判定で終わるため、`set -e` の下で理由も出ずに起動を止めていた (#64)

## 0.2.28（2026-09-24）

### Security

- GitHub CLI (`gh`) を焼き込むのをやめた。`api.github.com` へは関所の 443 passthrough を通る — 中身を読まずに中継する経路なので、トークンを持った `gh` は関所が課す操作ごとの権限をどれも受けない。同じことは `sekimore` がエージェント API 経由でできる (#62)

## 0.2.27（2026-09-24）

### Enhancement

- sekimore-gw 0.2.32 を取り込む。このイメージの CLI とエージェント向けガイドが `refs/pr/<branch>` と、ブランチ名の template 設定を知るようになる (#158)

## 0.2.26（2026-09-23）

### Fix

- `post-start.sh` が VS Code の HTTPS credential helper を起動のたびに取り除く。`/etc/gitconfig` は sudo で書き換える。各プロジェクトの `post-create.sh` にあった写しは起動を止めることがあり、サンプルの写しは system 側に届いていなかった (#57)

## 0.2.25（2026-09-23）

### Fix

- `sgw.sh` が、人が端末にいるときは `docker exec` に端末を渡す。`mise run dev:shell` が固まらずにシェルを開く。以前は `$(...)` の中で判定していて、そこでは標準出力が常にパイプだった (#55)

## 0.2.24（2026-09-23）

### Fix

- apply / sync が `upgrade.sh` 自身を入れ替えたら、最後に新しいものを `--owned` で実行する。新しいリリースがあなたのファイルに求める変更が、次の実行を待たずに、そのリリースを入れた apply で出る (#54)

## 0.2.23（2026-09-23）

### Fix

- `dev:shell` に `raw = true` を付けた。mise の prefix 出力モードでは標準出力がパイプになり、シェルが端末なしで起動してプロンプトが出なかった。シェルを起動するタスクや `gw-tty` を通るタスクに `raw = true` が無ければ CI が落ちる (#51)
- `relay:verify` が、`user.signingkey` が gateway の署名ソケットの出す鍵かを確かめ、`key::` で鍵を直接書いている、またはソケットが出さない鍵ファイルを指しているときに知らせる (#51)

### Enhancement

- gateway 0.2.31 を取り込む (#51)

## 0.2.22（2026-09-23）

### Fix

- `postStartCommand` が配布物の `.devcontainer/sgw/post-start.sh` を実行する。コンテナにある `SEKIMORE_*` 変数をすべて `sudo` 越しに agent-setup に渡す。手で持っていた `--preserve-env=` の一覧から漏れた変数は黙って無視され、サンプルには一覧自体が無かった。`mise run upgrade` が 1 行の書き換えを案内し、調べるだけのときもあなたのファイルに要る変更を表示する (#49)

## 0.2.21（2026-09-23）

### Enhancement

- gateway 0.2.30 を取り込む。sample も gateway 0.2.30 とそのタスクファイルで動く (#47)

## 0.2.20（2026-09-23）

### Enhancement

- `mise run upgrade` が、固定している gateway と base を GHCR の最新と比べ、何が変わるかを表示する。`upgrade:apply` は 2 つのタグを書き換え、`.devcontainer/sgw/` を入れ替え、確認のうえ gateway を作り直して解錠し、人がやることだけを最後に並べる。配布物が手で書き換えられていれば、何も書かずに差分を出して止まる。`upgrade:sync` が `gw:sync-tasks` を置き換え、`upgrade:notes` は間にある UPGRADING の節を表示する (#45)
- ホスト側のスクリプトとタスクを `.devcontainer/sgw/` に移した。ここは `upgrade` のもので、`mise.toml` には include と自分のタスクだけが残る。`mise.toml` のタスクは同じ名前の配布タスクより優先される。サンプルもこの配置にし、`FROM` を版で固定した (#45)
- `upgrade.sh` / `sgw.sh` / `vscode.sh` の表示とタスクの説明が、relay と同じ規則で言語を決める: `SEKIMORE_LANG`、`LC_ALL`、`LC_MESSAGES`、`LANG` (#45)

## 0.2.19（2026-09-22）

### Fix

- サンプルの devcontainer が取り込む gateway を、固定されていた 0.2.19 から、このイメージが取り込む 0.2.29 に上げた。コメントは 0.2.18 以降のサンプルと同じく全て英語にし、`gw:sync-tasks` は英語版のタスクファイルをイメージから取り出すようにした。隣に置いてある `gateway.mise.toml` も 0.2.29 のものになり、`gw:unlock-auto` が入る (#41)
- `mise run web` が、task に書かれた数字ではなく、gateway が実際に公開しているポートを開くようにした。動いているコンテナから引く (`sgw.sh port <service> [container-port]` を追加)。サンプルは `8080:8080` なので直書きの数字がたまたま合っており、それがこの問題を隠していた。8090 が埋まっていてポートをずらしたときに壊れるが、それはサンプルをコピーして行うことそのものである (#42)

## 0.2.18（2026-09-21）

### Fix

- ラッパー `sekimore` が期限切れの案件トークンを取り直せるようになった。`POST /bootstrap` を呼ぶ (`sekimore-relay agent bootstrap` は元から無い)。env ファイルは置き場が root のものなので上書きで書く (#38)

### Enhancement

- gateway 0.2.29 を取り込む (#40)
- README.md を英語、README.ja.md を日本語にした。他のリポジトリと同じ形。サンプルの `config.yml` はコメントを英語にし、gateway が読むキーを全部 (権限キー 28 個を含む) 載せた (#39)
- この変更履歴を英語と日本語で追加した。gateway と relay が既に使っている形に合わせた (#26)

## 0.2.18 より前

内容は書かない。各 PR とタグが記録。ここに残すのは、取り込んだ gateway の版だけ。

- 0.2.17 は gateway 0.2.15 を取り込んだ
- 0.2.16 は gateway 0.2.15 を取り込んだ
- 0.2.15 は gateway 0.2.14 を取り込んだ
- 0.2.14 は gateway 0.2.13 を取り込んだ
- 0.2.13 は gateway 0.2.13 を取り込んだ
- 0.2.12 は gateway 0.2.11 を取り込んだ
