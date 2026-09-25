# sekimore-gw 変更履歴

*[English](CHANGELOG.md)*

gateway 全体 — DNS、ファイアウォール、Squid、Web UI、ビルドと CI。
relay 自身の変更は [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) にある。
版番号は共通（1つのイメージに両方が入る）。

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

0.2.18 から始める。それ以前は relay の変更履歴にある。
両者を分けるまで、あちらが全体を抱えていた。

## 0.2.45（2026-09-25）

### Enhancement

- relay: login が device flow の前に必要なホスト鍵（まず踏み台、次にそれ越しの上流）を取り、保存できなかったときは非ゼロで終了するようにした。yes/no はバイト列として読み、その文字で判定する (#230)
- `gw:login` と `gw:logout` を `gw:unlock` と同じく `sgw.sh gw-tty` 上の `raw = true` のタスクにした。端末が無いと、答えが文字でないバイト列として届いていた (#230)
- relay: 接続を記録する監査の各行が `docs/paths.yml` の `edge=<id>` を持つようにした。`paths::AUDIT_EVENTS` が組を並べ、経路台帳のテストが検査し、relay タブが id を表示する (#228)
- `relay/README` に、`keyscan` が fingerprint を表示してから保存する理由と、`login` が先に尋ねる理由を書いた (#230)

## 0.2.44（2026-09-25）

### Enhancement

- 経路台帳 `docs/paths.yml` を足した。接続の各辺について、誰が名前を解決し、誰が相手を検証し、何を提示し、どこに記録が残るかを書く。`tests/unit/test_paths.py` がグラフとして検査し、id は `src/paths.py` と `relay/src/paths.rs` にある (#223)
- README からゲートウェイ単体の構成を消した。入口は dev コンテナである (#226)

## 0.2.43（2026-09-25）

### Security

- `/api/config` の上流プロキシのパスワードを伏せた。`squid.config_text` が生成後の squid.conf を `login=<user>:<password>` ごと dev に返していた。今は `***`。更新後にパスワードを変えること (#218)
- `/api/domains` の認証の無い `POST` / `DELETE` のスタブを消した。何も変えないもので、呼ぶものも無かった (#218)

## 0.2.42（2026-09-25）

### Security

- dev の通信のうち上流プロキシを通るのは関所の handler 経路と明示プロキシのクライアントだけだった。`proxy.direct_egress: deny` を足し、`allow_domains` のアドレスをファイアウォールに入れず Squid だけを出口にできるようにした。既定の `allow` は起動時に WARN を出す (#215)

### Enhancement

- dev コンテナに `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` を渡すようにした。`GET /api/proxy-env` と agent-setup 経由で、`NO_PROXY` は `domain_handlers` と運用者の `proxy.no_proxy` から組み立てる (#215)

## 0.2.41（2026-09-25）

### Fix

- 上流プロキシが TLS のとき、関所の HTTPS を同じコンテナの Squid 経由にした。rustls に無い RSA 鍵交換しか出さないプロキシでも通る。Squid には `relay_localhost` の許可を、宛先の拒否より下、関所ドメインの拒否より上に入れる (#210)
- `store-status` を状態語 1 つに戻した。0.2.39 でその下に足した資格情報の行が、解錠済みのストアで `relay:verify` を落としていた (#209)

### Enhancement

- `check` が上流プロキシに実際に接続して経路と結果を出すようにした。`HandshakeFailure` のときはプロキシが出すべきものを言う。診断用に `openssl` CLI をイメージに入れた (#207)

## 0.2.40（2026-09-25）

### Enhancement

- gateway 自体の変更は無い。0.2.39 と 0.2.40 は同じ Python。この版は関所の `check` と `store-status` を、端末で見る運用者向けに色付けする (#203)

## 0.2.39（2026-09-25）

### Fix

- `https://` の上流プロキシには CONNECT の前に TLS で接続するようにした。`upstream_proxy_tls: true` の背後にある関所経由の HTTPS ドメインが、`SSL_ERROR_SYSCALL` で落ちずに上流へ届く。Squid は以前から届いていた (#199)
- 上流プロキシの資格情報を秘密ストアから読み続けるようにした。`gw:unlock-auto` の後でも、後から `gw:proxy-credential set` した場合でも、`login=` が `squid.conf` に入る。解錠の瞬間の 1 回の読み取りに頼らない (#200)

### Enhancement

- 上流プロキシの資格情報の状態を `none` / `locked` / `set` / `config` / `unavailable` で `/api/config` とダッシュボードに出すようにした。次に打つコマンドも添える (#200)
- Relay タブの HTTPS の行に宛先を出すようにした。拒否した行の理由は `detail` にも写す (#198)
- dev の中から上流プロキシの経路を切り分ける手順を relay/README に書いた (#197)

## 0.2.38（2026-09-25）

### Security

- dev からホスト自身への通信を落とすようにした。DOCKER-USER の規則に加えて、ホストの INPUT に 2 行入れる。bridge 自身のアドレスは ping にも、他のコンテナが公開するポートにも、VM のサービスにも答えなくなった (#191)
- ホストが開いた接続への応答は通す。dev コンテナが公開するポートはこれまでどおり動く (#191)

## 0.2.37（2026-09-25）

### Security

- エージェントをホスト側で閉じ込めた。ホストの `DOCKER-USER` チェーンに FORWARD 規則を 2 行入れ、internal bridge から出られる先をゲートウェイだけにした。エージェントコンテナの root が Docker の NAT 経由でゲートウェイを迂回できなくなった (#189)
- 規則はゲートウェイ自身が `pid: host` と nsenter で入れて定期的に確かめる。タグは `sekimore:<project>`。`pid: host` が無ければ起動時にエラーを記録する (#189)
- `network.host_enforcement`（既定 on）で無効化できる。呼ばれていなかった `setup_host_firewall_rules` は削除した (#189)

## 0.2.36（2026-09-24）

### Security

- 許可した名前が指してよい宛先を検査するようにした。許可ドメインが link-local (IMDS)、ループバック、RFC1918、carrier-grade NAT とその IPv6 相当に解決したら拒否する。DNS・Squid・relay の 443 passthrough の3箇所すべてで効く (#178)
- DNS の答えが入る唯一の地点で判定するようにした。問い合わせ経路も TTL 更新もキャッシュも覆い、拒否した address はキャッシュに残らない (#178)
- IPv6 の形をした IPv4 (`::ffff:a.b.c.d`) をほどいて IPv4 として判定するようにした。`::ffff:169.254.169.254` が IPv4 で書いた一覧をすり抜けない (#178)
- `resolve_deny_cidrs` と `resolve_allow_cidrs` を足した。どちらも既定値があるので設定は要らない。`.lan` が解決する先なので、関所自身のネットワークは自動で例外になる (#178)

## 0.2.35（2026-09-24）

### Enhancement

- イメージに入るエージェントガイドに `pr files` と `pr diff` の説明を足した。どちらも既存の `pr:read` で PR の差分を読む (#173)

## 0.2.34（2026-09-24）

### Enhancement

- ダッシュボードの権限一覧に `pr:comment_update` `pr:comment_delete` `issue:comment_update` `issue:comment_delete` を出し、`config.sample.yml` に説明を足した (#174)

## 0.2.33（2026-09-24）

### Enhancement

- `config.sample.yml` に `ci:dispatch` の説明を足した。まだ動いたことのないワークフローを起動するので `ci:rerun` とは別 (#168)
- ダッシュボードの権限一覧に `ci:dispatch` を出す。何を許すか決める人に見えないと意味がないため (#168)

## 0.2.32（2026-09-24）

### Enhancement

- `config.sample.yml` に `repos[].push` と新しい `project.branch` の説明を足した。push がどのブランチに着くかを決める設定 (#158)

## 0.2.31（2026-09-23）

### Fix

- mise がタスクの出力に接頭辞を付けるときも `gw:shell` がシェルを開く。`raw` にして `gw-tty` を通すようにし、端末から読むタスクには `raw = true` を CI が求める (#150)
- README の上流 proxy の資格情報の置き場所を、dev コンテナから読める `.env` から秘密ストア (`gw:proxy-credential`) に改めた (#152)
- `agent-setup.sh` が署名の設定を root 所有のファイルに書き、`~/.gitconfig` の最後で include する。Dev Containers 拡張がホストの `user.signingkey` を上書きしても署名が壊れない (#153)

## 0.2.30（2026-09-23）

### Fix

- `gw:keychain-set` が再び動く。mise が `${#stored}` をテンプレートのコメント開始と読んでタスクを拒否していた。タスク本文にテンプレート構文があれば CI が落ちるようにした (#147)
- `gateway.mise.*.toml` の冒頭の説明を、手でコピーする手順から `.devcontainer/sgw/` と `mise run upgrade:sync` に改めた (#147)

## 0.2.29（2026-09-21）

### Security

- `relay.signing_key` を設定すると、dev コンテナの commit を relay のフィルタ付き ssh-agent 経由で操作者自身の鍵で署名するようにした。`agent-setup.sh` は使い捨て署名鍵の生成をやめ、`SSH_AUTH_SOCK` をその socket に向ける (#136)

### Enhancement

- ホスト自身のシークレットストアからストアを解錠できるようにした。`gw:unlock-auto` が macOS Keychain / Secret Service / root 所有ファイルからパスフレーズを読み `unlock --stdin` に渡す (#135)
- その解錠を `gw:recreate` 自身が行うようにした。`SGW_NO_AUTO_UNLOCK=1` で施錠のままにできる (#135)
- パスフレーズをホストごとに一度保存する `gw:keychain-set` を足した (#135)

## 0.2.28（2026-09-21）

### Enhancement

- Python の依存を lock から、マニフェストは bind mount で入れるようにした。依存レイヤには版を知るものが何も残らない。`uv pip install .` がプロジェクト自身の版付き dist-info を書き込んでいた (#131)
- Dependabot アラートを関所経由で読む・却下する。`security alerts` / `view` は `security:read`、`dismiss` / `reopen` は `security:dismiss`。トークンに `security_events` scope が要るので `gw:login` をやり直す (#133)

## 0.2.27（2026-09-21）

### Security

- 署名付き tag オブジェクトでないタグの push を拒否した。軽量タグ、署名なし、push に含まれないもの。見るのは署名の有無で正しさではない。`signed_tags: false` で案件・上流・repo 単位に外せる (#128)

### Fix

- `uv.lock` に対する `pip-audit` を PR ごとに走らせた。`ci:py-audit` は一度も動いておらず workflow にも無く、`cargo audit` だけがリポジトリ全体の顔になっていた (#123)

### Enhancement

- Dependabot で RustCrypto の crate をグループにした。次の世代はビルドできない 2 本組ではなく 1 本の PR で来る (#125)
- Dependabot の版上げを取り込んだ。actions/checkout 7、upload/download-artifact、setup-python 7 (#112)、cargo-zigbuild 0.23.4 (#106)、russh 0.63.3、clap 4.6.7 (#107)、getrandom 0.4 (#110)、base64 0.23 (#111)

## 0.2.26（2026-09-21）

### Enhancement

- Python のバイトコードを一切持たず `PYTHONDONTWRITEBYTECODE=1` にした。`.pyc` はソースの mtime を含むので、それを持つレイヤはビルド毎にダイジェストが変わっていた。起動時に一度 360ms ほどかかる。#114 と、それが足した 3.5MB を取り消す (#121)

## 0.2.25（2026-09-21）

### Enhancement

- `uv pip install` に `--no-cache` を付けた。落とした wheel が全部イメージに入っていた。1,195 ファイル 44MB、二度とインストールしないコンテナに (#118)

## 0.2.24（2026-09-21）

### Fix

- バイトコードを、それをインストールした層でコンパイルするようにした。0.2.23 は最終層で全体を再コンパイルしており、全依存の `.pyc` の複製がそこに入っていた。その層は 294,752 → 10,668,514 バイトになっていた (#116)

## 0.2.23（2026-09-21）

### Enhancement

- apt が「ビルドした事実」を記録する7ファイル（machine-id 2つ、ログ4つ、キャッシュ1つ）を消した。160MB の層の 114 バイト差はこれが全部だった (#114)
- `.pyc` を `unchecked-hash` で作り直すようにした。ヘッダのソース mtime が、毎ビルド site-packages に新しい digest を与えていた (#114)

## 0.2.22（2026-09-21）

### Security

- 上流プロキシの資格情報を秘密ストアから読み、解錠後に Squid の設定を作り直すようにした。それまでは上流認証なしで動く (#105)
- `config.sample.yml` を訂正した。資格情報に環境変数を勧めていたが、ホストのシェルと `.devcontainer/.env` を区別していなかった。後者はエージェント自身の env_file (#105)

### Fix

- Dependabot の PR を `preview` の対象から外した。`permissions:` に何を書いても `GITHUB_TOKEN` が read-only なので、依存更新の PR が毎回「誰にも直せない赤」になる (#104)

### Enhancement

- Dependabot を actions / cargo / uv / docker / docker-compose に設定した。0.2.18 と 0.2.19 で入れた pin に、ようやく読み手ができた (#104)

## 0.2.21（2026-09-21）

### Enhancement

- リリースのビルドキャッシュを廃止した。書き出しに 3m38s かかり、節約できるビルド 2m16s より長いうえ、#97 のとおり誰も読んでいなかった (#101)
- 層の timestamp を固定の epoch に正規化した。同じバイトに焼き直した層は digest が変わらないので、リリースのたびに同じ中身を 160MB 引き直さなくなる (#101)

## 0.2.20（2026-09-21）

### Enhancement

- gateway 自身の `gw:*` mise タスクをイメージに同梱した。各プロジェクトは自分の `mise.toml` に複製せず include する (#95)
- `gw:revoke` を追加した。`mise run gw -- revoke --label …` でしか届かなかった (#95)
- 運用サブコマンドに漏れなくタスクがあること、英日で同じ集合であること、`sgw.sh` に無い原始的な口を要求しないことを CI で検査するようにした (#95)

## 0.2.19（2026-09-21）

### Security

- Debian アーカイブを `snapshot.debian.org` の時刻に、全パッケージを版に固定した。`apt-get update` はその日に Debian が配っているものを取っていた (#93)
- `dnsutils` ではなく `bind9-dnsutils` を指定するようにした。trixie に実体は無く、仮想名には固定する版が無い (#93)

### Enhancement

- Debian スナップショットが90日より古くなったらビルドを落とすようにした。更新の間、security 更新はイメージに入らない (#93)

## 0.2.18（2026-09-21）

### Security

- 全ての action を commit に、全てのベースイメージを digest に固定した。版はコメントとして残す (#87)

### Enhancement

- `test_supply_chain_pins.py` を追加した。後から浮いたタグを足すとエラーになる (#87)
- この変更履歴を relay のものから分けた。あちらが gateway 自身の変更も抱えていた (#88)
- README が版番号ではなく両方の変更履歴を指すようにした。書いてあった番号は7版ぶん古かった (#88)
