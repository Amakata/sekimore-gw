# sekimore-gw 変更履歴

*[English](CHANGELOG.md)*

gateway のイメージ、その中の relay、dev コンテナの base イメージ、`sgw` バイナリは 1 つの版番号で出す。
だから変更履歴も 1 つ。各版に、4 つのどれで何が変わったかを書く。

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

base イメージは 0.2.45 まで独立したリポジトリで、版番号も別だった。その時期の履歴は
[base/CHANGELOG.ja.md](base/CHANGELOG.ja.md) にある。

## 0.2.49（2026-09-26）

### Fix

- `release edit` が draft の Release を見つけられるようにした。タグ引きは公開済みの Release しか返さないので、404 のときは Release 一覧に切り替える。workflow が作った draft は一覧には出る (#249)

### Enhancement

- sgw のコマンドを store / github / token / gw / dev のグループに分け、`--help` はグループごとに並べる。平らな名前は短縮形として残る。relay が出すヒントも mise のタスクではなく `sgw unlock` などを指す (#256)
- sgw down が dev コンテナも含めてスタック全体を `--remove-orphans` で落とす。何も動いていないときは `<folder>_devcontainer` と名指しする。「network … already exists」からの出口 (#250)
- sgw update が、gateway サービスの docker-compose.yml に `pid: host` が無いことを知らせる (#255)
- sgw open が出すヒントが mise のタスクではなく sgw のコマンドを指す (#253)
- README を読む人のために書き直した。7 手順で始める、設定とコマンド、Optional の節。base/README はイメージが抱えているものを書く (#248)
- gateway、relay、base、sgw で変更履歴を 1 つにした (#254)
- CI: 各 workflow は自分が読むファイルのときだけ走る。シェルのテストは base-tests.yml が持つ (#252)

## 0.2.48（2026-09-26）

### Enhancement

- sgw init: バイナリに埋め込んだプロジェクトの雛形を書き出す。sgw update はその雛形からプロジェクトを最新に保つ（旧 upgrade.sh。もうタグから取ってこない） (#241)
- README: sgw で始める手順、config.yml の各設定が何をするか、どの sgw コマンドが何をするか、DevContainer が立ち上がらないときに何が起きているか (#243)
- macOS arm64 と Linux 向けの sgw バイナリが再び Release に載る。クレートが macOS でコンパイルできるようになり（O_PATH は Linux だけのもの）、CI が pull request ごとにそのビルドを確認する (#244)
- README: プロキシのパスワードの行を Get started の下ではなくプロキシの設定のところに移した (#245)

## 0.2.47（2026-09-26）

### Enhancement

- ホスト側の運用者の道具 sgw を relay クレートの 2 つめのバイナリとして足した。gw:* / relay:* / dev:* の各タスクをサブコマンドにし、端末はホスト側で判断し、パスフレーズは stdin からだけ受け取る (#238)
- sgw verify: 受け入れ確認を Rust で書いた。各項目が経路台帳のどの行を見ているか、どの対象に当てはまるかを示す (#240)
- リリース成果物: macOS arm64 と Linux x86_64 / arm64 の sgw を install.sh と一緒に、タグの workflow が draft の Release に添える (#239)

## 0.2.46（2026-09-26）

### Enhancement

- リポジトリを 1 つに: sgw-devcontainer-base は `base/` に入り、そのイメージは同じタグから、この版番号で作って公開する。`UPGRADING.md` と `RELEASING.md` は最上位に置く (#236)
- `tests/unit/test_base_versions.py` が `base/` 配下に書かれた版をすべて `pyproject.toml` の版に揃える。base 側の版を対にする 4 本のテストと「take」の手順は無くなった (#236)
- `base/` も他と同じ Apache-2.0 にした。独立リポジトリのときは MIT だった (#236)

## 0.2.45（2026-09-25）

### Enhancement

- relay: login が device flow の前に必要なホスト鍵（まず踏み台、次にそれ越しの上流）を取り、保存できなかったときは非ゼロで終了するようにした。yes/no はバイト列として読み、その文字で判定する (#230)
- `gw:login` と `gw:logout` を `gw:unlock` と同じく `sgw.sh gw-tty` 上の `raw = true` のタスクにした。端末が無いと、答えが文字でないバイト列として届いていた (#230)
- relay: 接続を記録する監査の各行が `docs/paths.yml` の `edge=<id>` を持つようにした。`paths::AUDIT_EVENTS` が組を並べ、経路台帳のテストが検査し、relay タブが id を表示する (#228)
- `relay/README` に、`keyscan` が fingerprint を表示してから保存する理由と、`login` が先に尋ねる理由を書いた (#230)

## 0.2.44（2026-09-25）

### Security

- ProxyJump の各ホップを上流の known_hosts で `StrictHostKeyChecking yes` として検証するようにした。強制する設定は生成した ssh_config に置き `-F` で渡す。OpenSSH は踏み台への ssh にもこれを渡すので、鍵の無い踏み台は keyscan の案内を出して閉じる方向で失敗する (#220)

### Enhancement

- 経路台帳 `docs/paths.yml` を足した。接続の各辺について、誰が名前を解決し、誰が相手を検証し、何を提示し、どこに記録が残るかを書く。`tests/unit/test_paths.py` がグラフとして検査し、id は `src/paths.py` と `relay/src/paths.rs` にある (#223)
- README からゲートウェイ単体の構成を消した。入口は dev コンテナである (#226)
- `keyscan` と `login` が、ProxyJump の踏み台の先にある上流のホスト鍵を踏み台経由で取るようにした。鍵の種類ごとに1接続。`login` は先に不足している踏み台の鍵を、fingerprint を見せて yes/no で取る (#221)

## 0.2.43（2026-09-25）

### Security

- `/api/config` の上流プロキシのパスワードを伏せた。`squid.config_text` が生成後の squid.conf を `login=<user>:<password>` ごと dev に返していた。今は `***`。更新後にパスワードを変えること (#218)
- `/api/domains` の認証の無い `POST` / `DELETE` のスタブを消した。何も変えないもので、呼ぶものも無かった (#218)

## 0.2.42（2026-09-25）

### Security

- dev の通信のうち上流プロキシを通るのは関所の handler 経路と明示プロキシのクライアントだけだった。`proxy.direct_egress: deny` を足し、`allow_domains` のアドレスをファイアウォールに入れず Squid だけを出口にできるようにした。既定の `allow` は起動時に WARN を出す (#215)

### Enhancement

- dev コンテナに `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` を渡すようにした。`GET /api/proxy-env` と agent-setup 経由で、`NO_PROXY` は `domain_handlers` と運用者の `proxy.no_proxy` から組み立てる (#215)
- 運用者向けコマンドのエラー行を端末では赤にした。`proxy-credential set` が出すストアの拒否文も同じ。エージェント向けのサブコマンドは素のまま (#214)

## 0.2.41（2026-09-25）

### Fix

- 上流プロキシが TLS のとき、関所の HTTPS を同じコンテナの Squid 経由にした。rustls に無い RSA 鍵交換しか出さないプロキシでも通る。Squid には `relay_localhost` の許可を、宛先の拒否より下、関所ドメインの拒否より上に入れる (#210)
- `store-status` を状態語 1 つに戻した。0.2.39 でその下に足した資格情報の行が、解錠済みのストアで `relay:verify` を落としていた (#209)

### Enhancement

- `check` が上流プロキシに実際に接続して経路と結果を出すようにした。`HandshakeFailure` のときはプロキシが出すべきものを言う。診断用に `openssl` CLI をイメージに入れた (#207)

## 0.2.40（2026-09-25）

### Enhancement

- 端末では `check` と `store-status` の状態語に色を付ける。ok は緑、locked / missing / none は赤、環境変数由来の資格情報は黄。`NO_COLOR` と `SEKIMORE_COLOR` で切り替えられる (#203)

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
- `pr comments` がレビューと、そのとき出された行コメントをまとめて表示する。返信できるものには id が付く (#165)
- `pr reply --comment-id C` が行コメントにその場で返信する。権限は `pr:comment` (#165)
- `pr review --comment path:line:body` が差分の行に指摘を残せる。JSON で渡す `--comments-file` もある (#167)
- `pr create --draft` と `pr ready` / `pr draft`。誰かに見てもらう前に CI だけ回せる (#169)

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
- 同じ pack 内の別のコミットに対するコミットの delta を適用するようにした。`signing: required` で署名つきコミット 2 つの push が通る。判定するのは適用した結果 (#144)
- 保持できないコミット (1 MiB 超、または pack あたり 64 MiB 超) に対する delta は引き続き拒否し、案内を `--no-thin` から `git -c pack.window=0 push` に改めた (#144)
- `whoami` が各 repo の行に、その repo の allow / deny がプロジェクトの権限に足すもの・外すものを `+x` / `-x` で示す (#146)

## 0.2.29（2026-09-21）

### Security

- `relay.signing_key` を設定すると、dev コンテナの commit を relay のフィルタ付き ssh-agent 経由で操作者自身の鍵で署名するようにした。`agent-setup.sh` は使い捨て署名鍵の生成をやめ、`SSH_AUTH_SOCK` をその socket に向ける (#136)
- `signing: required` の push で、持ち込む commit に署名の無いものがあれば拒否するようにした。delta で届く commit や pack に無い commit は上流 API で確かめ、分からなければ拒否に倒す (#137)

### Enhancement

- ホスト自身のシークレットストアからストアを解錠できるようにした。`gw:unlock-auto` が macOS Keychain / Secret Service / root 所有ファイルからパスフレーズを読み `unlock --stdin` に渡す (#135)
- その解錠を `gw:recreate` 自身が行うようにした。`SGW_NO_AUTO_UNLOCK=1` で施錠のままにできる (#135)
- パスフレーズをホストごとに一度保存する `gw:keychain-set` を足した (#135)
- `signing: required | optional | off` を案件 / 上流 / repo で設定できるようにした。既定は `optional`。`whoami` と書き出すガイドは `required` のときだけ言及する (#137)

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
- RustCrypto 0.11 世代に移った。sha2 0.11、hmac 0.13、aes-gcm 0.11、argon2 0.6。russh の 0.11 と並んで抱えていた 0.10 系のツリーが消えた (#129)

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

### Fix

- Projects のボード解決を起動時から初回リクエスト時へ移した。解決には上流トークンが要り、0.2.19 以降それは施錠されたストアの中なので、全ボードがプロセスの寿命の間ずっと拒否されていた (#100)
- 解決できなかったボードを記憶しないようにした。再起動せずに解錠だけで直る (#100)
- 宣言済みだが解決できない、と言うようにした。以前は「未設定」と言い、既にある設定ファイルへ誘導していた (#100)

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
- 上流 API トークンを秘密ストアに封じた。0600 のファイルでは、volume の複製やバックアップが平文のまま持ち出す (#92)
- 上流が既に広告している `refs/tags/*` を動かす push を拒否するようにした。削除を拒否するのと同じ `delete` 権限の下 (#91)
- 施錠をトークンのキャッシュにも伝えるようにした。`lock` してもキャッシュ TTL の間は復号済みトークンが使えていた (#92)

### Fix

- `login` が device flow を始める前にストアが書けるか確かめるようにした。承認済みの認可を捨てなくなった (#92)
- 開けなかったストアを `Locked` として報告するのをやめた。パスフレーズでは解決しないのに解錠へ誘導していた (#92)

### Enhancement

- Debian スナップショットが90日より古くなったらビルドを落とすようにした。更新の間、security 更新はイメージに入らない (#93)
- 制御ソケットに `get` / `set` / `delete` / `list` を追加した。`not_found` と `locked` は文章ではなくコードで返す (#92)
- 0.2.18 以前の `upstream_token` ファイルを、最初に読んだときストアへ移して削除するようにした (#92)

## 0.2.18（2026-09-21）

### Security

- 全ての action を commit に、全てのベースイメージを digest に固定した。版はコメントとして残す (#87)
- 制御ソケットの読み込みを 8 MiB で打ち切るようにした。`import` が初めて小さくないリクエスト (#86)
- `prompt` が解放済みバッファにパスフレーズを残すのをやめ、リクエスト行も clear ではなく 0 埋めするようにした (#84)

### Fix

- パスフレーズの打ち間違いに、いま実行中の `mise run gw:unlock` ではなく、何が失敗したかを答えるようにした (#84)
- `prompt` を `TCSAFLUSH` にした。プロンプト表示前に打った字がパスフレーズに混ざらなくなった (#84)
- `passphrase` に違う旧パスフレーズを渡したとき「何も変えていない」と言うようにした (#84)

### Enhancement

- `test_supply_chain_pins.py` を追加した。後から浮いたタグを足すとエラーになる (#87)
- この変更履歴を relay のものから分けた。あちらが gateway 自身の変更も抱えていた (#88)
- README が版番号ではなく両方の変更履歴を指すようにした。書いてあった番号は7版ぶん古かった (#88)
- CLI と制御ソケットに `store-export` / `store-import` を追加した。0.2.17 はストアの `export` / `import` を実行する手段なしに出していた (#86)
- この changelog の全25リリースを、Security / Fix / Enhancement の下に1行ずつ、末尾に PR 番号を置く形に書き直した (#85)

## 0.2.17（2026-09-21）

### Security

- レコード集合を MAC で封じ、解錠時に検査するようにした。抜かれた・他ストアから継がれたレコードに気づける (#77)
- 全 PR で `pip-audit` を走らせ、Python 6 パッケージ 29 件の勧告を解消した (#80)

### Fix

- Python のテストジョブが自前のタイムアウト kill を成功として読むのをやめた。0.2.15 から落ち続けていたテストがあった (#80)
- `dashboard.html` に `pr:label` / `pr:assign` / `issue:update` を追加した (#80)

### Enhancement

- 秘密ストアの `export` / `import` を追加した。封じたまま、施錠中でもバックアップが取れる (#77)
- 無人解錠の `relay.store.unlock: file` / `env` を追加した。どちらもパスフレーズを保存するので起動時に警告する (#78)
- `COPY src/` を `uv pip install` の下へ移した。1行の編集で site-packages を作り直さなくなった (#79)

## 0.2.16（2026-09-21）

### Fix

- 制御ソケットに `init` を追加した。パスフレーズの無いストアに `mise run gw:unlock` で設定できる (#73)
- stdin が端末でないときの文言を「端末で実行せよ」から「パイプするな」に変えた (#73)

## 0.2.15（2026-09-21）

### Security

- 番号が PR を指すとき `issue` の書き込みに `pr:*` を要求するようにした。`pr:label` / `pr:assign` を新設 (#67)

### Fix

- 設定リロードを gateway のイベントループへ載せ、ファイアウォールの規則変更と交錯しないようにした (#66)
- `domain_handlers` が中継するドメインを `allow_domains` が覆っていない設定を、起動時に名指しで拒否するようにした (#65)

### Enhancement

- 秘密ストアを追加した。専用ファイルの SQLite、値ごとに AES-256-GCM、レコードの識別子を AAD に使う (#70)
- `unlock` / `lock` / `store-status` / `passphrase` を、relay の状態の隣の unix ソケット経由で追加した (#71)
- `project` 系に `--board 2` を追加した。`config.yml` と URL が既に使っている番号 (#64)
- `project list` が各 item のフィールド値を返すようにした。`update-item` で書いた値を読み戻せる (#64)
- `issue update --number N [--title …] [--body …]` を新しい `issue:update` の下に追加した (#69)
- PR と `main` への push で `:pr-<n>` / `:main` の arm64 イメージを作るようにした。版を消費せず試せる (#63)

## 0.2.14（2026-09-18）

### Fix

- リロードを跨いで `allow_ips` / `block_ips` を保つようにした。ipset が `allow_domains` だけから作り直されていた (#56)
- 古い状態を流す前に Squid の設定を生成するようにした。生成に失敗して両方失うことがなくなった (#56)
- リロードの判定が `proxy` ブロックも比較するようにした。`proxy.enabled` が再起動まで固定だった (#56)
- `issue view` / `pr view` に `node_id` を追加した。既存の issue もボードに載せられる (#56)

## 0.2.13（2026-09-18）

### Security

- 常時有効だった設定リロードを `reload: auto | manual | <duration>` にした。開け直せるのは gateway の中からだけ (#49)
- PR の head を push と同じ glob で検査するようにした。fork 経由で未検査のコードを持ち込めなくなった (#49)
- 起動時の allow ipset を `domain_handlers` も見て作るようにした。上流の実アドレスへ直接到達できなくなった (#49)
- ドメイン比較をラベル境界で行うようにした。`.debian.org` が `evildebian.org` を覆わなくなった (#49)
- SNI の無い TLS 接続に、既定ではなく最も厳しい送信上限を当てるようにした (#49)

### Fix

- 1回の push が上流の同じ ref を2回更新するとき、report-status がどの ref の結果か言えるようにした (#49)
- リロード判定の relay セクションのモデルを広げた。4キーしか持たず、ほとんどの変更を無変更と読んでいた (#49)
- `truncate()` が `str` を1バイトずつ切っていたのを直した。日本語のラベル名でタスクが panic していた (#49)
- 運用コマンドがどこで走るかを明示し、docker bridge 内のプロキシに対する login のタイムアウトを起動時に名指しするようにした (#49)
- `domain_handlers` の綴り違いを拒否し、31文字に切られた ipset 名の衝突をなくした (#49)
- その他: `merged` 欠落が true と読まれる、`repo vocabulary` が読み取り失敗を「ラベル無し」と答える、アイドルタイムアウトが 0 バイトと記録する、SSH のセッションチャネルが解放されない、`glob_match` が指数的にバックトラックする (#49)

### Enhancement

- `python -m src.maint reload-follow 30m` / `reload-freeze` / `reload-status` を追加した (#49)

## 0.2.12（2026-09-18）

### Security

- 生成する `squid.conf` で relay 自身のドメインを拒否するようにした。Squid は Docker の DNS で解決するため、`https_proxy=<gateway>:3128` を設定した者に `github.com` を出していた (#48)
- 拒否するドメインを1つずつ名指しにした。`.github.com` は api.github.com と codeload.github.com を通し続ける (#48)

### Fix

- 起動・リロード・再起動のすべてで拒否を適用し、リロードでは新旧どちらの handler 集合も拒否するようにした (#48)
- それを含むワイルドカードと並ぶ名前を除いた。`deb.debian.org` と `.debian.org` の併記は Squid には FATAL (#48)
- 拒否規則を、それ以前のテンプレートにも挿入するようにした。置き場所が分からないテンプレートは生成を失敗させる (#48)

## 0.2.11（2026-09-17）

### Enhancement

- `cli/agent.rs`（948行）を `cli/agent/` に分割した。clap の木、ディスパッチ、表示、HTTP クライアント (#47)
- 各エンドポイントのパスをフラグの隣で宣言するようにした。パスの無いサブコマンドはコンパイルが通らない (#47)
- `api/handlers.rs` の繰り返しの前置きを3つのスコープヘルパに畳んだ。約150行 (#47)
- コマンド・フラグ・エンドポイント・権限・メッセージは変えていない。47枚のヘルプは両言語ともバイト一致 (#47)

## 0.2.10（2026-09-17）

### Fix

- `SEKIMORE_WEB_HOST` / `SEKIMORE_WEB_PORT` / `SEKIMORE_ULOG_PATH` を実際に読むようにした。誰も使わない定数に入れていた (#46)
- `ULOG_FILE_PATH` の既定を、ulogd が書く `firewall.log` にした。`syslogemu.log` になっていた (#46)

### Enhancement

- `login` が `proxy.upstream_proxy` 経由か直接かを言うようにした (#46)
- 未使用の依存5件を削除した: `thiserror` / `http` / `pydantic-settings` / `python-json-logger` / `jinja2` (#46)
- 呼び出しの無い Rust 関数7つ、`bootstrap` サブコマンド、`bootstrap status`、Python の定義4つを削除した (#46)

## 0.2.9（2026-09-17）

### Fix

- `pr merge` が本文を送るようにした。squash のみのリポジトリが空の本文を 405 で弾いていた (#45)
- `repo:read` を検査するようにした。宣言だけされてどこでも検査されていなかった (#45)

### Enhancement

- `pr merge` に `--method merge|squash|rebase` / `--title` / `--message` / `--delete-branch` を追加した (#45)
- `pr reopen` / `issue reopen` / `issue unlabel` / `issue unassign` / `pr update --title/--body/--base` を追加した (#45)
- `release edit` を追加した。draft を published にするには新しい `release:publish` が要る (#45)
- `ci rerun --run-id N [--all]` と `ci cancel` を新しい `ci:rerun` の下に追加した。`ci:read` ではない (#45)
- `repo vocabulary` を追加した。ラベル、担当にできる人、open なマイルストーン (#45)
- changelog の形式を CI で検査するようにした。行の長さ、日付のみの見出し、両言語の歩調 (#45)

## 0.2.8（2026-09-17）

### Enhancement

- `pr view` / `pr comments` / `pr list` と `issue view` / `issue comments` / `issue list` を追加した (#43)
- `pr comments` が会話・レビュー判定・行コメントを1つの並びに統合するようにした。古い順 (#43)
- `search "is:open label:bug"` を案件横断で追加した。`repo:` で絞り、結果ごとに再検査する (#43)
- `issue:read` と `search:read` を新設した (#43)
- コメント本文は指示ではなくデータだとガイドに書いた (#43)

## 0.2.7（2026-09-17）

### Security

- パスセグメントで `/` と `.` を percent-encode するようにした。細工した tag や CI ref が運用者のトークンで別リポジトリを読めた。0.1.7 から到達可能 (#40)
- Projects v2 のボードを `relay.project.boards` で宣言し起動時に解決するようにした。**破壊的変更**、空なら全 Projects 呼び出しを拒否 (#42)
- `dns_server.py` が `git-relay` としか比較していなかったのを直した。`github` と書いたドメインが relay に届かなかった (#39)

### Fix

- `find_pull_request` が `pr:read` を受け付けるようにした。読み取りに `pr:create` を要求していた (#41)
- force push を拒否するというガイドの記述を訂正した。拒否するのは上流のブランチ保護 (#41)

### Enhancement

- `pr request-review --reviewers alice,bob [--teams t]` を新しい `pr:request_review` の下に追加した (#41)
- `project fields` を追加した。ボードのフィールドと single-select の option id。`update-item` に要る (#42)

## 0.2.6（2026-09-16）

### Enhancement

- `release create --tag vX.Y.Z [--title T] [--notes … | --notes-file F] [--draft] [--prerelease]` と `release view` / `release list` を追加した (#38)
- 本文を渡さなければ、前のタグ以降の PR から GitHub が書くようにした (#38)
- `release:create` と `release:read` を新設した (#38)
- `handler: git-relay` を `handler: github` に改名した。`gitlab` / `gitea` の余地を残す (#38)
- `git-relay` は Rust 側・Python 側とも別名として残した (#38)

## 0.2.5（2026-09-16）

### Fix

- `relay/locales` を Docker の builder ステージへコピーするようにした。これが無く v0.2.4 のイメージは公開されなかった (#36)

## 0.2.4（2026-09-16）

### Enhancement

- Web UI の文言を `src/locales/{en,ja}.json` へ移した。`?lang=` → cookie → `ui.language` → `Accept-Language` → 英語 の順で解決 (#33)
- `python -m src.maint` が `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` に従うようにした (#33)
- Rust CLI のヘルプと運用者向け出力を `relay/locales/{en,ja}.json` へ移した。欠けたキーは英語、次にキー名 (#34)
- `guide --lang en|ja` を追加した。`agent-guide.{en,ja}.md`、agent-setup が書くものは `SEKIMORE_GUIDE_LANG` (#34)
- README と CHANGELOG を英語正本にし、`README.ja.md` / `CHANGELOG.ja.md` を置いた (#34)
- 拒否理由（`sekimore: …`）と監査ログは英語のままにした (#34)

## 0.2.3（2026-09-16）

### Enhancement

- Web UI の行ごとの push を、rowid カーソルを進める1つのポーラに置き換えた。新着をまとめて1メッセージで送る (#32)
- `/api/stats` を新着後に最短3秒間隔で取るようにした。ログ行ごとではなくなった (#32)
- SQLite を `journal_mode=WAL` / `synchronous=NORMAL` / `busy_timeout` にし、`dns_queries(timestamp)` と `(status, timestamp)` に索引を張った (#32)
- `python -m src.maint db-stats | db-prune | db-reset | db-vacuum` を追加した。記録は自動では消さない (#32)
- 上流が1つでも Relay タブに送信上限を表示するようにした (#32)

## 0.2.2（2026-09-16）

### Security

- 443 passthrough の dev → 上流の送信に上限を付けた（`relay.https_max_upload_bytes`、既定 1 MiB、`-1` で無効）。超えた接続は切る (#30)
- `network.allowed_ports` を追加した。許可ドメイン・IP に届く宛先ポートを絞る (#30)

### Enhancement

- `handler: https-relay` を追加した。443 のみを通し、宛先ごとの `max_upload_bytes` を当てる (#30)
- Web UI に宛先ごとの上限、LARGE UPLOAD の印、24時間の件数を追加した (#30)
- `sekimore guide` を追加した。agent-setup が Claude Code のスキルと Codex CLI の `AGENTS.md` に置く (#31)

## 0.2.1（2026-09-16）

### Enhancement

- `project.upstreams.<domain>` を追加した。案件の既定と repos の間に入る上流ごとの層 (#27)
- `ssh_options` を追加した。上流の ssh に `-o` で渡す。relay が強制する項目は上書きできない (#28)
- 上流ごとの `api_base` / `graphql_base` を追加した (#28)
- `keyscan` を追加した。上流や踏み台のホスト鍵を known_hosts に入れ、指紋を表示する (#28)
- Web UI に上流ごとの `ssh_options` / `api_base` を表示し、`ssh_port` の変更を要再起動と判定するようにした (#28)

## 0.2.0（2026-09-16）

### Enhancement

- `domain_handlers` に git-relay を複数書けるようにした。上流ごとに待ち受けポートを分ける (#24)
- `repos[].name` が `host/Org/Repo` を受けるようにした。接続が来た上流に属する repos だけを見る (#24)
- 443 passthrough が TLS の SNI で上流を選ぶようにした (#25)
- `login` / `logout` / `whoami` に `--upstream` を追加した。状態は `/data/relay/upstreams/<host>/` (#25)
- `/bootstrap` が `git_domains` を返すようにした。agent-setup が上流ごとに `Host` と known_hosts を書く (#25)
- Web UI の Relay タブに上流一覧を出した (#26)

## 0.1.9（2026-09-16）

### Enhancement

- 権限を `project` の下にまとめた。`permissions` は `[…]` か `{allow, deny}`、加えて `push` / `tags` / `delete` (#23)
- `repos[]` が `tags` / `delete` / `permissions` を差分で上書きできるようにした (#23)
- `relay.allow_tags` / `relay.allow_delete` を非推奨にした。読みはするが警告付きで既定に畳む (#23)

## 0.1.8（2026-09-16）

### Enhancement

- `ci jobs --number` が PR の全ワークフロー実行をまとめるようにした (#22)
- Docker Publish を `provenance: false` にした (#22)

## 0.1.7（2026-09-16）

### Enhancement

- `ci runs --ref <tag|branch|sha>` と、`ci jobs` / `ci log` の `--run-id` を追加した (#19)
- Docker Publish をアーキごとのネイティブランナーに並列化した。0.1.6 は公開に失敗し飛ばした (#17)

## 0.1.5（2026-09-15）

### Enhancement

- `relay.allow_tags` を追加した (#16)
- `ci:read` と `ci jobs` / `ci log` を追加した。GitHub Actions の失敗ログを末尾から読む (#16)

## 0.1.4（2026-09-15）

### Fix

- Web UI の Relay タブの API が実プロセスで 404 を返すのを直した (#15)

## 0.1.3（2026-09-15）

### Security

- 監査の漏れを塞いだ: tcpip-forward、Authorization 欠落、不正な本文 (#14)
- 同じ鍵での再 bootstrap で前のトークンを失効させ、期限切れ7日後にトークン記録を掃除するようにした (#14)
- dev 側の HTTPS git で credential helper と GIT_ASKPASS を無効にした。運用者の資格情報で relay を迂回できなくなった (#14)

### Fix

- `proxy.enabled` を尊重し、認証バナーを外し、拒否した push を report-status で `ng` と返すようにした (#14)

### Enhancement

- Web UI の Relay タブ、`pr status`（`pr:read`）、署名鍵のコメントに案件名とユーザ名を追加した (#14)

## 0.1.0 〜 0.1.2（2026-09-08 〜 13）

### Enhancement

- 最初のリリース。SSH（git）と GitHub API の中継、案件ポリシー、`refs/for/<base>` からの PR 作成、bootstrap、443 passthrough、devcontainer base への同梱 (#11)
