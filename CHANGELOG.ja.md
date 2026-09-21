# sekimore-gw 変更履歴

*[English](CHANGELOG.md)*

gateway 全体 — DNS、ファイアウォール、Squid、Web UI、ビルドと CI。
relay 自身の変更は [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) にある。
版番号は共通（1つのイメージに両方が入る）。

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

0.2.18 から始める。それ以前は relay の変更履歴にある。
両者を分けるまで、あちらが全体を抱えていた。

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
