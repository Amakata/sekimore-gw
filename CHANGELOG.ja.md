# sekimore-gw 変更履歴

*[English](CHANGELOG.md)*

gateway 全体 — DNS、ファイアウォール、Squid、Web UI、ビルドと CI。
relay 自身の変更は [relay/CHANGELOG.ja.md](relay/CHANGELOG.ja.md) にある。
版番号は共通（1つのイメージに両方が入る）。

**Security** / **Fix** / **Enhancement** に分け、重いものから並べる。
各行は何が変わったかと、変えた PR だけを書く。理由は PR にある。

0.2.18 から始める。それ以前は relay の変更履歴にある。
両者を分けるまで、あちらが全体を抱えていた。

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
