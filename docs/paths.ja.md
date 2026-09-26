# 経路台帳

*[English](paths.md)*

`docs/paths.yml` は、ゲートウェイが開く・管理するすべての接続をグラフとして列挙します。1 行が 1 本の辺です。
`tests/unit/test_paths.py` が NetworkX で読み込み、グラフ全体に対する規則を検査します。
2026-09-25 の不具合（#186, #190, #205, #212, #217, #220）はどれも「行が無い」か「属性が無い」ことが原因でした。
台帳はそれをテストの失敗に変えます。

## 行に書くこと

| 属性 | 答える問い |
|---|---|
| `from`, `to`, `via` | 誰が誰へ、どの中継を経て接続するか |
| `proto` | 線の上を何が流れるか |
| `resolves` | 名前をアドレスに変えるのは誰か |
| `verifies_peer` | 相手の身元を誰が何で確かめるか |
| `presents` | どの資格情報が線に乗るか、どこから来るか |
| `audit` | 記録がどこに残るか |
| `switches` | 辺の形を変える設定キー |
| `impl`, `tests` | 実装の場所と、それを覆うテスト（ファイルは実在すること） |
| `verify`, `check` | 実機で確かめる `relay:verify` の項目、または `check` の行 |
| `blocked_by` | 通っては**いけない**辺について、それを閉じるノード |
| `hops`, `tls_impl`, `interop` | 多段 SSH、使う TLS 実装、相互運用を証明する辺 |

`secrets` は資格情報ごとに、誰が持ち、どの辺が使い、どの辺から読めるかを書きます。

## テストが強制する規則

- すべての辺が必須属性を持ち、実在するノードと実在するファイルを指し、テストを最低 1 つ持つ
- `src/paths.py` と `relay/src/paths.rs` の id は台帳の id と一致する
- 関所が張る SSH の各ホップは、関所が所有する known_hosts で検証される（#220）
- `dev` から外部ノードへの経路は、必ず policy・proxy・relay のいずれかを通る。直接送出の辺は 1 本だけで `warned` を持つ。
  通ってはいけない辺は `blocked_by` と `verify` を持つ（#186, #190, #212）
- ゲートウェイが持つ秘密は、`dev` から始まる辺では読めない（#217）
- 同じ相手に 2 つの TLS 実装で届く場合は `interop` を書く（#205）

## 監査エントリは自分の辺を名乗る

接続を記録する audit.jsonl のエントリはすべて `edge=<id>` を持ちます（`Audit::log_edge` / `deny_edge` が書く）。
関所が書いてよい組は `relay/src/paths.rs` の `AUDIT_EVENTS` に列挙され、そこに無い組は debug ビルドで落ちます。
テストは、各辺の `audit` 属性がちょうどその event を挙げていることを確かめます。Web UI の relay タブは行ごとに id を出します。
接続を記録しないエントリ（トークンの発行、ストアの解錠）には辺がありません。

## 問い合わせる

```
uv run scripts/paths.py edges                        すべての辺
uv run scripts/paths.py edges -v --switch direct_egress
uv run scripts/paths.py edges --without verify       relay:verify が確かめていない辺
uv run scripts/paths.py paths dev internet           すべての経路と、その中継ノード
uv run scripts/paths.py secret upstream_proxy_password
uv run scripts/paths.py dot | dot -Tsvg > paths.svg  描く（Graphviz）
```

## 辺を追加する

1. `docs/paths.yml` に行を足す
2. `src/paths.py` か `relay/src/paths.rs` に id を足し、接続を開く場所でその定数を使う
3. 覆うテストを書く。実機で確かめる必要があれば `base/share/sgw/tasks.mise.*.toml` の `relay:verify` に項目を足す
4. `uv run pytest tests/unit/test_paths.py` を実行する
