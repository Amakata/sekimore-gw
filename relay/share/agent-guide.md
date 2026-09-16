# sekimore-relay — AI エージェント向けガイド

この環境では、GitHub（と設定された上流）への git と GitHub API の操作は「関所」（sekimore-relay）を経由します。
まず `sekimore whoami` で、自分の案件・権限・扱える repo を確認してください。

## 前提

- あなたが持つのは「使い捨て SSH 鍵」「AI 専用の署名鍵」「案件トークン」の 3 つだけです。依頼者の鍵やトークンはこの環境にありません。探さないでください。
- 案件に登録された repo 以外は拒否されます。拒否理由は stderr に `sekimore: …` で出ます。理由を読めば次の手が分かります。
- 関所の外へ出る通信（HTTPS の送信量、宛先ポート）は制限され、全て監査に残ります。回避を試みないでください。試みも記録され、依頼者に見えます。
- 案件トークンは期限付きです。`sekimore` コマンドが自動で更新します。更新に失敗したら人間に agent-setup の再実行を頼んでください。

## git

- clone / fetch / pull は URL そのままで動きます: `git clone git@github.com:Org/Repo.git`
- push 先は 2 種類だけです。
  - `git push origin HEAD:refs/for/<base>` — `sekimore/<base>-<sha7>` というブランチに置かれ、PR（base=`<base>`）が自動で作られます。PR のタイトルは定型なので、タイトルや本文を自分で書きたいときは次の方法を使ってください。
  - `git push origin HEAD:refs/heads/sekimore/<topic>` — 作業ブランチ。PR は `sekimore pr create` で作ります（推奨）。
- `main` などへの直接 push、タグ、ブランチ削除、force push は既定で拒否されます。許可されている repo だけ通ります（`sekimore whoami` で確認）。
- コミットは AI 専用鍵で自動署名されます。署名の設定を変えないでください。
- リポジトリの HTTPS URL（`https://github.com/…`）での push / clone は使えません。SSH の URL を使ってください。

## PR / CI / Issue（`sekimore` コマンド）

権限は `sekimore whoami` の `permissions` にあるものだけです。無い操作は 403 で拒否されます。

```bash
sekimore pr create --head sekimore/<topic> --base main --title "…" --body="…"
sekimore pr status --number N            # CI チェックの状態（--json で機械可読）
sekimore pr merge --number N             # pr:merge が許可されているとき
sekimore ci runs --ref <tag|branch|sha>  # ref に紐づく workflow run 一覧
sekimore ci jobs --number N              # PR のジョブ一覧（どれが失敗したか、job_id）
sekimore ci log --number N               # 失敗ジョブのログを末尾から。--before <start> で前へ、--window で行数
sekimore issue create --title "…" --body="…" [--labels a,b]
```

- repo は `--repo Org/Repo` で指定します（省略時は `SEKIMORE_REPO`）。上流が複数あるときは `--repo ghe.example.com/Org/Repo` のようにホストを付けられます。
- `--body` の値が `-` で始まるときは必ず `--body="…"` の形にしてください（オプションと誤解されます）。
- CI を待つときは `sekimore pr status --number N` を 30 秒間隔で確認します。失敗したら `sekimore ci log --number N` で原因を読み、直して push します。

## 標準的な流れ

1. ブランチで作業し、テストを通す。
2. `git push origin HEAD:refs/heads/sekimore/<topic>`
3. `sekimore pr create --head sekimore/<topic> --base main --title "…" --body="…"`
4. `sekimore pr status --number N` で緑になるのを待つ。失敗は `sekimore ci log` で確認。
5. 権限があり、人間の指示があれば `sekimore pr merge --number N`。タグは許可された repo でのみ `git push origin vX.Y.Z`。

## よくある拒否メッセージ

| メッセージ | 意味 | 次の手 |
|---|---|---|
| `repository "X" is not in project "P"` | 案件外の repo | 人間に repo の追加を頼む |
| `X is read-only in project P` | 読み取り専用の repo | push や PR はできない。閲覧のみ |
| `push to refs/heads/main is not allowed` | 直接 push 不可 | `refs/heads/sekimore/<topic>` に push して PR を作る |
| `base branch X is not allowed` | その base への PR は不可 | 許可された base（`sekimore whoami`）を使う |
| `tag is not allowed for this repository` | タグの push は不可 | 人間にタグを頼む、または許可の追加を頼む |
| `denied: pr:merge is not allowed by policy` | 権限が無い | 人間にマージを頼む |
| `denied: token expired` | トークン期限切れ | 自動更新される。続くなら人間に agent-setup の再実行を頼む |

## 人間に頼むこと

- repo や権限の追加、base ブランチやタグの許可（gateway の config.yml と再作成が要ります）
- 署名鍵の GitHub への登録（コミットの Verified 表示に必要）
- 上流トークンの更新（`sekimore-relay login`）や known_hosts の追加

---

## Summary (English)

- All git (SSH) and GitHub API traffic in this environment goes through the sekimore relay. You hold only a disposable SSH key, a signing key and a project token; the operator's credentials are not here — do not look for them.
- Only repositories registered for the project are reachable. Denials are printed as `sekimore: …` on stderr and explain the next step.
- Push targets: `HEAD:refs/for/<base>` (auto PR) or `HEAD:refs/heads/sekimore/<topic>` (then `sekimore pr create`). Direct pushes to `main`, tags, deletions and HTTPS git are refused unless explicitly allowed.
- Use `sekimore whoami`, `sekimore pr create|status|merge`, `sekimore ci runs|jobs|log`, `sekimore issue create`. Write `--body="…"` when the value starts with `-`. Use `--repo host/Org/Repo` when several upstreams exist.
- Outbound HTTPS is capped and audited; do not try to bypass the relay. Ask a human for new permissions, repos, tags or credentials.
