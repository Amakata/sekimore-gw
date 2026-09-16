# sekimore-relay 変更履歴

各版の設計判断と詳細は workspace リポジトリの
[doc/sekimore-gw/design/relay.md](https://github.com/Amakata/sgw-devcontainer/blob/main/doc/sekimore-gw/design/relay.md) にあります。

## 0.2.2（未リリース）

- 持ち出し対策: 443 passthrough に dev → 上流の送信上限（`relay.https_max_upload_bytes`、既定 1 MiB、`-1` で無制限）。超えた接続は切断して監査 `https_upload_capped`
- `handler: https-relay`: 443 だけを関所の passthrough で通し、宛先ごとに `max_upload_bytes` を掛ける（自分で image を push する宛先は `-1`）
- `network.allowed_ports`（sekimore-gw 本体）: 許可ドメイン / 許可 IP へ通す宛先ポートを絞る。未設定は従来どおり全ポート
- Web UI: 宛先ごとの上限、1 MiB 以上を送った passthrough 接続に LARGE UPLOAD、24 時間の件数（大きな送信 / 上限超過）
- `sekimore guide`: AI エージェント向けの使い方（CLI に埋め込み）。agent-setup が Claude Code の skill と Codex CLI の `AGENTS.md` ブロックとして置く（`SEKIMORE_AGENT_INSTRUCTIONS`）

## 0.2.1（2026-09-16）

- `project.upstreams.<domain>`: 案件既定と repo の間に上流ごとの層（`permissions` の差分、`push` / `tags` / `delete` の既定、`repos`）
- `domain_handlers.<domain>.ssh_options` / `relay.ssh_options`: 上流 ssh に `-o` で渡す（踏み台の `ProxyJump=` など）。関所が強制するオプションは上書き不可
- `domain_handlers.<domain>.api_base` / `graphql_base`: 上流ごとの API の宛先
- `sekimore-relay keyscan`: 上流や踏み台のホスト鍵を fingerprint 表示付きで known_hosts に追加
- Web UI: 上流ごとの `ssh_options` と `api_base`。orchestrator は `ssh_port` の変更も再起動要と判定

## 0.2.0（2026-09-16）

- 複数上流: `domain_handlers` に git-relay を複数書ける。上流ごとに別ポートで listen し、接続を受けたポートで上流を決める
- `repos[].name` に `host/Org/Repo`。SSH 経路は接続を受けた上流の repo だけを探す
- 443 passthrough は TLS の SNI で上流を選ぶ
- `login` / `logout` / `whoami --upstream`。既定以外の上流の state は `/data/relay/upstreams/<host>/`
- `/bootstrap` が `git_domains` を返し、agent-setup が上流ごとに `Host` ブロックと known_hosts を書く
- Web UI Relay タブに上流の一覧

## 0.1.9（2026-09-16）

- 権限を `project` 配下に集約: `permissions` は `[…]` か `{allow, deny}`（deny が勝つ）、`push` / `tags`（glob）/ `delete`
- `repos[]` で `tags` / `delete` / `permissions`（差分）を上書き
- 旧 `relay.allow_tags` / `relay.allow_delete` は非推奨（読めば既定に畳み込んで警告）

## 0.1.8（2026-09-16）

- `ci jobs --number` が PR の全 workflow run を集約
- Docker Publish の `provenance: false`

## 0.1.7（2026-09-16）

- `ci runs --ref <tag|branch|sha>`、`ci jobs` / `ci log` の `--run-id`
- Docker Publish をアーキごとの native runner で並列化（0.1.6 は公開に失敗し欠番）

## 0.1.5（2026-09-15）

- `relay.allow_tags`
- `ci:read`: `ci jobs` / `ci log`（GitHub Actions の失敗ログを末尾から）

## 0.1.4（2026-09-15）

- Web UI Relay タブの API が実プロセスで 404 になる問題を修正

## 0.1.3（2026-09-15）

- `proxy.enabled` を見る。認証バナーの廃止。拒否した push を report-status の `ng` で返す
- 監査の抜け（tcpip-forward、Authorization 無し、不正 body）を記録
- 同じ鍵での再 bootstrap は前のトークンを失効。期限切れ 7 日後にレコードを掃除
- Web UI Relay タブ。署名鍵のコメントに案件名と利用者名
- `pr status`（`pr:read`）。HTTPS git の credential helper と GIT_ASKPASS を dev 側で無効化（依頼者の認証の迂回を防ぐ）

## 0.1.0 〜 0.1.2（2026-09-08 〜 13）

- 初版。SSH（git）と GitHub API の中継、案件ポリシー、`refs/for/<base>` から PR 作成、bootstrap、443 passthrough、devcontainer base への同梱
