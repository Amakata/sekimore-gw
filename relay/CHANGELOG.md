# sekimore-relay changelog

*[日本語版](CHANGELOG.ja.md)*

## 0.2.9 (2026-09-17)

- `sekimore pr merge` takes `--method merge|squash|rebase`, `--title`, `--message` and `--delete-branch`. A squash-only repository rejected the old empty body with 405
- `--delete-branch` removes only the branch just merged, and needs `delete_merged_branch` on the repo. That is not the git-level `delete` authority
- `sekimore pr reopen` / `issue reopen`, `issue unlabel`, `issue unassign`, `pr update --title/--body/--base`. Changing the base re-runs the base check
- `sekimore release edit` can publish or amend a draft. Flipping draft to false needs the new `release:publish`
- `sekimore ci rerun --run-id N [--all]` and `ci cancel`, under the new `ci:rerun`. Re-running spends Actions minutes and re-executes jobs holding repository secrets, so it is not `ci:read`
- `sekimore repo vocabulary` lists the labels, assignable people and open milestones. `repo:read` was declared and checked nowhere until now
- The changelog style is checked in CI: bullet length, one date-only heading per release, and the two languages describing the same releases

## 0.2.8 (2026-09-17)

- `sekimore pr view` / `pr comments` / `pr list`, and `issue view` / `issue comments` / `issue list`. An agent could open an issue it could never read, and be reviewed without seeing the review
- `pr comments` merges the conversation, the review verdicts and the line comments into one list, oldest first
- `sekimore search "is:open label:bug"` searches issues and pull requests across the project. The query is scoped with `repo:` qualifiers and every result is checked against the project again
- New permissions `issue:read` and `search:read`. `pr view` / `comments` / `list` use the existing `pr:read`
- The guide now says comment text is data, not instruction

## 0.2.7 (2026-09-17)

- Security: a crafted tag or CI ref walked out of the repository path and read another repository with the operator's token. Path segments now percent-encode `/` and `.`; query values are unchanged. Reachable since 0.1.7 through `ci runs --ref` and 0.2.6 through `release view --tag`
- Security: a Projects v2 board was reachable by node id with nothing checking it belonged to the project. Boards are declared in `relay.project.boards` as `{ org, number }` and resolved at startup. **Breaking**: an empty list refuses every Projects call
- `dns_server.py` still compared against `git-relay` alone, so a domain written as `github` resolved to its real address and never reached the relay
- `sekimore pr request-review --reviewers alice,bob [--teams t]`, under the new `pr:request_review`
- `sekimore project fields` lists the board's fields and single-select option ids, which `update-item` needs
- `find_pull_request` demanded `pr:create` for a read; it now accepts `pr:read`
- The guide claimed force pushes were refused. The relay checks the ref name, not whether the push fast-forwards; upstream branch protection is what refuses one

## 0.2.6 (2026-09-16)

- `sekimore release create --tag vX.Y.Z [--title T] [--notes … | --notes-file F] [--draft] [--prerelease]`, plus `release view` and `release list`. With no body given, GitHub writes the notes from the pull requests since the previous tag
- The tag has to exist upstream first, so this runs after `git push origin vX.Y.Z`
- New permissions `release:create` and `release:read`. The device flow token already carries the `repo` scope
- `handler: git-relay` is now written `handler: github`. The SSH git half is forge-agnostic but the API half is GitHub's, which leaves room for `gitlab` / `gitea` in 0.3.0
- `git-relay` keeps working as an alias on both the Rust and the Python side; no config has to change

## 0.2.5 (2026-09-16)

- Docker: copy `relay/locales` into the builder stage. The 0.2.4 dictionaries are pulled in with `include_str!` but only `relay/share` was copied, so the v0.2.4 image never published
- No change to the relay; 0.2.4 and 0.2.5 are the same code

## 0.2.4 (2026-09-16)

- Web UI: strings moved into `src/locales/{en,ja}.json`, English by default. The language is resolved in this order: `?lang=` → cookie (the in-page switcher) → `ui.language` in `config.yml` (`auto` / `en` / `ja`) → the browser's `Accept-Language` → English. New `/api/i18n`
- `python -m src.maint`: `--help` and all messages follow `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` (English by default)
- Rust CLI: `--help` and operator-facing output moved into `relay/locales/{en,ja}.json` and selected at runtime from `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` (English by default). A missing key falls back to English, then to the key name
- `sekimore guide --lang en|ja`: the guide is now `relay/share/agent-guide.en.md` and `agent-guide.ja.md` (the English one is the full text, not a summary). What agent-setup writes into the skill and `AGENTS.md` is English by default (`SEKIMORE_GUIDE_LANG`)
- README and CHANGELOG are English-primary; the Japanese versions are `README.ja.md` and `CHANGELOG.ja.md`
- Denial reasons (`sekimore: …`) and the audit log stay English

## 0.2.3 (2026-09-16)

- Web UI: one poller walks a rowid cursor and ships only what is new, as a single message. Immediate for one row, batched when there are many. A snapshot of the latest 50 on connect and when a hidden tab returns
- `/api/stats` is fetched at most once every 3 seconds after new rows, rather than per log line
- SQLite: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`, and indexes on `dns_queries(timestamp)` and `(status, timestamp)`
- Records are never deleted. `python -m src.maint db-stats | db-prune | db-reset | db-vacuum` is run explicitly by the operator; `mise run gw:db-*` under Dev Containers
- Relay tab: show the upstream's upload cap even when there is only one
- No change to the relay itself

## 0.2.2 (2026-09-16)

- Exfiltration controls: an upload cap on dev → upstream traffic through the 443 passthrough (`relay.https_max_upload_bytes`, 1 MiB by default, `-1` for unlimited). A connection that exceeds it is cut and audited as `https_upload_capped`
- `handler: https-relay`: pass only 443 through the relay's passthrough and apply a per-destination `max_upload_bytes` (`-1` for destinations you push images to)
- `network.allowed_ports` (sekimore-gw itself): restrict which destination ports reach allowed domains and IPs. Unset behaves as before — all ports
- Web UI: the per-destination cap, a LARGE UPLOAD marker on passthrough connections that sent 1 MiB or more, and 24-hour counts (large uploads / cap hits)
- `sekimore guide`: usage written for AI agents, embedded in the CLI. agent-setup installs it as a Claude Code skill and as a block in Codex CLI's `AGENTS.md` (`SEKIMORE_AGENT_INSTRUCTIONS`)

## 0.2.1 (2026-09-16)

- `project.upstreams.<domain>`: a per-upstream layer between the project defaults and the repos (a `permissions` delta, defaults for `push` / `tags` / `delete`, and `repos`)
- `domain_handlers.<domain>.ssh_options` / `relay.ssh_options`: passed to the upstream ssh as `-o` (a bastion's `ProxyJump=`, for example). Options the relay enforces cannot be overridden
- `domain_handlers.<domain>.api_base` / `graphql_base`: per-upstream API endpoints
- `sekimore-relay keyscan`: add an upstream's or bastion's host key to known_hosts, printing its fingerprint
- Web UI: per-upstream `ssh_options` and `api_base`. The orchestrator now treats a change to `ssh_port` as requiring a restart

## 0.2.0 (2026-09-16)

- Multiple upstreams: `domain_handlers` may list git-relay more than once. The relay listens on a separate port per upstream and picks the upstream from the port the connection arrived on
- `repos[].name` accepts `host/Org/Repo`. The SSH path only looks at repos belonging to the upstream the connection arrived on
- The 443 passthrough picks the upstream from the TLS SNI
- `login` / `logout` / `whoami --upstream`. State for non-default upstreams lives in `/data/relay/upstreams/<host>/`
- `/bootstrap` returns `git_domains`, and agent-setup writes a `Host` block and known_hosts entry per upstream
- The Web UI Relay tab lists the upstreams

## 0.1.9 (2026-09-16)

- Permissions consolidated under `project`: `permissions` is either `[…]` or `{allow, deny}` (deny wins), plus `push`, `tags` (globs) and `delete`
- `repos[]` can override `tags`, `delete` and `permissions` (as a delta)
- The old `relay.allow_tags` / `relay.allow_delete` are deprecated (still read, folded into the defaults with a warning)

## 0.1.8 (2026-09-16)

- `ci jobs --number` aggregates every workflow run of a PR
- `provenance: false` for Docker Publish

## 0.1.7 (2026-09-16)

- `ci runs --ref <tag|branch|sha>`, and `--run-id` for `ci jobs` / `ci log`
- Docker Publish parallelized across native runners per architecture (0.1.6 failed to publish and was skipped)

## 0.1.5 (2026-09-15)

- `relay.allow_tags`
- `ci:read`: `ci jobs` / `ci log` (GitHub Actions failure logs, read from the end)

## 0.1.4 (2026-09-15)

- Fix the Web UI Relay tab's API returning 404 in the real process

## 0.1.3 (2026-09-15)

- Honour `proxy.enabled`. Drop the authentication banner. Report a denied push through report-status as `ng`
- Close audit gaps (tcpip-forward, missing Authorization, malformed bodies)
- Re-bootstrapping with the same key revokes the previous token. Token records are swept 7 days after expiry
- Web UI Relay tab. The signing key comment carries the project name and the user name
- `pr status` (`pr:read`). Disable the credential helper and GIT_ASKPASS for HTTPS git on the dev side (so the operator's credentials cannot bypass the relay)

## 0.1.0 – 0.1.2 (2026-09-08 – 13)

- First release. Relaying SSH (git) and the GitHub API, project policy, PR creation from `refs/for/<base>`, bootstrap, the 443 passthrough, and bundling into the devcontainer base
