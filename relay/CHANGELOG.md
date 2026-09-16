# sekimore-relay changelog

*[日本語版](CHANGELOG.ja.md)*

## 0.2.7 (2026-09-16. Fixes the DNS redirect under the new handler name)

- DNS: `handler: github` now redirects to the relay, as `git-relay` always did. 0.2.6 renamed the handler and updated the config layer, but `dns_server.py` still compared against the old spelling alone, so a domain written the new way resolved to its real address and never reached the relay. Both spellings are accepted there now, with a test that asserts they behave identically. Anyone who kept writing `git-relay` was unaffected

## 0.2.6 (2026-09-16. Releases from the agent, and the handler is named after the forge)

- `sekimore release create --tag vX.Y.Z [--title T] [--notes "…" | --notes-file F] [--generate-notes] [--draft] [--prerelease]`, `sekimore release view --tag vX.Y.Z`, `sekimore release list [--limit N]`. The endpoints are `/release/create`, `/release/view`, `/release/list`
- The tag has to exist upstream, so `release create` runs after `git push origin vX.Y.Z`; GitHub answers 422 otherwise. With no body the relay sets `generate_release_notes`, and GitHub writes the notes from the pull requests merged since the previous tag — the usual path. `--notes` / `--notes-file` is used as the body instead, and adding `--generate-notes` makes GitHub append its generated notes to it. `--title` defaults to the tag, `--draft` leaves publishing to a human (published by default)
- Two new permissions, `release:create` and `release:read`, denied by default like the rest. The device flow token already carries the `repo` scope, so there is nothing to re-authenticate
- `handler: git-relay` is now written `handler: github`. The SSH git half (refs/for, the policy, receive-pack) is plain git and would work against any forge, but the API half (pulls, check-runs, Projects v2) is GitHub's, so the handler carries the forge's name and leaves room for `gitlab` / `gitea` when 0.3.0 makes the API layer pluggable
- `git-relay` keeps working — it is an alias on both the Rust and the Python side. No config has to be edited, now or later

## 0.2.5 (2026-09-16. Fixes the 0.2.4 image build)

- Docker: copy `relay/locales` into the builder stage. The 0.2.4 CLI dictionaries are pulled in with `include_str!`, but only `relay/share` was copied, so the release build could not read `locales/ja.json` and the v0.2.4 image never published. No change to the relay itself; 0.2.4 and 0.2.5 are the same code.

## 0.2.4 (2026-09-16. Localization: English is primary, Japanese ships as a language file)

- Web UI: strings moved into `src/locales/{en,ja}.json`, English by default. The language is resolved in this order: `?lang=` → cookie (the in-page switcher) → `ui.language` in `config.yml` (`auto` / `en` / `ja`) → the browser's `Accept-Language` → English. New `/api/i18n`
- `python -m src.maint`: `--help` and all messages follow `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` (English by default)
- Rust CLI: `--help` and operator-facing output moved into `relay/locales/{en,ja}.json` and selected at runtime from `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` (English by default). A missing key falls back to English, then to the key name
- `sekimore guide --lang en|ja`: the guide is now `relay/share/agent-guide.en.md` and `agent-guide.ja.md` (the English one is the full text, not a summary). What agent-setup writes into the skill and `AGENTS.md` is English by default (`SEKIMORE_GUIDE_LANG`)
- README and CHANGELOG are English-primary; the Japanese versions are `README.ja.md` and `CHANGELOG.ja.md`
- Denial reasons (`sekimore: …`) and the audit log stay English

## 0.2.3 (2026-09-16. Performance and operations in sekimore-gw itself. No change to the relay)

- Web UI: the WebSocket no longer scans the whole table per connection. A single poller walks a rowid cursor, reads only what is new, and ships it as one message (an array) — immediate for a single row, batched when there are many. On connect and when a hidden tab comes back, a snapshot of the latest 50. `/api/stats` is no longer fetched per log line, but at most once every 3 seconds after new rows
- SQLite: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`, plus indexes on `dns_queries(timestamp)` and `(status, timestamp)`. Records are never deleted (they persist)
- `python -m src.maint db-stats | db-prune | db-reset | db-vacuum`, run explicitly by the operator. `mise run gw:db-*` under Dev Containers
- Relay tab: show the upload cap of the upstream even when there is only one

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
