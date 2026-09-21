# sekimore-relay changelog

*[日本語版](CHANGELOG.ja.md)*

## 0.2.16 (2026-09-21)

- `mise run gw:unlock` could not set a passphrase on a store that had none: it asked twice, then sent `unlock`, which unwraps a key using parameters not yet written. The control socket had no `init`
- The message when stdin is not a terminal said to run it on one, which is unhelpful to someone sitting at a terminal. It now says not to pipe it

## 0.2.15 (2026-09-21)

- `project list` / `fields` / `add-item` / `update-item` take `--board 2`, the number `config.yml` and the URL already use. `--project-id` still works, and a project with one board can leave both out
- `project list` carries each item's field values — single-select, text, number and date — so a field written with `update-item` can be read back
- The `issue` writes require `pr:*` when the number names a pull request: GitHub serves pull requests from the issues endpoints, so `issue:close` reached one. `pr:label` and `pr:assign` are new
- `issue update --number N [--title …] [--body …]`, under a new `issue:update` rather than `issue:create`
- The config reload runs on the gateway's own event loop and the firewall's rule changes hold a lock. They could interleave, leaving the NFLOG rule ahead of the ACCEPTs or gone
- A config whose `domain_handlers` relays a domain `allow_domains` does not cover is refused at start-up, naming it. `deny` and `splice` entries are not checked
- A secret store: SQLite in its own file, AES-256-GCM per value, the record's identity as associated data. Nothing consumes it yet
- `sekimore-relay unlock` / `lock` / `store-status` / `passphrase`, over a unix socket beside the relay's state rather than the agent-facing API. `mise run gw:unlock` and friends
- A pull request and a push to `main` build `:pr-<n>` and `:main` for arm64, so a gateway change can be tried without spending a version number

## 0.2.14 (2026-09-18)

- A reload rebuilt the ipsets from `allow_domains` alone, so `allow_ips` and `block_ips` were dropped until the next restart. Addresses named directly in the config are the ones with no DNS name to fall back on
- A reload flushed the existing state before generating the new Squid config, so a config that failed to generate left the gateway holding neither the old rules nor the new ones. The config is now built first, and one missing the relayed-domain denial is refused rather than written
- `ProxyManager` is built once at start-up, so every key under `proxy` is fixed until a restart - `enabled` included. Turning the proxy on did nothing and the reload said nothing about it; the only clue was Squid being absent. The reload check now compares the proxy block too
- `project add-item` takes a GraphQL node id and nothing handed one out, so an item could join a board only in the same breath as being created - anything already filed could not be put on a board at all. `issue view` and `pr view` now carry `node_id`

## 0.2.13 (2026-09-18)

- The config file is writable from dev and applied on save, so an agent that read a hostile prompt could rewrite the rules holding it. `reload:` now takes auto (as before), manual, or a duration — a window that runs out rather than a mode someone has to close. Reopened only from inside the gateway
- `python -m src.maint reload-follow 30m` / `reload-freeze` / `reload-status`. A save arriving with the window shut is counted and logged rather than dropped quietly
- A pull request's head was never checked. GitHub reads `owner:branch` as a fork, so an agent could open a PR against a project repository carrying code the relay never saw. A head now satisfies the same globs a direct push would
- Two updates to one upstream ref in a single push left the report-status rewriter unable to say which result belonged to which client ref. The rewrite produces a branch name from the agent's own commit, so it could name that branch as a second ref deliberately
- Start-up seeded the allow ipset from allow_domains without consulting domain_handlers, so the upstream's real address went in for every domain the relay answers for — six here. The agent could reach the address directly and miss the relay
- Domain matching compared suffixes without label boundaries, so `.debian.org` covered `evildebian.org`, a name anyone can register. The allow, block and ignore lists now share one comparison, which also settles a three-way disagreement about wildcards
- The reload check compared the relay section through a model that keeps four keys, so adding a repository to the project, granting pr:merge or lifting the upload cap all read as no change at all
- An unnamed TLS connection took the default upload cap, so omitting the SNI was a way to ask for whichever cap was loosest. It now takes the tightest of them
- truncate() cut a byte at a time into a str: an upstream error body echoes what the agent sent, so a Japanese label name was enough to panic the task
- Two messages that sent people the wrong way: operator commands now say they run inside the gateway, since an agent told to run `sekimore-relay keyscan` ran it in dev and got an unrelated cause; and a login timing out against a proxy inside a docker bridge subnet is now named at start-up
- Two things the config quietly built wrong: a misspelled `domain_handlers` key was ignored, and the ones worth misspelling loosen (`max_uploads_bytes` read as no cap); and an ipset named from the domain cut to 31 characters was shared by any two agreeing on their first 25
- Also: a missing `merged` field read as true and gated deleting the branch; `repo vocabulary` answered "no labels" when the read had failed; an idle timeout recorded zero bytes sent; SSH session channels were never released; glob_match backtracked exponentially over a ref name the agent chooses

## 0.2.12 (2026-09-18)

- Squid served the domains the relay owns. It resolves through Docker's DNS, never sees the DNS filter's answers, and served `github.com` to anyone setting `https_proxy=<gateway>:3128` — the real upstream, with none of the project's policy. Open whenever `proxy.enabled` is true
- The generated squid.conf now denies the `github`, `https-relay` and `deny` domains ahead of the allowlist. The deny names each domain exactly, so `.github.com` keeps serving api.github.com and codeload.github.com — neither is the relay's, and taking the wildcard out would break fetching source tarballs
- Applied on startup, reload and restart; a reload denies the old and the new handler sets both, since the relay keeps the old one until a restart. With no handlers the file is byte-identical to before
- Separately: a name listed beside a wildcard that contains it (`deb.debian.org` and `.debian.org`) is a FATAL error to Squid, not a warning, so the proxy would not start at all. The redundant entry is now left out of the generated ACL
- The squid.conf template is bind-mounted by each deployment, not baked into the image, so upgrading the gateway leaves an older one in place. The deny rule is now inserted into a template that predates it; one too unfamiliar to place it in fails the generation instead

## 0.2.11 (2026-09-17)

- `cli/agent.rs` (948 lines) split into `cli/agent/`: the clap tree, the dispatch, the printing and the HTTP client. Each part now knows one thing — printing knows nothing about endpoints, the client nothing about subcommands
- An endpoint's path is declared beside its flags, so the two cannot drift. A subcommand written without a path does not compile. The field mapping stays explicit: covering all 38 endpoints in a macro would need seven features and sixteen escapes, which costs more reading than it saves
- The repeated handler preamble in `api/handlers.rs` folded into three scope helpers, about 150 lines. The permission stays an argument at every call site, because that is the security boundary and belongs where it can be read
- No change to any command, flag, endpoint, permission or message. All 47 help screens are byte-identical in both languages

## 0.2.10 (2026-09-17)

- `SEKIMORE_WEB_HOST`, `SEKIMORE_WEB_PORT` and `SEKIMORE_ULOG_PATH` were read into constants that nothing used, so setting them did nothing. They work now. `ULOG_FILE_PATH` also defaulted to `syslogemu.log` while the code read `firewall.log`; the default matches what ulogd writes
- `login` now says whether it went through `proxy.upstream_proxy` or straight out. An unreachable proxy and an unreachable upstream produced the same timeout, and they are fixed in different places
- Removed five unused dependencies: `thiserror` and `http` on the Rust side (the `http::` paths resolve to a local module of the same name), `pydantic-settings`, `python-json-logger` and `jinja2` on the Python side
- Removed seven Rust functions, the `bootstrap` agent subcommand and `bootstrap status`, and four Python definitions, none of which had a caller. `agent-setup.sh` calls `POST /bootstrap` over HTTP, so the endpoint stays

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
