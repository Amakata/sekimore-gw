# sekimore-relay changelog

*[日本語版](CHANGELOG.ja.md)*

Entries are grouped **Security**, **Fix**, **Enhancement** — most urgent first —
and say what changed, with the pull request that changed it. The reasoning is in
the pull request.

## 0.2.30 (2026-09-23)

### Fix

- applied a commit delta against another commit in the same pack, so a push of two signed commits under `signing: required` goes through; the delta's result is what is judged (#144)
- a delta against a commit too large to keep (over 1 MiB, or past 64 MiB per pack) is still refused, and the refusal names `git -c pack.window=0 push` instead of `--no-thin` (#144)
- `whoami` marks each repository with what its own allow / deny add to or take from the project's permissions, as `+x` / `-x` (#146)

## 0.2.29 (2026-09-21)

### Security

- served a filtered ssh-agent on a shared unix socket for the dev container: one fingerprint, SSHSIG in namespace `git` only, everything else answers FAILURE and is audited. The private key never leaves the host agent (#136)
- refused a push under `signing: required` when any commit it brings lacks a signature; a commit arriving as a delta or missing from the pack is settled with the upstream API and fails closed (#137)
- set the signing socket's mode through its own descriptor and its owner with `lchown`, so a symlink planted on the shared volume cannot redirect either (#136)

### Enhancement

- added `relay.signing_key {source: agent, fingerprint, namespace, timeout, socket, socket_uid}`; `/bootstrap` tells dev where the socket is and `check` shows whether the host agent holds the key (#136)
- added `signing: required | optional | off` at project, upstream and repo level, default `optional`; `whoami` and the written guide say so only under `required` (#137)
- added `unlock --stdin` for a passphrase piped from the host: refused on a terminal, and on a store that has no passphrase yet (#135)

## 0.2.28 (2026-09-21)

### Enhancement

- added `security alerts [--state]` / `security view --number N` (`security:read`) over the Dependabot alerts API, one line per alert: severity, ecosystem/package, manifest, advisory, first fixed version (#133)
- added `security dismiss --number N --reason … [--comment …]` / `security reopen` under their own key `security:dismiss`: hiding a vulnerability is not reading one. The reason is required and goes into the audit as `security_alert_dismissed` (#133)
- asked for the `security_events` OAuth scope in the device flow; a token issued before 0.2.28 lacks it and GitHub answers 403 until `gw:login` is run again (#133)

## 0.2.27 (2026-09-21)

### Security

- refused a pushed tag that is not an annotated tag object carrying a signature: the pack is read on the way through and its trailer withheld, so the upstream unpacks nothing and reports ng (#128)
- refused lightweight tags, `tag.gpgsign=false` tags and tags whose object is not in the push; `signed_tags` (default true) at project / upstream / repo turns it off, audited as `push_denied_tag_not_signed` (#128)

### Enhancement

- moved to the RustCrypto 0.11 generation — sha2 0.11, hmac 0.13, aes-gcm 0.11, argon2 0.6 — dropping the 0.10 tree the relay had carried beside russh's 0.11 (#129)
- took rusqlite 0.40 (#127), getrandom 0.4 (#110), base64 0.23 (#111), russh 0.63.3 and clap 4.6.7 (#107)
- showed `signed_tags` per repository in `check` and in the Web UI's Relay tab (#128)

## 0.2.26 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.25 and 0.2.26 are the same binary. The release ships the gateway with no Python bytecode (#121)

## 0.2.25 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.24 and 0.2.25 are the same binary. The release drops 44 MB of uv's download cache from the image (#118)

## 0.2.24 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.23 and 0.2.24 are the same binary. The release takes back the 10 MB the last one added (#116)

## 0.2.23 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.22 and 0.2.23 are the same binary. The release stops the image layers changing when their contents do not (#114)

## 0.2.22 (2026-09-21)

### Security

- added `proxy-credential set` / `clear`, so the corporate proxy's credential lives in the secret store rather than in `config.yml` or `.devcontainer/.env`, both of which the agent can read (#105)

## 0.2.21 (2026-09-21)

### Fix

- resolved the Projects v2 boards on the first request instead of at start-up; resolving needs the upstream token, which since 0.2.19 is behind a locked store, so every board stayed refused for the life of the process (#100)
- stopped remembering a board that would not resolve, so unlocking fixes it without a restart (#100)
- said that a declared board could not be resolved, rather than that none was configured — the old wording sent the operator to a file that already had it (#100)

## 0.2.20 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.19 and 0.2.20 are the same binary. The release ships the gateway's own mise tasks in the image (#95)

## 0.2.20 (2026-09-21)

### Enhancement

- no change to the relay; 0.2.19 and 0.2.20 are the same binary. The release ships the gateway's own `gw:*` mise tasks in the image (#95)

## 0.2.19 (2026-09-21)

### Security

- sealed the upstream API token into the secret store; it was a 0600 file a copied volume or a backup carried in the clear (#92)
- refused a push that moves a `refs/tags/*` ref the upstream already advertises, under the same `delete` authority that refuses removing one (#91)
- told the token cache when the store is locked, so `lock` no longer leaves the decrypted token usable for the rest of its TTL (#92)

### Fix

- checked the store is writable before `login` starts a device flow, rather than discarding an authorisation a person already granted (#92)
- stopped reporting a store that would not open as `Locked`, which sent the operator to a passphrase that cannot help (#92)

### Enhancement

- added `get` / `set` / `delete` / `list` to the control socket, with `not_found` and `locked` as codes rather than prose (#92)
- moved a pre-0.2.18 `upstream_token` file into the store the first time it is read, and deleted it (#92)

## 0.2.18 (2026-09-21)

### Security

- pinned every action to a commit and every base image to a digest, with the version kept as a comment (#87)
- bounded the control socket read at 8 MiB; `import` is the first request that is not tiny (#86)
- stopped `prompt` leaving the passphrase in a freed buffer, and zeroed the request line rather than clearing it (#84)

### Fix

- answered a mistyped passphrase with what failed, not with the `mise run gw:unlock` the reader is already running (#84)
- switched `prompt` to `TCSAFLUSH`, so a character typed before the prompt no longer joins the passphrase (#84)
- said "nothing was changed" when `passphrase` is given the wrong old one (#84)

### Enhancement

- added `store-export` / `store-import` to the CLI and the control socket; 0.2.17 shipped the store's `export` / `import` with no way to run them (#86)
- rewrote all 25 releases of this changelog as one line each, under Security / Fix / Enhancement, ending with the pull request (#85)
- added `test_supply_chain_pins.py`, so a floating tag added later is an error rather than nothing (#87)

## 0.2.17 (2026-09-21)

### Security

- sealed the set of records with a MAC, checked at unlock, so a dropped or spliced-in record is noticed (#77)
- added `pip-audit` to every pull request, and cleared 29 advisories across six Python packages (#80)

### Fix

- stopped the Python test job reading the kill from its own timeout as success; a test had been failing since 0.2.15 (#80)
- added `pr:label`, `pr:assign` and `issue:update` to `dashboard.html` (#80)

### Enhancement

- added `export` / `import` for the secret store, sealed, so a backup can be taken while locked (#77)
- added `relay.store.unlock: file` / `env` for unattended unlock; both put the passphrase at rest, and the relay says so at start-up (#78)
- moved `COPY src/` below `uv pip install`, so one edited line no longer rebuilds site-packages (#79)

## 0.2.16 (2026-09-21)

### Fix

- added `init` to the control socket, so `mise run gw:unlock` can set a passphrase on a store that has none (#73)
- reworded the not-a-terminal message to say not to pipe it, rather than to use a terminal (#73)

## 0.2.15 (2026-09-21)

### Security

- required `pr:*` for the `issue` writes when the number names a pull request; added `pr:label` and `pr:assign` (#67)

### Fix

- moved the config reload onto the gateway's event loop, so it no longer interleaves with the firewall's rule changes (#66)
- refused at start-up a config whose `domain_handlers` relays a domain `allow_domains` does not cover (#65)

### Enhancement

- added a secret store: SQLite in its own file, AES-256-GCM per value, the record's identity as associated data (#70)
- added `unlock` / `lock` / `store-status` / `passphrase` over a unix socket beside the relay's state (#71)
- added `--board 2` to the `project` commands, the number `config.yml` and the URL already use (#64)
- added each item's field values to `project list`, so a field written with `update-item` can be read back (#64)
- added `issue update --number N [--title …] [--body …]`, under a new `issue:update` (#69)
- added `:pr-<n>` and `:main` arm64 images, so a gateway change can be tried without spending a version (#63)

## 0.2.14 (2026-09-18)

### Fix

- kept `allow_ips` and `block_ips` across a reload; the ipsets were rebuilt from `allow_domains` alone (#56)
- generated the Squid config before flushing the old state, so a failed generation no longer leaves neither (#56)
- made the reload check compare the `proxy` block, so `proxy.enabled` is no longer fixed until a restart (#56)
- added `node_id` to `issue view` and `pr view`, so anything already filed can join a board (#56)

## 0.2.13 (2026-09-18)

### Security

- replaced the always-on config reload with `reload: auto | manual | <duration>`, reopened only from inside the gateway (#49)
- checked a pull request's head against the same globs a push satisfies, so a fork cannot carry in code the relay never saw (#49)
- seeded the allow ipset from `domain_handlers` as well, so the upstream's real address is no longer reachable directly (#49)
- compared domains on label boundaries, so `.debian.org` no longer covers `evildebian.org` (#49)
- gave an unnamed TLS connection the tightest upload cap rather than the default (#49)

### Fix

- named the client ref in report-status when one push updates an upstream ref twice (#49)
- widened the reload check's model of the relay section, which kept four keys and read most changes as none (#49)
- fixed `truncate()` cutting a byte at a time into a `str`; a Japanese label name panicked the task (#49)
- said where operator commands run, and named a login timing out against a proxy in a docker bridge subnet (#49)
- rejected a misspelled `domain_handlers` key, and stopped ipset names colliding after being cut to 31 characters (#49)
- also: a missing `merged` field read as true; `repo vocabulary` said "no labels" on a failed read; an idle timeout recorded zero bytes; SSH session channels leaked; `glob_match` backtracked exponentially (#49)

### Enhancement

- added `python -m src.maint reload-follow 30m` / `reload-freeze` / `reload-status` (#49)

## 0.2.12 (2026-09-18)

### Security

- denied the relay's own domains in the generated `squid.conf`; Squid resolved through Docker's DNS and served `github.com` to anyone setting `https_proxy=<gateway>:3128` (#48)
- named each denied domain exactly, so `.github.com` keeps serving api.github.com and codeload.github.com (#48)

### Fix

- applied the deny on startup, reload and restart, covering the old and new handler sets both (#48)
- left out a name listed beside a wildcard containing it; `deb.debian.org` with `.debian.org` is FATAL to Squid (#48)
- inserted the deny rule into a bind-mounted template that predates it, and failed generation on one too unfamiliar to place it in (#48)

## 0.2.11 (2026-09-17)

### Enhancement

- split `cli/agent.rs` (948 lines) into `cli/agent/`: the clap tree, the dispatch, the printing and the HTTP client (#47)
- declared each endpoint's path beside its flags, so a subcommand written without a path does not compile (#47)
- folded the repeated handler preamble in `api/handlers.rs` into three scope helpers, about 150 lines (#47)
- no change to any command, flag, endpoint, permission or message; all 47 help screens are byte-identical in both languages (#47)

## 0.2.10 (2026-09-17)

### Fix

- honoured `SEKIMORE_WEB_HOST`, `SEKIMORE_WEB_PORT` and `SEKIMORE_ULOG_PATH`, read into constants nothing used (#46)
- defaulted `ULOG_FILE_PATH` to `firewall.log`, which is what ulogd writes, rather than `syslogemu.log` (#46)

### Enhancement

- made `login` say whether it went through `proxy.upstream_proxy` or straight out (#46)
- removed five unused dependencies: `thiserror`, `http`, `pydantic-settings`, `python-json-logger`, `jinja2` (#46)
- removed seven Rust functions, the `bootstrap` agent subcommand, `bootstrap status`, and four Python definitions (#46)

## 0.2.9 (2026-09-17)

### Fix

- gave `pr merge` a body; a squash-only repository rejected the old empty one with 405 (#45)
- checked `repo:read`, which was declared and checked nowhere until now (#45)

### Enhancement

- added `--method merge|squash|rebase`, `--title`, `--message` and `--delete-branch` to `pr merge` (#45)
- added `pr reopen`, `issue reopen`, `issue unlabel`, `issue unassign`, `pr update --title/--body/--base` (#45)
- added `release edit`, which needs the new `release:publish` to flip a draft to published (#45)
- added `ci rerun --run-id N [--all]` and `ci cancel` under the new `ci:rerun`, not `ci:read` (#45)
- added `repo vocabulary`: the labels, assignable people and open milestones (#45)
- added a CI check on changelog style: bullet length, date-only headings, and the two languages in step (#45)

## 0.2.8 (2026-09-17)

### Enhancement

- added `pr view` / `pr comments` / `pr list` and `issue view` / `issue comments` / `issue list` (#43)
- merged the conversation, review verdicts and line comments into one `pr comments` list, oldest first (#43)
- added `search "is:open label:bug"` across the project, scoped with `repo:` and re-checked per result (#43)
- added the `issue:read` and `search:read` permissions (#43)
- said in the guide that comment text is data, not instruction (#43)

## 0.2.7 (2026-09-17)

### Security

- percent-encoded `/` and `.` in path segments; a crafted tag or CI ref read another repository with the operator's token, reachable since 0.1.7 (#40)
- declared Projects v2 boards in `relay.project.boards` and resolved them at startup; **breaking**, an empty list refuses every Projects call (#42)
- fixed `dns_server.py` comparing against `git-relay` alone, so a domain written as `github` never reached the relay (#39)

### Fix

- accepted `pr:read` in `find_pull_request`, which demanded `pr:create` for a read (#41)
- corrected the guide's claim that force pushes are refused; upstream branch protection is what refuses one (#41)

### Enhancement

- added `pr request-review --reviewers alice,bob [--teams t]` under the new `pr:request_review` (#41)
- added `project fields`: the board's fields and single-select option ids, which `update-item` needs (#42)

## 0.2.6 (2026-09-16)

### Enhancement

- added `release create --tag vX.Y.Z [--title T] [--notes … | --notes-file F] [--draft] [--prerelease]`, `release view` and `release list` (#38)
- left the notes to GitHub when no body is given, written from the pull requests since the previous tag (#38)
- added the `release:create` and `release:read` permissions (#38)
- renamed `handler: git-relay` to `handler: github`, leaving room for `gitlab` / `gitea` (#38)
- kept `git-relay` working as an alias on both the Rust and the Python side (#38)

## 0.2.5 (2026-09-16)

### Fix

- copied `relay/locales` into the Docker builder stage; the v0.2.4 image never published without it (#36)
- no change to the relay; 0.2.4 and 0.2.5 are the same code (#37)

## 0.2.4 (2026-09-16)

### Enhancement

- moved the Web UI strings into `src/locales/{en,ja}.json`, resolved `?lang=` → cookie → `ui.language` → `Accept-Language` → English (#33)
- made `python -m src.maint` follow `SEKIMORE_LANG` / `LC_ALL` / `LC_MESSAGES` / `LANG` (#33)
- moved the Rust CLI's help and operator output into `relay/locales/{en,ja}.json`, falling back to English then the key (#34)
- added `guide --lang en|ja`, with `agent-guide.{en,ja}.md` and `SEKIMORE_GUIDE_LANG` for what agent-setup writes (#34)
- made README and CHANGELOG English-primary, with `README.ja.md` and `CHANGELOG.ja.md` (#34)
- kept denial reasons (`sekimore: …`) and the audit log English (#34)

## 0.2.3 (2026-09-16)

### Enhancement

- replaced the Web UI's per-line push with one poller walking a rowid cursor, shipping what is new as one message (#32)
- fetched `/api/stats` at most once every 3 seconds after new rows, rather than per log line (#32)
- set SQLite `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`, and indexed `dns_queries(timestamp)` and `(status, timestamp)` (#32)
- added `python -m src.maint db-stats | db-prune | db-reset | db-vacuum`; records are never deleted automatically (#32)
- showed the upstream's upload cap in the Relay tab even when there is only one (#32)
- no change to the relay itself (#32)

## 0.2.2 (2026-09-16)

### Security

- capped dev → upstream uploads through the 443 passthrough (`relay.https_max_upload_bytes`, 1 MiB, `-1` to disable); exceeding it cuts the connection (#30)
- added `network.allowed_ports` to restrict which destination ports reach allowed domains and IPs (#30)

### Enhancement

- added `handler: https-relay`: 443 only, with a per-destination `max_upload_bytes` (#30)
- added the per-destination cap, a LARGE UPLOAD marker and 24-hour counts to the Web UI (#30)
- added `sekimore guide`, installed by agent-setup as a Claude Code skill and into Codex CLI's `AGENTS.md` (#31)

## 0.2.1 (2026-09-16)

### Enhancement

- added `project.upstreams.<domain>`: a per-upstream layer between the project defaults and the repos (#27)
- added `ssh_options`, passed to the upstream ssh as `-o`; options the relay enforces cannot be overridden (#28)
- added `api_base` / `graphql_base` per upstream (#28)
- added `keyscan`: add an upstream's or bastion's host key to known_hosts, printing its fingerprint (#28)
- showed `ssh_options` and `api_base` per upstream in the Web UI, and treated an `ssh_port` change as needing a restart (#28)

## 0.2.0 (2026-09-16)

### Enhancement

- allowed `domain_handlers` to list git-relay more than once, one listening port per upstream (#24)
- accepted `host/Org/Repo` in `repos[].name`, matched only against the upstream the connection arrived on (#24)
- picked the upstream from the TLS SNI in the 443 passthrough (#25)
- added `--upstream` to `login` / `logout` / `whoami`, with state under `/data/relay/upstreams/<host>/` (#25)
- returned `git_domains` from `/bootstrap`, so agent-setup writes a `Host` block and known_hosts entry per upstream (#25)
- listed the upstreams in the Web UI Relay tab (#26)

## 0.1.9 (2026-09-16)

### Enhancement

- consolidated permissions under `project`: `permissions` as `[…]` or `{allow, deny}`, plus `push`, `tags`, `delete` (#23)
- allowed `repos[]` to override `tags`, `delete` and `permissions` as a delta (#23)
- deprecated `relay.allow_tags` / `relay.allow_delete`, still read and folded into the defaults with a warning (#23)

## 0.1.8 (2026-09-16)

### Enhancement

- made `ci jobs --number` aggregate every workflow run of a PR (#22)
- set `provenance: false` for Docker Publish (#22)

## 0.1.7 (2026-09-16)

### Enhancement

- added `ci runs --ref <tag|branch|sha>`, and `--run-id` for `ci jobs` / `ci log` (#19)
- parallelized Docker Publish across native runners per architecture; 0.1.6 failed to publish and was skipped (#17)

## 0.1.5 (2026-09-15)

### Enhancement

- added `relay.allow_tags` (#16)
- added `ci:read` with `ci jobs` / `ci log`, reading GitHub Actions failure logs from the end (#16)

## 0.1.4 (2026-09-15)

### Fix

- fixed the Web UI Relay tab's API returning 404 in the real process (#15)

## 0.1.3 (2026-09-15)

### Security

- closed audit gaps: tcpip-forward, missing Authorization, malformed bodies (#14)
- revoked the previous token when re-bootstrapping with the same key, and swept token records 7 days after expiry (#14)
- disabled the credential helper and GIT_ASKPASS for HTTPS git on the dev side, so the operator's credentials cannot bypass the relay (#14)

### Fix

- honoured `proxy.enabled`, dropped the authentication banner, and reported a denied push through report-status as `ng` (#14)

### Enhancement

- added the Web UI Relay tab, `pr status` (`pr:read`), and the project and user name in the signing key comment (#14)

## 0.1.0 – 0.1.2 (2026-09-08 – 13)

### Enhancement

- first release: SSH (git) and GitHub API relaying, project policy, PR creation from `refs/for/<base>`, bootstrap, the 443 passthrough, and bundling into the devcontainer base (#11)
