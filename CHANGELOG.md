# sekimore-gw changelog

*[日本語版](CHANGELOG.ja.md)*

One version number covers the gateway image, the relay inside it, the dev-container base image
and the `sgw` binary, so one file covers them: a release lists what changed in any of the four.

Entries are grouped **Security**, **Fix**, **Enhancement** — most urgent first —
and say what changed, with the pull request that changed it. The reasoning is in
the pull request.

The base image was a repository of its own until 0.2.45, numbered on its own; those releases
are in [base/CHANGELOG.md](base/CHANGELOG.md).

## Unreleased

### Fix

- `release edit` finds a draft Release again: the by-tag lookup answers with published releases only, so a 404 now falls back to the release listing, where a workflow's draft is visible (#249)

## 0.2.48 (2026-09-26)

### Enhancement

- sgw init writes the project template, embedded in the binary; sgw update keeps a project current from it (the former upgrade.sh, nothing fetched from a tag any more) (#241)
- README: get started with sgw; what each config.yml setting does and which sgw command does what; what goes wrong when the dev container comes up (#243)
- the sgw binaries for macOS arm64 and Linux are on the Release again: the crate compiles on macOS (O_PATH was Linux-only), and CI checks that build on every pull request (#244)
- README: the proxy password line sits with the proxy setting, not under Get started (#245)

## 0.2.47 (2026-09-26)

### Enhancement

- sgw, the operator's tool on the host, as a second binary of the relay crate: every gw:* / relay:* / dev:* task as a subcommand, the terminal decided on the host, the passphrase down stdin only (#238)
- sgw verify: the acceptance check in Rust; every item names its path-ledger rows and the targets it applies to (#240)
- release assets: sgw for macOS arm64 and Linux x86_64 / arm64 with install.sh, attached to a draft Release by the tag's workflow (#239)

## 0.2.46 (2026-09-26)

### Enhancement

- one repository: sgw-devcontainer-base lives in `base/` and its image is built and published from the same tag, under this version number; `UPGRADING.md` and `RELEASING.md` sit at the top level (#236)
- `tests/unit/test_base_versions.py` holds every version written under `base/` to `pyproject.toml`'s; the base's four version-pairing tests and the "take" step are gone (#236)
- `base/` is Apache-2.0 like the rest of the repository; it was MIT on its own (#236)

## 0.2.45 (2026-09-25)

### Enhancement

- relay: login takes the host keys it needs (the bastions, then the upstream through them) before the device flow and stops with a non-zero exit when one was not saved; the yes/no is read as bytes and judged by its letters (#230)
- `gw:login` and `gw:logout` are `raw = true` tasks on `sgw.sh gw-tty`, like `gw:unlock`; without a terminal the answer arrived as bytes that were not text (#230)
- relay: every audit entry that records a connection carries `edge=<id>` from `docs/paths.yml`; `paths::AUDIT_EVENTS` lists the pairs, the ledger test checks them, and the relay tab shows the id (#228)
- `relay/README` says why `keyscan` saves after printing the fingerprints and `login` asks first (#230)

## 0.2.44 (2026-09-25)

### Security

- every ProxyJump hop is held to the upstream's known_hosts with `StrictHostKeyChecking yes`; the enforced options move into a generated ssh_config passed with `-F`, which OpenSSH hands to the jump ssh, so a bastion with no key fails closed (#220)

### Enhancement

- a path ledger, `docs/paths.yml`: every edge with who resolves, who verifies the peer, what is presented and where it is audited. `tests/unit/test_paths.py` checks it as a graph; the ids are in `src/paths.py` and `relay/src/paths.rs` (#223)
- README: the gateway-only setup is gone; the dev container is the way in (#226)
- `keyscan` and `login` fetch the host key of an upstream behind a ProxyJump bastion through the bastion, one connection per key type; `login` takes the missing bastion keys first, with fingerprints and a yes/no (#221)

## 0.2.43 (2026-09-25)

### Security

- redacted the upstream proxy password in `/api/config`: `squid.config_text` returned the generated squid.conf whole, `login=<user>:<password>` included, to anything in dev; it is `***` now. Rotate the password after upgrading (#218)
- removed the unauthenticated `POST` / `DELETE` stubs under `/api/domains`; they changed nothing, and nothing called them (#218)

## 0.2.42 (2026-09-25)

### Security

- added `proxy.direct_egress: deny`, which keeps `allow_domains` addresses out of the firewall so Squid is the only way out; until now only the relay's paths and explicit-proxy clients used the upstream, and `allow` (default) now warns (#215)

### Enhancement

- handed the dev container `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` through `GET /api/proxy-env` and agent-setup, with `NO_PROXY` built from `domain_handlers` and the operator's `proxy.no_proxy` (#215)
- the operator commands' error lines are red on a terminal, including the store's refusal that `proxy-credential set` prints; the agent subcommands stay plain (#214)

## 0.2.41 (2026-09-25)

### Fix

- routed the relay's HTTPS through the local Squid when the upstream proxy speaks TLS, so a proxy offering only RSA key exchange works; Squid gets a `relay_localhost` allow below the destination deny and above the relayed-domain deny (#210)
- kept `store-status` to its one state word again; the credential line 0.2.39 added under it made `relay:verify` fail an unlocked store (#209)

### Enhancement

- `check` probes the upstream proxy and prints the route and the result, and a `HandshakeFailure` says what the proxy must offer; the image gains the `openssl` CLI for that diagnosis (#207)

## 0.2.40 (2026-09-25)

### Enhancement

- colored the state words of `check` and `store-status` at a terminal: green for ok, red for locked / missing / none, yellow for a credential out of the environment; `NO_COLOR` and `SEKIMORE_COLOR` decide otherwise (#203)

## 0.2.39 (2026-09-25)

### Fix

- spoke TLS to an `https://` upstream proxy before the CONNECT, so a relayed HTTPS domain behind `upstream_proxy_tls: true` reaches the upstream instead of failing with `SSL_ERROR_SYSCALL`; Squid already did (#199)
- kept watching the secret store for the upstream proxy credential for the whole run, so `login=` reaches `squid.conf` after `gw:unlock-auto` and after a later `gw:proxy-credential set`, not only when one read at unlock time succeeded (#200)

### Enhancement

- reported the upstream proxy credential as `none` / `locked` / `set` / `config` / `unavailable` in `/api/config` and the dashboard, with the command to run next (#200)
- showed the destination of HTTPS audit rows in the Relay tab, and mirrored a denied row's reason into `detail` (#198)
- documented how to triage the upstream proxy path from inside dev, in relay/README (#197)

## 0.2.38 (2026-09-25)

### Security

- dropped what dev sends to the host itself: two INPUT rules on the host beside the DOCKER-USER ones, so the bridge's own address no longer answers ping, the ports other containers publish, or the VM's services (#191)
- kept replies to connections the host opens, so a port a dev container publishes still works (#191)

## 0.2.37 (2026-09-25)

### Security

- confined the agent on the host: two FORWARD rules in the host's `DOCKER-USER` chain let the internal bridge reach only the gateway, so a root process in the agent container can no longer route past it through Docker's own NAT (#189)
- the gateway inserts and re-checks the rules itself through `pid: host` and nsenter, tags them `sekimore:<project>`, and logs an error at start when `pid: host` is missing (#189)
- `network.host_enforcement` (default on) turns the rules off; the never-called `setup_host_firewall_rules` is gone (#189)

## 0.2.36 (2026-09-24)

### Security

- refused a destination an allowed name may not reach: an allowlisted domain resolving into link-local (IMDS), loopback, RFC1918, carrier-grade NAT or their IPv6 equivalents is denied, in the DNS path, in Squid and in the 443 passthrough (#178)
- checked the address at the single point a DNS answer enters, so the query path, the TTL refresh and the cache are all covered and a refused address is never cached (#178)
- unwrapped an IPv4 address in IPv6 shape (`::ffff:a.b.c.d`) and judged it as IPv4, so `::ffff:169.254.169.254` cannot walk past a list written in IPv4 (#178)
- added `resolve_deny_cidrs` and `resolve_allow_cidrs`; both have defaults, so nothing has to be configured. The gateway's own network is an exception automatically, since `.lan` names resolve into it (#178)

## 0.2.35 (2026-09-24)

### Enhancement

- the agent guide shipped in the image documents `pr files` and `pr diff`, which read a pull request's diff under the existing `pr:read` (#173)

## 0.2.34 (2026-09-24)

### Enhancement

- the dashboard lists `pr:comment_update`, `pr:comment_delete`, `issue:comment_update` and `issue:comment_delete` among the permissions, and `config.sample.yml` documents them (#174)

## 0.2.33 (2026-09-24)

### Enhancement

- `config.sample.yml` documents `ci:dispatch`, which starts a workflow that has never run and is therefore separate from `ci:rerun` (#168)
- the dashboard lists `ci:dispatch` among the permissions, so an operator deciding what to allow can see it (#168)
- `pr comments` shows a review with the line comments it was submitted with, nested under it, and prints the id of the ones that can be answered (#165)
- `pr reply --comment-id C` answers a line comment in its own thread, under `pr:comment` (#165)
- `pr review --comment path:line:body` leaves notes on lines of the diff instead of only a body; `--comments-file` takes them as JSON (#167)
- `pr create --draft`, and `pr ready` / `pr draft`, so work can get CI before anyone is asked to look (#169)

## 0.2.32 (2026-09-24)

### Enhancement

- `config.sample.yml` documents `repos[].push` and the new `project.branch` block, which name the branch a push lands on (#158)

## 0.2.31 (2026-09-23)

### Fix

- `gw:shell` opens a shell again when mise prefixes task output: it is `raw` and goes through `gw-tty`, and CI requires `raw = true` of every task that reads the terminal (#150)
- the README puts the upstream proxy credential in the secret store (`gw:proxy-credential`) instead of `.env`, which the dev container can read (#152)
- `agent-setup.sh` puts the signing settings in a root-owned file that `~/.gitconfig` includes last, so the Dev Containers extension copying the host's `user.signingkey` over them no longer breaks signing (#153)

## 0.2.30 (2026-09-23)

### Fix

- `gw:keychain-set` runs again: mise read `${#stored}` as the start of a template comment and refused the task; CI now fails on Tera syntax in any task script (#147)
- the header of `gateway.mise.*.toml` describes `.devcontainer/sgw/` and `mise run upgrade:sync` instead of copying the file by hand (#147)
- applied a commit delta against another commit in the same pack, so a push of two signed commits under `signing: required` goes through; the delta's result is what is judged (#144)
- a delta against a commit too large to keep (over 1 MiB, or past 64 MiB per pack) is still refused, and the refusal names `git -c pack.window=0 push` instead of `--no-thin` (#144)
- `whoami` marks each repository with what its own allow / deny add to or take from the project's permissions, as `+x` / `-x` (#146)

## 0.2.29 (2026-09-21)

### Security

- signed the dev container's commits with the operator's own key through the relay's filtered ssh-agent when `relay.signing_key` is set; `agent-setup.sh` stops generating a disposable signing key and points `SSH_AUTH_SOCK` at the socket (#136)
- refused a push under `signing: required` when any commit it brings lacks a signature; a commit arriving as a delta or missing from the pack is settled with the upstream API and fails closed (#137)

### Enhancement

- unlocked the store from the host's own secret store: `gw:unlock-auto` reads the passphrase from the macOS Keychain, the Secret Service or a root-owned file and pipes it into `unlock --stdin` (#135)
- ran that unlock from `gw:recreate` itself; `SGW_NO_AUTO_UNLOCK=1` leaves the store locked (#135)
- added `gw:keychain-set` to store the passphrase once per host (#135)
- added `signing: required | optional | off` at project, upstream and repo level, default `optional`; `whoami` and the written guide say so only under `required` (#137)

## 0.2.28 (2026-09-21)

### Enhancement

- installed the Python dependencies from the lock with the manifests bind-mounted, so the dependency layer holds nothing that knows which release it is; `uv pip install .` had been writing the project's versioned dist-info into it (#131)
- read and dismiss Dependabot alerts through the gateway: `security alerts` / `view` under `security:read`, `dismiss` / `reopen` under `security:dismiss`. The token needs the `security_events` scope — `gw:login` again to get it (#133)

## 0.2.27 (2026-09-21)

### Security

- refused a pushed tag that is not a signed tag object — lightweight, unsigned, or not in the push. Presence of a signature, not validity; `signed_tags: false` turns it off per project, upstream or repo (#128)

### Fix

- ran `pip-audit` over `uv.lock` on every pull request; `ci:py-audit` had never worked and was in no workflow, so `cargo audit` alone stood for the whole repository (#123)

### Enhancement

- grouped the RustCrypto crates for Dependabot, so a new generation of them arrives as one pull request instead of the pair that could not build (#125)
- took Dependabot's bumps: actions/checkout 7, upload/download-artifact, setup-python 7 (#112); cargo-zigbuild 0.23.4 (#106); russh 0.63.3, clap 4.6.7 (#107); getrandom 0.4 (#110); base64 0.23 (#111)
- moved to the RustCrypto 0.11 generation — sha2 0.11, hmac 0.13, aes-gcm 0.11, argon2 0.6 — dropping the 0.10 tree the relay had carried beside russh's 0.11 (#129)

## 0.2.26 (2026-09-21)

### Enhancement

- shipped no Python bytecode and set `PYTHONDONTWRITEBYTECODE=1`: a `.pyc` carries its source's mtime, so a layer holding one changed digest every build. Costs ~360 ms once per start; undoes #114 and the 3.5 MB it added (#121)

## 0.2.25 (2026-09-21)

### Enhancement

- passed `--no-cache` to `uv pip install`: every wheel it downloaded was shipping in the image, 1,195 files and 44 MB, in a container that never installs anything again (#118)

## 0.2.24 (2026-09-21)

### Fix

- compiled the bytecode in the layer that installed it. 0.2.23 recompiled the whole tree from the last layer, putting a second copy of every dependency's `.pyc` in it — that layer went 294,752 → 10,668,514 bytes (#116)

## 0.2.23 (2026-09-21)

### Enhancement

- cleared the seven files apt writes to record that a build happened — two machine-ids, four logs and a cache — which were the whole of the 114-byte difference in a 160 MB layer (#114)
- recompiled the `.pyc` files with `unchecked-hash`, so the source mtime in their headers stops giving site-packages a new digest every build (#114)

## 0.2.22 (2026-09-21)

### Security

- read the upstream proxy credential from the secret store, and redo Squid's config once the store is unlocked; until then it runs without upstream authentication (#105)
- corrected `config.sample.yml`, which recommended the environment for the credential without distinguishing the host shell from `.devcontainer/.env` — the latter is the agent's own env_file (#105)

### Fix

- excluded Dependabot's pull requests from `preview`: its `GITHUB_TOKEN` is read-only whatever `permissions:` says, so every one of them would have carried a red check nobody could fix (#104)

### Enhancement

- configured Dependabot for actions, cargo, uv, docker and docker-compose, so the pins added in 0.2.18 and 0.2.19 finally have a reader (#104)

## 0.2.21 (2026-09-21)

### Fix

- resolved the Projects v2 boards on the first request instead of at start-up; resolving needs the upstream token, which since 0.2.19 is behind a locked store, so every board stayed refused for the life of the process (#100)
- stopped remembering a board that would not resolve, so unlocking fixes it without a restart (#100)
- said that a declared board could not be resolved, rather than that none was configured — the old wording sent the operator to a file that already had it (#100)

### Enhancement

- dropped the release build cache: exporting it took 3m38s, longer than the 2m16s of build it could save, and #97 showed nothing read it (#101)
- normalised the layer timestamps to a fixed epoch, so a layer rebuilt to the same bytes keeps its digest and a release stops re-pulling 160 MB of identical content (#101)

## 0.2.20 (2026-09-21)

### Enhancement

- shipped the gateway's own `gw:*` mise tasks in the image, so a project includes them instead of copying them into its `mise.toml` (#95)
- added `gw:revoke`, which was reachable only as `mise run gw -- revoke --label …` (#95)
- checked in CI that every operator subcommand has a task, that both languages carry the same set, and that no task needs an `sgw.sh` primitive that does not exist (#95)

## 0.2.19 (2026-09-21)

### Security

- pinned the Debian archive to a `snapshot.debian.org` timestamp and every package to a version; `apt-get update` took whatever Debian served that day (#93)
- named `bind9-dnsutils` instead of `dnsutils`, which trixie has no package for — a virtual name has no version to pin (#93)
- sealed the upstream API token into the secret store; it was a 0600 file a copied volume or a backup carried in the clear (#92)
- refused a push that moves a `refs/tags/*` ref the upstream already advertises, under the same `delete` authority that refuses removing one (#91)
- told the token cache when the store is locked, so `lock` no longer leaves the decrypted token usable for the rest of its TTL (#92)

### Fix

- checked the store is writable before `login` starts a device flow, rather than discarding an authorisation a person already granted (#92)
- stopped reporting a store that would not open as `Locked`, which sent the operator to a passphrase that cannot help (#92)

### Enhancement

- failed the build once the Debian snapshot is more than 90 days old, since no security update reaches the image between bumps (#93)
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

- added `test_supply_chain_pins.py`, so a floating tag added later is an error rather than nothing (#87)
- split this changelog out of the relay's, which had been carrying the gateway's own changes as well (#88)
- pointed the README at both changelogs instead of naming a version, which had been seven releases stale (#88)
- added `store-export` / `store-import` to the CLI and the control socket; 0.2.17 shipped the store's `export` / `import` with no way to run them (#86)
- rewrote all 25 releases of this changelog as one line each, under Security / Fix / Enhancement, ending with the pull request (#85)

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
