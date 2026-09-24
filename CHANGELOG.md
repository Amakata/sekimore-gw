# sekimore-gw changelog

*[日本語版](CHANGELOG.ja.md)*

The gateway as a whole: DNS, the firewall, Squid, the Web UI, the build and CI.
The relay's own changes are in [relay/CHANGELOG.md](relay/CHANGELOG.md), under
the same version number — one image carries both.

Entries are grouped **Security**, **Fix**, **Enhancement** — most urgent first —
and say what changed, with the pull request that changed it. The reasoning is in
the pull request.

Starts at 0.2.18. Everything before it is in the relay's changelog, which
carried the whole project until the two were separated.

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

## 0.2.29 (2026-09-21)

### Security

- signed the dev container's commits with the operator's own key through the relay's filtered ssh-agent when `relay.signing_key` is set; `agent-setup.sh` stops generating a disposable signing key and points `SSH_AUTH_SOCK` at the socket (#136)

### Enhancement

- unlocked the store from the host's own secret store: `gw:unlock-auto` reads the passphrase from the macOS Keychain, the Secret Service or a root-owned file and pipes it into `unlock --stdin` (#135)
- ran that unlock from `gw:recreate` itself; `SGW_NO_AUTO_UNLOCK=1` leaves the store locked (#135)
- added `gw:keychain-set` to store the passphrase once per host (#135)

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

### Enhancement

- failed the build once the Debian snapshot is more than 90 days old, since no security update reaches the image between bumps (#93)

## 0.2.18 (2026-09-21)

### Security

- pinned every action to a commit and every base image to a digest, with the version kept as a comment (#87)

### Enhancement

- added `test_supply_chain_pins.py`, so a floating tag added later is an error rather than nothing (#87)
- split this changelog out of the relay's, which had been carrying the gateway's own changes as well (#88)
- pointed the README at both changelogs instead of naming a version, which had been seven releases stale (#88)
