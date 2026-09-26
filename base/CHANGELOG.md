# sgw-devcontainer-base changelog

*[日本語版](CHANGELOG.ja.md)*

The devcontainer base image: the Dockerfile and the tools baked into it, the zsh
configuration and the scripts it ships, and the sample devcontainer under
`examples/`.

Entries are grouped **Security**, **Fix**, **Enhancement** — most urgent first —
and say what changed, with the pull request that changed it. The reasoning is in
the pull request.

From 0.2.46 the image is built from `base/` of the sekimore-gw repository and
released from the same tag, under the gateway's version number (#235). Entries
before that name pull requests of the former `Amakata/sgw-devcontainer-base`
repository; each of those releases named the gateway version it took.

Starts at 0.2.18. Releases before it are not written up here; the pull requests
and the tag on each are the record. The gateway each of them took is at the
bottom.

## 0.2.43 (2026-09-25)

### Enhancement

- `sgw.sh` silences the Docker CLI's "What's next" hints, which landed inside `relay:verify`'s output (#102)
- takes sekimore-gw 0.2.45: `gw:login` runs on a terminal and stops before the device flow when a host key was not saved; audit entries name their path-ledger edge (sekimore-gw#230, sekimore-gw#228)

## 0.2.42 (2026-09-25)

### Enhancement

- takes sekimore-gw 0.2.44: ProxyJump bastions are held to the upstream's known_hosts, and keyscan and login go through the bastion (sekimore-gw#220, sekimore-gw#221)
- `relay:verify` names the path-ledger edge each item probes, e.g. `[dev.egress.route_past_gateway]` (#99)
- `relay:refresh` rebuilds dev's Host blocks and proxy environment without Rebuild Container (#98)

## 0.2.41 (2026-09-25)

### Security

- takes sekimore-gw 0.2.43, which no longer hands out the upstream proxy password from `/api/config`
- `relay:verify` checks it: from dev, the gateway's API must not carry the upstream proxy password (#95)
- rotate the upstream proxy password after upgrading: the old one was readable from the dev container

## 0.2.40 (2026-09-25)

### Security

- takes sekimore-gw 0.2.42
- dev receives `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` from the gateway when an upstream proxy is configured; the shipped zsh rc.d snippet sources them, so ordinary traffic goes through the gateway instead of leaving directly (#91)
- `relay:verify` checks that dev's ordinary traffic cannot bypass the upstream when the gateway denies direct egress (#91)
- Rebuild Container is needed for the rc.d snippet

## 0.2.39 (2026-09-25)

### Fix

- takes sekimore-gw 0.2.41
- an upstream proxy that speaks TLS works again: the relay sends its HTTPS through the local Squid
- `relay:verify` probes HTTPS through the relay and one GitHub API call (#86)
- `relay:verify` and `upgrade.sh` read only the first line of `store-status` (#88)
- no file of yours changes

## 0.2.38 (2026-09-25)

### Enhancement

- takes sekimore-gw 0.2.40
- `relay:verify` prints OK in green and FAIL in red at a terminal, and the `gw:*` tasks let the relay's `check` and `store-status` color their state words (#84)
- `NO_COLOR` and `SEKIMORE_COLOR` decide otherwise
- no file of yours changes

## 0.2.37 (2026-09-25)

### Fix

- takes sekimore-gw 0.2.39: the relay speaks TLS to an `https://` upstream proxy before it sends the CONNECT, so a proxy that terminates TLS itself works
- Squid gets the stored upstream proxy credential after every restart, not only after a manual unlock; the gateway watches the secret store for as long as it runs
- the credential's state — none, locked or set — shows in `gw:check` and in the dashboard, with the command that fixes it
- no file of yours changes

## 0.2.36 (2026-09-25)

### Security

- takes sekimore-gw 0.2.38, which closes the host itself to dev: two INPUT rules on the host accept replies to connections the host opened and drop everything else from the internal bridge. dev can no longer reach the host, the published ports of every other container on the machine, or the Docker Desktop VM's services (#190)
- `relay:verify` checks it: the bridge's `.1` must not answer a ping from dev
- no file of yours changes; `pid: host` from base 0.2.35 is all the gateway needs

## 0.2.35 (2026-09-25)

### Security

- takes sekimore-gw 0.2.37, which confines the agent on the host: FORWARD rules in the host's `DOCKER-USER` chain let the internal bridge reach only the gateway, so a root process in dev can no longer route past it through Docker's NAT (#189)
- the sample's gateway service runs with `pid: host`, which those rules need. A project must add it to its own `.devcontainer/docker-compose.yml`; see [UPGRADING](UPGRADING.md#0237-the-gateway-needs-pid-host)
- `relay:verify` checks the bypass: a host route from dev through the bridge's own router must not reach the internet

## 0.2.34 (2026-09-24)

### Security

- takes sekimore-gw 0.2.36, which refuses a destination an allowed name may not reach: an allowlisted domain resolving into link-local (IMDS), loopback, RFC1918 or carrier-grade NAT is denied (#178)

## 0.2.33 (2026-09-24)

### Enhancement

- takes sekimore-gw 0.2.35, so the CLI and the agent guide in this image know `pr files` and `pr diff`, which read a pull request's diff under `pr:read` (#173)

## 0.2.32 (2026-09-24)

### Enhancement

- takes sekimore-gw 0.2.34, so the CLI and the agent guide in this image know `pr comment-edit` / `comment-delete` and the `issue` pair (#174)

## 0.2.31 (2026-09-24)

### Enhancement

- takes sekimore-gw 0.2.33, so the CLI and the agent guide in this image know `pr reply`, review comments on a line, `ci dispatch` and draft pull requests (#165 #167 #168 #169)

## 0.2.30 (2026-09-24)

### Fix

- a login shell finds the mise shims again, so `codex`, `node` and `npm` are on PATH there: Debian's `/etc/profile` assigns PATH rather than appending, throwing away the image's `ENV PATH` (#60)

### Enhancement

- the README starts with how to start: Getting started opens the file, and What's inside is a table rather than a list of ten-line items. The `FROM` line it shows is checked against the sample's, which had been four releases behind (#67)

## 0.2.29 (2026-09-24)

### Fix

- `post-start.sh` says so when a project's `post-create.sh` still defines `disable_vscode_credential_helper`: the copy 0.2.26 made unnecessary ends in a test that is false once the helper is gone, and `set -e` then stops the start with nothing said (#64)

## 0.2.28 (2026-09-24)

### Security

- the GitHub CLI (`gh`) is no longer baked in: it reaches `api.github.com` through the relay's 443 passthrough, which forwards without reading, so a `gh` holding a token acts with none of the per-action permissions the relay enforces. `sekimore` covers the same ground through the agent API (#62)

## 0.2.27 (2026-09-24)

### Enhancement

- takes sekimore-gw 0.2.32, so the CLI and the agent guide in this image know `refs/pr/<branch>` and the configurable branch template (#158)

## 0.2.26 (2026-09-23)

### Fix

- `post-start.sh` takes out the VS Code HTTPS credential helper on every start, with sudo for `/etc/gitconfig`; the copies of this in projects' `post-create.sh` could stop the start, and the sample's never reached the system file (#57)

## 0.2.25 (2026-09-23)

### Fix

- `sgw.sh` gives `docker exec` a terminal when the person has one, so `mise run dev:shell` opens a shell instead of hanging; it chose the flag inside `$(...)`, where stdout is always a pipe (#55)

## 0.2.24 (2026-09-23)

### Fix

- an apply or sync that replaces `upgrade.sh` ends by running the new one with `--owned`, so what a new release asks of your own files shows on the apply that brings it, not a run later (#54)

## 0.2.23 (2026-09-23)

### Fix

- `dev:shell` gets `raw = true`: in mise's prefix output mode its stdout was a pipe, so the shell started without a terminal and showed no prompt. CI now fails on any task that starts a shell or goes through `gw-tty` without `raw = true` (#51)
- `relay:verify` checks that `user.signingkey` is the key the gateway's signing socket offers, and says so when it is not — an inline `key::` value, or a key file the socket does not offer (#51)

### Enhancement

- takes gateway 0.2.31 (#51)

## 0.2.22 (2026-09-23)

### Fix

- `postStartCommand` runs the distributed `.devcontainer/sgw/post-start.sh`, which passes every `SEKIMORE_*` variable through `sudo` to agent-setup; a variable missing from a hand-kept `--preserve-env=` list was silently ignored, and the sample had none. `mise run upgrade` points at the one-line change, and a plain check now shows what the project's own files need (#49)

## 0.2.21 (2026-09-23)

### Enhancement

- takes gateway 0.2.30, and the sample runs gateway 0.2.30 with its task file (#47)

## 0.2.20 (2026-09-23)

### Enhancement

- `mise run upgrade` compares the pinned gateway and base with the newest on GHCR and says what would change; `upgrade:apply` rewrites the two tags, replaces `.devcontainer/sgw/`, recreates the gateway after asking and unlocks it, then lists only what a person has to do. A hand-edited distributed file stops it with the diff before anything is written. `upgrade:sync` replaces `gw:sync-tasks`, and `upgrade:notes` prints the UPGRADING sections in between (#45)
- the host scripts and tasks move into `.devcontainer/sgw/`, which `upgrade` owns; `mise.toml` keeps only the includes and the project's own tasks, and a task there wins over the distributed one of the same name. The sample moves to the layout and pins `FROM` to a version (#45)
- what `upgrade.sh`, `sgw.sh` and `vscode.sh` print, and the task descriptions, follow the relay's language rule: `SEKIMORE_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG` (#45)

## 0.2.19 (2026-09-22)

### Fix

- the sample devcontainer takes gateway 0.2.29 — the one this image takes — instead of the 0.2.19 it was pinned to, its comments are English throughout as the rest of the sample has been since 0.2.18, and `gw:sync-tasks` pulls the English task file out of the image, so the `gateway.mise.toml` committed beside it is 0.2.29's and has `gw:unlock-auto` (#41)
- `mise run web` opens the port the gateway actually publishes, read off the running container through the new `sgw.sh port <service> [container-port]`, instead of a number written into the task. The sample publishes `8080:8080` so its literal was right, which is what hid this: it breaks once a project moves the port because 8090 is taken, which is what a sample is copied in order to do (#42)

## 0.2.18 (2026-09-21)

### Fix

- the `sekimore` wrapper renews an expired project token again: it calls `POST /bootstrap` (`sekimore-relay agent bootstrap` never existed) and rewrites the env file in place, because its directory is root's (#38)

### Enhancement

- takes gateway 0.2.29 (#40)
- README.md is English and README.ja.md Japanese, as the other repositories are; the sample `config.yml` is commented in English and lists every key the gateway reads, all 28 permissions among them (#39)
- added this changelog, in English and Japanese, in the shape the gateway and the relay already use (#26)

## Before 0.2.18

Not written up: the pull request and the tag on each is the record. What is kept
here is the gateway each one took.

- 0.2.17 took gateway 0.2.15
- 0.2.16 took gateway 0.2.15
- 0.2.15 took gateway 0.2.14
- 0.2.14 took gateway 0.2.13
- 0.2.13 took gateway 0.2.13
- 0.2.12 took gateway 0.2.11
