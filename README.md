# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Let an AI agent work on GitHub without handing over your GitHub account.**

To let an agent open a pull request, you would normally give it a token. A token that can open a
pull request carries the `repo` scope, which grants **read and write access to every repository
your account can access**. Storing a key in a different place does not solve this, because an
agent with a terminal can read `~/.ssh` and `.env`.

sekimore-gw keeps that credential **outside the agent**. The agent holds only a disposable key and
a project token, and neither of them is valid anywhere except at the gateway:

```console
$ curl -H "Authorization: token $SEKIMORE_TOKEN" https://api.github.com/user
401 Bad credentials          # GitHub rejects the project token

$ sekimore pr create --title "..." --base main    # through the gateway: an allowed operation succeeds
#42 https://github.com/Org/Repo/pull/42

$ sekimore pr merge --number 42                   # an operation that is not allowed is rejected here
sekimore: denied: pr:merge is not allowed by policy
```

This setup does not use `gh`. A `gh` that holds a token connects to GitHub directly and bypasses
the gateway, so **none of the permissions configured here apply to it**: even when the policy
denies `pr:merge`, `gh pr merge` still succeeds. For this reason, the
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) image does not include
`gh`.

**Instead, the operator grants permissions one action at a time.**

```yaml
# config.yml — set per project
permissions: [pr:create, pr:read, issue:create, issue:comment, ci:read]
repos:
  - { name: Org/Repo, mode: read-write, bases: [main] }
```

The following 33 permissions are available:

```
pr:      create  read  comment  comment_update  comment_delete  review  request_review
         label  assign  close  merge
issue:   create  read  update  comment  comment_update  comment_delete  label  assign  close
ci:      read  rerun  dispatch          security: read  dismiss
release: create  read  publish          project:  read  add_item  update_item
repo:    read                           search:   read
```

The relay grants only the permissions that the configuration lists. When `permissions` is not
set, every permission is denied. Consequential permissions such as `pr:merge`, `ci:rerun`,
`ci:dispatch` and `security:dismiss` therefore stay denied until the operator adds them. The
operator can also add or remove permissions per repository.

The `sekimore` command provides all of these operations. `sekimore guide` prints the usage guide
written for the agent.

## Quick start

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # list the domains you allow
docker compose up -d                             # http://localhost:8080 for the dashboard
```

The gateway requires Docker 20.10 or later, Docker Compose 2.0 or later, and a Linux host on which
iptables works. If the host is behind an upstream proxy that requires credentials, run
`cp .env.example .env` and edit `.env` before you start the gateway.

**To use the gateway with a dev container, copy `examples/sgw-sample/` from
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) instead.** The sample
contains the gateway container, the dev container and the host-side tasks, already configured to
work together.

## Features

| | |
|---|---|
| **Git access without an agent key** | The agent holds a disposable key that only this gateway accepts. The gateway forwards each operation to GitHub with the operator's key. |
| **Per-action GitHub permissions** | The operator can deny `pr:merge` and allow `issue:create`, for example. No request reaches a repository outside the project. |
| **Destination allowlist** | A domain that is not allowlisted does not resolve. When the agent connects to an IP address directly, the firewall drops the connection. |
| **Upload cap** | The gateway counts the bytes that each connection sends to a destination the gateway handles. It cuts a connection that exceeds the limit and records the event in the audit log. |
| **Audit log** | The audit log records allowed operations as well as refusals. |
| **Commit signing by the gateway** | The gateway holds the signing key. The agent can request a signature but has no other access to the key. GitHub shows the resulting commits as Verified. |

For a dev container, [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base)
provides the dev side of this setup.

## When to use it

**sekimore-gw is a good fit** when you want an agent to work on GitHub within limits: it can open
a pull request but not merge it, it can access this repository and no other, it signs every
commit, it cannot send more than a set amount of data, and every operation is recorded. The agent
holds no upstream credential throughout.

**sekimore-gw is not a good fit** in the following cases, where a smaller or a different tool
serves better:

| | |
|---|---|
| API restrictions for an upstream other than GitHub | The SSH git relay works with any Git host, but **the API translation supports only GitHub**. The gateway can allowlist GitLab or an internal Artifactory as a domain, or pass it through port 443 with an upload cap, but cannot restrict it further. [#50](https://github.com/Amakata/sekimore-gw/issues/50) tracks changing this. |
| Rules based on request content | The gateway does not terminate TLS, so it sees the destination and the byte count but not the request itself (for example, `GET /v1/public/`). In exchange, no MITM certificate is required. |
| Network restriction alone | The four layers and the relay exist to restrict what an agent can do on GitHub. If you only need to restrict destinations, a simpler tool is sufficient. |
| An agent that does not use GitHub | If a person runs the git commands, the relay has no role. |

## How it works

sekimore-gw builds four layers from one file (`config.yml`). The layers are configured together
because **restricting only one layer leaves the others open as a bypass**.

| Layer | Role |
|---|---|
| **DNS** (:53) | Returns a real IP address only for an allowlisted domain, and admits that address in the firewall at the same time. Domains that the gateway handles resolve to the gateway itself. |
| **Firewall** | Uses iptables and ipset. Allows only the destinations and ports that DNS admitted. A connection to an IP address that the agent specifies directly stops here. |
| **Squid** (:3128) | Blocks bypass through a proxy. Squid resolves names on its own, so DNS filtering alone does not cover it. |
| **Relay** (sekimore-relay) | Handles git (SSH :22), the GitHub API (:8420) and other HTTPS (:443). **The relay is the only component that holds upstream credentials.** |

For details, see [Architecture](#architecture), and see [relay/README.md](relay/README.md) for
the relay.

## Other features

- **Web UI** (:8080): Shows traffic in real time. The UI is available in English and Japanese, and each viewer selects a language.
- **Packet log**: Records packets with NFLOG through ulogd2.
- **SQLite**: Stores the access log and statistics (in WAL mode, with indexes). The `mise run gw:db-prune` task and the related `gw:db-*` tasks remove records.
  The relay's audit log (`/data/relay/audit.jsonl`) is a separate file, and these tasks do not modify it.
- **Squid and corporate proxies**: The gateway works behind an upstream proxy.
- **No fixed subnet**: The gateway reads the network layout from the Docker API, so it continues to work when Docker assigns a different subnet.

## Example: AI agent setup

`docker-compose.yml` defines a sample agent, the `ai-agent` service, which starts with the other services:

```yaml
ai-agent:
  build:
    context: .
    dockerfile: Dockerfile.agent
  cap_add:
    - NET_ADMIN            # the agent sets its own default route
  networks:
    internal-net: {}
  dns:
    - 127.0.0.1            # disables Docker's internal DNS (127.0.0.11), which would bypass the filter
  dns_search: []
  volumes:
    - ./agent-setup.sh:/agent-setup.sh:ro
  command: ["bash", "-c", "/agent-setup.sh && sleep infinity"]
  depends_on:
    sekimore-gw:
      condition: service_healthy
```

The agent discovers the gateway automatically and routes all traffic through it.

### Operator tasks (mise)

The image includes the `gw:*` tasks that an operator uses to control the gateway, in two
languages: `/usr/local/share/sekimore/gateway.mise.en.toml` and `gateway.mise.ja.toml`. A project
includes one of these files instead of copying the tasks, because a copy does not receive the
updates that accompany relay changes. From sgw-devcontainer-base 0.2.20, `mise run upgrade:sync`
(or `upgrade:apply`) takes the file from the gateway's release tag and writes it to
`.devcontainer/sgw/gateway.mise.toml`, next to `sgw.sh`. Do not edit that file. If it has been
edited by hand, the next upgrade stops instead of overwriting it. To change a `gw:*` task, define
a task with the same name in the project's own `mise.toml`; that definition takes precedence over
the included one.

The language choice affects only the descriptions that `mise tasks` prints. The task names and the
commands they run are identical in both files, and a test verifies this.

```toml
# the project's mise.toml
[task_config]
includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
```

The project owns `sgw.sh`. The script locates the gateway container, so the image cannot provide
it. The tasks use only four of its subcommands: `gw`, `gw-tty`, `id` and `recreate`. `gw-tty`
always runs `docker exec -it`. `gw:unlock` and `gw:passphrase` require it because they read a
passphrase from the terminal.

Since 0.2.29, the operator does not have to type the passphrase each time the gateway is
recreated. `mise run gw:keychain-set` stores the passphrase once in the host's own secret store:
the macOS Keychain, the Secret Service (through `secret-tool`), or a root-owned file under
`/etc/sekimore`. `gw:recreate` then unlocks the gateway's store automatically. Set
`SGW_NO_AUTO_UNLOCK=1` to leave the store locked. The gateway itself is not involved: the
passphrase still arrives over the control socket, and nothing inside the container can retrieve
it from the host. `gw:unlock` is unchanged, and it remains the way to unlock the store when the
host has no stored passphrase.

## Configuration

### Upstream proxy authentication

Store the corporate proxy's credentials in the secret store, not in `.env`:

```bash
mise run gw:proxy-credential      # prompts for the username and the password; stores them sealed
```

Once the store is unlocked, Squid and the relay (for its HTTPS passthrough and its GitHub API
calls) both read the credentials from it, and both apply a change without a restart.
`mise run gw:check` shows which credentials the relay presents. When the store holds no
credentials, the gateway still reads `SEKIMORE_UPSTREAM_PROXY_USERNAME` and
`SEKIMORE_UPSTREAM_PROXY_PASSWORD`. However, `.devcontainer/.env` is also the dev container's
`env_file`, so the agent can read any value stored there.

**Note**: Docker Compose uses the directory name as the project name by default. The gateway uses
the default network names `internal-net` and `internet`. To use different names, set the
`INTERNAL_NETWORK_NAME` and `INTERNET_NETWORK_NAME` environment variables.

### Domain filtering

Edit `config/config.yml`:

```yaml
allow_domains:
  - pypi.org
  - .pythonhosted.org  # Wildcard: *.pythonhosted.org
  - api.openai.com

block_domains:
  - .malicious.com

network:
  allowed_ports: [80, 443]   # Optional (0.2.2): destination TCP ports allowed towards allowlisted
                             # domains/IPs. Empty (default) keeps the previous behavior (all ports).
```

Restricting `allowed_ports` closes bypass routes such as SSH to an allowlisted IP address. A change
to `allowed_ports` requires a container restart.

### Proxy configuration

```yaml
proxy:
  enabled: true
  port: 3128
  cache_enabled: true
  cache_size_mb: 1000
  upstream_proxy: "proxy.company.com:8080"  # Optional
```

## Localization (0.2.4)

English is the primary language. Japanese is available wherever a person reads text, and text
that machines read stays in English.

### Web UI

The dashboard text comes from `src/locales/<lang>.json` (`en`, `ja`). `/api/i18n` resolves the
language and returns the dictionary, and the page applies it through `data-i18n` attributes. The
language selector in the header sets a `sekimore_lang` cookie (one year, `SameSite=Lax`) and
reloads the page.

The Web UI resolves the language in the following order, and the first match wins:

| Order | Source | Notes |
|-------|--------|-------|
| 1 | `?lang=en` / `?lang=ja` query parameter | One-off override, useful for links and screenshots |
| 2 | `sekimore_lang` cookie | Set by the language selector; per viewer |
| 3 | `ui.language` in `config.yml` | Applies only when the value is not `auto`; sets the language for every viewer |
| 4 | `Accept-Language` | The browser's preference |
| 5 | English | Default |

To keep the language from following the browser, set it in `config/config.yml`:

```yaml
ui:
  language: auto   # auto | en | ja  (default: auto)
```

An unsupported language tag falls back to English, and a key that is missing from a translation
falls back to the English string. A partial translation therefore never leaves a blank in the UI.

### CLI

Command-line tools read the environment instead of the configuration file. They check
`SEKIMORE_LANG`, `LC_ALL`, `LC_MESSAGES` and `LANG` in that order, and default to English. This
applies to `python -m src.maint` in the gateway container and to the Rust `sekimore-relay` binary.

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

### What stays in English

Denial messages (the `sekimore: ...` lines that the relay writes to stderr) and the audit log are
always in English, regardless of the locale. Scripts, CI and AI agents match on this text, so it
must not change with the operator's language.

### Documentation

The documentation is written in English, with a Japanese translation (`*.ja.md`) next to each
file: this file and [README.ja.md](README.ja.md), and [relay/README.md](relay/README.md) and
[relay/README.ja.md](relay/README.ja.md).

## Architecture

```
┌─────────────┐       ┌──────────────┐       ┌──────────┐
│ AI Agent    │──────▶│ sekimore-gw  │──────▶│ Internet │
│ (internal)  │       │ (gateway)    │       │          │
└─────────────┘       └──────────────┘       └──────────┘
                             │
                             │ Web UI :8080
                             ▼
                       ┌──────────┐
                       │ Browser  │
                       └──────────┘
```

### Network design

- **internal-net**: The network that AI agents connect to (dynamic subnet)
- **internet**: The gateway's external interface (dynamic subnet)
- **Host-side firewall**: An additional layer that blocks unauthorized traffic

### Security layers

1. **DNS filtering**: Name resolution only for allowlisted domains
2. **Container firewall**: iptables/ipset rules inside sekimore-gw
3. **Host firewall**: Additional iptables rules on the Docker host
4. **DNS exfiltration protection**: Port 53 blocked for every host except the gateway

## Development

### Requirements

- Python 3.11 or later
- [uv](https://github.com/astral-sh/uv) (Python package manager)

### Setup

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Run linter
uv run ruff check src/
uv run ruff format src/

# Type check
uv run mypy src/
```

### Testing

```bash
# Unit tests
uv run pytest tests/unit/ -v

# Integration tests (includes timeout tests for infinite loop detection)
uv run pytest tests/integration/ -v

# All tests except E2E (for CI and the dev container)
uv run pytest -m "not e2e" -v

# E2E tests (require docker compose; run on the host machine only)
uv run pytest tests/e2e/ -v

# With coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

**E2E testing notes:**
- The E2E tests (`tests/e2e/`) verify actual port binding and Docker integration.
- They must run on a host machine with `docker compose`, not in CI or in a dev container.
- The tests cover:
  - The DNS server binding to port 53
  - Subnet auto-detection through the Docker API
  - Actual DNS query responses
- Run them with `pytest tests/e2e -v` after stopping any existing containers.

## Docker images

### Build locally

```bash
docker build -t sekimore-gw:latest .
```

### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/Amakata/sekimore-gw:latest
```

### Preview images

Pull requests and pushes to `main` build an image for verification. **These images are not
releases.**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # the image for that pull request
docker pull ghcr.io/Amakata/sekimore-gw:main    # the tip of main
```

Preview images are built for `linux/arm64` only. The next push overwrites the tag, so no
long-running deployment should reference it. Version tags (`:0.2.14`) and `:latest` are created
only from a `v*.*.*` Git tag.

Preview images separate deploying a change for testing from publishing a version. Without them,
testing a change on a real machine would require a release.

## Multi-organization support

Each organization can run an isolated instance by using a different `COMPOSE_PROJECT_NAME`:

```bash
# Organization A
COMPOSE_PROJECT_NAME=sekimore-org-a docker compose up -d

# Organization B
COMPOSE_PROJECT_NAME=sekimore-org-b docker compose up -d
```

The networks and subnets of each instance are isolated automatically.

## Git / GitHub API relay (sekimore-relay)

The relay is optional. When `config.yml` declares
`domain_handlers: { github.com: { handler: git-relay } }`, the gateway starts `sekimore-relay`, a
Rust program bundled in the image. With the relay enabled:

- DNS resolves `github.com` to the gateway.
- The relay accepts `git` over SSH on port 22 and authenticates agents by their disposable keys.
- The relay enforces a per-project policy: the allowed repositories, read-only or read-write mode,
  the allowed pull request base branches, and permissions such as `pr:create` and `issue:comment`.
- The relay converts `git push HEAD:refs/for/main` into a branch and a pull request.
- The relay forwards requests to the real upstream with the operator's ssh-agent and a
  device-flow token that agents never see.

Without `domain_handlers`, the relay does not start and the gateway's behavior is unchanged.

For setup, agent-side steps, daily usage and troubleshooting, see
**[relay/README.md](relay/README.md)**.

## Troubleshooting

### The agent cannot find the gateway

- Make sure that `dns: [127.0.0.1]` is set. This setting disables Docker's internal DNS.
- Check the subnet size. The agent scans the entire subnet only when the prefix length is 24 or
  more (256 addresses or fewer, for example /24 or /25). On a larger subnet, it checks only
  selected addresses.
- Check the agent logs: `docker logs <agent-container>`

### DNS resolution fails

- Verify that `config/config.yml` lists the allowed domains.
- Check the Web UI for blocked requests.
- Check the firewall logs: `docker logs sekimore-gw`

### The Web UI is slow or the database is large

- `docker compose exec sekimore-gw python -m src.maint db-stats` shows the row counts, the time range, the indexes and `journal_mode`. On 0.2.3 and later, `journal_mode` is `wal`.
- The gateway never deletes records automatically. To delete old records, run `python -m src.maint db-prune --before-days 90 --yes --vacuum`. To start over with an empty database, run `python -m src.maint db-reset --yes`.
- Both commands work while the gateway is running. DNS, the firewall and the proxy continue to record afterward.

### The host-side firewall does not work

- Make sure that `privileged: true` is set in docker-compose.yml.
- Check the host iptables rules: `sudo iptables -L -n -v`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

## Version

The gateway and the relay ship in one image and share one version number.

- [CHANGELOG.md](CHANGELOG.md) — the gateway: DNS, the firewall, Squid, the Web UI and the build
- [relay/CHANGELOG.md](relay/CHANGELOG.md) — the relay

Each changelog lists the current version first.
