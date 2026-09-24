# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**A gateway that keeps the keys, so the agent's environment does not have to.**

Everything leaving the container an AI agent runs in comes through here. **The agent holds no
upstream credential at all** — the keys and tokens stay on this side, and what gets through is
git and the GitHub operations the project allows, and nothing else.

## Quick Start

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # list the domains you allow
docker compose up -d                             # http://localhost:8080 for the dashboard
```

Needs Docker 20.10+, Docker Compose 2.0+, and a Linux host where iptables works.
Behind an upstream proxy that wants a password, `cp .env.example .env` first and edit it.

**For a DevContainer, copy `examples/sgw-sample/` from
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) instead** — it has
the gateway and dev containers together with the host-side tasks, already wired up.

## What it gets you

| | |
|---|---|
| **git without giving the agent a key** | It holds a disposable key only this gateway accepts. What reaches GitHub is what the gateway sent on with the operator's key |
| **GitHub actions allowed one at a time** | `pr:merge` refused, `issue:create` allowed, and so on. Nothing reaches a repository outside the project |
| **Somewhere to go, and nowhere else** | An unlisted domain does not resolve, and naming its IP directly gets dropped by the firewall |
| **A cap on what can leave** | The gateway counts the bytes sent to the destinations it handles, and cuts the connection when they pass the limit |
| **A record of what happened** | Not only refusals: what went through is in the audit log too |
| **Signing, done for the agent** | The signing key is the gateway's; the agent can ask for a signature and nothing more. Commits come out Verified |

For a DevContainer, the dev side of this is
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base).

## When it fits, and when it does not

**It fits** when you want an agent to work on GitHub but not to have the run of it: open a
pull request but not merge it, touch this repository and no other, sign every commit, stay
under a cap on what leaves, and leave a record of all of it — with no upstream credential in
the agent's hands.

**It does not fit** in these cases, where something smaller or something else will serve you
better:

| | |
|---|---|
| Narrowing the API of an upstream that is not GitHub | The SSH git half is not tied to a forge, but **the half that translates the API is GitHub's**. GitLab or an internal Artifactory can be allowed as a domain, or passed through 443 with an upload cap, and no further ([#50](https://github.com/Amakata/sekimore-gw/issues/50) is about changing that) |
| Rules on the content of a request | TLS is not terminated, so the gateway sees the destination and the byte count, not `GET /v1/public/`. That is the trade for needing no MITM certificate |
| Only closing the network | The four layers and the relay are there to narrow what an agent may do on GitHub. To restrict destinations alone, less will do |
| An agent that never touches GitHub | If a person runs the git commands, the relay has nothing to do |

## How it works

Four layers, built from one file (`config.yml`), because **fixing only one of them leaves the
others as a way around it**.

| Layer | What it decides |
|---|---|
| **DNS** (:53) | Returns a real IP only for an allowed domain, and admits the traffic at the same time. Domains the gateway handles resolve to the gateway itself |
| **Firewall** | iptables / ipset. Only the destinations and ports DNS admitted. Naming an IP directly ends here |
| **Squid** (:3128) | Closes the way round through a proxy. Squid resolves names on its own, so DNS alone is not enough |
| **The relay** (sekimore-relay) | git (SSH :22), the GitHub API (:8420) and other HTTPS (:443). **The only part holding an upstream credential** |

See [Architecture](#architecture), and [relay/README.md](relay/README.md) for the relay.

## Also in here

- **Web UI** (:8080): live traffic, in English and Japanese, per viewer
- **Packet log**: NFLOG through ulogd2
- **SQLite**: access log and statistics (WAL + indexes); pruned with `mise run gw:db-prune` and friends.
  The relay's audit log (`/data/relay/audit.jsonl`) is kept separately and none of those touch it
- **Squid / corporate proxy**: works behind an upstream proxy
- **No fixed subnet**: the Docker API reports the layout, so a changing allocation is fine

## Example: AI Agent Setup

Uncomment the `ai-agent` service in `docker-compose.yml` and start:

```yaml
ai-agent:
  image: python:3.11-slim
  cap_add:
    - NET_ADMIN
  networks:
    internal-net: {}
  dns:
    - 127.0.0.1  # Disable Docker internal DNS
  dns_search: []
  volumes:
    - ./agent-setup.sh:/agent-setup.sh:ro
  command: ["/agent-setup.sh"]
  depends_on:
    - sekimore-gw
```

The agent will automatically discover the gateway and route all traffic through it.

### Operator tasks (mise)

The `gw:*` tasks an operator drives the gateway with are shipped in the image, in two languages:
`/usr/local/share/sekimore/gateway.mise.en.toml` and `gateway.mise.ja.toml`. A project includes
one of them rather than keeping a copy of the tasks, which falls behind the relay. From
sgw-devcontainer-base 0.2.20 on, `mise run upgrade:sync` (or `upgrade:apply`) takes the file from
the gateway's release tag and writes it to `.devcontainer/sgw/gateway.mise.toml`, beside `sgw.sh`.
Do not edit that copy — an edit by hand stops the next upgrade. To change a `gw:*` task, define one
with the same name in the project's own `mise.toml`; mise prefers it.

The choice of language only decides what `mise tasks` prints; the task names and the commands
they run are identical in both, and a test holds them to that.

```toml
# the project's mise.toml
[task_config]
includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
```

The project owns `sgw.sh` (it is what finds the container, so it cannot come from the image). The
tasks use only its `gw`, `gw-tty`, `id` and `recreate` subcommands. `gw-tty` — `docker exec -it`
unconditionally — is required by `gw:unlock` and `gw:passphrase`, which read a passphrase from the
terminal.

Since 0.2.29 the passphrase does not have to be typed after every recreate. `mise run
gw:keychain-set` puts it in the host's own secret store — the macOS Keychain, a Secret Service, or
a root-owned file under `/etc/sekimore` — and `gw:recreate` unlocks with it by itself
(`SGW_NO_AUTO_UNLOCK=1` leaves the store locked). The gateway takes no part in it: the passphrase
still arrives over the control socket, and nothing inside the container can go and look for it.
`gw:unlock` is unchanged, and is still the way in when nothing is stored.

## Configuration

### Upstream proxy authentication

Put the corporate proxy's credential in the secret store, not in `.env`:

```bash
mise run gw:proxy-credential      # prompts for the username and the password; stored sealed
```

Squid and the relay (its HTTPS passthrough and its GitHub API calls) both read it from the store
once it is unlocked, and pick up a change without a restart. `mise run gw:check` shows which
credential the relay presents. `SEKIMORE_UPSTREAM_PROXY_USERNAME` / `_PASSWORD` are still read when
the store holds none, but `.devcontainer/.env` is also the dev container's `env_file`, so a value
there is readable by the agent.

**Note**: Docker Compose automatically uses the directory name as the project name. Network names use default values (`internal-net` and `internet`). Override these with environment variables if needed.

### Domain Filtering

Edit `config/config.yml`:

```yaml
allow_domains:
  - pypi.org
  - .pythonhosted.org  # Wildcard: *.pythonhosted.org
  - api.openai.com

block_domains:
  - .malicious.com

network:
  allowed_ports: [80, 443]   # Optional (0.2.2): destination TCP ports allowed towards allow-listed
                             # domains/IPs. Empty (default) keeps the previous behaviour (all ports).
```

Restricting `allowed_ports` closes bypass routes such as SSH to an allow-listed IP. Changing it requires a container restart.

### Proxy Configuration

```yaml
proxy:
  enabled: true
  port: 3128
  cache_enabled: true
  cache_size_mb: 1000
  upstream_proxy: "proxy.company.com:8080"  # Optional
```

## Localization (0.2.4)

English is the primary language. Japanese is available everywhere a human reads text; anything a machine reads stays English.

### Web UI

The dashboard is translated from `src/locales/<lang>.json` (`en`, `ja`). `/api/i18n` resolves the language and returns the
dictionary, which the page applies through `data-i18n` attributes. The language selector in the header sets a
`sekimore_lang` cookie (one year, `SameSite=Lax`) and reloads.

Resolution order, first match wins:

| Order | Source | Notes |
|-------|--------|-------|
| 1 | `?lang=en` / `?lang=ja` query parameter | One-off override, handy for links and screenshots |
| 2 | `sekimore_lang` cookie | What the language selector sets; per viewer |
| 3 | `ui.language` in `config.yml` | Only when it is not `auto` - pins the language for everyone |
| 4 | `Accept-Language` | The browser's preference |
| 5 | English | Default |

Pin the language in `config/config.yml` if you do not want it to follow the browser:

```yaml
ui:
  language: auto   # auto | en | ja  (default: auto)
```

Unsupported tags fall back to English, and a key missing from a translation falls back to the English string, so a
partial translation never leaves a blank in the UI.

### CLI

Command-line tools follow the environment instead of the config file: `SEKIMORE_LANG`, then `LC_ALL`, `LC_MESSAGES`,
`LANG`, defaulting to English. This covers `python -m src.maint` in the gateway container and the Rust `sekimore-relay`
binary.

```bash
SEKIMORE_LANG=ja python -m src.maint db-stats
```

### What stays English

Denial messages (the `sekimore: ...` lines the relay writes to stderr) and the audit log are always English, whatever the
locale. Scripts, CI and AI agents match on that text, so it must not shift with the operator's language.

### Documentation

Docs are English-primary with `*.ja.md` translations alongside - this file and [README.ja.md](README.ja.md),
[relay/README.md](relay/README.md) and [relay/README.ja.md](relay/README.ja.md).

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

### Network Design

- **internal-net**: AI agents connect here (dynamic subnet)
- **internet**: Gateway's external interface (dynamic subnet)
- **Host-side firewall**: Additional layer blocking unauthorized traffic

### Security Layers

1. **DNS Filtering**: Only allowed domains resolve
2. **Container Firewall**: iptables/ipset rules within sekimore-gw
3. **Host Firewall**: Additional iptables rules on Docker host
4. **DNS Exfiltration Protection**: Port 53 blocked except from gateway

## Development

### Requirements

- Python 3.11+
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

# All tests except E2E (for CI/devcontainer)
uv run pytest -m "not e2e" -v

# E2E tests (requires docker-compose, run on host machine only)
uv run pytest tests/e2e/ -v

# With coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

**E2E Testing Notes:**
- E2E tests (`tests/e2e/`) verify actual port binding and Docker integration
- Must be run on a host machine with docker-compose (not in CI or devcontainer)
- Tests include:
  - DNS server actually binds to port 53
  - Docker API subnet auto-detection
  - Actual DNS query responses
- Run with: `pytest tests/e2e -v` (requires stopping existing containers first)

## Docker Images

### Build Locally

```bash
docker build -t sekimore-gw:latest .
```

### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/Amakata/sekimore-gw:latest
```

### Preview Images

Pull requests and pushes to `main` build an image for verification. **These are
not releases.**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # that pull request
docker pull ghcr.io/Amakata/sekimore-gw:main    # the tip of main
```

`linux/arm64` only. The tag is rewritten by the next push, so nothing long-lived
should point at it. Version numbers (`:0.2.14`) and `:latest` come only from a
`v*.*.*` tag.

Without these, trying a change on a real machine means cutting a release — which
is what separates deploying for work from publishing a version.

## Multi-Organization Support

Each organization can run isolated instances using different `COMPOSE_PROJECT_NAME`:

```bash
# Organization A
COMPOSE_PROJECT_NAME=sekimore-org-a docker-compose up -d

# Organization B
COMPOSE_PROJECT_NAME=sekimore-org-b docker-compose up -d
```

Networks and subnets are automatically isolated.

## Git / GitHub API Relay (sekimore-relay)

Optional. When `config.yml` declares `domain_handlers: { github.com: { handler: git-relay } }`, the gateway starts
`sekimore-relay` (Rust, bundled in the image): DNS points `github.com` at the gateway, the relay accepts `git` over SSH
on port 22 with disposable agent keys, enforces a per-project policy (allowed repos, read-only / read-write, PR base
branches, `pr:create` / `issue:comment` … permissions), turns `git push HEAD:refs/for/main` into a branch + pull request,
and forwards to the real upstream with the operator's ssh-agent and a device-flow token that agents never see.
Without `domain_handlers` nothing changes.

Setup, agent-side steps, daily usage and troubleshooting: **[relay/README.md](relay/README.md)**.

## Troubleshooting

### Agent can't find gateway

- Ensure `dns: [127.0.0.1]` is set (disables Docker internal DNS)
- Check subnet size: /24 or smaller works best
- Review agent logs: `docker logs <agent-container>`

### DNS resolution fails

- Verify `config/config.yml` has allowed domains
- Check Web UI for blocked requests
- View firewall logs: `docker logs sekimore-gw`

### Web UI is slow or the database is large

- `docker compose exec sekimore-gw python -m src.maint db-stats` shows row counts, time range, indexes and `journal_mode` (should be `wal` since 0.2.3)
- Records are never deleted automatically. To trim: `python -m src.maint db-prune --before-days 90 --yes --vacuum`; to start over: `python -m src.maint db-reset --yes`
- Both work while the gateway is running; DNS / firewall / proxy keep recording afterwards

### Host-side firewall not working

- Ensure `privileged: true` in docker-compose.yml
- Check host iptables: `sudo iptables -L -n -v`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Version

One image carries the gateway and the relay, under one version number.

- [CHANGELOG.md](CHANGELOG.md) — the gateway: DNS, the firewall, Squid, the Web UI, the build
- [relay/CHANGELOG.md](relay/CHANGELOG.md) — the relay

Both lead with the current version.
