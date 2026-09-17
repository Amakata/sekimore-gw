# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**AI Agent Security Gateway** - DNS/Firewall/Proxy for Docker

A security gateway designed for AI agent environments running in Docker. Provides DNS-based access control, iptables/ipset firewall management, and optional Squid proxy integration.

## Features

### Core Security

- **DNS-based Access Control**: Dynamic domain filtering with whitelist/blacklist support
- **Multi-layer Firewall**: Container-side and host-side iptables rules for defense in depth
- **DNS Exfiltration Protection**: Blocks unauthorized DNS queries from agents
- **Static IP Filtering**: CIDR and IP range support for additional access control

### Dynamic Configuration

- **Docker API Integration**: Auto-detects network configuration using Docker API
- **No Static Subnets**: Supports multi-organization deployments with dynamic subnet assignment
- **Automatic Discovery**: AI agents discover gateway via ARP-based subnet scanning

### Monitoring & Management

- **Web UI**: Real-time monitoring dashboard on port 8080
- **Packet Logging**: NFLOG-based firewall logging with ulogd2
- **SQLite Database**: Persistent storage for access logs and statistics (WAL, indexed; records are kept until an operator prunes them)
- **Maintenance CLI** (0.2.3): `python -m src.maint db-stats | db-prune --before-days N --yes | db-reset --yes | db-vacuum` inside the gateway container. Safe while the gateway is running. The relay audit (`/data/relay/audit.jsonl`) is separate and untouched. Dev Containers setups expose these as `mise run gw:db-stats` / `gw:db-prune` / `gw:db-reset`
- **Localized UI** (0.2.4): the Web UI ships in English and Japanese, chosen per viewer. See [Localization](#localization-024)

### Optional Components

- **Git / GitHub API Relay (sekimore-relay)**: Opt-in, in-container relay that lets AI agents use `git@github.com:…` and a small GitHub API CLI under a per-project policy, without ever holding upstream credentials. See [relay/README.md](relay/README.md)
- **Squid Proxy**: HTTP/HTTPS caching proxy with upstream proxy support
- **Corporate Proxy Integration**: Transparent proxy chaining for enterprise environments

## Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Linux host with iptables support

### Installation

1. Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/sekimore-gw.git
cd sekimore-gw
```

2. Copy the example configuration:

```bash
cp config/config.sample.yml config/config.yml
```

3. (Optional) Create `.env` file if you need upstream proxy authentication:

```bash
cp .env.example .env
# Edit .env and uncomment proxy authentication settings
```

4. Edit `config/config.yml` to configure allowed/blocked domains and IPs.

5. Start the gateway:

```bash
docker-compose up -d
```

6. Access the Web UI at `http://localhost:8080`

### Example: AI Agent Setup

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

## Configuration

### Environment Variables (Optional)

The `.env` file is optional. Create it only if you need upstream proxy authentication:

```bash
# Optional: Upstream Proxy Authentication
SEKIMORE_UPSTREAM_PROXY_USERNAME=your-username
SEKIMORE_UPSTREAM_PROXY_PASSWORD=your-password
```

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

0.2.11. The relay has its own changelog in [relay/CHANGELOG.md](relay/CHANGELOG.md).
