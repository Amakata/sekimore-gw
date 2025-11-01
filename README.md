# sekimore-gw

[![CI](https://github.com/Amakata/sekimore-gw/workflows/CI/badge.svg)](https://github.com/Amakata/sekimore-gw/actions)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/workflows/Docker%20Publish/badge.svg)](https://github.com/Amakata/sekimore-gw/actions)
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
- **SQLite Database**: Persistent storage for access logs and statistics

### Optional Components

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
cp .env.example .env
```

3. Edit `config/config.yml` to configure allowed/blocked domains and IPs.

4. Start the gateway:

```bash
docker-compose up -d
```

5. Access the Web UI at `http://localhost:8080`

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
    - ./scripts/agent-setup.sh:/agent-setup.sh:ro
  command: ["/agent-setup.sh"]
  depends_on:
    - sekimore-gw
```

The agent will automatically discover the gateway and route all traffic through it.

## Configuration

### Environment Variables

Create `.env` file:

```bash
COMPOSE_PROJECT_NAME=sekimore-gw
INTERNAL_NETWORK_NAME=internal-net
INTERNET_NETWORK_NAME=internet
```

### Domain Filtering

Edit `config/config.yml`:

```yaml
allow_domains:
  - pypi.org
  - .pythonhosted.org  # Wildcard: *.pythonhosted.org
  - api.openai.com

block_domains:
  - .malicious.com
```

### Proxy Configuration

```yaml
proxy:
  enabled: true
  port: 3128
  cache_enabled: true
  cache_size_mb: 1000
  upstream_proxy: "proxy.company.com:8080"  # Optional
```

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
docker pull ghcr.io/YOUR_USERNAME/sekimore-gw:latest
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

## Troubleshooting

### Agent can't find gateway

- Ensure `dns: [127.0.0.1]` is set (disables Docker internal DNS)
- Check subnet size: /24 or smaller works best
- Review agent logs: `docker logs <agent-container>`

### DNS resolution fails

- Verify `config/config.yml` has allowed domains
- Check Web UI for blocked requests
- View firewall logs: `docker logs sekimore-gw`

### Host-side firewall not working

- Ensure `privileged: true` in docker-compose.yml
- Check host iptables: `sudo iptables -L -n -v`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Version

v0.0.1 (Initial Release)
