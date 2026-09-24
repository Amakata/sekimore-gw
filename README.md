# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Let an AI agent work on GitHub without handing over your account.**

sekimore-gw (sgw) is a network gateway for AI agents in Docker.

- One container, four layers: DNS, firewall, Squid, relay. One `config.yml`.
- The relay holds the operator's GitHub credentials. The agent holds nothing that works outside the gateway.
- Permissions are granted per action: `pr:create` allowed, `pr:merge` denied.

## Why not a token

- Any token in the agent's container is readable. So are `~/.ssh` and `.env`.
- A classic `repo` token: read and write on every repository the account can reach.
- A fine-grained token narrows repositories, not actions. "Pull requests: write" both opens and merges.
- Neither records what the agent did. Neither caps what it sends.

```console
# anywhere: the project token means nothing to GitHub
$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token skm_..." https://api.github.com/user
401

# in the dev container: allowed by the policy
$ sekimore pr create --head sekimore/topic --base main --title "..."
#42 https://github.com/Org/Repo/pull/42

# in the dev container: not allowed
$ sekimore pr merge --number 42
sekimore: denied: pr:merge is not allowed by policy
```

`gh` is not part of this setup. With a token, it would bypass every permission here. The dev-container image does not include it.

## Get started

### A. Dev container (recommended)

Use the `examples/sgw-sample/` template in [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base).
Its README goes from clone to a verified relay.

### B. Gateway only

DNS allowlist, firewall, Squid and the dashboard. No relay.

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # allow_domains: what the agent may reach
docker compose up -d                             # dashboard: http://localhost:8080
```

To add the relay:

- Set `domain_handlers` and `relay` in `config.yml`. The template is at the end of `config.sample.yml`. See [relay/README.md](relay/README.md).
- Give the agent container `agent-setup.sh`, the `sekimore-relay` CLI and the `sekimore` wrapper. The `ai-agent` service in `docker-compose.yml` is a minimal example.

Behind a proxy that requires credentials, standalone gateway:

```bash
cp .env.example .env    # SEKIMORE_UPSTREAM_PROXY_USERNAME / _PASSWORD
```

Dev-container setup (`.devcontainer/.env` is readable by the agent, so use the secret store):

```bash
mise run gw:proxy-credential -- set
```

## How it works

Four layers from one `config.yml`. Restricting one leaves the others as a bypass.

| Layer | Role |
|---|---|
| **DNS** (:53) | Resolves allowlisted domains only. Opens the firewall for the returned addresses. Relay domains resolve to the gateway. |
| **Firewall** (iptables, ipset) | Forwards only to addresses and ports that DNS admitted. Drops direct-IP connections. `network.allowed_ports` limits ports; unset means all ports. |
| **Squid** (:3128) | The agent's HTTP proxy. Resolves names itself, so it carries the same allowlist. Refuses relay domains. |
| **Relay** (sekimore-relay) | git over SSH (:22), GitHub API (:8420), HTTPS passthrough (:443). The only holder of upstream credentials. |

The relay:

- enforces a per-project policy: repositories, read-only or read-write, 33 permissions, pull request base branches
- turns `git push HEAD:refs/for/main` into a branch and a pull request
- signs commits with a key the agent can use but not read
- caps uploads through the 443 passthrough
- logs allowed and refused operations

The relay is optional. Without `domain_handlers`, the first three layers run alone.
Details: [relay/README.md](relay/README.md).

## When to use it

Fits when the agent should:

- open a pull request, not merge it
- reach this repository, no other
- sign every commit
- stay under an upload cap on the HTTPS passthrough
- leave a record of every operation
- hold no upstream credential

Does not fit:

| Case | Why |
|---|---|
| API rules for an upstream other than GitHub | Git over SSH works with any host. API translation is GitHub only. GitLab or Artifactory: allowlist, or 443 passthrough with a cap. [#50](https://github.com/Amakata/sekimore-gw/issues/50) |
| Rules on request content | TLS is not terminated. Destination and byte count only. No MITM certificate needed. |
| Destinations only | A plain allowlist needs less than this. |
| An agent that does not use GitHub | The relay has no role. |

## Requirements

- Docker 20.10 or later, Docker Compose 2.0 or later
- A Linux host, or Docker Desktop on macOS (the layers run inside the Docker VM)
- The gateway runs with `NET_ADMIN` and `privileged: true` (see `docker-compose.yml`)
- Agent containers: `dns: [127.0.0.1]`, and `agent-setup.sh` to find the gateway and set the default route
- `network.allowed_ports` is unset by default, so every port is open. Set `[80, 443]` unless the agent needs more. A change requires a restart.

## Names

| Name | What it is |
|---|---|
| sekimore-gw, sgw | This gateway. `sgw` appears in sgw-devcontainer-base, `sgw.sh` and `.devcontainer/sgw/`. |
| sekimore-relay | The relay daemon in the gateway, and the CLI of the same name in the dev container. |
| `sekimore` | The wrapper in the dev container. Runs `sekimore-relay agent …`. `sekimore guide` prints the agent's guide. |
| sgw-devcontainer-base | The dev-container image. `examples/sgw-sample/` is the project template. |
| `.devcontainer/sgw/`, `gw:*` | Host-side scripts and mise tasks. Distributed with the images, replaced by `mise run upgrade:apply`. |

## Documentation

- [relay/README.md](relay/README.md) — relay setup, agent-side steps, everyday use, configuration reference, permission catalog
- [config/config.sample.yml](config/config.sample.yml) — every key, with its default and a comment
- [docs/localization.md](docs/localization.md) — Web UI and CLI in English and Japanese
- [CONTRIBUTING.md](CONTRIBUTING.md) — development, tests, images
- [CHANGELOG.md](CHANGELOG.md), [relay/CHANGELOG.md](relay/CHANGELOG.md) — one image, one version number
- [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) — the dev-container side

## Troubleshooting

**The agent cannot find the gateway**

- Check `dns: [127.0.0.1]` on the agent container
- Check the agent's logs: `docker logs <agent-container>`
- `agent-setup.sh` scans the whole subnet only when the prefix length is 24 or more

**A domain does not resolve**

- Check `allow_domains` in `config/config.yml`
- Blocked requests: the Web UI, or `docker logs sekimore-gw`

**The database is large**

Run in the gateway container (the `gw:db-*` mise tasks wrap these):

```bash
python -m src.maint db-stats                                   # size and row counts
python -m src.maint db-prune --before-days 90 --yes --vacuum   # delete old records
```

The relay's audit log (`/data/relay/audit.jsonl`) is a separate file. These commands do not touch it.

## License

Apache License 2.0 — [LICENSE](LICENSE).
