# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Let an AI agent work on GitHub without handing over your account.**

sekimore-gw (short form: sgw) is a network gateway for AI agents that run in Docker. One
container holds four layers — DNS, a firewall, Squid and a relay — configured from one file. The
relay is the part that matters for GitHub: it holds the operator's credentials, and the agent
holds nothing that works outside the gateway.

## Why a token is not enough

Any token the agent holds is readable: an agent with a terminal reads `~/.ssh` and `.env`. A
classic token with the `repo` scope grants read and write access to every repository the account
can reach. A fine-grained token narrows the repositories but not the actions: "Pull requests:
write" covers opening a pull request and merging it. Neither records what the agent did or caps
what it sends.

sekimore-gw keeps the credential in the gateway. The agent holds a disposable SSH key and a
project token, and both are valid only at the gateway. The operator grants permissions one action
at a time, for example `pr:create` allowed and `pr:merge` denied.

```console
# anywhere, including outside the container: the project token means nothing to GitHub
$ curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: token skm_..." https://api.github.com/user
401

# in the dev container: an operation the policy allows goes through the gateway
$ sekimore pr create --head sekimore/topic --base main --title "..."
#42 https://github.com/Org/Repo/pull/42

# an operation the policy does not allow stops at the gateway
$ sekimore pr merge --number 42
sekimore: denied: pr:merge is not allowed by policy
```

`gh` is not part of this setup. Given a token, it would connect to GitHub directly, past every
permission configured here, so the dev-container image ships without it.

## Get started

**A. Dev container (recommended).** The complete setup — the gateway, the dev container, the relay
and the host-side tasks — is the `examples/sgw-sample/` template in
[sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base). Its README takes a new
project from clone to a verified relay.

**B. Gateway only.** Three commands on a Linux host give you the DNS allowlist, the firewall, Squid
and the dashboard:

```bash
git clone https://github.com/Amakata/sekimore-gw.git && cd sekimore-gw
cp config/config.sample.yml config/config.yml    # allow_domains: the domains the agent may reach
docker compose up -d                             # dashboard: http://localhost:8080
```

This path does not include the relay. To add it, set `domain_handlers` and `relay` in
`config.yml` as [relay/README.md](relay/README.md) describes (the end of `config.sample.yml` is
the template), and give the agent container the pieces the dev-container template provides:
`agent-setup.sh`, the `sekimore-relay` CLI and the `sekimore` wrapper. The `ai-agent` service in
`docker-compose.yml` is a minimal agent container.

If the host is behind a proxy that requires credentials: for a standalone gateway, run
`cp .env.example .env` and fill in `SEKIMORE_UPSTREAM_PROXY_USERNAME` and `_PASSWORD`. In the
dev-container setup, `mise run gw:proxy-credential -- set` stores them in the gateway's secret
store instead, because `.devcontainer/.env` is also the dev container's `env_file` and the agent
can read it.

## How it works

The four layers are built from one `config.yml`, because restricting one of them leaves the others
as a way around it.

| Layer | What it does |
|---|---|
| **DNS** (:53) | Resolves only allowlisted domains, and opens the firewall for the addresses it returns. The domains the relay handles resolve to the gateway itself. |
| **Firewall** (iptables, ipset) | Forwards only to the addresses and ports that DNS admitted, and drops a connection to an IP address named directly. Agents can query the gateway's DNS; nothing else is reachable until DNS admits it. `network.allowed_ports` limits the destination ports; when it is not set, every port of an admitted address is open. |
| **Squid** (:3128) | The proxy the agent's tools use. Squid resolves names itself, so the DNS layer does not cover it; Squid applies the same allowlist and refuses the domains the relay handles. |
| **Relay** (sekimore-relay) | git over SSH (:22), the GitHub API (:8420) and a passthrough for other HTTPS (:443). The only component that holds upstream credentials. It enforces a per-project policy — repositories, read-only or read-write, 33 permissions, pull request base branches — turns `git push HEAD:refs/for/main` into a branch and a pull request, signs commits with a key the agent can use but not read, caps what a connection may upload through the 443 passthrough, and writes allowed and refused operations to an audit log. |

The relay is optional. Without `domain_handlers`, the first three layers run alone.
[relay/README.md](relay/README.md) covers its setup, the agent-side steps and the policy.

## When to use it

**sekimore-gw fits** when an agent should work on GitHub within limits: open a pull request but
not merge it, reach this repository and no other, sign every commit, stay under an upload cap on
the HTTPS passthrough, and leave a record of every operation — with no upstream credential in the
agent's hands.

**sekimore-gw does not fit** the following cases, where a smaller or a different tool serves
better:

| | |
|---|---|
| Restricting the API of an upstream other than GitHub | The SSH git relay works with any Git host, but the API translation supports only GitHub. GitLab or an internal Artifactory can be allowlisted as a domain, or passed through port 443 with an upload cap, and no further. [#50](https://github.com/Amakata/sekimore-gw/issues/50) tracks changing this. |
| Rules based on request content | The gateway does not terminate TLS. It sees the destination and the byte count, not `GET /v1/public/`. In exchange, no MITM certificate is needed. |
| Restricting destinations alone | The four layers exist to restrict what an agent can do on GitHub. For an allowlist alone, a simpler tool is enough. |
| An agent that does not use GitHub | If a person runs the git commands, the relay has no role. |

## Requirements

- Docker 20.10 or later and Docker Compose 2.0 or later.
- A Linux host, or Docker Desktop on macOS. The layers run inside the Docker VM; the dev-container
  template is used on macOS.
- `docker-compose.yml` runs the gateway with `NET_ADMIN` and `privileged: true`.
- An agent container disables Docker's embedded DNS (`dns: [127.0.0.1]`) and runs
  `agent-setup.sh`, which finds the gateway and sets the default route.
- `network.allowed_ports` is unset by default, so every port of an admitted address is open. Set
  it to `[80, 443]` unless the agent needs more; a change requires a restart.

## Names

| Name | What it is |
|---|---|
| sekimore-gw, sgw | This gateway. `sgw` is the short form in sgw-devcontainer-base, `sgw.sh` and `.devcontainer/sgw/`. |
| sekimore-relay | The relay daemon inside the gateway, and the CLI binary of the same name in the dev container. |
| `sekimore` | The wrapper in the dev container that runs `sekimore-relay agent …`. `sekimore guide` prints the agent's guide. |
| sgw-devcontainer-base | The dev-container image. `examples/sgw-sample/` in it is the project template. |
| `.devcontainer/sgw/`, `gw:*` | The host-side scripts and mise tasks, distributed with the images and replaced by `mise run upgrade:apply`. |

## Documentation

- [relay/README.md](relay/README.md) — relay setup, agent-side steps, everyday use, the
  configuration reference and the permission catalog
- [config/config.sample.yml](config/config.sample.yml) — every key the gateway reads, with its
  default and a comment
- [docs/localization.md](docs/localization.md) — the Web UI and the CLI in English and Japanese
- [CONTRIBUTING.md](CONTRIBUTING.md) — development, tests, building and preview images
- [CHANGELOG.md](CHANGELOG.md) and [relay/CHANGELOG.md](relay/CHANGELOG.md) — one image carries
  the gateway and the relay under one version number
- [sgw-devcontainer-base](https://github.com/Amakata/sgw-devcontainer-base) — the dev-container
  side of the setup

## Troubleshooting

- **The agent cannot find the gateway.** Check `dns: [127.0.0.1]` on the agent container and its
  logs (`docker logs <agent-container>`). `agent-setup.sh` scans the whole subnet only when the
  prefix length is 24 or more (256 addresses or fewer).
- **A domain does not resolve.** Check `allow_domains` in `config/config.yml`, and the blocked
  requests in the Web UI or in `docker logs sekimore-gw`.
- **The database is large.** `python -m src.maint db-stats` in the gateway container shows the
  size; `python -m src.maint db-prune --before-days 90 --yes --vacuum` deletes old records. The
  `gw:db-*` mise tasks run these commands. The relay's audit log (`/data/relay/audit.jsonl`) is
  a separate file that they do not touch.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
