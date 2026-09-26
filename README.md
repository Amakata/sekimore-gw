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


## Get started

Needs Docker (Docker Desktop on macOS, or Docker Engine on Linux) and VS Code with the Dev Containers extension.

1. Install `sgw`, the operator's tool:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. Write the project template into a directory:
   ```bash
   sgw init --devcontainer my-project
   ```
3. [base/README.md](base/README.md) takes it from there: `config.yml`, the dev container, `sgw unlock`, `sgw login`, `sgw verify`.

## What you set, and what it does

Everything is in `.devcontainer/config/config.yml`; [config.sample.yml](config/config.sample.yml) lists every key with a comment.

| Setting | Effect |
|---|---|
| `allow_domains` | The destinations the agent's ordinary traffic may reach. DNS, the firewall and Squid all follow this one list |
| `domain_handlers`, `relay` | These domains go through the relay instead: git over SSH, the GitHub API, HTTPS with an upload cap. The relay holds the upstream credentials; the agent holds none |
| `relay.project.repos`, `permissions` | Which repositories, read-only or read-write, and which of the 33 actions: `pr:create` allowed, `pr:merge` denied |
| `proxy.upstream_proxy`, `proxy.direct_egress` | A corporate proxy for everything that leaves; `deny` closes the way around it. Its password goes into the secret store (`sgw proxy-credential set`), not into a file the agent can read |
| `network.allowed_ports` | The ports the agent may reach. Unset means all; `[80, 443]` is the usual |

| Operation | Command |
|---|---|
| Unlock the secret store (after every recreate; `sgw keychain-set` once makes it automatic) | `sgw unlock` |
| Log in to GitHub, once | `sgw login` |
| Check the whole setup | `sgw verify` |
| After changing `domain_handlers` or `relay` | `sgw restart` |
| Move to a newer release | `sgw update --apply` |
| Watch what the agent did and was refused | `sgw audit` |

Every other command: `sgw --help`.

## Fits, does not fit

Fits when the agent should:

- open a pull request, not merge it
- reach this repository, no other
- sign every commit
- stay under an upload cap on the HTTPS passthrough
- leave a record of every operation
- hold no upstream credential

Does not fit when the agent should:

- follow rules on an API other than GitHub's (git over SSH works anywhere; API rules are GitHub only, [#50](https://github.com/Amakata/sekimore-gw/issues/50))
- be judged by what a request contains (TLS is not terminated; only the destination and the byte count are seen)
- be limited in destinations only (a plain allowlist is enough)
- never touch GitHub (the relay has no role)

## Documentation

- [relay/README.md](relay/README.md) — relay setup, agent-side steps, everyday use, configuration reference, permission catalog
- [config/config.sample.yml](config/config.sample.yml) — every key, with its default and a comment
- [docs/localization.md](docs/localization.md) — Web UI and CLI in English and Japanese
- [docs/paths.md](docs/paths.md) — the path ledger: every connection edge, checked as a graph
- [CONTRIBUTING.md](CONTRIBUTING.md) — development, tests, images
- [CHANGELOG.md](CHANGELOG.md), [relay/CHANGELOG.md](relay/CHANGELOG.md), [base/CHANGELOG.md](base/CHANGELOG.md) — two images, one version number
- [UPGRADING.md](UPGRADING.md) — what a release asks of a project
- [base/README.md](base/README.md) — the dev-container side: the image and the project template
- [RELEASING.md](RELEASING.md) — how a release is cut

## When the dev container does not come up right

`sgw verify` names the item that fails and what to run. The usual ones:

| Symptom | Do |
|---|---|
| The agent cannot reach GitHub after a restart or an update | The secret store is locked: `sgw unlock` (or `sgw keychain-set` once, so `sgw recreate` unlocks by itself) |
| `sekimore whoami` in dev says there is no token | `sgw login`, then `sgw verify` |
| `ssh-add -l` in dev lists your own keys | VS Code was started with `SSH_AUTH_SOCK`. Quit it completely and start it with `sgw open` |
| A change to `domain_handlers` or `relay` in `config.yml` has no effect | `sgw restart`; a change to `allow_domains` alone is picked up while the reload window is open (`sgw reload-status`) |
| A domain the agent needs is not resolved | Add it to `allow_domains`; the refusals are in the Web UI (`sgw web`) and in `sgw logs` |
| The gateway image is old after `sgw update --apply` | `sgw recreate` pulls it; `docker restart` keeps the old one. A base change needs Rebuild Container in VS Code |

## License

Apache License 2.0 — [LICENSE](LICENSE).
