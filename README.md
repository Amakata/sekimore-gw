# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Let an AI agent work on GitHub without handing over your account.**

sekimore-gw (sgw) is a network gateway for AI agents in Docker.

- All in one container:
  - DNS filter
  - IP firewall
  - HTTP proxy
  - the relay (sekimore-relay) for git and the GitHub API
- One `config.yml`
- The relay holds the GitHub credentials. The agent holds none
- Permissions per action: `pr:create` allowed, `pr:merge` denied
- Every allowed and blocked access is visible in the Web UI

## Why not a token

- A token in the container is readable by the agent
- A token narrows repositories, not actions
- Nothing records what the agent did

## Get started

You need:

- Docker (Docker Desktop on macOS, Docker Engine on Linux)
- VS Code with the Dev Containers extension

1. Install `sgw`:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. Write the template:
   ```bash
   sgw init --devcontainer my-project
   cd my-project
   ```
3. Fill in `.devcontainer/.env` and `.devcontainer/config/config.yml`
4. Quit VS Code completely, open it again, and choose "Reopen in Container":
   ```bash
   sgw open
   ```
   ⚠️ VS Code is always started with `sgw open`
5. Unlock the secret store:
   ```bash
   sgw unlock
   ```
   ⚠️ The passphrase set the first time unlocks it from then on
6. Log in to GitHub:
   ```bash
   sgw login
   ```
   ⚠️ Once. The result goes into the secret store
7. Check:
   ```bash
   sgw verify
   ```

## What you set, and what it does

The settings are in `.devcontainer/config/config.yml`; [config.sample.yml](config/config.sample.yml) explains every key.

| Setting | Effect |
|---|---|
| `allow_domains` | The destinations the agent may reach |
| `domain_handlers` | The domains that go through the relay: git, the GitHub API, HTTPS |
| `relay.project.repos` | The repositories the agent may touch |
| `relay.project.permissions` | The actions it may take |
| `network.allowed_ports` | The ports it may reach |

| To | Run |
|---|---|
| Unlock the secret store (it is locked again whenever the gateway container is recreated) | `sgw unlock` |
| Make the unlock automatic | `sgw keychain-set` |
| Log in to GitHub | `sgw login` |
| Check the setup | `sgw verify` |
| Apply a change to `config.yml` | `sgw restart` |
| Move to a newer release | `sgw update --apply` |
| See allowed and blocked access in the Web UI | `sgw web` |
| See what the agent did | `sgw audit` |

Everything else: `sgw --help`.

## Optional

| To | Set |
|---|---|
| Go through a corporate proxy | `proxy.upstream_proxy`. Its password: `sgw proxy-credential set` |
| Reach GitHub through a bastion | `domain_handlers.<host>.ssh_options: [ProxyJump=…]` |
| Use GitHub Enterprise | Add its host to `domain_handlers` (`ssh_port`, `api_base`) |
| Have the agent's commits show as Verified on GitHub | Register the key `sgw signing-key` prints as a Signing Key |

## Fits, does not fit

Fits when the agent should:

- open a pull request, not merge it
- reach this repository, no other
- sign every commit
- stay under an upload cap on the HTTPS passthrough
- leave a record of every operation
- hold no upstream credential

Does not fit when the agent should:

- follow rules on an API other than GitHub's
- be judged by what a request contains (TLS is not terminated)
- be limited in destinations only (an allowlist is enough)
- never touch GitHub

## Documentation

- [base/examples/sgw-sample/README.md](base/examples/sgw-sample/README.md) — the files `sgw init` writes
- [base/README.md](base/README.md) — what the dev container's image holds
- [relay/README.md](relay/README.md) — the relay's configuration and the permission catalog
- [config/config.sample.yml](config/config.sample.yml) — every key
- [UPGRADING.md](UPGRADING.md) — what a release asks of a project
- [CHANGELOG.md](CHANGELOG.md) — the changes
- [docs/paths.md](docs/paths.md) — the path ledger
- [docs/localization.md](docs/localization.md) — English and Japanese
- [CONTRIBUTING.md](CONTRIBUTING.md), [RELEASING.md](RELEASING.md)

## When the dev container does not come up right

First `sgw verify`. It names the item that fails and what to run.

| Symptom | Do |
|---|---|
| The agent cannot reach GitHub after a restart or an update | `sgw unlock` |
| `ssh-add -l` in dev lists your own keys | Quit VS Code completely, then `sgw open` |
| A change to `config.yml` has no effect | `sgw restart` |
| "network … already exists" while starting | A network of the previous compose run is left behind. `sgw down`, then open again. If it persists, `docker network prune` |
| A domain the agent needs is not resolved | Add it to `allow_domains`. The blocked access shows in `sgw web` |
| The gateway is old after an update | `sgw recreate` |
| The dev container is old after an update | Rebuild Container in VS Code |

## License

Apache License 2.0 — [LICENSE](LICENSE).
