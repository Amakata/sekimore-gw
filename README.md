# sekimore-gw

*[日本語版](README.ja.md)*

[![Lint](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/lint.yml)
[![Test](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/test.yml)
[![Docker Publish](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Amakata/sekimore-gw/actions/workflows/docker-publish.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Let an AI agent work on GitHub without handing over your account.**

sekimore-gw (sgw) is a network gateway for AI agents in Docker. On the host you run `sgw`;
inside the dev container the agent runs `sgw-agent`. Its usage guide is installed at every start as a
Claude Code skill and into Codex's `AGENTS.md`, so the agent reads it without being told;
`sgw-agent guide` prints the same text.

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

## How it works

The dev container's only route out is the gateway.

1. A domain not in `allow_domains` does not resolve
2. A direct connection to an IP is dropped by the firewall
3. The HTTP proxy checks the same list, so `http_proxy` is no way around it
4. `github.com` resolves to the relay. It speaks git and the GitHub API to the upstream with
   your ssh-agent on the host and a token from the device flow, both of which stay on the gateway
5. The relay checks the project's repositories and permissions on every operation, and records it

The agent sees one ssh host and one API endpoint, and holds no credential for either.

## Get started

The supported setup is VS Code Dev Containers on macOS or Linux. Windows is not tested.

You need:

- Docker (Docker Desktop on macOS, Docker Engine on Linux). The gateway runs `privileged` with
  `pid: host`: the rules that keep the dev container on the gateway live in the host's firewall
- VS Code with the Dev Containers extension

1. Install `sgw`, one binary at `~/.local/bin/sgw` (put that directory on your PATH). The script checks the sha256 the release
   publishes; the [Releases page](https://github.com/Amakata/sekimore-gw/releases) has the same
   archives to install by hand:
   ```bash
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. Write the template into your repository (a new directory: `sgw init --devcontainer my-project`):
   ```bash
   cd your-project
   sgw init --devcontainer
   ```
3. Fill in the minimum. `.devcontainer/.env`: `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL` (and the
   committer pair), `DEVCONTAINER_ID` (a name unique on this host). `.devcontainer/config/config.yml`: `allow_domains`,
   `relay.project.name`, `relay.project.repos`, `relay.project.permissions`.
   [config.sample.yml](config/config.sample.yml) explains every other key
4. Quit VS Code completely, then start it with `sgw open`. Choose "Reopen in Container":
   ```bash
   sgw open
   ```
   ⚠️ Always `sgw open`: it keeps your ssh-agent out of the container
5. Unlock the secret store, in a host terminal, with VS Code left running. The first run sets
   the passphrase; later runs ask for it (`sgw keychain-set` stops the asking):
   ```bash
   sgw unlock
   ```
6. Log in to GitHub, once. The token goes into the secret store:
   ```bash
   sgw login
   ```
7. Check:
   ```bash
   sgw verify
   ```
8. Try it, in the dev container's terminal:
   ```bash
   sgw-agent whoami            # the permissions: pr:create … and no pr:merge
   sgw-agent pr merge --number 1
   # sgw-agent: denied: pr:merge is not allowed by policy
   ```

## Settings

The settings are in `.devcontainer/config/config.yml`; [config.sample.yml](config/config.sample.yml) explains every key.

| Setting | Effect |
|---|---|
| `allow_domains` | The destinations the agent may reach |
| `relay.project.name` | The project's name: what the agent's token is issued for, and the label on the audit |
| `domain_handlers` | The domains that go through the relay: git, the GitHub API, HTTPS |
| `relay.project.repos` | The repositories the agent may touch |
| `relay.project.permissions` | The actions it may take |
| `network.allowed_ports` | The ports it may reach |

## Commands

| To | Run |
|---|---|
| Unlock the secret store (it is locked again whenever the gateway container is recreated) | `sgw unlock` |
| Make the unlock automatic | `sgw keychain-set` |
| Log in to GitHub | `sgw login` |
| Check the setup | `sgw verify` |
| Apply a change to `config.yml` | `sgw restart`. When you added or changed an upstream, then `sgw refresh` (it rewrites the agent's ssh config) |
| Move to a newer release | `sgw update --apply` (it installs the newer `sgw` first when there is one) |
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
| Run the dev container on a Linux VM reached by Remote-SSH | [docs/remote-ssh.md](docs/remote-ssh.md) |

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

- [docs/template.md](docs/template.md) — the files `sgw init` writes
- [docs/remote-ssh.md](docs/remote-ssh.md) — run the dev container on a Linux VM reached by Remote-SSH
- [base/README.md](base/README.md) — what the dev container's image holds
- [relay/README.md](relay/README.md) — the relay's configuration and the permission catalog
- [config/config.sample.yml](config/config.sample.yml) — every key
- [UPGRADING.md](UPGRADING.md) — what a release asks of a project
- [CHANGELOG.md](CHANGELOG.md) — the changes
- [docs/paths.md](docs/paths.md) — every path a request can take, who checks it, and what `sgw verify` probes
- [docs/localization.md](docs/localization.md) — English and Japanese
- [CONTRIBUTING.md](CONTRIBUTING.md), [RELEASING.md](RELEASING.md)

## Troubleshooting

First `sgw verify`. It names the item that fails and what to run.

| Symptom | Do |
|---|---|
| The agent cannot reach GitHub after a restart or an update | `sgw unlock` |
| `ssh-add -l` in dev lists your own keys | Quit VS Code completely, then `sgw open` |
| A change to `config.yml` has no effect | `sgw restart` |
| A domain the agent needs is not resolved | Add it to `allow_domains`. The blocked access shows in `sgw web` |
| The gateway is old after an update | `sgw recreate` |
| "network … already exists" while starting | The previous dev container and gateway are still there. `sgw down` removes the whole stack; open again |
| HTTP 503 "the secret store is locked" right after a start | The upstream proxy's password is in the locked store. `sgw unlock` |
| The dev container is old after an update | Rebuild Container in VS Code |

## License

Apache License 2.0 — [LICENSE](LICENSE).
