# sgw-devcontainer-base

*[日本語版](README.ja.md)*

The dev-container side of [sekimore-gw](https://github.com/Amakata/sekimore-gw) (sgw for short).
It is not used on its own. The sekimore-gw README explains why the setup exists.

- Published at: `ghcr.io/amakata/sgw-devcontainer-base`
- Platforms: `linux/amd64`, `linux/arm64`

## Start a project

A project starts as a copy of [`examples/sgw-sample/`](examples/sgw-sample/). It contains:

- the gateway and dev containers
- the host-side mise tasks

Run the steps on the host, in order.
[`examples/sgw-sample/README.md`](examples/sgw-sample/README.md) describes each one in detail.

1. Clone this repository:
   ```
   git clone https://github.com/Amakata/sgw-devcontainer-base.git
   ```
2. Copy the following into the project:
   - `examples/sgw-sample/.devcontainer/`
   - `examples/sgw-sample/mise.toml`
3. Copy `.devcontainer/.env.sample` to `.devcontainer/.env`:
   ```
   cp .devcontainer/.env.sample .devcontainer/.env
   ```
   Fill in the project name, the user name and the email address.
4. Edit `.devcontainer/config/config.yml`:
   - Set `relay.project.repos` and `permissions`.
   - The file lists every key the gateway reads.
   - The consequential permissions are commented out.
5. Quit VS Code completely, then run the following and select "Reopen in Container":
   ```
   mise run vscode
   ```
   The task opens VS Code without `SSH_AUTH_SOCK`.
   The operator's ssh-agent does not reach the dev container.
6. Unlock the secret store:
   ```
   mise run gw:unlock
   ```
   - The first run sets the passphrase.
   - The store must be unlocked again every time the gateway is recreated.
   - To avoid that, run the following once:
     ```
     mise run gw:keychain-set
     ```
     It stores the passphrase on the host: in the macOS Keychain, the Secret Service or a root-owned file.
     `gw:recreate` then unlocks the store automatically.
7. Log in to GitHub (first time only):
   ```
   mise run gw:login
   ```
   - It uses the device flow.
   - It stores the upstream token and `known_hosts`.
   - It requires an unlocked store.
8. Print the signing key:
   ```
   mise run dev:signing-key
   ```
   Register the public key it prints on GitHub as a Signing Key.
   The agent's commits are signed with this key.
9. Check the whole setup:
   ```
   mise run relay:verify
   ```
   The setup is complete when it passes.

## Project Dockerfile

The project's `.devcontainer/Dockerfile` needs only the following:

```dockerfile
# a version, not latest: `mise run upgrade:apply` raises it
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.43

# only what this project adds
# e.g. mise use -g python@3.13.0 && mise reshim
```

The sample's [Dockerfile](examples/sgw-sample/.devcontainer/Dockerfile) shows how to:

- pre-install language versions
- keep them when a volume is mounted over the mise data directory

## Image contents

| | |
|---|---|
| Base | `mcr.microsoft.com/devcontainers/base:bookworm` (`vscode` user, uid=1000) |
| Shell | zsh, oh-my-zsh and plugins, `fzf`, `jq`, `vim`, `nano`, `curl`, `wget`, `unzip`, `rsync`, `pv`, `gnupg`, `sudo` |
| Network | `iptables`, `iproute2`, `iputils-ping`, `dnsutils` |
| Git | `git-delta` |
| DB headers | `libpq-dev`, `default-libmysqlclient-dev` |
| Languages | `mise` for Python, Node.js, Ruby, PHP, Rust and Go. No language version included |
| AI | Claude Code CLI, OpenAI Codex CLI |
| Cloud | AWS CLI v2, Docker CE with buildx and compose |
| Gateway | `sekimore-agent-setup.sh`, `sekimore-relay` CLI, `sekimore` wrapper |
| zsh defaults | `/etc/skel/zsh-rc.d/`: XDG, the upstream proxy's environment, mise activation, aliases, plugins. Post-create copies them into `~/.config/zsh/rc.d/` |

- `sekimore-agent-setup.sh` and `sekimore-relay` come from the same sekimore-gw image.
  Their versions cannot diverge.
- The image contains nothing project-specific.
  The project provides the following, as in the sample:
  - language build dependencies
  - the configuration
  - the Docker daemon's privileges

## Ownership and keeping up to date

Everything copied from the sample belongs to the project, except `.devcontainer/sgw/`.

- `.devcontainer/sgw/` contains the host scripts and tasks.
- `mise run upgrade:apply` replaces it. Do not edit it by hand.
- To change a distributed task, define a task with the same name in the project's `mise.toml`.
  That definition takes precedence.
- `.devcontainer/sgw/gateway.mise.toml` holds the `gw:*` tasks.
  The gateway image ships it in English and Japanese.
  `mise run upgrade:sync` fetches the one for the current language.
  The language comes from `SEKIMORE_LANG`, then `LC_ALL`, `LC_MESSAGES`, `LANG`.
- Set `SGW_NO_AUTO_UNLOCK=1` to keep `gw:recreate` from unlocking the store with the stored passphrase.
- With `proxy.upstream_proxy` in `config.yml`, the gateway writes `HTTP_PROXY`, `HTTPS_PROXY` and
  `NO_PROXY` into dev and `10-sekimore-proxy.zsh` hands them to every shell.
  A project that sets its own must remove them or keep them in step; `mise run relay:verify`
  says whether dev's ordinary traffic really takes the upstream (UPGRADING: base 0.2.40).

```bash
mise run upgrade          # what is newer, which files it would change, what UPGRADING asks. Changes nothing
mise run upgrade:apply    # move to it
```

`upgrade:apply` does the following:

1. Raises the gateway's `image:` tag and the `FROM` tag to the newest versions on GHCR.
2. Replaces `.devcontainer/sgw/`.
3. Recreates the gateway after asking.
4. Unlocks it when the passphrase is stored.
5. Lists what only the operator can do:
   - Rebuild Container when the base changed
   - the [UPGRADING.md](UPGRADING.md) sections the upgrade crosses
   - a commit

It stops without writing if a file in `.devcontainer/sgw/` was edited by hand.

The three parts depend on one another.
That is why a single command updates all of them:

```
sekimore-gw (the gateway)  ── this image copies the relay binaries out of it
        ↓
sgw-devcontainer-base      ── your .devcontainer/Dockerfile FROMs it
        ↓
.devcontainer/sgw/         ── the host scripts and tasks for both
```

- The `sekimore-relay` CLI and `sekimore-agent-setup.sh` in this image come from gateway `ghcr.io/amakata/sekimore-gw:0.2.45` (`ARG SEKIMORE_GW_IMAGE`).
  Base and gateway are separate 0.2.x series.
- The gateway a project runs is the `image:` tag in its compose file.
  `mise run upgrade:apply` raises both.

## Links

- [UPGRADING.md](UPGRADING.md) — what each release requires of a project. It includes:
  - the move from gateway 0.0.x
  - the one-time move to `.devcontainer/sgw/` for projects created before base 0.2.20
- [CHANGELOG.md](CHANGELOG.md) — this image, with the gateway version each release used. See also:
  - the gateway's [CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/CHANGELOG.md)
  - the relay's [CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/relay/CHANGELOG.md)
- [RELEASING.md](RELEASING.md) — the release order, local builds and the tags pushed to GHCR, for maintainers
- License: MIT ([LICENSE](LICENSE))
