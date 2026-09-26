# sgw-devcontainer-base

*[日本語版](README.ja.md)*

The dev-container side of sekimore-gw (sgw for short): this directory of the gateway's
repository. It is not used on its own; the [top-level README](../README.md) explains why the
setup exists. It was a repository of its own until 0.2.45 (`Amakata/sgw-devcontainer-base`, archived).

- Published at: `ghcr.io/amakata/sgw-devcontainer-base`, under the gateway's version number, from the same tag
- Platforms: `linux/amd64`, `linux/arm64`

## Start a project

`sgw`, the operator's tool, writes the project and runs the gateway from the host. The steps run
on the host, in order. [`examples/sgw-sample/README.md`](examples/sgw-sample/README.md) describes
the template `sgw init` writes.

1. Install `sgw`:
   ```
   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
   ```
2. Write the template:
   ```
   sgw init --devcontainer my-project
   cd my-project
   ```
   It writes `.devcontainer/` (the gateway and dev containers, `config.yml`, the host-side files)
   and `mise.toml`, and `.devcontainer/.env` from `.env.sample`.
   Fill in `.devcontainer/.env`: the project name, the user name and the email address.
3. Edit `.devcontainer/config/config.yml`:
   - Set `relay.project.repos` and `permissions`.
   - The file lists every key the gateway reads.
   - The consequential permissions are commented out.
4. Quit VS Code completely, then run the following and select "Reopen in Container":
   ```
   sgw open
   ```
   It opens VS Code without `SSH_AUTH_SOCK`.
   The operator's ssh-agent does not reach the dev container.
5. Unlock the secret store:
   ```
   sgw unlock
   ```
   - The first run sets the passphrase.
   - The store must be unlocked again every time the gateway is recreated.
   - To avoid that, run the following once:
     ```
     sgw keychain-set
     ```
     It stores the passphrase on the host: in the macOS Keychain, the Secret Service or a root-owned file.
     `sgw recreate` then unlocks the store automatically.
6. Log in to GitHub (first time only):
   ```
   sgw login
   ```
   - It uses the device flow.
   - It stores the upstream token and `known_hosts`, asking before it saves a host key.
   - It requires an unlocked store.
7. Print the signing key:
   ```
   sgw signing-key
   ```
   Register the public key it prints on GitHub as a Signing Key.
   The agent's commits are signed with this key.
8. Check the whole setup:
   ```
   sgw verify
   ```
   The setup is complete when it passes.

The mise tasks in `.devcontainer/sgw/` do the same for a project that uses them
(`mise run gw:unlock`, `mise run relay:verify` …); `mise tasks` lists them.

## Project Dockerfile

The project's `.devcontainer/Dockerfile` needs only the following:

```dockerfile
# a version, not latest: `mise run upgrade:apply` raises it
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.47

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

Everything `sgw init` wrote belongs to the project, except `.devcontainer/sgw/`.

- `.devcontainer/sgw/` holds the host scripts and mise tasks of the way before `sgw`.
  `sgw update --apply` (or `mise run upgrade:apply`) replaces it. Do not edit it by hand.
- To change a distributed task, define a task with the same name in the project's `mise.toml`.
  That definition takes precedence.
- The task files come in English and Japanese; `sgw update --sync` takes the ones for the
  current language. The language comes from `SEKIMORE_LANG`, then `LC_ALL`, `LC_MESSAGES`, `LANG`.
- `sgw recreate --no-unlock` (or `SGW_NO_AUTO_UNLOCK=1`) keeps the recreate from unlocking the store with the stored passphrase.
- With `proxy.upstream_proxy` in `config.yml`, the gateway writes `HTTP_PROXY`, `HTTPS_PROXY` and
  `NO_PROXY` into dev and `10-sekimore-proxy.zsh` hands them to every shell.
  A project that sets its own must remove them or keep them in step; `sgw verify`
  says whether dev's ordinary traffic really takes the upstream (UPGRADING: base 0.2.40).

```bash
sgw update            # what is newer, which files it would change, what UPGRADING asks. Changes nothing
sgw update --apply    # move to it
```

`sgw update --apply` does the following:

1. Raises the gateway's `image:` tag and the `FROM` tag to `sgw`'s own version. When GHCR has a
   newer release than `sgw` itself, it says so and points at `install.sh` instead.
2. Replaces `.devcontainer/sgw/` with the files of that version, which the binary carries.
3. Recreates the gateway after asking.
4. Unlocks it when the passphrase is stored.
5. Lists what only the operator can do:
   - Rebuild Container when the base changed
   - the [UPGRADING.md](../UPGRADING.md) sections the upgrade crosses (`sgw update --notes`)
   - a commit

It stops without writing if a file in `.devcontainer/sgw/` was edited by hand (`--force` overwrites).

The parts depend on one another, and one version number covers them:

```
sekimore-gw (the gateway)  ── this image copies the relay binaries out of it
        ↓
sgw-devcontainer-base      ── your .devcontainer/Dockerfile FROMs it
        ↓
sgw / .devcontainer/sgw/   ── the operator's tool and the host-side files, of the same version
```

- The `sekimore-relay` CLI and `sekimore-agent-setup.sh` in this image come from gateway `ghcr.io/amakata/sekimore-gw:0.2.47` (`ARG SEKIMORE_GW_IMAGE`).
  The base carries the gateway's version number; the two are released from one tag.
- The gateway a project runs is the `image:` tag in its compose file.
  `sgw update --apply` raises both.

## Links

- [UPGRADING.md](../UPGRADING.md) — what each release requires of a project. It includes:
  - the move from gateway 0.0.x
  - the one-time move to `.devcontainer/sgw/` for projects created before base 0.2.20
- [CHANGELOG.md](CHANGELOG.md) — this image, with the gateway version each release used. See also:
  - the gateway's [CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/CHANGELOG.md)
  - the relay's [CHANGELOG](https://github.com/Amakata/sekimore-gw/blob/main/relay/CHANGELOG.md)
- [RELEASING.md](../RELEASING.md) — how a release is cut, local builds and the tags pushed to GHCR, for maintainers
- License: Apache-2.0 ([LICENSE](../LICENSE)), the same as the gateway
