# sgw-devcontainer-base

*[日本語版](README.ja.md)*

The image the dev container is built from. How to use it is in the [top-level README](../README.md).
This page is what the image holds, and where to change the base itself.

- `ghcr.io/amakata/sgw-devcontainer-base`, the gateway's version number, from the same tag
- `linux/amd64`, `linux/arm64`

## The project's Dockerfile

```dockerfile
# a version, not latest: sgw update --apply raises it
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.56

# only what this project adds, e.g. mise use -g python@3.13.0 && mise reshim
```

The template's [Dockerfile](../relay/templates/devcontainer/.devcontainer/Dockerfile) shows how to pre-install language versions.

## What is in the image

| | |
|---|---|
| Base | `mcr.microsoft.com/devcontainers/base:bookworm` (`vscode`, uid 1000) |
| Shell | zsh, oh-my-zsh, `fzf`, `jq`, `vim`, `nano`, `curl`, `wget`, `unzip`, `rsync`, `pv`, `gnupg`, `sudo` |
| Network | `iptables`, `iproute2`, `iputils-ping`, `dnsutils` |
| Git | `git-delta` |
| DB headers | `libpq-dev`, `default-libmysqlclient-dev` |
| Languages | `mise`. No language version |
| AI | Claude Code CLI, OpenAI Codex CLI, the official Anthropic skills |
| Cloud | AWS CLI v2, Docker CE with buildx and compose |
| Gateway | four tools copied out of `ghcr.io/amakata/sekimore-gw:0.2.56`, below |
| zsh defaults | `/etc/skel/zsh-rc.d/`, copied into `~/.config/zsh/rc.d/` by post-create |

From the gateway image:

| Tool | Role |
|---|---|
| `sgw-agent` | the AI's command for git through the relay and the GitHub API. `sgw-agent setup` runs at every start: it points the container at the gateway, fetches the proxy environment, makes the disposable key and gets the project token, writes `~/.ssh/config` and known_hosts, sets up commit signing, and installs the usage guide at `~/.claude/skills/sgw-agent/SKILL.md` and in `~/.codex/AGENTS.md` (`SEKIMORE_AGENT_INSTRUCTIONS=none\|claude\|codex` limits that). `sgw-agent guide` prints the same guide |
| `sekimore-relay` | the relay itself, for `sgw-agent setup` to talk to the gateway with |
| `sekimore` | the former name of `sgw-agent`, kept as an alias; its removal will be announced in UPGRADING.md |
| `sgw-post-start` | what `postStartCommand` runs: the setup, the inner Docker daemon, the project's post-create.sh |

Not in the image:

- the GitHub CLI: a token in dev would act past the relay's permissions
- anything project-specific: language versions, build dependencies, `config.yml`

## Where to change what

| To change | Edit |
|---|---|
| apt packages | the `Base apt packages` block of [Dockerfile](Dockerfile) |
| git-delta, AWS CLI, Docker CE, Claude Code, Codex, the skills | the section of [Dockerfile](Dockerfile) with that name |
| What every zsh starts with | [zsh-config/rc.d/](zsh-config/rc.d/) |
| Claude Code's managed settings | [managed-settings.json](managed-settings.json) |
| The `sekimore` wrapper, `docker-init.sh`, the Docker install | [scripts/](scripts/) |
| Which gateway the relay tools come from | `ARG SEKIMORE_GW_IMAGE`. A release sets it |

Build and test locally:

```sh
docker build -t sgw-devcontainer-base:dev base
base/tests/test_image.sh sgw-devcontainer-base:dev
```

## Links

- [docs/template.md](../docs/template.md) — the template `sgw init` writes
- [UPGRADING.md](../UPGRADING.md) — what a release asks of a project
- [CHANGELOG.md](../CHANGELOG.md) — one for the gateway, the relay, the base and sgw; [base/CHANGELOG.md](CHANGELOG.md) is the base's own history up to 0.2.43, its last release of its own (the gateway's 0.2.44 and 0.2.45 had no base release)
- [RELEASING.md](../RELEASING.md)
