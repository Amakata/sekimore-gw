# Languages in the dev container

The base image has mise and nothing else of a language's but the node codex runs on. A project
adds its languages one of three ways.

| Who | How | Where it lands |
|---|---|---|
| The project, a language with a prebuilt image | `COPY --from=` the language image | `/opt/mise` (read-only) |
| The project, any other language | `mise install --system` in the Dockerfile | `/opt/mise` (read-only) |
| One person | `mise use -g <lang>@<version>` in the container | the mise-store volume |

- `/opt/mise` is mise's system directory (`MISE_SYSTEM_DATA_DIR`). Root owns it; the user's mise
  reads it and never writes it, and nothing chowns it at start.
- A version in the mise-store volume wins over the same version in `/opt/mise`.
- Write versions as `x.y.z`. `node@24` or `latest` resolves to whatever is newest, which may not be
  the version in the image, and mise then installs another one in the volume.

## The project: in the Dockerfile

Install as root into the system directory, publish its shims, close it:

```dockerfile
USER root
RUN umask 022 \
 && HOME=/root mise install --system python@3.13.7 node@22.21.1 uv@0.8.22 \
 && HOME=/root mise reshim --system \
 && chmod -R a-w /opt/mise
USER vscode
RUN mise use -g python@3.13.7 node@22.21.1 uv@0.8.22
```

- `mise reshim --system` is needed: without it the user's mise tries to publish the system shims
  itself and fails (`refusing to publish outside the system installs or shims directories`).
- `mise use -g` as the user only records the versions; nothing is downloaded or copied.

### From a prebuilt language image

Source-built languages (PHP, Python 2.7) take minutes to build. Their prebuilt images (#376, when published) hold them
under `/opt/mise`:

```dockerfile
FROM ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm AS php
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.67
USER root
RUN apt-get update && apt-get install -y --no-install-recommends <the image's runtime packages> \
 && rm -rf /var/lib/apt/lists/*
COPY --from=php /opt/mise/installs/php/ /opt/mise/installs/php/
COPY --from=php --chown=vscode:vscode /home/ /home/
RUN HOME=/root mise reshim --system && chmod -R a-w /opt/mise
USER vscode
RUN mise use -g php@8.3.26
```

- Tags: `<version>-<revision>-bookworm` (`8.3.33-1-bookworm`) never changes; a rebuild of the same version is a new revision. `<version>-bookworm` follows the newest revision. Name the revision to pin the exact image.
- Followed lines: for a line in `lang/versions.yml`'s `track` (PHP 8.3), each new patch is published the day it appears. Other versions are built once, as pinned there. `sgw update` reports a newer patch of a followed line in a project's Dockerfile, and `--apply` writes it (a literal tag only, not one written through an ARG); it never moves to another line, and leaves other versions alone.
- Copy the whole `/opt/mise/installs/<lang>/`: beside the version it holds mise's backend note and the version's aliases (`8.3`, `latest`).
- `/home/` carries the mise plugin a language needs at run time (PHP: vfox-php). mise has no system directory for plugins, so it goes where the user's mise looks. A language without one (Python) has an empty `/home/`.
- `/opt/mise/installs/<lang>/<version>/.sgw-runtime-packages` lists the apt packages its binaries need at run time.

### Global npm tools

The system node is read-only, so `npm install -g` fails with EACCES. Install a CLI as a mise tool
instead: `HOME=/root mise install --system npm:<package>@<version>` (or `pnpm@<version>`).

## One person: in the container

```sh
mise use -g node@24.21.0
```

It downloads into `~/.local/share/mise/installs`, the mise-store volume, so it survives a
rebuild. The download goes through the gateway, so its hosts have to be in `allow_domains`:

| Language | Hosts |
|---|---|
| node | `nodejs.org` |
| python (prebuilt), uv | `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` |
| most others (aqua, GitHub releases) | `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `api.github.com` |
| yarn | `repo.yarnpkg.com` |
| mise itself, for any of them (the version lists) | `mise.jdx.dev`, `mise-versions.jdx.dev` |

A refused download names its host in `sgw web` / `sgw audit`.

A Dockerfile is built by the Docker on the host, which does not go through the gateway, so its
`mise install --system` needs none of this. Where the build itself runs behind the gateway (Docker
in the dev container), it needs the same hosts, and `download.docker.com` for an image that adds
Docker's apt repository.

## The older way

Installing into the user's data directory and copying it to
`~/.local/share/mise/installs-default`, which post-create copies into an empty mise-store volume,
still works on 0.2.x. 0.3 drops it; see UPGRADING when moving there.
