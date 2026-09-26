# syntax=docker/dockerfile:1.7
#
# sgw-devcontainer-base
# Base image for Amakata personal-dev devcontainers that sit behind sekimore-gw.
#
# What's baked in:
#   - mcr.microsoft.com/devcontainers/base:bookworm  (provides vscode user uid=1000, git, sudo, etc.)
#   - common shell tooling (fzf, iproute2, jq, vim, rsync, ...)
#   - DB client dev headers (libpq-dev, default-libmysqlclient-dev)
#   - git-delta
#   - zsh + oh-my-zsh + plugins
#   - mise (jdx/mise) — unified version manager for python/node/ruby/php/rust/...
#     (no specific language versions — those are downstream's responsibility).
#     shims are on PATH via ENV, so non-interactive subprocesses (Claude Code
#     tool invocations, `docker exec cmd`, make, etc.) resolve language binaries
#     without needing `mise activate` to run.
#   - Claude Code CLI
#   - OpenAI Codex CLI
#   - sekimore-gw agent-setup script (at /usr/local/bin/sekimore-agent-setup.sh)
#   - AWS CLI v2                (== devcontainers/features/aws-cli)
#   - Docker CE + buildx + compose plugin   (== devcontainers/features/docker-in-docker)
#
# What is NOT baked in (intentionally case-specific):
#   - GitHub CLI (gh). Deliberately absent: api.github.com is reached through the relay's 443
#     passthrough, which forwards without reading, so a `gh` holding a token would act on GitHub
#     with none of the per-action permissions the relay enforces (pr:merge and the rest) and
#     against repositories outside the project. `sekimore` covers the same ground through the
#     agent API, where each action is checked and audited (#62)
#   - sekimore-gw service itself (runs as a separate compose service)
#   - /workspace contents, .env, config.yml, zsh rc.d overlays
#   - anything pinned to a specific project layout
# ---------------------------------------------------------------------------
# sekimore-gw image: source of the sekimore-relay binary (static musl) and the
# agent-setup script. Taking both from the SAME tag keeps them in lock-step.
# Override for local testing: --build-arg SEKIMORE_GW_IMAGE=sekimore-gw:relay-dev
# ---------------------------------------------------------------------------
ARG SEKIMORE_GW_IMAGE=ghcr.io/amakata/sekimore-gw:0.2.46
FROM ${SEKIMORE_GW_IMAGE} AS sekimore-gw

FROM mcr.microsoft.com/devcontainers/base:bookworm

ARG USERNAME=vscode
ARG TARGETARCH

# ---------------------------------------------------------------------------
# Base apt packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      fzf \
      iptables \
      iproute2 \
      iputils-ping \
      dnsutils \
      jq \
      nano \
      vim \
      pv \
      wget \
      curl \
      ca-certificates \
      unzip \
      sudo \
      rsync \
      gnupg \
      media-types \
      chromium \
      fonts-noto-cjk \
      fonts-noto-color-emoji \
      # DB client dev headers
      libpq-dev default-libmysqlclient-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure default vscode user has access to /usr/local/share
RUN chown -R ${USERNAME}:${USERNAME} /usr/local/share

# Persist zsh history via a well-known path (devcontainer mounts /commandhistory).
RUN mkdir -p /commandhistory \
    && touch /commandhistory/.zsh_history \
    && chown -R ${USERNAME} /commandhistory

# Orientation hint for tools that special-case devcontainers.
ENV DEVCONTAINER=true

RUN mkdir -p /workspace /home/${USERNAME}/.claude \
    && chown -R ${USERNAME}:${USERNAME} /workspace /home/${USERNAME}/.claude

WORKDIR /workspace

# ---------------------------------------------------------------------------
# git-delta
# ---------------------------------------------------------------------------
ARG GIT_DELTA_VERSION=0.18.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    dpkg -i "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    rm "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"

# ---------------------------------------------------------------------------
# AWS CLI v2  (replaces ghcr.io/devcontainers/features/aws-cli:1)
# ---------------------------------------------------------------------------
RUN set -eux; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) AWS_ARCH=x86_64 ;; \
        arm64) AWS_ARCH=aarch64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}.zip" -o awscliv2.zip; \
    unzip -q awscliv2.zip; \
    ./aws/install; \
    rm -rf awscliv2.zip aws

# ---------------------------------------------------------------------------
# Docker CE + buildx + compose  (replaces ghcr.io/devcontainers/features/docker-in-docker:2)
# ---------------------------------------------------------------------------
COPY scripts/install-docker.sh /tmp/install-docker.sh
RUN USERNAME=${USERNAME} bash /tmp/install-docker.sh && rm /tmp/install-docker.sh

# dockerd startup helper. Consumers call this from postStartCommand.
COPY scripts/docker-init.sh /usr/local/bin/docker-init.sh
RUN chmod +x /usr/local/bin/docker-init.sh

# ---------------------------------------------------------------------------
# zsh / oh-my-zsh / plugins  (as vscode user)
# ---------------------------------------------------------------------------
USER ${USERNAME}
ENV SHELL=/bin/zsh

# zsh plugins (oh-my-zsh is already installed in the devcontainers base image)
RUN git clone --depth 1 https://github.com/zsh-users/zsh-completions.git           ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-completions && \
    git clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions.git       ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions && \
    git clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting.git   ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting && \
    git clone --depth 1 https://github.com/zdharma-continuum/fast-syntax-highlighting.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/fast-syntax-highlighting && \
    git clone --depth 1 https://github.com/marlonrichert/zsh-autocomplete.git      ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autocomplete

# ---------------------------------------------------------------------------
# mise (jdx/mise) — unified version manager
#
# Only mise itself is installed here — no specific language versions.
# Downstream images run e.g. `mise use -g python@3.13.0` as needed.
#
# ~/.local/share/mise/installs is the data directory. Downstream images that
# pre-install languages should stage a copy at ~/.local/share/mise/installs-default
# so a devcontainer that mounts an empty volume there can restore via:
#   rsync -a --ignore-existing \
#     ~/.local/share/mise/installs-default/ \
#     ~/.local/share/mise/installs/
#   mise reshim
# ---------------------------------------------------------------------------
USER root
RUN install -dm 0755 /etc/apt/keyrings && \
    curl -fsSL https://mise.jdx.dev/gpg-key.pub \
      -o /etc/apt/keyrings/mise-archive-keyring.asc && \
    chmod a+r /etc/apt/keyrings/mise-archive-keyring.asc && \
    echo "deb [signed-by=/etc/apt/keyrings/mise-archive-keyring.asc] https://mise.jdx.dev/deb stable main" \
      > /etc/apt/sources.list.d/mise.list && \
    apt-get update && apt-get install -y --no-install-recommends mise && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

USER ${USERNAME}

# Put the mise shims directory on PATH for EVERY process — including non-login
# and non-interactive ones (Claude Code tool subprocesses, `docker exec cmd`,
# postCreateCommand, make, etc.). /etc/profile.d is NOT read by those paths,
# so we rely on Docker ENV here. `mise activate` in the zsh rc.d adds the
# interactive-only cd hook on top of this.
ENV PATH="/home/${USERNAME}/.local/share/mise/shims:${PATH}"

# ...and put it back for LOGIN shells, which is the one path ENV does not cover.
# Debian's /etc/profile assigns PATH rather than appending to it, so a login shell
# (`docker exec -l`, `sh -lc`, a terminal a person opens) throws the line above away
# and loses node, npm and codex with it (#60). /etc/profile.d runs after that
# assignment, so this is where it goes back.
USER root
RUN printf '%s\n' \
      '# mise shims: /etc/profile assigns PATH, so a login shell would drop the image ENV (#60)' \
      'case ":$PATH:" in' \
      '  *":$HOME/.local/share/mise/shims:"*) ;;' \
      '  *) PATH="$HOME/.local/share/mise/shims:$PATH" ;;' \
      'esac' \
      'export PATH' \
    > /etc/profile.d/05-mise-shims.sh && chmod 0644 /etc/profile.d/05-mise-shims.sh
USER ${USERNAME}


# Claude Codeの設定ファイルを配置
USER root
RUN mkdir -p /etc/claude-code
COPY managed-settings.json /etc/claude-code/managed-settings.json

# ---------------------------------------------------------------------------
# Bundle official Anthropic skills (pptx / docx / xlsx / pdf)
#
# Skills are placed in /etc/skel/.claude/skills/ so that post-create.sh can
# copy them to each user's ~/.claude/skills/. Claude Code only resolves
# skills from ~/.claude/skills/ or <workspace>/.claude/skills/, so a true
# system-wide path is not supported.
#
# Source: https://github.com/anthropics/skills (main branch, sparse checkout)
# ---------------------------------------------------------------------------
RUN mkdir -p /etc/skel/.claude/skills && \
  tmpdir="$(mktemp -d)" && \
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/anthropics/skills.git "$tmpdir/skills" && \
  git -C "$tmpdir/skills" sparse-checkout set \
    skills/pptx \
    skills/docx \
    skills/xlsx \
    skills/pdf && \
  cp -r "$tmpdir/skills/skills/pptx" /etc/skel/.claude/skills/ && \
  cp -r "$tmpdir/skills/skills/docx" /etc/skel/.claude/skills/ && \
  cp -r "$tmpdir/skills/skills/xlsx" /etc/skel/.claude/skills/ && \
  cp -r "$tmpdir/skills/skills/pdf"  /etc/skel/.claude/skills/ && \
  rm -rf "$tmpdir"

# ---------------------------------------------------------------------------
# Claude Code CLI
# ---------------------------------------------------------------------------
USER ${USERNAME}
RUN curl -fsSL https://claude.ai/install.sh | bash -s stable

# ---------------------------------------------------------------------------
# OpenAI Codex CLI
# Requires Node.js 18+. mise is already on PATH, so we install a temporary
# Node runtime via mise, install codex globally with npm, then leave the
# shims in place. Downstream images that `mise use -g node@...` will
# naturally keep codex available.
# ---------------------------------------------------------------------------
RUN mise use -g node@lts && npm install -g @openai/codex

# ---------------------------------------------------------------------------
# Default zsh rc.d snippets
#
# Staged at /etc/skel/zsh-rc.d/. Downstream post-create scripts can copy
# these into ~/.config/zsh/rc.d/ (same pattern as envs-default):
#   rsync -a --ignore-existing /etc/skel/zsh-rc.d/ "$HOME/.config/zsh/rc.d/"
# Projects can override or add more snippets as needed.
# ---------------------------------------------------------------------------
USER root
COPY zsh-config/rc.d/ /etc/skel/zsh-rc.d/
RUN chown -R ${USERNAME}:${USERNAME} /etc/skel/zsh-rc.d/

USER root
# ---------------------------------------------------------------------------
# sekimore-gw agent-setup script + sekimore-relay CLI
#
# Both come from the sekimore-gw image (see the sekimore-gw stage at the top),
# so the devcontainer can run `sudo /usr/local/bin/sekimore-agent-setup.sh`
# without a network fetch, and `sekimore` / `sekimore-relay agent ...` talk to
# the relay with the project token that agent-setup writes to
# /etc/sekimore-agent/env.
#
# Last on purpose. The relay binary changes with every sekimore-gw release and
# nothing below depends on these three files, so a gateway bump invalidates only
# these layers — not node, codex, Claude Code or the oh-my-zsh plugins, which is
# what made every bump a full re-pull.
# ---------------------------------------------------------------------------
COPY --from=sekimore-gw /usr/local/share/sekimore/agent-setup.sh /usr/local/bin/sekimore-agent-setup.sh
COPY --from=sekimore-gw /usr/local/bin/sekimore-relay /usr/local/bin/sekimore-relay
COPY scripts/sekimore /usr/local/bin/sekimore
RUN chmod +x /usr/local/bin/sekimore-agent-setup.sh /usr/local/bin/sekimore-relay /usr/local/bin/sekimore
RUN mkdir -p /etc/sekimore-agent

USER ${USERNAME}
WORKDIR /workspace
