# syntax=docker/dockerfile:1.7
#
# sgw-sample devcontainer image
#
# Builds on sgw-devcontainer-base. Only project-specific extras go here.
# Base tools (zsh, mise, aws-cli, docker, sekimore agent-setup script, ...)
# are already baked in.
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.76

# Claude Code, Codex and the Anthropic skills: not in the base image, downloaded here when you
# build this image. `sgw-install-ai claude codex skills` picks; remove the lines for none of them
USER root
RUN sgw-install-ai
USER vscode

# ---------------------------------------------------------------------------
# Language build dependencies
#
# mise builds PHP from source (php-build), and Ruby too where it has no
# precompiled one, so the required -dev headers are installed here. The common
# block also covers native gem and cargo extensions; the PHP block is commented
# out and should be uncommented together with the PHP install lines below.
# ---------------------------------------------------------------------------
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      # Common build tooling (Ruby + cargo native ext + PHP all share these)
      build-essential autoconf pkg-config \
      libssl-dev libreadline-dev zlib1g-dev \
      libyaml-dev libffi-dev libgmp-dev \
    # Uncomment the following lines to enable PHP build deps:
    #  bison re2c \
    #  libxml2-dev libsqlite3-dev libcurl4-openssl-dev \
    #  libbz2-dev libzip-dev libonig-dev \
    #  # Image libs (GD)
    #  libpng-dev libjpeg-dev libfreetype6-dev libwebp-dev libavif-dev \
    #  # PHP extensions commonly required by CMSes (Adobe Commerce etc.)
    #  libtidy-dev libxslt1-dev libsodium-dev libicu-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Language versions, baked into the image root-owned and read-only (#444, docs/languages.md).
#
# Adjust versions to taste (x.y.z, not `latest`), or remove the ones you don't need.
#
# mise's system directory, /opt/mise (MISE_SYSTEM_DATA_DIR in the base image): installed as
# root, shims published with `mise reshim --system`, then closed with `chmod -R a-w`. Why not
# the user's `mise use -g` into ~/.local/share/mise/installs: docker-compose.yml mounts the
# mise-store volume there, which hides what the image put there, and the user could overwrite
# it. The volume keeps only what a person adds in the container, and a version there wins over
# the same version here.
#
# The base image puts the mise shims, the user's then /opt/mise/shims, first in ENV PATH, so the
# languages resolve from non-interactive processes too (Claude Code tool calls, `docker exec`,
# postCreateCommand), and a script in /etc/profile.d adds them back for login shells.
#
# Being read-only, the system node and ruby take no global packages: `npm install -g` and
# `gem install` fail. Install a CLI as a mise tool (docs/languages.md), and gems with bundler
# or `gem install --user-install`.
# ---------------------------------------------------------------------------
ARG PYTHON_VERSION=3.13.0
ARG NODE_VERSION=22.11.0
ARG RUBY_VERSION=3.3.6
# PHP builds from source for minutes; a prebuilt language image is quicker (docs/languages.md).
# Uncomment to enable it (also uncomment the PHP build deps above):
# ARG PHP_VERSION=8.3.12

# MISE_PYTHON_GITHUB_ATTESTATIONS=false: python-build-standalone artifacts for some versions
# (3.13.0 included) lack attestations, and mise then refuses them. For this command only, so a
# version a person installs later is still checked.
RUN umask 022 \
 && HOME=/root MISE_PYTHON_GITHUB_ATTESTATIONS=false mise install --system \
      "python@${PYTHON_VERSION}" \
      "node@${NODE_VERSION}" \
      "ruby@${RUBY_VERSION}" \
 && HOME=/root mise reshim --system \
 && chmod -R a-w /opt/mise
# Uncomment to enable PHP (and add php@${PHP_VERSION} to `mise use -g` below):
# RUN umask 022 \
#  && HOME=/root mise install --system "php@${PHP_VERSION}" \
#  && HOME=/root mise reshim --system \
#  && chmod -R a-w /opt/mise

# ---------------------------------------------------------------------------
# Rust: rustup into /opt/rustup and /opt/cargo, root-owned and read-only.
#
# Why not mise: its rust goes through rustup and keeps the toolchain in root's ~/.rustup, which
# the user cannot read, so the user's rustup downloads it again into its own home. The
# toolchain is fixed in the image: a project's rust-toolchain.toml has to name this version, or
# rustup tries to install another one into the read-only directory and fails; so do
# `rustup update`, `rustup component add` and a person's `mise use rust@…`, which runs the same
# rustup on RUSTUP_HOME. Change it here and rebuild. cargo's registry and build cache stay in
# the user's ~/.cargo.
# ---------------------------------------------------------------------------
ARG RUST_VERSION=1.99.1
ENV RUSTUP_HOME=/opt/rustup
RUN umask 022 \
 && curl --proto '=https' -sSf https://sh.rustup.rs \
    | env CARGO_HOME=/opt/cargo sh -s -- -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_VERSION}" -c rustfmt -c clippy \
 && chmod -R a-w /opt/rustup /opt/cargo
ENV CARGO_HOME=/home/vscode/.cargo \
    PATH="${PATH}:/opt/cargo/bin"
# Login shells: Debian's /etc/profile assigns PATH and drops the ENV above, as with the base's
# mise shims (#60)
RUN printf '%s\n' \
      'case ":$PATH:" in *":/opt/cargo/bin:"*) ;; *) PATH="$PATH:/opt/cargo/bin" ;; esac' \
      'export PATH RUSTUP_HOME=/opt/rustup CARGO_HOME="$HOME/.cargo"' \
    > /etc/profile.d/10-rust.sh \
 && chmod 0644 /etc/profile.d/10-rust.sh

USER vscode
# Records the versions as the user's defaults; nothing is downloaded or copied
RUN mise use -g "python@${PYTHON_VERSION}" "node@${NODE_VERSION}" "ruby@${RUBY_VERSION}"

WORKDIR /workspace
