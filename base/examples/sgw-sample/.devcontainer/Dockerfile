# syntax=docker/dockerfile:1.7
#
# sgw-sample devcontainer image
#
# Builds on sgw-devcontainer-base. Only project-specific extras go here.
# Base tools (zsh, mise, aws-cli, docker, sekimore agent-setup script, ...)
# are already baked in.
FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.48

# ---------------------------------------------------------------------------
# Language build dependencies
#
# mise installs Ruby / PHP from source (via ruby-build / php-build), so the
# required -dev headers are installed here.  The common block covers Ruby and
# cargo native extensions; the PHP block is commented out and should be
# uncommented together with the PHP install lines below.
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

USER vscode

# ---------------------------------------------------------------------------
# Install specific language versions via mise (pre-installed in base image).
#
# Adjust versions to taste, or remove blocks you don't need. After adding a
# version with `mise use -g`, run `mise reshim` to regenerate the shims.
#
# The base image puts ~/.local/share/mise/shims first in ENV PATH, so the
# languages resolve from non-interactive processes too (Claude Code tool
# calls, `docker exec`, postCreateCommand). Debian's /etc/profile resets PATH
# for login shells, and a script in /etc/profile.d in the base image adds the
# shims directory back.
# ---------------------------------------------------------------------------
ARG PYTHON_VERSION=3.13.0
ARG NODE_VERSION=22.11.0
ARG RUBY_VERSION=3.3.6
ARG RUST_VERSION=stable
# Uncomment to enable PHP (also uncomment the PHP build deps above):
# ARG PHP_VERSION=8.3.12

# Disable GitHub attestation verification for pre-built Python binaries.
# python-build-standalone artifacts for some versions lack attestations,
# causing `mise use` to fail. This is safe in a Docker build context.
ENV MISE_PYTHON_GITHUB_ATTESTATIONS=false

RUN mise use -g "python@${PYTHON_VERSION}" \
             "node@${NODE_VERSION}" \
             "ruby@${RUBY_VERSION}" \
             "rust@${RUST_VERSION}" \
    && mise reshim

# Uncomment to enable PHP:
# RUN mise use -g "php@${PHP_VERSION}" && mise reshim

# ---------------------------------------------------------------------------
# Stage the populated mise installs so the sample's mise-store volume
# can be bootstrapped on first start (see scripts/post-create.sh).
#
# docker-compose.yml mounts the mise-store volume over
# ~/.local/share/mise/installs, which hides what this image installed there.
# On the first start the volume is empty, and post-create.sh restores the
# copy made here:
#   rsync -a --ignore-existing ~/.local/share/mise/installs-default/ ~/.local/share/mise/installs/
#   mise reshim
# ---------------------------------------------------------------------------
RUN cp -a ~/.local/share/mise/installs ~/.local/share/mise/installs-default

WORKDIR /workspace
