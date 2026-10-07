# syntax=docker/dockerfile:1.7
#
# sgw-sample devcontainer image
#
# Builds on sgw-devcontainer-base. Only project-specific extras go here.
# Base tools (zsh, mise, aws-cli, docker, sekimore agent-setup script, ...)
# are already baked in.
FROM ghcr.io/amakata/sgw-devcontainer-base:0.3.0-alpha.1

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

# ---------------------------------------------------------------------------
# The project's languages, in mise's system directory (/opt/mise; 0.3, #377).
#
# Installed as root, read-only, and part of the image: a rebuild brings the
# versions written here, and the agent cannot change them. Write versions as
# x.y.z. A person adds a version of their own with `mise use -g <lang>@<x.y.z>`
# in the container; it goes to the mise-store volume and survives a rebuild.
#
# PHP and Python 2.7 have prebuilt images, which take seconds instead of a
# source build (docs/languages.md):
#   FROM ghcr.io/amakata/sgw-lang-php:8.3.35-1-bookworm AS php   (above FROM base)
#   COPY --from=php /opt/mise/installs/php/ /opt/mise/installs/php/
#   COPY --from=php --chown=vscode:vscode /home/ /home/
#   then apt-get install the packages in
#   /opt/mise/installs/php/8.3.35/.sgw-runtime-packages
#
# Rust is a person's: `mise use -g rust@<x.y.z>` in the container. mise installs
# it through rustup, which does not work from the system directory.
# ---------------------------------------------------------------------------
ARG PYTHON_VERSION=3.13.0
ARG NODE_VERSION=22.11.0
ARG RUBY_VERSION=3.3.6

# Disable GitHub attestation verification for pre-built Python binaries.
# python-build-standalone artifacts for some versions lack attestations,
# causing `mise install` to fail. This is safe in a Docker build context.
ENV MISE_PYTHON_GITHUB_ATTESTATIONS=false

RUN umask 022 \
 && HOME=/root mise install --system \
      "python@${PYTHON_VERSION}" \
      "node@${NODE_VERSION}" \
      "ruby@${RUBY_VERSION}" \
 && HOME=/root mise reshim --system \
 && chmod -R a-w /opt/mise

USER vscode
# records the versions for the user; nothing is downloaded or copied
RUN mise use -g "python@${PYTHON_VERSION}" "node@${NODE_VERSION}" "ruby@${RUBY_VERSION}"

WORKDIR /workspace
