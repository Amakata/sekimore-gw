# syntax=docker/dockerfile:1.7
#
# A prebuilt language for the dev container (#376): one language at one version, installed into
# mise's system directory (/opt/mise) on the base image, for a project to `COPY --from=`.
#
#   docker build --build-arg LANG_NAME=php --build-arg LANG_VERSION=8.3.26 -t sgw-lang-php lang/
#
# Each language has a directory beside this file: `deps` (apt packages the build needs), `env`
# (the build's environment, `KEY=value` lines) and `check.sh` (run as the user in a container that
# has only the base, the runtime packages and the language — and no network).
#
# Targets: `build` installs it; `test` is a downstream image made the documented way, and runs
# check.sh; the default, `image`, holds only /opt/mise/installs/<lang>/<version> and the list of
# runtime packages, which is all a project copies.

ARG BASE=ghcr.io/amakata/sgw-devcontainer-base:0.2.67

FROM ${BASE} AS build
ARG LANG_NAME
ARG LANG_VERSION
USER root
COPY ${LANG_NAME}/ /tmp/lang/
# what the base has, before the build's own packages: a runtime need it covers is not one to list
RUN dpkg-query -W -f '${Package}\n' > /tmp/base-packages
RUN apt-get update \
 && grep -v '^#' /tmp/lang/deps | xargs apt-get install -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
RUN set -a && . /tmp/lang/env && set +a \
 && umask 022 \
 && HOME=/root mise install --system "${LANG_NAME}@${LANG_VERSION}"
COPY runtime-packages.sh /tmp/runtime-packages.sh
RUN dir="/opt/mise/installs/${LANG_NAME}/${LANG_VERSION}" \
 && test -d "$dir" \
 && sh /tmp/runtime-packages.sh "$dir" /tmp/base-packages > "$dir/.sgw-runtime-packages" \
 && echo "runtime packages:" && cat "$dir/.sgw-runtime-packages"

# A downstream image, the way docs/languages.md says to make one
FROM ${BASE} AS test
ARG LANG_NAME
ARG LANG_VERSION
USER root
COPY --from=build /opt/mise/installs/${LANG_NAME}/${LANG_VERSION}/ /opt/mise/installs/${LANG_NAME}/${LANG_VERSION}/
RUN apt-get update \
 && xargs apt-get install -y --no-install-recommends < "/opt/mise/installs/${LANG_NAME}/${LANG_VERSION}/.sgw-runtime-packages" \
 && rm -rf /var/lib/apt/lists/* \
 && HOME=/root mise reshim --system \
 && chmod -R a-w /opt/mise
COPY ${LANG_NAME}/check.sh /tmp/check.sh
USER vscode
# no network: whatever the language needs at run time has to be in the image already
RUN --network=none cd /tmp && mise use -g "${LANG_NAME}@${LANG_VERSION}" && sh /tmp/check.sh

FROM scratch AS image
ARG LANG_NAME
ARG LANG_VERSION
COPY --from=build /opt/mise/installs/${LANG_NAME}/${LANG_VERSION}/ /opt/mise/installs/${LANG_NAME}/${LANG_VERSION}/
