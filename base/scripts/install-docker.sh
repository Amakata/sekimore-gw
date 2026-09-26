#!/usr/bin/env bash
#
# Install Docker CE + buildx + compose plugin.
#
# This is a simplified equivalent of
# ghcr.io/devcontainers/features/docker-in-docker:2
# baked into the base image at build time.
#
# Runtime privileges (NET_ADMIN, cgroup, /var/lib/docker volume, dockerd startup)
# are still the responsibility of the consuming devcontainer.json /
# docker-compose.yml.

set -eux

USERNAME="${USERNAME:-vscode}"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    iptables \
    pigz \
    xz-utils

# Add Docker's official GPG key and repository
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"

echo \
  "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Allow the non-root user to use docker without sudo.
if ! getent group docker >/dev/null 2>&1; then
    groupadd docker
fi
usermod -aG docker "${USERNAME}"

apt-get clean
rm -rf /var/lib/apt/lists/*
