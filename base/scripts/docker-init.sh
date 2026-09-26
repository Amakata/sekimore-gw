#!/usr/bin/env bash
#
# dockerd entrypoint helper, baked into the base image.
#
# Starts dockerd in the background if it is not already running.
# Intended to be called from the consuming devcontainer.json's
# postStartCommand.
#
# Equivalent of the init script in
# ghcr.io/devcontainers/features/docker-in-docker:2.

set -e

if [ -S /var/run/docker.sock ] && docker info >/dev/null 2>&1; then
    exit 0
fi

sudo rm -f /var/run/docker.pid /var/run/docker.sock 2>/dev/null || true

sudo sh -c 'nohup dockerd > /var/log/dockerd.log 2>&1 &'

for _ in $(seq 1 30); do
    if docker info >/dev/null 2>&1; then
        exit 0
    fi
    sleep 1
done

echo "dockerd failed to start within 30s — see /var/log/dockerd.log" >&2
exit 1
