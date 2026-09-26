# Releasing

This document is for maintainers of sgw-devcontainer-base.

## Release order

This image copies its relay binaries from the gateway image, so a gateway release comes first and
no step can be skipped:

1. Tag sekimore-gw.
2. Publish it to GHCR.
3. Raise the `ARG SEKIMORE_GW_IMAGE` default in this repository's `Dockerfile` and push.
4. Publish this image to GHCR.
5. Update the gateway's image tag in `examples/sgw-sample/.devcontainer/docker-compose.yml`.

When the base is released, the sample's `.devcontainer/Dockerfile` moves to the new `FROM` tag,
and `scripts/sync-sample-sgw.sh` updates the sample's `.devcontainer/sgw/` to match.
`tests/test_sample_sgw.sh` fails until they agree, and `tests/test_versions.sh` fails until every
version quoted in the READMEs, the sample and UPGRADING agrees with the Dockerfile.

## Network access

The build requires access to `ghcr.io` and `pkg-containers.githubusercontent.com`.

## Local build

A multi-platform build:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t sgw-devcontainer-base:dev \
  .
```

A single-platform build for local testing:

```sh
docker build -t sgw-devcontainer-base:dev .
docker run --rm -it sgw-devcontainer-base:dev zsh
```

To take the relay from a locally built sekimore-gw image, override the gateway image:

```sh
docker build -t sgw-devcontainer-base:dev --build-arg SEKIMORE_GW_IMAGE=sekimore-gw:relay-dev .
```

## Tags pushed to GHCR

GitHub Actions (`.github/workflows/build-and-push.yml`) pushes the following tags:

| Trigger | Tags |
| --- | --- |
| Push to `main` | `main`, `latest`, `sha-<short>` |
| Push of a `v1.2.3` tag | `1.2.3`, `1.2`, `1`, `sha-<short>` |
| Pull request | (build only, nothing pushed) |
