# Releasing

One tag releases everything: the gateway image (`ghcr.io/amakata/sekimore-gw`), the dev-container
base image (`ghcr.io/amakata/sgw-devcontainer-base`, built from `base/` against the gateway image
of the same tag) and, later, the `sgw` binaries. One version number, `pyproject.toml`'s.

## Steps

1. Bump the version in `pyproject.toml` and `relay/Cargo.toml`; refresh `uv.lock` (`uv lock`) and
   `relay/Cargo.lock` (`cargo update -p sekimore-relay` in `relay/`)
2. Write the release up in `CHANGELOG.md` and `CHANGELOG.ja.md`: one section for the gateway, the
   relay, the base and sgw (`tests/unit/test_changelog_style.py` holds the shape)
3. Move the base's pins to the new version: `ARG SEKIMORE_GW_IMAGE` in `base/Dockerfile`, the
   sample's compose and Dockerfile, the READMEs under `base/`, and the `reviewed-up-to` marker of
   `UPGRADING.md` / `UPGRADING.ja.md` after deciding whether the release asks anything of a
   project. `tests/unit/test_base_versions.py` fails until every one of them says the new version
4. `docker build -t sekimore-gw:X.Y.Z-local .` must succeed before anything is tagged
5. Open the release pull request, merge it, tag the merge commit (signed) and push the tag.
   `docker-publish.yml` builds the gateway image, then the base image, then the `sgw` binaries
   (macOS arm64, Linux x86_64 / arm64), and creates a **draft** Release with the binaries,
   their sha256 files and `install.sh` attached
6. Publish the Release with the changelog's bullets as its notes:
   ```
   sekimore release edit --repo Amakata/sekimore-gw --tag vX.Y.Z --notes="- …" --draft false
   ```
   (`release create` would collide with the draft the workflow made)

## Tags pushed to GHCR

| Trigger | Gateway image | Base image |
| --- | --- | --- |
| Push of a `vX.Y.Z` tag | `X.Y.Z`, `X.Y`, `X`, `latest` | the same |

## Release assets

`sgw-<target>.tar.gz` and `.sha256` for `aarch64-apple-darwin`, `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, and `install.sh` (`scripts/install-sgw.sh`). The asset names carry
no version, so `releases/latest/download/…` works:

```sh
curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
```
| Push to `main`, pull request | preview image (`preview.yml`); base built but not pushed (`base.yml`), its files tested (`base-tests.yml`) | — |

## Local builds of the base image

```sh
docker build -t sgw-devcontainer-base:dev base
docker build -t sgw-devcontainer-base:dev --build-arg SEKIMORE_GW_IMAGE=sekimore-gw:X.Y.Z-local base
base/tests/test_image.sh sgw-devcontainer-base:dev
```

The build needs `ghcr.io` and `pkg-containers.githubusercontent.com`.
