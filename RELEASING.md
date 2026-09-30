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
   template's compose and Dockerfile (`relay/templates/devcontainer/`), the READMEs under
   `base/`, and the `reviewed-up-to` marker of `UPGRADING.md` / `UPGRADING.ja.md` after
   deciding whether the release asks anything of a project.
   `tests/unit/test_base_versions.py` fails until every one of them says the new version
4. Open the release pull request. Its CI builds what the tag will build: `base.yml` builds the gateway
   image of that commit and the base image against it and runs `base/tests/test_image.sh`, and
   `preview.yml` builds the arm64 gateway image — so a COPY that names a path that moved fails
   here, not after the tag. No local image build is needed; to look at one anyway:
   `docker build -t sekimore-gw:X.Y.Z-local .`
5. Merge it, tag the merge commit (signed) and push the tag.
   `docker-publish.yml` builds the gateway image, then the base image, then the `sgw` binaries
   (macOS arm64, Linux x86_64 / arm64), and creates a **draft** Release with the binaries,
   their sha256 files and `install.sh` attached
6. Publish the Release with the changelog's bullets as its notes:
   ```
   sekimore release edit --repo Amakata/sekimore-gw --tag vX.Y.Z --notes="- …" --draft false
   ```
   (`release create` would collide with the draft the workflow made)

## Two lines: 0.2 on `main`, 0.3 on `next`

- `main` carries the 0.2 line and releases `vX.Y.Z` as above.
- `next` carries the 0.3 line. Until 0.3.0, it releases prereleases only: `v0.3.0-alpha.N`.
  Tag the merge commit on `next` the same way.
- A prerelease tag publishes its own version tag on GHCR and nothing else (`0.3`, `0`, `latest`
  stay on the 0.2 line), and its Release is marked prerelease, so `releases/latest/download/` and
  `sgw update` keep handing out 0.2.
- Fixes land on `main` first. Merge `main` into `next` from time to time; do not rebase `next`.
- Pull requests for the 0.3 line use `--base next`.
- A prerelease is spelled the SemVer way everywhere a person writes it: `0.3.0-alpha.1` in
  `pyproject.toml`, `relay/Cargo.toml`, the pins, the CHANGELOG heading, the UPGRADING marker and
  the tag. `uv.lock` records it as `0.3.0a1`; that is uv normalising it (PEP 440), not a mismatch.
- `sgw update` on a 0.2 sgw never offers a prerelease; on a prerelease sgw it offers the newest
  version, alpha or release, and moves the pins as for any version.

## Tags pushed to GHCR

| Trigger | Gateway image | Base image |
| --- | --- | --- |
| Push of a `vX.Y.Z` tag | `X.Y.Z`, `X.Y`, `X`, `latest` | the same |
| Push of a `vX.Y.Z-pre` tag (0.3 line) | `X.Y.Z-pre` only | the same |

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
