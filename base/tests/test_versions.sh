#!/usr/bin/env bash
# Every place that names a version agrees with the one place that decides it.
#
# The gateway version is decided by `ARG SEKIMORE_GW_IMAGE` in the Dockerfile: it is where the
# relay binary and the agent guide baked into this image come from. Several other files repeat
# that number for a reader, and repeating it is how it goes stale.
#
# 0.2.27 is why this exists. The gateway had been released as 0.2.32 and upgraded in a project,
# but this image still took 0.2.31, so `sekimore-relay --version` inside a dev container answered
# 0.2.31 and its agent guide never mentioned `refs/pr/<branch>`. Nothing failed: the sample's own
# pins agreed with each other, and no test compared them with the Dockerfile.
#
#   - the sample's compose file pins the same gateway the Dockerfile takes
#   - the READMEs quote that gateway
#   - UPGRADING's `reviewed-up-to` is that gateway, so a release cannot skip deciding whether it
#     asks anything of the reader
#   - the sample's FROM is a release this repository has written up
#
# It reads files only. That the image really holds the relay it claims is a different question,
# and a build answers it; this one catches the drift that a build would not.
#
# Run it directly: tests/test_versions.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
SAMPLE=$ROOT/examples/sgw-sample
fail() { echo "FAIL: $*" >&2; exit 1; }

# ---- the one place that decides it ----
GW=$(sed -n 's|^ARG SEKIMORE_GW_IMAGE=ghcr.io/amakata/sekimore-gw:\([0-9][0-9.]*\).*|\1|p' "$ROOT/Dockerfile")
[ -n "$GW" ] || fail "Dockerfile has no 'ARG SEKIMORE_GW_IMAGE=ghcr.io/amakata/sekimore-gw:<version>'"
echo "== the Dockerfile takes gateway $GW"

# ---- the sample runs what this image was built against ----
sgw=$(sed -n 's|^[[:space:]]*image:[[:space:]]*ghcr.io/amakata/sekimore-gw:\([0-9][0-9.]*\).*|\1|p' "$SAMPLE/.devcontainer/docker-compose.yml")
[ -n "$sgw" ] || fail "the sample's compose file does not pin the gateway"
[ "$sgw" = "$GW" ] ||
  fail "the sample runs gateway $sgw but this image takes $GW; a project copying the sample would get a CLI older than its gateway"

# ---- the prose ----
for f in README.md README.ja.md; do
  quoted=$(sed -n 's|.*ghcr.io/amakata/sekimore-gw:\([0-9][0-9.]*\).*|\1|p' "$ROOT/$f" | sort -u)
  [ -n "$quoted" ] || fail "$f no longer quotes the gateway image; drop it from this test if that is deliberate"
  for v in $quoted; do
    [ "$v" = "$GW" ] || fail "$f says gateway $v, the Dockerfile takes $GW"
  done
done
echo "== the READMEs quote gateway $GW"

# ---- UPGRADING was considered for this gateway ----
for f in UPGRADING.md UPGRADING.ja.md; do
  r=$(sed -n 's|^<!-- reviewed-up-to: \([0-9][0-9.]*\) -->.*|\1|p' "$ROOT/$f")
  [ -n "$r" ] || fail "$f has no 'reviewed-up-to' marker on its first line"
  [ "$r" = "$GW" ] ||
    fail "$f is reviewed up to $r but this image takes $GW; decide whether $GW asks anything of the reader, then move the marker"
done
echo "== UPGRADING is reviewed up to $GW"

# ---- the sample starts from a base this repository has released ----
base=$(sed -n 's|^FROM ghcr.io/amakata/sgw-devcontainer-base:\([0-9][0-9.]*\).*|\1|p' "$SAMPLE/.devcontainer/Dockerfile")
[ -n "$base" ] || fail "the sample's Dockerfile does not pin the base"
grep -q "^## $base[ (（]" "$ROOT/CHANGELOG.md" ||
  fail "the sample starts from base $base, which CHANGELOG.md does not write up; release it, or point the sample at one that exists"
grep -q "^## $base[ (（]" "$ROOT/CHANGELOG.ja.md" ||
  fail "CHANGELOG.ja.md has no entry for base $base, though CHANGELOG.md does"
echo "== the sample starts from base $base, which is written up"

# The READMEs show a project's own FROM line. It is the first thing a new project copies, so a
# stale one hands out a version that is behind before anything else happens — 0.2.26 sat there
# while the sample had moved four releases on.
for f in README.md README.ja.md; do
  for v in $(sed -n 's|.*ghcr.io/amakata/sgw-devcontainer-base:\([0-9][0-9]*\.[0-9.]*[0-9]\).*|\1|p' "$ROOT/$f"); do
    [ "$v" = "$base" ] ||
      fail "$f shows base $v in a FROM line, the sample pins $base; a new project would start behind"
  done
done
echo "== the READMEs show base $base"

echo "PASS: every version agrees with the Dockerfile"
