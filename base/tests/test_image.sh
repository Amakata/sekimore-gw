#!/usr/bin/env bash
# What the built image actually holds, asked of the image rather than of the files that built it.
#
# The Dockerfile copies the relay CLI and the agent guide out of a sekimore-gw image, and a COPY
# that names the wrong path, or a stage that silently resolves to another tag, leaves an image
# that looks right in every file in this repository. tests/test_versions.sh compares the numbers
# people write down; this one opens the result.
#
# 0.2.27 is why both exist. A dev container answered `sekimore-relay --version` with 0.2.31 while
# its gateway ran 0.2.32, and no test looked inside an image to notice.
#
#   - the relay CLI runs, and is the version ARG SEKIMORE_GW_IMAGE pins
#   - the agent guide ships in both languages and came from that same release
#   - the tools the base promises are on PATH
#
# Needs docker and a built image. Pass one, or let it build:
#
#   tests/test_image.sh                     # builds from ./Dockerfile
#   tests/test_image.sh ghcr.io/…:0.2.27    # checks one that exists
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker is not available"; exit 0; }

GW=$(sed -n 's|^ARG SEKIMORE_GW_IMAGE=ghcr.io/amakata/sekimore-gw:\([0-9][0-9.]*\).*|\1|p' "$ROOT/Dockerfile")
[ -n "$GW" ] || fail "Dockerfile has no 'ARG SEKIMORE_GW_IMAGE=…:<version>'"

IMAGE=${1:-}
BUILT=""
if [ -z "$IMAGE" ]; then
  IMAGE=sgw-devcontainer-base:test-$$
  BUILT=$IMAGE
  echo "== building $IMAGE (gateway $GW)"
  docker build -q -t "$IMAGE" "$ROOT" >/dev/null || fail "the image does not build"
fi
cleanup() { [ -n "$BUILT" ] && docker rmi -f "$BUILT" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# `docker run` with an explicit entrypoint, because this image's own entrypoint is a login shell.
in_image() { docker run --rm --entrypoint "$1" "$IMAGE" "${@:2}" 2>&1; }

# ---- the relay CLI is the one the Dockerfile asked for ----
got=$(in_image /usr/local/bin/sekimore-relay --version) ||
  fail "sekimore-relay does not run in the image: $got"
case "$got" in
  *"$GW"*) ;;
  *) fail "the image holds '$got' but ARG SEKIMORE_GW_IMAGE pins gateway $GW" ;;
esac
echo "== the image holds $got"

# ---- the agent guide came from that release, in both languages ----
# An agent reads this, so a stale copy is a wrong instruction rather than a wrong number.
for lang in en ja; do
  guide=$(in_image /usr/local/bin/sekimore-relay agent guide --lang "$lang") ||
    fail "sekimore-relay agent guide --lang $lang fails in the image"
  [ -n "$guide" ] || fail "the $lang agent guide is empty in the image"
  case "$guide" in
    *sekimore-relay*) ;;
    *) fail "the $lang agent guide does not look like the guide" ;;
  esac
done
echo "== the agent guide ships in both languages"

# ---- the tools this image promises ----
# Each is named in the Dockerfile's own header as baked in, so a project gets it without
# installing it, and dropping one breaks projects rather than this repository. Things the header
# calls case-specific (uv, language runtimes) are deliberately not here.
# A login shell, because that is how a person and a `docker exec -l` reach them; some land in
# ~/.local/bin, which the shell rc adds rather than ENV PATH.
# node, npm and codex come from the mise shims, which Debian's /etc/profile would drop from a
# login shell if /etc/profile.d did not put them back (#60) — so checking them here is checking
# that too.
for t in git delta zsh mise claude codex node npm aws docker sekimore sekimore-agent-setup.sh; do
  in_image /bin/sh -lc "command -v $t >/dev/null" ||
    fail "$t is not on PATH in the image"
done
echo "== the tools the base promises are on PATH"

# ---- and the ones it deliberately leaves out ----
# `gh` reaches api.github.com through the relay's 443 passthrough, which forwards without reading:
# a `gh` holding a token would act with none of the per-action permissions the relay enforces, and
# on repositories outside the project. Absent on purpose, so its return is a failure (#62).
for t in gh; do
  if in_image /bin/sh -lc "command -v $t >/dev/null"; then
    fail "$t is in the image; it bypasses the relay's permission checks, and sekimore covers it"
  fi
done
echo "== the tools the base leaves out are absent"

echo "PASS: the image holds gateway $GW"
