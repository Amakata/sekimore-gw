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
#   - the tools the base promises are on PATH, and the AI tools are not (#405)
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

# ---- sgw-agent, the AI's command, is the same release (#257) ----
agent=$(in_image /usr/local/bin/sgw-agent --version) ||
  fail "sgw-agent does not run in the image: $agent"
case "$agent" in
  *"$GW"*) ;;
  *) fail "the image holds sgw-agent '$agent', not gateway $GW" ;;
esac
alias_out=$(in_image /usr/local/bin/sekimore --version) ||
  fail "the sekimore alias does not run in the image: $alias_out"
[ "$alias_out" = "$agent" ] || fail "sekimore (alias) answers '$alias_out', sgw-agent '$agent'"
echo "== sgw-agent $agent, and the sekimore alias answers the same"

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
# node and npm come from the mise shims, which Debian's /etc/profile would drop from a login shell
# if /etc/profile.d did not put them back (#60) — so checking them here is checking that too.
for t in git delta zsh mise node npm aws docker sekimore sgw-agent sgw-post-start sgw-install-ai; do
  in_image /bin/sh -lc "command -v $t >/dev/null" ||
    fail "$t is not on PATH in the image"
done
echo "== the tools the base promises are on PATH"

# ---- and the ones it deliberately leaves out ----
# `gh` reaches api.github.com through the relay's 443 passthrough, which forwards without reading:
# a `gh` holding a token would act with none of the per-action permissions the relay enforces, and
# on repositories outside the project. Absent on purpose, so its return is a failure (#62).
# #405: Claude Code, Codex and the Anthropic skills are not ours to put in a public image; the
# project's image installs them with sgw-install-ai (below).
for t in gh claude codex; do
  if in_image /bin/sh -lc "command -v $t >/dev/null || test -e \"\$HOME/.local/bin/$t\""; then
    fail "$t is in the image"
  fi
done
for p in /etc/skel/.claude/skills /opt/codex /usr/local/bin/codex; do
  if in_image /bin/sh -c "test -e $p"; then
    fail "$p is in the image (#405)"
  fi
done
echo "== the tools the base leaves out are absent"

# ---- #375: the system mise directory ----
# Root-owned and read-only, so a project's baked languages are neither changed nor chowned by the
# user.
env_dir=$(in_image /usr/bin/env | sed -n 's/^MISE_SYSTEM_DATA_DIR=//p')
[ "$env_dir" = /opt/mise ] || fail "MISE_SYSTEM_DATA_DIR is '$env_dir', not /opt/mise"
owner=$(in_image /usr/bin/stat -c %U /opt/mise/installs)
[ "$owner" = root ] || fail "/opt/mise/installs is owned by $owner, not root"
if in_image /bin/sh -c 'test -w /opt/mise/installs'; then
  fail "/opt/mise/installs is writable by the user"
fi
echo "== /opt/mise is the system directory, root-owned and read-only"
# 0.3 (#377): /usr/local/share is root's again, so nothing a project puts there is the agent's to change
share_owner=$(in_image /usr/bin/stat -c %U /usr/local/share)
[ "$share_owner" = root ] || fail "/usr/local/share is owned by $share_owner, not root"
echo "== /usr/local/share stays root's"
# #393: with the mise-store volume mounted on installs, as the dev container runs, the user still
# owns its mise directory and can reshim. Docker makes a missing mount point's parents root's
vol=sgw-test-mise-store-$$
out=$(docker run --rm -v "$vol:/home/vscode/.local/share/mise/installs" --entrypoint /bin/sh "$IMAGE" -c 'stat -c %U ~/.local/share/mise && mise reshim && echo reshim-ok' 2>&1) || true
docker volume rm "$vol" >/dev/null 2>&1 || true
case "$out" in
  vscode*reshim-ok*) ;;
  *) fail "with the mise-store volume mounted, the user's mise directory or reshim fails: $out" ;;
esac
echo "== with the mise-store volume mounted, the user owns ~/.local/share/mise and reshim works"

# The recipe docs/languages.md gives a project, end to end: root installs into the system directory
# and reshims, and the user then selects that version without installing anything of its own.
# Needs the network for node's download; SGW_TEST_OFFLINE=1 skips it.
if [ -n "${SGW_TEST_OFFLINE:-}" ]; then
  echo "SKIP: the system-install recipe (SGW_TEST_OFFLINE)"
elif docker run --rm --user root --entrypoint /bin/sh "$IMAGE" -c \
  'umask 022 && HOME=/root mise install --system node@22.21.1 >/dev/null 2>&1 && HOME=/root mise reshim --system && chmod -R a-w /opt/mise && su vscode -s /bin/sh -c "cd /tmp && mise use -g node@22.21.1 >/dev/null && node --version && test ! -d ~/.local/share/mise/installs/node/22.21.1"' \
  > /tmp/sgw-system-node.$$ 2>&1; then
  grep -q '^v22.21.1$' /tmp/sgw-system-node.$$ ||
    fail "a system-installed node did not run for the user: $(cat /tmp/sgw-system-node.$$)"
  echo "== a language installed with mise install --system is the user's without a copy of its own"
else
  fail "the system-install recipe failed: $(tail -5 /tmp/sgw-system-node.$$)"
fi
rm -f /tmp/sgw-system-node.$$

# ---- #405: sgw-install-ai, the way the template's Dockerfile runs it ----
# As root, then the user finds claude, codex on its own node through the wrapper, and the skills.
# Needs the network for the downloads; SGW_TEST_OFFLINE=1 skips it.
if in_image /usr/local/bin/sgw-install-ai >/dev/null; then
  fail "sgw-install-ai ran as the user; it installs into /opt and /etc/skel, and has to refuse"
fi
if [ -n "${SGW_TEST_OFFLINE:-}" ]; then
  echo "SKIP: sgw-install-ai (SGW_TEST_OFFLINE)"
elif docker run --rm --user root --entrypoint /bin/sh "$IMAGE" -c \
  'sgw-install-ai >/dev/null 2>&1 || { sgw-install-ai; exit 1; }
   su vscode -s /bin/sh -c "cd /tmp && sh -lc \"command -v claude && claude --version && command -v codex && codex --version\" && ls /etc/skel/.claude/skills && test ! -w /opt/codex"' \
  > /tmp/sgw-install-ai.$$ 2>&1; then
  out=$(cat /tmp/sgw-install-ai.$$)
  case "$out" in
    */home/vscode/.local/bin/claude*/usr/local/bin/codex*) ;;
    *) fail "after sgw-install-ai, claude or codex is not where it belongs: $out" ;;
  esac
  for s in docx pdf pptx xlsx; do
    printf '%s\n' "$out" | grep -qx "$s" || fail "sgw-install-ai left out the $s skill: $out"
  done
  echo "== sgw-install-ai installs claude, codex (/usr/local/bin/codex) and the skills"
else
  fail "sgw-install-ai failed: $(tail -20 /tmp/sgw-install-ai.$$)"
fi
rm -f /tmp/sgw-install-ai.$$

# ---- #339: GID 20 is free ----
# Dev Containers' updateRemoteUserUID changes nothing when the host's GID is taken, and 20 is the
# Mac's `staff`: a Linux VM built with 501:20 left the user at 1000:1000.
if in_image /usr/bin/getent group 20 >/dev/null; then
  fail "GID 20 is taken in the image ($(in_image /usr/bin/getent group 20)); updateRemoteUserUID will not run on a host user in group 20"
fi
echo "== GID 20 is free for the host user's group"

echo "PASS: the image holds gateway $GW"
