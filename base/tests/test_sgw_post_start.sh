#!/usr/bin/env bash
# scripts/sgw-post-start runs setup as root with the whole environment, copies the staged skills
# into ~/.claude/skills, then docker-init, then the project's post-create.sh — in that order, and
# stops when setup fails.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$ROOT/scripts/sgw-post-start
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$TMP/bin" "$TMP/log" "$TMP/ws/.devcontainer/scripts"
# a fake sudo that records its arguments and runs the command in place
cat > "$TMP/bin/sudo" <<S
#!/bin/sh
echo "sudo \$*" >> "$TMP/log/sudo"
while [ "\$#" -gt 0 ]; do case "\$1" in -E) shift ;; *) break ;; esac; done
exec "\$@"
S
cat > "$TMP/sgw-agent" <<S
#!/bin/sh
echo "sgw-agent \$*" >> "$TMP/log/order"
env | grep '^SEKIMORE_' | sort > "$TMP/log/seen"
[ -z "\${FAIL_SETUP:-}" ] || exit 7
S
cat > "$TMP/docker-init" <<S
#!/bin/sh
echo docker-init >> "$TMP/log/order"
S
cat > "$TMP/ws/.devcontainer/scripts/post-create.sh" <<S
echo post-create >> "$TMP/log/order"
S
chmod +x "$TMP/bin/sudo" "$TMP/sgw-agent" "$TMP/docker-init"
mkdir -p "$TMP/owned/a" "$TMP/owned/b"
cat > "$TMP/chown" <<S
#!/bin/sh
echo "chown \$*" >> "$TMP/log/chown"
S
chmod +x "$TMP/chown"
run() {
  env -i PATH="$TMP/bin:$PATH" HOME="$TMP" SGW_WORKSPACE="$TMP/ws" SGW_AGENT_BIN="$TMP/sgw-agent" SGW_DOCKER_INIT="$TMP/docker-init" \
    SGW_OWNED_DIRS="$TMP/owned/a $TMP/owned/b $TMP/owned/absent" SGW_CHOWN="$TMP/chown" SGW_SKEL_SKILLS="$TMP/skel" \
    SEKIMORE_PROJECT=p SEKIMORE_GUIDE_LANG=ja OTHER=1 "$@" sh "$SCRIPT"
}
echo "== setup runs as root with -E, then docker-init, then post-create"
run
grep -q '^sudo -E .*sgw-agent setup$' "$TMP/log/sudo" || fail "setup was not run through sudo -E: $(cat "$TMP/log/sudo")"
grep -qx 'SEKIMORE_GUIDE_LANG=ja' "$TMP/log/seen" || fail "the environment did not reach setup"
[ "$(tr '\n' ' ' < "$TMP/log/order")" = "sgw-agent setup docker-init post-create " ] || fail "steps out of order: $(cat "$TMP/log/order")"
echo "== a failing setup stops the start"
rm -f "$TMP/log/order"
if run FAIL_SETUP=1 2>/dev/null; then fail "the start went on after setup failed"; fi
[ "$(tr '\n' ' ' < "$TMP/log/order")" = "sgw-agent setup " ] || fail "steps ran after the failure: $(cat "$TMP/log/order")"
echo "== without a post-create.sh the start still completes"
rm -f "$TMP/log/order" "$TMP/ws/.devcontainer/scripts/post-create.sh"
run
[ "$(tr '\n' ' ' < "$TMP/log/order")" = "sgw-agent setup docker-init " ] || fail "unexpected steps: $(cat "$TMP/log/order")"
echo "== #339: a volume that already belongs to this user is left alone"
rm -f "$TMP/log/chown"
run
[ ! -e "$TMP/log/chown" ] || fail "chowned what was already ours: $(cat "$TMP/log/chown")"
echo "== #339: a volume owned by another uid is handed over, a missing one skipped"
rm -f "$TMP/log/chown"
other=$(( $(id -u) + 1 ))
run SGW_UID="$other" SGW_GID=20 > /dev/null
[ "$(wc -l < "$TMP/log/chown")" -eq 2 ] || fail "expected two chowns: $(cat "$TMP/log/chown")"
grep -qx "chown -R $other:20 $TMP/owned/a" "$TMP/log/chown" || fail "a was not handed over: $(cat "$TMP/log/chown")"
echo "== #407: without staged skills ~/.claude/skills is not touched"
run
[ ! -e "$TMP/.claude/skills" ] || fail "made ~/.claude/skills with nothing staged: $(ls -R "$TMP/.claude")"
echo "== #407: each staged skill is copied into ~/.claude/skills, replacing that skill only"
mkdir -p "$TMP/skel/pptx/scripts" "$TMP/skel/pdf"
echo new > "$TMP/skel/pptx/SKILL.md"
echo helper > "$TMP/skel/pptx/scripts/run.py"
echo pdf > "$TMP/skel/pdf/SKILL.md"
mkdir -p "$TMP/.claude/skills/pptx" "$TMP/.claude/skills/mine"
echo old > "$TMP/.claude/skills/pptx/SKILL.md"
echo stale > "$TMP/.claude/skills/pptx/stale.md"
echo mine > "$TMP/.claude/skills/mine/SKILL.md"
run
[ "$(cat "$TMP/.claude/skills/pptx/SKILL.md")" = new ] || fail "pptx was not replaced"
[ -f "$TMP/.claude/skills/pptx/scripts/run.py" ] || fail "pptx's subdirectory was not copied"
[ ! -e "$TMP/.claude/skills/pptx/stale.md" ] || fail "a file the image no longer has stayed in pptx"
[ "$(cat "$TMP/.claude/skills/pdf/SKILL.md")" = pdf ] || fail "pdf was not copied"
[ "$(cat "$TMP/.claude/skills/mine/SKILL.md")" = mine ] || fail "a skill of another name was touched"
run
[ ! -e "$TMP/.claude/skills/pptx/pptx" ] || fail "a second start nested pptx inside itself"
echo "PASS: sgw-post-start runs setup, copies the skills, then docker-init and post-create"
