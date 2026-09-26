#!/usr/bin/env bash
# scripts/sgw-post-start runs setup as root with the whole environment, then docker-init, then the
# project's post-create.sh — in that order, and stops when setup fails.
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
run() {
  env -i PATH="$TMP/bin:$PATH" HOME="$TMP" SGW_WORKSPACE="$TMP/ws" SGW_AGENT_BIN="$TMP/sgw-agent" SGW_DOCKER_INIT="$TMP/docker-init" \
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
echo "PASS: sgw-post-start runs setup, docker-init and post-create in order"
