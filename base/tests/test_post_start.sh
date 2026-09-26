#!/bin/sh
# share/sgw/post-start.sh passes every SEKIMORE_* variable to agent-setup through sudo, and runs
# the three steps in order (sgw-devcontainer-base#48).
#
# A fake `sudo` on PATH records its arguments and runs the command, so what reaches agent-setup is
# what the real sudo would let through with --preserve-env. What must not pass:
#   - a name that only starts like one (SEKIMOREX) or merely contains it (FOO_SEKIMORE_X)
#   - post-create after agent-setup failed
#
# Run it directly: tests/test_post_start.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
SCRIPT=$ROOT/share/sgw/post-start.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$TMP/bin"
# sudo: record the arguments, then run the command with only the preserved variables (plus PATH),
# the way env_reset + --preserve-env behaves
cat > "$TMP/bin/sudo" <<'S'
#!/bin/sh
echo "$*" >> "$LOG/sudo"
keep=
case $1 in --preserve-env=*) keep=${1#--preserve-env=}; shift ;; esac
# unset everything that is not preserved, then run: what env_reset + --preserve-env leaves
for v in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'); do
  case ",$keep,PATH,LOG,HOME,GIT_CONFIG_SYSTEM," in *",$v,"*) ;; *) unset "$v" 2>/dev/null || true ;; esac
done
exec "$@"
S
cat > "$TMP/agent-setup" <<'S'
#!/bin/sh
env | grep '^SEKIMORE' | sort > "$LOG/seen"
echo agent-setup >> "$LOG/order"
[ "${SEKIMORE_FAIL:-}" != 1 ]
S
printf '#!/bin/sh\necho docker-init >> "$LOG/order"\n' > "$TMP/docker-init"
printf 'echo post-create >> "$LOG/order"\n' > "$TMP/post-create.sh"
chmod +x "$TMP/bin/sudo" "$TMP/agent-setup" "$TMP/docker-init"

run() {
  rm -rf "$TMP/log"; mkdir -p "$TMP/log"
  RC=0
  env -i PATH="$TMP/bin:$PATH" LOG="$TMP/log" HOME="$TMP/home" GIT_CONFIG_SYSTEM="$TMP/etc-gitconfig" SGW_AGENT_SETUP="$TMP/agent-setup" \
    SGW_DOCKER_INIT="$TMP/docker-init" SGW_POST_CREATE="${POST_CREATE-$TMP/post-create.sh}" \
    "$@" sh "$SCRIPT" >/dev/null 2>"$TMP/log/err" || RC=$?
}

echo "== every SEKIMORE_* variable reaches agent-setup, and nothing that only looks like one"
run SEKIMORE_PROJECT=p SEKIMORE_GUIDE_LANG=ja SEKIMORE_SIGNING_KEY_COMMENT="a b c" SEKIMOREX=1 FOO_SEKIMORE_X=2
[ "$RC" = 0 ] || fail "exited $RC"
grep -q '^--preserve-env=SEKIMORE_GUIDE_LANG,SEKIMORE_PROJECT,SEKIMORE_SIGNING_KEY_COMMENT ' "$TMP/log/sudo" || { cat "$TMP/log/sudo"; fail "the preserve list is not the three SEKIMORE_ names"; }
grep -qx 'SEKIMORE_GUIDE_LANG=ja' "$TMP/log/seen" || fail "SEKIMORE_GUIDE_LANG did not reach agent-setup"
grep -qx 'SEKIMORE_SIGNING_KEY_COMMENT=a b c' "$TMP/log/seen" || fail "a value with spaces did not survive"
if grep -q 'SEKIMOREX\|FOO_SEKIMORE' "$TMP/log/seen" "$TMP/log/sudo"; then fail "a name that only resembles SEKIMORE_* was passed"; fi
[ "$(cat "$TMP/log/order" | tr '\n' ' ')" = "agent-setup docker-init post-create " ] || fail "steps out of order: $(cat "$TMP/log/order")"

echo "== no SEKIMORE_* variable at all: sudo without --preserve-env"
run
[ "$RC" = 0 ] || fail "exited $RC"
if grep -q 'preserve-env' "$TMP/log/sudo"; then fail "an empty --preserve-env was passed"; fi

echo "== agent-setup fails: nothing after it runs"
run SEKIMORE_FAIL=1
[ "$RC" != 0 ] || fail "a failed agent-setup was not a failure"
[ "$(cat "$TMP/log/order")" = "agent-setup" ] || fail "ran past a failed agent-setup: $(cat "$TMP/log/order")"

echo "== a project without post-create.sh"
POST_CREATE=$TMP/none.sh run SEKIMORE_PROJECT=p
[ "$RC" = 0 ] || fail "a missing post-create.sh failed the start"

echo "== the VS Code credential helper is taken out of system and global config"
mkdir -p "$TMP/home"
VS='!f() { /vscode/vscode-server/bin/node /tmp/vscode-remote-containers-abc.js git-credential-helper $*; }; f'
sysgit() { GIT_CONFIG_SYSTEM="$TMP/etc-gitconfig" HOME="$TMP/home" git config "$@"; }
reset_git() { rm -f "$TMP/etc-gitconfig" "$TMP/home/.gitconfig"; }
reset_git; sysgit --system credential.helper "$VS"; sysgit --global credential.helper "$VS"
run SEKIMORE_PROJECT=p
[ "$RC" = 0 ] || fail "exited $RC"
[ "$(sysgit --system --get-all credential.helper)" = "" ] || fail "the system helper is still there: $(sysgit --system --get-all credential.helper)"
[ "$(sysgit --global --get-all credential.helper)" = "" ] || fail "the global helper is still there"
grep -q post-create "$TMP/log/order" || fail "post-create did not run after the helper was taken out"

echo "== nothing to take out is not a failure (the copies in post-create.sh stopped the start here)"
reset_git
run SEKIMORE_PROJECT=p
[ "$RC" = 0 ] || fail "exited $RC with no helper to remove"
[ "$(tail -1 "$TMP/log/order")" = "post-create" ] || fail "did not reach post-create"

echo "== a helper that is not VS Code's is left alone"
reset_git; sysgit --global credential.helper store
run SEKIMORE_PROJECT=p
[ "$(sysgit --global --get-all credential.helper)" = "store" ] || fail "a helper that is not VS Code's was changed"

echo "== SEKIMORE_ALLOW_CREDENTIAL_HELPER=1 keeps it"
reset_git; sysgit --global credential.helper "$VS"
run SEKIMORE_ALLOW_CREDENTIAL_HELPER=1
[ "$(sysgit --global --get-all credential.helper)" = "$VS" ] || fail "the escape hatch did not keep the helper"

# #64: 0.2.26 moved this out of each project's post-create.sh, and a copy left behind there stops
# the start — its last statement is false once the helper is already gone, and `set -e` does the
# rest. The project saw no reason why, so the warning has to arrive before post-create.sh runs.
echo "== a stale copy in post-create.sh is called out, and the start still goes on"
reset_git
printf 'disable_vscode_credential_helper() { :; }\necho post-create >> "$LOG/order"\n' > "$TMP/stale-post-create.sh"
POST_CREATE="$TMP/stale-post-create.sh" run SEKIMORE_PROJECT=p
[ "$RC" = 0 ] || fail "a stale copy must warn, not stop the start (exited $RC)"
grep -q 'disable_vscode_credential_helper' "$TMP/log/err" || { cat "$TMP/log/err"; fail "no warning about the stale copy"; }
grep -q '0.2.26' "$TMP/log/err" || fail "the warning does not say which release made it unnecessary"
grep -qx 'post-create' "$TMP/log/order" || fail "post-create.sh did not run after the warning"

echo "== a post-create.sh without the copy says nothing"
reset_git
run SEKIMORE_PROJECT=p
if grep -q 'disable_vscode_credential_helper' "$TMP/log/err" 2>/dev/null; then
  fail "warned about a stale copy that is not there"
fi

echo "PASS: post-start.sh"
