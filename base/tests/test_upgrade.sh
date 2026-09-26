#!/usr/bin/env bash
# share/sgw/upgrade.sh against a fake GHCR, a fake raw.githubusercontent.com and a fake gateway
# (sgw-devcontainer-base#44).
#
# `curl` serves fixtures instead of the network, the distributed sgw.sh is a stand-in that logs
# `recreate` and answers `store-status` from a file, and `mise` logs `gw:unlock-auto`. The real
# upgrade.sh is what runs, from a project directory laid out like a real one.
#
# What must not pass, each tried on purpose:
#   - 0.2.9 sorts after 0.2.10 as text; the newest is 0.2.10
#   - moving 0.2.1 → 0.2.10 must leave a ":0.2.19" elsewhere in the file alone
#   - "## 0.2.9 ..." inside a code fence in UPGRADING is text, not a section
#   - a registry that only has older tags must not move a project backwards
#   - the newest tag on the second page of the tag list is still the newest
#   - a distributed file edited by hand is not overwritten
#   - a failed fetch changes nothing
#
# Run it directly: tests/test_upgrade.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
UPGRADE=$ROOT/share/sgw/upgrade.sh

TMP=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$TMP"' EXIT INT TERM
FIX=$TMP/fix BIN=$TMP/bin LOG=$TMP/log
mkdir -p "$FIX" "$BIN" "$LOG"

fail() { echo "FAIL: $*" >&2; exit 1; }
has() { grep -qF -- "$2" "$1" || { echo "--- $1" >&2; cat "$1" >&2; fail "expected '$2' in $(basename "$1")"; }; }
hasnt() { if grep -qF -- "$2" "$1"; then echo "--- $1" >&2; cat "$1" >&2; fail "did not expect '$2' in $(basename "$1")"; fi; }
hasnt_line() { if grep -qxF -- "$2" "$1"; then echo "--- $1" >&2; cat "$1" >&2; fail "did not expect the line '$2' in $(basename "$1")"; fi; }
tree_sum() { (cd "$1" && find . -type f | sort | xargs cat | cksum); }

# ---- fakes ----
cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
out= url= hdr=
while [ $# -gt 0 ]; do
  case $1 in -o) out=$2; shift ;; -D) hdr=$2; shift ;; -H) shift ;; http*) url=$1 ;; esac
  shift
done
echo "$url" >> "$LOG/curl"
emit() { if [ -n "$out" ]; then cat "$1" > "$out"; else cat "$1"; fi; }
[ -z "$hdr" ] || echo "HTTP/1.1 200 OK" > "$hdr"
case $url in
  https://ghcr.io/token*) printf '{"token":"t0k"}' ;;
  https://ghcr.io/v2/*/tags/list*)
    n=${url#https://ghcr.io/v2/}; n=${n%/tags/list*}
    # a second page, when the fixture has one: the first answer names it in a Link header
    case $url in
      *last=*) [ -f "$FIX/tags/$n.page2" ] || exit 22; emit "$FIX/tags/$n.page2" ;;
      *) [ -f "$FIX/tags/$n" ] || exit 22
         if [ -f "$FIX/tags/$n.page2" ] && [ -n "$hdr" ]; then
           printf 'HTTP/1.1 200 OK\r\nLink: </v2/%s/tags/list?last=x&n=1000>; rel="next"\r\n' "$n" > "$hdr"
         fi
         emit "$FIX/tags/$n" ;;
    esac ;;
  https://raw.githubusercontent.com/*)
    f=$FIX/raw/${url#https://raw.githubusercontent.com/}
    [ -f "$f" ] || exit 22; emit "$f" ;;
  *) exit 6 ;;
esac
EOF
cat > "$BIN/mise" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LOG/mise"
if [ "$*" = "run gw:unlock-auto" ] && [ "${FAKE_UNLOCK_WORKS:-0}" = 1 ]; then echo unlocked > "$LOG/store"; fi
EOF
chmod +x "$BIN/curl" "$BIN/mise"

# ---- fixtures: two base releases, two gateway releases ----
B=$FIX/raw/Amakata/sgw-devcontainer-base G=$FIX/raw/Amakata/sekimore-gw
for v in 0.2.19 0.2.20; do
  d=$B/v$v/share/sgw; mkdir -p "$d"
  cp "$UPGRADE" "$d/upgrade.sh"
  # the stand-in sgw.sh: what upgrade.sh asks of the gateway
  cat > "$d/sgw.sh" <<EOF
#!/usr/bin/env bash
# sgw.sh base $v
case \$1 in
  id) [ "\${FAKE_GW_RUNNING:-0}" = 1 ] ;;
  recreate) echo recreate >> "\$LOG/sgw" ;;
  gw) cat "\$LOG/store" 2>/dev/null || echo locked ;;
esac
EOF
  printf '# vscode.sh base %s\n' "$v" > "$d/vscode.sh"
  printf '# post-start.sh base %s\n' "$v" > "$d/post-start.sh"
  printf '# tasks base %s en\n' "$v" > "$d/tasks.mise.en.toml"
  printf '# tasks base %s ja\n' "$v" > "$d/tasks.mise.ja.toml"
done
for v in 0.2.1 0.2.10; do
  d=$G/v$v/share; mkdir -p "$d"
  for l in en ja; do printf '# gateway %s %s\n["gw:unlock-auto"]\nrun = "true"\n' "$v" "$l" > "$d/gateway.mise.$l.toml"; done
done
cat > "$B/v0.2.20/UPGRADING.md" <<'EOF'
# Upgrading
## Where to start reading
## 0.2.1 old
body-0.2.1
## 0.2.9 nine
body-0.2.9
```bash
## 0.2.9 not a heading
```
## 0.2.10 ten
body-0.2.10
## 0.2.11 eleven
body-0.2.11
## base 0.2.19 b19
## base 0.2.20 b20
body-b20
EOF
sed 's/^## 0.2.10 ten$/## 0.2.10 十/' "$B/v0.2.20/UPGRADING.md" > "$B/v0.2.20/UPGRADING.ja.md"
cp "$B/v0.2.20/UPGRADING.md" "$B/v0.2.19/UPGRADING.md"
mkdir -p "$FIX/tags/amakata"
printf '{"name":"amakata/sekimore-gw","tags":["0.2.1","0.2.9","0.2.10","0.2","latest","0.2.11-rc1","sha256-abc"]}' > "$FIX/tags/amakata/sekimore-gw"
# the base's tags come in two pages, and the newest is on the second
printf '{"name":"amakata/sgw-devcontainer-base","tags":["0.2.19"]}' > "$FIX/tags/amakata/sgw-devcontainer-base"
printf '{"name":"amakata/sgw-devcontainer-base","tags":["0.2.20","latest"]}' > "$FIX/tags/amakata/sgw-devcontainer-base.page2"

# ---- a project ----
# new_project <dir>: pinned to gateway 0.2.1 and base 0.2.19, with only upgrade.sh in .devcontainer/sgw/
new_project() {
  local p=$1
  mkdir -p "$p/.devcontainer/sgw"
  cat > "$p/.devcontainer/docker-compose.yml" <<'EOF'
services:
  sekimore-gw:
    # ghcr.io/amakata/sekimore-gw:0.2.19 is what the other project runs
    image: "ghcr.io/amakata/sekimore-gw:0.2.1"   # pinned
EOF
  printf 'FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.19 AS dev\nRUN true\n' > "$p/.devcontainer/Dockerfile"
  cat > "$p/mise.toml" <<'EOF'
[task_config]
includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]
[env]
SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
EOF
  cp "$UPGRADE" "$p/.devcontainer/sgw/upgrade.sh"
}
# up <dir> [args...]: run the project's upgrade.sh; output in $LOG/out and $LOG/err, status in $RC
up() {
  local p=$1; shift
  RC=0
  (cd "$p" && env -u MISE_PROJECT_ROOT DEVCONTAINER=false PATH="$BIN:$PATH" FIX="$FIX" LOG="$LOG" \
     SEKIMORE_LANG="${T_SEKIMORE_LANG:-}" LC_ALL="${T_LC_ALL:-}" LC_MESSAGES= LANG="${T_LANG:-en_US.UTF-8}" \
     bash "$p/.devcontainer/sgw/upgrade.sh" "$@" </dev/null >"$LOG/out" 2>"$LOG/err") || RC=$?
}
reset_log() { rm -f "$LOG/sgw" "$LOG/mise" "$LOG/store" "$LOG/curl"; }

P=$TMP/p1
new_project "$P"

echo "== first sync: only upgrade.sh is there, no MANIFEST"
up "$P" --sync
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "sync exited $RC"; }
has "$P/.devcontainer/sgw/sgw.sh" "sgw.sh base 0.2.19"
has "$P/.devcontainer/sgw/tasks.mise.toml" "tasks base 0.2.19 en"
has "$P/.devcontainer/sgw/gateway.mise.toml" "gateway 0.2.1 en"
has "$P/.devcontainer/sgw/MANIFEST" "base 0.2.19"
has "$P/.devcontainer/sgw/MANIFEST" "gateway 0.2.1"
has "$P/.devcontainer/sgw/MANIFEST" "lang en"
[ -x "$P/.devcontainer/sgw/sgw.sh" ] || fail "sgw.sh is not executable"
has "$P/.devcontainer/docker-compose.yml" 'sekimore-gw:0.2.1"'

echo "== check: reports, changes nothing"
before=$(tree_sum "$P")
up "$P"
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "check exited $RC"; }
[ "$(tree_sum "$P")" = "$before" ] || fail "check changed the project"
has "$LOG/out" "0.2.10"
grep -q '^gateway  *0\.2\.1  *0\.2\.10 ' "$LOG/out" || { cat "$LOG/out"; fail "newest gateway is not 0.2.10 (0.2.9 sorts after 0.2.10 as text)"; }
grep -q '^base  *0\.2\.19  *0\.2\.20 ' "$LOG/out" || fail "newest base is not 0.2.20"
has "$LOG/out" "0.2.9 nine"
has "$LOG/out" "0.2.10 ten"
has "$LOG/out" "base 0.2.20 b20"
hasnt "$LOG/out" "0.2.1 old"
hasnt "$LOG/out" "0.2.11 eleven"
hasnt "$LOG/out" "base 0.2.19 b19"
hasnt "$LOG/out" "not a heading"
has "$LOG/out" "upgrade:apply"

echo "== notes: the bodies of the same sections"
up "$P" --notes
has "$LOG/out" "body-0.2.10"
has "$LOG/out" "body-b20"
hasnt_line "$LOG/out" "body-0.2.1"
hasnt "$LOG/out" "body-0.2.11"

echo "== an edited distributed file stops --apply, and nothing changes"
echo "# my change" >> "$P/.devcontainer/sgw/sgw.sh"
before=$(tree_sum "$P")
up "$P" --apply --yes
[ "$RC" = 1 ] || fail "apply over an edited file exited $RC, not 1"
has "$LOG/err" ".devcontainer/sgw/sgw.sh"
has "$LOG/err" "+# my change"
[ "$(tree_sum "$P")" = "$before" ] || fail "apply changed the project although it stopped"
up "$P"
has "$LOG/out" "edited by hand"
cp "$B/v0.2.19/share/sgw/sgw.sh" "$P/.devcontainer/sgw/sgw.sh"

echo "== a failed fetch changes nothing"
mv "$B/v0.2.20/share/sgw/vscode.sh" "$TMP/vscode.hidden"
before=$(tree_sum "$P")
up "$P" --apply --yes
[ "$RC" = 1 ] || fail "apply with a missing file exited $RC, not 1"
has "$LOG/err" "v0.2.20/share/sgw/vscode.sh"
[ "$(tree_sum "$P")" = "$before" ] || fail "a failed fetch changed the project"
mv "$TMP/vscode.hidden" "$B/v0.2.20/share/sgw/vscode.sh"

echo "== apply without a terminal: rewrites, replaces, and leaves the recreate to a person"
reset_log
FAKE_GW_RUNNING=1 up "$P" --apply
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "apply exited $RC"; }
has "$P/.devcontainer/docker-compose.yml" 'image: "ghcr.io/amakata/sekimore-gw:0.2.10"   # pinned'
has "$P/.devcontainer/docker-compose.yml" "sekimore-gw:0.2.19 is what the other project runs"
has "$P/.devcontainer/Dockerfile" "FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.20 AS dev"
has "$P/.devcontainer/sgw/sgw.sh" "sgw.sh base 0.2.20"
has "$P/.devcontainer/sgw/gateway.mise.toml" "gateway 0.2.10 en"
has "$P/.devcontainer/sgw/MANIFEST" "gateway 0.2.10"
[ -x "$P/.devcontainer/sgw/sgw.sh" ] || fail "the replaced sgw.sh is not executable"
[ ! -e "$LOG/sgw" ] || fail "recreated the gateway without being asked"
has "$LOG/out" "mise run gw:recreate"
has "$LOG/out" "mise run gw:unlock"
has "$LOG/out" "Rebuild Container"
has "$LOG/out" "UPGRADING.md"
has "$LOG/out" "git diff"
ls -a "$P/.devcontainer/sgw" | grep -q '\.new$' && fail "a temporary file was left behind"

echo "== up to date: check and apply say so, and write nothing"
up "$P"
has "$LOG/out" "Everything is up to date."
before=$(tree_sum "$P")
up "$P" --apply
[ "$RC" = 0 ] || fail "apply when up to date exited $RC"
has "$LOG/out" "Everything is up to date."
hasnt "$LOG/out" "git diff"
[ "$(tree_sum "$P")" = "$before" ] || fail "apply wrote something although everything was up to date"

echo "== language: LC_ALL=C falls through to LANG=ja; SEKIMORE_LANG=en wins over LANG"
T_LC_ALL=C T_LANG=ja_JP.UTF-8 up "$P" --sync
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "sync to ja exited $RC"; }
has "$P/.devcontainer/sgw/tasks.mise.toml" "tasks base 0.2.20 ja"
has "$P/.devcontainer/sgw/gateway.mise.toml" "gateway 0.2.10 ja"
has "$P/.devcontainer/sgw/MANIFEST" "lang ja"
has "$LOG/out" "言語: en → ja"
T_SEKIMORE_LANG=en T_LANG=ja_JP.UTF-8 up "$P" --sync
has "$P/.devcontainer/sgw/tasks.mise.toml" "tasks base 0.2.20 en"
has "$LOG/out" "language: ja → en"

echo "== apply --yes: recreates, and gw:unlock-auto unlocks"
P=$TMP/p2; new_project "$P"; up "$P" --sync
reset_log
FAKE_GW_RUNNING=1 FAKE_UNLOCK_WORKS=1 up "$P" --apply --yes
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "apply --yes exited $RC"; }
has "$LOG/sgw" "recreate"
has "$LOG/mise" "run gw:unlock-auto"
hasnt "$LOG/out" "mise run gw:unlock"
hasnt "$LOG/out" "mise run gw:recreate"

echo "== apply --yes: the store stays locked, so gw:unlock is left to a person"
P=$TMP/p3; new_project "$P"; up "$P" --sync
reset_log
FAKE_GW_RUNNING=1 up "$P" --apply --yes
has "$LOG/sgw" "recreate"
has "$LOG/out" "mise run gw:unlock"

echo "== with a terminal: it asks first; y recreates, anything else leaves it to a person"
# script(1) gives upgrade.sh a terminal, which is the only way it asks. util-linux's script is on
# the CI runner; BSD's takes different arguments, so elsewhere this case is skipped.
if script --version 2>/dev/null | grep -q util-linux; then
  for answer in y n; do
    P=$TMP/tty-$answer; new_project "$P"; up "$P" --sync
    reset_log
    (cd "$P" && printf '%s\n' "$answer" | env -u MISE_PROJECT_ROOT DEVCONTAINER=false PATH="$BIN:$PATH" FIX="$FIX" LOG="$LOG" \
       FAKE_GW_RUNNING=1 SEKIMORE_LANG= LC_ALL= LC_MESSAGES= LANG=en_US.UTF-8 \
       script -qec "bash .devcontainer/sgw/upgrade.sh --apply" /dev/null >"$LOG/out" 2>&1)
    has "$LOG/out" "Recreate the gateway on 0.2.10 now?"
    if [ "$answer" = y ]; then
      has "$LOG/sgw" "recreate"
    else
      [ ! -e "$LOG/sgw" ] || fail "recreated the gateway after a no"
      has "$LOG/out" "mise run gw:recreate"
    fi
  done
else
  echo "SKIP: no util-linux script(1)"
fi

echo "== the gateway is not running: nothing to recreate, say how it comes up"
P=$TMP/p4; new_project "$P"; up "$P" --sync
reset_log
up "$P" --apply --yes
[ ! -e "$LOG/sgw" ] || fail "recreated a gateway that is not running"
has "$LOG/out" "the gateway is not running"

echo "== a file equal to the one about to replace it is not an edit"
P=$TMP/p5; new_project "$P"; up "$P" --sync
cp "$B/v0.2.20/share/sgw/sgw.sh" "$P/.devcontainer/sgw/sgw.sh"
up "$P" --apply
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "a file already at the new version stopped apply"; }

echo "== no MANIFEST and a file unlike the pinned version: the first sync stops"
P=$TMP/p6; new_project "$P"
echo "# someone else's sgw.sh" > "$P/.devcontainer/sgw/sgw.sh"
up "$P" --sync
[ "$RC" = 1 ] || fail "the first sync over an unknown sgw.sh exited $RC, not 1"
has "$P/.devcontainer/sgw/sgw.sh" "someone else's sgw.sh"

echo "== the registry has only older tags: the project does not move backwards"
P=$TMP/p7; new_project "$P"
sed -i.bak 's/base:0.2.19/base:0.2.20/' "$P/.devcontainer/Dockerfile"
mv "$FIX/tags/amakata/sgw-devcontainer-base.page2" "$TMP/page2.hidden"
up "$P"
grep -q '^base  *0\.2\.20  *0\.2\.20 ' "$LOG/out" || { cat "$LOG/out"; fail "an older registry moved the base backwards"; }
mv "$TMP/page2.hidden" "$FIX/tags/amakata/sgw-devcontainer-base.page2"

echo "== the old layout and a mise.toml that does not include .devcontainer/sgw/"
P=$TMP/p8; new_project "$P"
mkdir -p "$P/.devcontainer/scripts"; echo old > "$P/.devcontainer/scripts/sgw.sh"; echo old > "$P/.devcontainer/gateway.mise.toml"
printf '[env]\nSGW = "{{config_root}}/.devcontainer/scripts/sgw.sh"\n' > "$P/mise.toml"
up "$P" --sync
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "sync exited $RC"; }
has "$LOG/out" 'includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]'
has "$LOG/out" "git rm .devcontainer/scripts/sgw.sh .devcontainer/gateway.mise.toml"
has "$P/mise.toml" "scripts/sgw.sh"

echo "== a devcontainer.json that calls agent-setup itself is told to run post-start.sh; one that does is not"
P=$TMP/p10; new_project "$P"
printf '{ "postStartCommand": "sudo --preserve-env=SEKIMORE_PROJECT /usr/local/bin/sekimore-agent-setup.sh" }\n' > "$P/.devcontainer/devcontainer.json"
# the check alone already says so: it is where a person looks first
up "$P"
has "$LOG/out" "What your own files need"
has "$LOG/out" '"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh",'
up "$P" --sync
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "sync exited $RC"; }
has "$LOG/out" '"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh",'
has "$P/.devcontainer/sgw/post-start.sh" "post-start.sh base 0.2.19"
printf '{ "postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh" }\n' > "$P/.devcontainer/devcontainer.json"
up "$P" --sync
hasnt "$LOG/out" "postStartCommand"

echo "== an apply that replaces upgrade.sh lets the new one say what your files need"
# The release moved to carries a rule the running upgrade.sh has never heard of. Without the hand-off
# it would only show on the next run (#53).
sed 's/^collect_owned() {$/collect_owned() {\n  remain "a rule only the new upgrade.sh knows"/' "$UPGRADE" > "$B/v0.2.20/share/sgw/upgrade.sh"
P=$TMP/p11; new_project "$P"; up "$P" --sync
printf '{ "postStartCommand": "sudo /usr/local/bin/sekimore-agent-setup.sh" }\n' > "$P/.devcontainer/devcontainer.json"
up "$P" --apply
[ "$RC" = 0 ] || { cat "$LOG/err"; fail "apply exited $RC"; }
has "$LOG/out" "a rule only the new upgrade.sh knows"
has "$LOG/out" "What your own files need"
# said once, by the new script, not once by each
[ "$(grep -c 'sgw/post-start.sh",' "$LOG/out")" = 1 ] || { cat "$LOG/out"; fail "the postStartCommand line was not said exactly once"; }
cp "$UPGRADE" "$B/v0.2.20/share/sgw/upgrade.sh"

echo "== unpinned, and inside the dev container"
P=$TMP/p9; new_project "$P"
printf 'FROM ghcr.io/amakata/sgw-devcontainer-base:latest\n' > "$P/.devcontainer/Dockerfile"
up "$P"
[ "$RC" = 1 ] || fail "an unpinned base exited $RC, not 1"
has "$LOG/err" "not pinned"
RC=0; (cd "$P" && DEVCONTAINER=true PATH="$BIN:$PATH" bash .devcontainer/sgw/upgrade.sh >/dev/null 2>&1) || RC=$?
[ "$RC" = 2 ] || fail "inside the dev container exited $RC, not 2"

echo "PASS: upgrade.sh"
