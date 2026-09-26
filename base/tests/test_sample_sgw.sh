#!/usr/bin/env bash
# The distributed files agree with each other and with the sample (sgw-devcontainer-base#44).
#
# share/sgw/ is what `mise run upgrade` hands out; examples/sgw-sample/.devcontainer/sgw/ is the
# copy a new project starts from. Fixing one and forgetting the other is the drift this layout
# exists to end, so it fails here instead of in someone's project:
#
#   - the sample's copies equal share/sgw/ (tasks.mise.toml equals tasks.mise.en.toml)
#   - the sample's gateway.mise.toml is share/gateway.mise.en.toml at the gateway the sample pins
#     (from a sekimore-gw checkout in SEKIMORE_GW_SRC, else raw.githubusercontent.com; #105)
#   - the sample's MANIFEST is exactly what upgrade.sh would write for the sample's pinned versions
#   - tasks.mise.en.toml and tasks.mise.ja.toml differ in their descriptions and nowhere else
#   - the three scripts decide the language with the same function, and it follows the relay's rule
#   - every message a script prints exists in English (the fallback) and in Japanese
#   - every script a task calls is distributed
#
# Run it directly: tests/test_sample_sgw.sh
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
SRC=$ROOT/share/sgw
SAMPLE=$ROOT/examples/sgw-sample
DST=$SAMPLE/.devcontainer/sgw
SCRIPTS="sgw.sh vscode.sh upgrade.sh"
# every distributed script, including the one that runs inside dev and prints nothing of its own
ALL_SCRIPTS="$SCRIPTS post-start.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

echo "== the scripts parse, and are executable"
for f in $ALL_SCRIPTS; do
  bash -n "$SRC/$f" || fail "$f does not parse"
  [ -x "$SRC/$f" ] || fail "share/sgw/$f is not executable"
  [ -x "$DST/$f" ] || fail "the sample's $f is not executable"
done

echo "== the sample's copies equal share/sgw/"
for f in $ALL_SCRIPTS; do
  cmp -s "$SRC/$f" "$DST/$f" || fail "examples/sgw-sample/.devcontainer/sgw/$f differs from share/sgw/$f (scripts/sync-sample-sgw.sh)"
done
cmp -s "$SRC/tasks.mise.en.toml" "$DST/tasks.mise.toml" ||
  fail "the sample's tasks.mise.toml differs from share/sgw/tasks.mise.en.toml (scripts/sync-sample-sgw.sh)"

base=$(sed -n 's|^FROM ghcr.io/amakata/sgw-devcontainer-base:\([0-9.]*\).*|\1|p' "$SAMPLE/.devcontainer/Dockerfile")
gw=$(sed -n 's|^[[:space:]]*image:[[:space:]]*ghcr.io/amakata/sekimore-gw:\([0-9.]*\).*|\1|p' "$SAMPLE/.devcontainer/docker-compose.yml")
[ -n "$base" ] || fail "the sample's Dockerfile does not pin the base to a version; upgrade needs one"
[ -n "$gw" ] || fail "the sample's compose file does not pin the gateway to a version; upgrade needs one"

echo "== the sample's gateway.mise.toml is the gateway's own, at $gw"
# The file is sekimore-gw's (share/gateway.mise.en.toml), so the sample cannot be checked against
# anything in this repository: it is read at the pinned tag, the way scripts/sync-sample-sgw.sh
# writes it. The copy taken at 0.2.31 was still there at 0.2.45, without the raw = true that
# sekimore-gw#230 gave gw:login, and a new project started with that bug (#105).
if [ -n "${SEKIMORE_GW_SRC:-}" ]; then
  git -C "$SEKIMORE_GW_SRC" show "v$gw:share/gateway.mise.en.toml" > "$TMP/gateway.mise.toml" 2>/dev/null ||
    fail "SEKIMORE_GW_SRC=$SEKIMORE_GW_SRC has no tag v$gw (or no share/gateway.mise.en.toml at it)"
else
  curl -fsSL --max-time 20 "${SGW_RAW_URL:-https://raw.githubusercontent.com}/Amakata/sekimore-gw/v$gw/share/gateway.mise.en.toml" > "$TMP/gateway.mise.toml" 2>/dev/null ||
    fail "cannot read share/gateway.mise.en.toml of sekimore-gw v$gw from raw.githubusercontent.com; set SEKIMORE_GW_SRC to a sekimore-gw checkout that has the tag"
fi
[ -s "$TMP/gateway.mise.toml" ] || fail "share/gateway.mise.en.toml of sekimore-gw v$gw came back empty"
if ! cmp -s "$TMP/gateway.mise.toml" "$DST/gateway.mise.toml"; then
  diff -u "$DST/gateway.mise.toml" "$TMP/gateway.mise.toml" >&2 || true
  fail "the sample's gateway.mise.toml is not sekimore-gw v$gw's share/gateway.mise.en.toml (scripts/sync-sample-sgw.sh)"
fi

echo "== the sample's MANIFEST is what upgrade.sh would write"
{
  sed -n '/^new_manifest() {/,/^}/p' "$SRC/upgrade.sh" | sed -n 's/^  echo "\(# .*\)"$/\1/p'
  echo "base $base"; echo "gateway $gw"; echo "lang en"
  for f in sgw.sh vscode.sh upgrade.sh post-start.sh tasks.mise.toml gateway.mise.toml; do echo "file $f $(sha "$DST/$f")"; done
} > "$TMP/MANIFEST"
[ "$(grep -c '^#' "$TMP/MANIFEST")" -ge 1 ] || fail "could not read MANIFEST's header out of upgrade.sh"
if ! cmp -s "$TMP/MANIFEST" "$DST/MANIFEST"; then
  diff -u "$DST/MANIFEST" "$TMP/MANIFEST" >&2 || true
  fail "the sample's MANIFEST is stale (a copied file, or a pinned version, changed without it: scripts/sync-sample-sgw.sh)"
fi

echo "== the sample starts through post-start.sh"
# the list of variables sudo lets through lives in post-start.sh; a postStartCommand that calls
# agent-setup itself brings back the list that kept falling behind
grep -q '"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh"' "$SAMPLE/.devcontainer/devcontainer.json" ||
  fail "the sample's postStartCommand does not run .devcontainer/sgw/post-start.sh"

echo "== tasks.mise.en.toml and .ja.toml differ only in their descriptions"
strip() { grep -v '^description = ' "$1"; }
strip "$SRC/tasks.mise.en.toml" > "$TMP/en"
strip "$SRC/tasks.mise.ja.toml" > "$TMP/ja"
if ! cmp -s "$TMP/en" "$TMP/ja"; then diff -u "$TMP/en" "$TMP/ja" >&2 || true; fail "the two task files differ beyond their descriptions"; fi
[ "$(grep -c '^description = ' "$SRC/tasks.mise.en.toml")" = "$(grep -c '^description = ' "$SRC/tasks.mise.ja.toml")" ] ||
  fail "a task is described in one language only"

echo "== a task that opens an interactive shell has raw = true"
# mise's prefix output mode makes stdout a pipe; sgw.sh then drops -t and the shell shows no
# prompt. raw hands the task the terminal. Every task whose run starts a shell, or goes through
# gw-tty, needs it.
missing=$(awk '
  /^\[/ { if (task != "" && interactive && !raw) print task; task = $0; raw = 0; interactive = 0; next }
  /^raw = true/ { raw = 1 }
  /^run = / && (/"\$SGW" (dev|gw) (zsh|bash|sh)'"'"'/ || /gw-tty/) { interactive = 1 }
  END { if (task != "" && interactive && !raw) print task }
' "$SRC/tasks.mise.en.toml")
[ -z "$missing" ] || fail "interactive without raw = true: $missing"

echo "== every script a task calls is distributed"
for s in $(grep -o '\$(dirname "\$SGW")/[a-z-]*\.sh' "$SRC/tasks.mise.en.toml" | sed 's|.*/||' | sort -u); do
  [ -f "$SRC/$s" ] || fail "a task calls $s, which share/sgw/ does not have"
done

echo "== one language rule, the relay's"
sed -n '/^sgw_lang() {/,/^}/p' "$SRC/sgw.sh" > "$TMP/lang.sgw"
[ -s "$TMP/lang.sgw" ] || fail "sgw.sh has no sgw_lang()"
for f in vscode.sh upgrade.sh; do
  sed -n '/^sgw_lang() {/,/^}/p' "$SRC/$f" | cmp -s - "$TMP/lang.sgw" || fail "$f decides the language differently from sgw.sh"
done
# expect <want> <env assignments...>: sgw_lang in that environment
expect() {
  local want=$1 got; shift
  got=$(env -i PATH="$PATH" "$@" bash -c ". '$TMP/lang.sgw'; sgw_lang")
  [ "$got" = "$want" ] || fail "sgw_lang with $* gave $got, not $want"
}
expect en
expect ja LANG=ja_JP.UTF-8
expect en LANG=en_US.UTF-8
expect en LANG=C
expect ja LC_ALL=C LANG=ja_JP.UTF-8               # C falls through, as in the relay
expect ja LC_ALL=POSIX LANG=ja
expect en LANG=fr_FR.UTF-8                        # a language we do not have falls through, to the default
expect ja LC_MESSAGES=ja LANG=en_US.UTF-8         # LC_MESSAGES before LANG
expect en SEKIMORE_LANG=en LANG=ja_JP.UTF-8       # SEKIMORE_LANG first
expect ja SEKIMORE_LANG=ja-JP LC_ALL=en_US.UTF-8
expect en LANG=japanese                           # "ja" has to be the whole primary tag

echo "== every message exists in English and in Japanese"
for f in $SCRIPTS; do
  used=$(grep -v '^[[:space:]]*#' "$SRC/$f" | grep -oE '(say|msg|die) [a-z_]+' | awk '{print $2}' | sort -u)
  for k in $used; do
    grep -q "^    \*:$k) " "$SRC/$f" || fail "$f uses the message '$k', which has no English (fallback) entry"
    grep -q "^    ja:$k) " "$SRC/$f" || fail "$f uses the message '$k', which has no Japanese entry"
  done
  for k in $(sed -n 's/^    ja:\([a-z_]*\)) .*/\1/p' "$SRC/$f"); do
    grep -q "^    \*:$k) " "$SRC/$f" || fail "$f has a Japanese message '$k' with no English one"
  done
done

echo "PASS: the distributed files and the sample agree"
