#!/usr/bin/env bash
# upgrade.sh — keep this project's gateway, base image and .devcontainer/sgw/ current. Run it on the host (Mac).
#
#   upgrade.sh              compare the pinned versions with the newest and say what would change (changes nothing)
#   upgrade.sh --apply      upgrade to the newest: rewrite the tags, replace .devcontainer/sgw/, recreate the
#                           gateway after asking, unlock, and list what only a person can do
#   upgrade.sh --apply --yes  the same, without asking before recreating the gateway
#   upgrade.sh --sync       bring .devcontainer/sgw/ in line with the versions already pinned
#   upgrade.sh --notes      print the UPGRADING sections between the pinned versions and the newest
#   upgrade.sh --owned      only what your own files (mise.toml, devcontainer.json, …) need; no network
#
# The versions are the gateway's `image:` tag in .devcontainer/docker-compose.yml and the base's `FROM` tag in
# .devcontainer/Dockerfile. The newest is the highest X.Y.Z tag on GHCR — what can actually be pulled.
# The distributed files come from the release tags on GitHub (the base's share/sgw/, the gateway's share/),
# the same sources the images are built from; reading them there needs no multi-gigabyte pull.
#
# .devcontainer/sgw/ is overwritten, never merged. MANIFEST records what was written last; a file that
# matches neither that record nor a version this script can fetch has been edited by hand, and --apply and
# --sync stop with the diff rather than lose it. Nothing outside .devcontainer/sgw/ is written except the two
# tags.
#
# The language (output, and which task files are taken) follows the relay: SEKIMORE_LANG, LC_ALL,
# LC_MESSAGES, LANG — ja is Japanese, en English, anything else falls through; English when none decides.
#
# Distributed by sgw-devcontainer-base: `mise run upgrade:apply` replaces this file, and stops
# rather than overwrite it once it has been edited.
set -euo pipefail

SGW_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=${MISE_PROJECT_ROOT:-$(cd "$SGW_DIR/../.." && pwd)}
COMPOSE=${SGW_COMPOSE_FILE:-$ROOT/.devcontainer/docker-compose.yml}
DOCKERFILE=${SGW_DOCKERFILE:-$ROOT/.devcontainer/Dockerfile}
MANIFEST=$SGW_DIR/MANIFEST

# Where things come from. Environment variables override them, for a fork.
GW_IMAGE=${SGW_GATEWAY_IMAGE:-ghcr.io/amakata/sekimore-gw}
BASE_IMAGE=${SGW_BASE_IMAGE:-ghcr.io/amakata/sgw-devcontainer-base}
GW_REPO=${SGW_GATEWAY_REPO:-Amakata/sekimore-gw}
BASE_REPO=${SGW_BASE_REPO:-Amakata/sgw-devcontainer-base}
RAW=${SGW_RAW_URL:-https://raw.githubusercontent.com}

FILES="sgw.sh vscode.sh upgrade.sh post-start.sh tasks.mise.toml gateway.mise.toml"

# ---- language ----
# The relay's rule, so the gateway and these scripts agree: the first of these that names a
# language we have decides; C, POSIX, empty and languages we do not have fall through.
sgw_lang() {
  local v p
  for v in "${SEKIMORE_LANG:-}" "${LC_ALL:-}" "${LC_MESSAGES:-}" "${LANG:-}"; do
    p=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[^A-Za-z].*//' | tr 'A-Z' 'a-z')
    case $p in en|ja) echo "$p"; return ;; esac
  done
  echo en
}
L=$(sgw_lang)

# msg <key>: the format string for the current language. English is the fallback.
msg() {
  case "$L:$1" in
    ja:inside) echo 'upgrade: ここは dev コンテナの中です。ホスト (Mac) で実行してください。' ;;
    *:inside) echo 'upgrade: this is the inside of the dev container; run it on the host (Mac).' ;;
    ja:need) echo 'upgrade: %s が見つかりません' ;;
    *:need) echo 'upgrade: %s not found' ;;
    ja:usage) echo '使い方: upgrade.sh [--apply [--yes] | --sync | --notes | --owned]' ;;
    *:usage) echo 'usage: upgrade.sh [--apply [--yes] | --sync | --notes | --owned]' ;;
    ja:unpinned) echo 'upgrade: %s の %s が X.Y.Z のタグで固定されていません (latest やダイジェスト)。版を書いてから実行してください。' ;;
    *:unpinned) echo 'upgrade: %s in %s is not pinned to an X.Y.Z tag (latest, or a digest). Write a version there first.' ;;
    ja:no_newest) echo 'upgrade: %s の最新の版を GHCR から取れませんでした' ;;
    *:no_newest) echo 'upgrade: could not get the newest version of %s from GHCR' ;;
    ja:registry) echo 'upgrade: %s のレジストリには対応していません (ghcr.io のみ)' ;;
    *:registry) echo 'upgrade: the registry of %s is not supported (ghcr.io only)' ;;
    ja:fetch) echo 'upgrade: 取得できませんでした: %s' ;;
    *:fetch) echo 'upgrade: could not fetch %s' ;;
    ja:unchanged) echo '何も変更していません。' ;;
    *:unchanged) echo 'Nothing was changed.' ;;
    ja:hdr) echo '%-12s %-10s %-10s' ;;
    *:hdr) echo '%-12s %-10s %-10s' ;;
    ja:col_pinned) echo 'いま' ;;
    *:col_pinned) echo 'pinned' ;;
    ja:col_newest) echo '最新' ;;
    *:col_newest) echo 'newest' ;;
    ja:up_to_date) echo '最新' ;;
    *:up_to_date) echo 'up to date' ;;
    ja:update) echo '← 更新あり' ;;
    *:update) echo '← update available' ;;
    ja:files_at) echo '.devcontainer/sgw/ (配布物。%sにしたとき)' ;;
    *:files_at) echo '.devcontainer/sgw/ (distributed files, at the %s versions)' ;;
    ja:at_newest) echo '最新の版' ;;
    *:at_newest) echo 'newest' ;;
    ja:at_pinned) echo 'いまの版' ;;
    *:at_pinned) echo 'pinned' ;;
    ja:f_same) echo '変わらず' ;;
    *:f_same) echo 'same' ;;
    ja:f_changes) echo '更新あり' ;;
    *:f_changes) echo 'changes' ;;
    ja:f_new) echo '新規' ;;
    *:f_new) echo 'new' ;;
    ja:f_edited) echo '手で書き換えられています — 適用はここで止まります' ;;
    *:f_edited) echo 'edited by hand — applying stops here' ;;
    ja:lang_changed) echo '言語: %s → %s (タスクファイルを取り直します)' ;;
    *:lang_changed) echo 'language: %s → %s (the task files are taken again)' ;;
    ja:notes_hdr) echo 'UPGRADING (いまの版から最新まで。本文は mise run upgrade:notes)' ;;
    *:notes_hdr) echo 'UPGRADING, between the pinned and the newest versions (mise run upgrade:notes prints them)' ;;
    ja:notes_none) echo 'UPGRADING: 手作業が要る版はありません' ;;
    *:notes_none) echo 'UPGRADING: no release in between asks anything of you' ;;
    ja:notes_unavail) echo 'UPGRADING: 取得できませんでした (%s)' ;;
    *:notes_unavail) echo 'UPGRADING: could not be fetched (%s)' ;;
    ja:all_current) echo 'すべて最新です。' ;;
    *:all_current) echo 'Everything is up to date.' ;;
    ja:next_apply) echo '適用するには: mise run upgrade:apply' ;;
    *:next_apply) echo 'To apply: mise run upgrade:apply' ;;
    ja:next_edited) echo '手で書き換えた配布物を元に戻すか、変更を mise.toml に移してから適用してください。' ;;
    *:next_edited) echo 'Restore the distributed files you edited, or move the change into mise.toml, before applying.' ;;
    ja:edited_stop) echo 'upgrade: %s は手で書き換えられています。上書きすると失われるので止まります。' ;;
    *:edited_stop) echo 'upgrade: %s has been edited by hand; overwriting it would lose that, so this stops.' ;;
    ja:edited_how) echo '  タスクを変えたいなら、同じ名前のタスクを mise.toml に書いてください (include より優先されます)。その後このファイルを git checkout で戻すか消してから、もう一度実行してください。' ;;
    *:edited_how) echo '  To change a task, define one with the same name in mise.toml (it wins over the include). Then restore this file with git checkout, or delete it, and run this again.' ;;
    ja:tag) echo '%s: %s → %s (%s)' ;;
    *:tag) echo '%s: %s → %s (%s)' ;;
    ja:wrote) echo '書き換え: .devcontainer/sgw/%s' ;;
    *:wrote) echo 'wrote .devcontainer/sgw/%s' ;;
    ja:ask_recreate) echo 'gateway を %s で作り直します。作業中の接続は切れます。よろしいですか? [y/N] ' ;;
    *:ask_recreate) echo 'Recreate the gateway on %s now? Connections in use are dropped. [y/N] ' ;;
    ja:unlock_try) echo 'gateway の秘密ストアが「%s」です。gw:unlock-auto を試します' ;;
    *:unlock_try) echo 'the gateway'"'"'s secret store is "%s"; trying gw:unlock-auto' ;;
    ja:owned_hdr) echo 'あなたのファイルで要る変更 (upgrade はここを書き換えません)' ;;
    *:owned_hdr) echo 'What your own files need (upgrade does not write these)' ;;
    ja:owned_none) echo 'あなたのファイルで要る変更: なし' ;;
    *:owned_none) echo 'What your own files need: nothing' ;;
    ja:remain) echo '残り (人がやること)' ;;
    *:remain) echo 'What is left (for you)' ;;
    ja:r_recreate) echo 'gateway を作り直す: mise run gw:recreate' ;;
    *:r_recreate) echo 'recreate the gateway: mise run gw:recreate' ;;
    ja:r_unlock) echo '秘密ストアを解錠する: mise run gw:unlock' ;;
    *:r_unlock) echo 'unlock the secret store: mise run gw:unlock' ;;
    ja:r_gw_down) echo 'gateway は動いていません。次に開いたとき %s で起動します (mise run vscode → Reopen in Container → mise run gw:unlock)' ;;
    *:r_gw_down) echo 'the gateway is not running; it comes up on %s the next time it is opened (mise run vscode → Reopen in Container → mise run gw:unlock)' ;;
    ja:r_rebuild) echo 'dev コンテナを作り直す: VS Code のコマンドパレットで Dev Containers: Rebuild Container (base %s)' ;;
    *:r_rebuild) echo 'rebuild the dev container: Dev Containers: Rebuild Container from the VS Code command palette (base %s)' ;;
    ja:r_notes) echo 'UPGRADING の節を読む: %s (mise run upgrade:notes)' ;;
    *:r_notes) echo 'read the UPGRADING sections: %s (mise run upgrade:notes)' ;;
    ja:r_include) echo 'mise.toml が .devcontainer/sgw/ を読んでいません。次を mise.toml に書いてください:' ;;
    *:r_include) echo 'mise.toml does not take .devcontainer/sgw/ in. Put this into mise.toml:' ;;
    ja:r_leftover) echo 'もう使われていないファイル: git rm %s' ;;
    *:r_leftover) echo 'no longer used: git rm %s' ;;
    ja:r_poststart) echo 'devcontainer.json の postStartCommand を次の 1 行にしてください (sudo に渡す SEKIMORE_* の一覧を post-start.sh が持ちます。以前の --preserve-env= の一覧は要りません):' ;;
    *:r_poststart) echo 'make devcontainer.json'"'"'s postStartCommand this one line (post-start.sh passes every SEKIMORE_* variable to sudo; the old --preserve-env= list goes):' ;;
    ja:r_commit) echo '変更を確かめてコミットする: git diff' ;;
    *:r_commit) echo 'review the change and commit it: git diff' ;;
    ja:r_none) echo 'なし' ;;
    *:r_none) echo 'nothing' ;;
  esac
}
say() { local f; f=$(msg "$1"); shift; printf "$f\n" "$@"; }
die() { say "$@" >&2; exit 1; }

# ---- arguments and preconditions ----
MODE=check YES=0
while [ $# -gt 0 ]; do
  case $1 in
    --apply) MODE=apply ;;
    --sync) MODE=sync ;;
    --notes) MODE=notes ;;
    --owned) MODE=owned ;;
    --yes) YES=1 ;;
    *) say usage >&2; exit 2 ;;
  esac
  shift
done

if [ "${DEVCONTAINER:-}" = "true" ] && [ -z "${SGW_FORCE:-}" ]; then
  say inside >&2; exit 2
fi
command -v curl >/dev/null 2>&1 || die need curl
if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die need 'sha256sum / shasum'
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sgw-upgrade.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM

# ---- what the project's own files need ----
# Collected into REMAIN; never written. A function, so that `--owned` can run it alone.
REMAIN=
remain() { REMAIN="$REMAIN$1
"; }
collect_owned() {
  # mise.toml is the user's: say what it needs, never write it
  M=$ROOT/mise.toml
  if ! grep -q '\.devcontainer/sgw/tasks\.mise\.toml' "$M" 2>/dev/null ||
     ! grep -q '\.devcontainer/sgw/gateway\.mise\.toml' "$M" 2>/dev/null ||
     ! grep -q '^[[:space:]]*SGW[[:space:]]*=.*\.devcontainer/sgw/sgw\.sh' "$M" 2>/dev/null; then
    remain "$(msg r_include)
        [task_config]
        includes = [\".devcontainer/sgw/tasks.mise.toml\", \".devcontainer/sgw/gateway.mise.toml\"]

        [env]
        SGW = \"{{config_root}}/.devcontainer/sgw/sgw.sh\""
  fi
  # devcontainer.json is the user's too. Its postStartCommand used to name the variables agent-setup
  # needs in --preserve-env=, a list that fell behind whenever agent-setup gained one; post-start.sh
  # passes them all. Say so until the project runs it.
  DCJ=$ROOT/.devcontainer/devcontainer.json
  if [ -f "$DCJ" ] && grep -q 'sekimore-agent-setup' "$DCJ" && ! grep -q '\.devcontainer/sgw/post-start\.sh' "$DCJ"; then
    remain "$(msg r_poststart)
        \"postStartCommand\": \"sh /workspace/.devcontainer/sgw/post-start.sh\","
  fi
  # the layout before .devcontainer/sgw/
  LEFT=
  for old in .devcontainer/scripts/sgw.sh .devcontainer/scripts/vscode.sh .devcontainer/gateway.mise.toml; do
    [ -e "$ROOT/$old" ] && LEFT="$LEFT $old"
  done
  [ -z "$LEFT" ] || remain "$(say r_leftover "${LEFT# }")"
}

# `--owned`: only what the project's own files need. No network: the apply that replaced this file
# runs it last, so the checks of the version it moved to are the ones that speak (#53).
if [ "$MODE" = owned ]; then
  collect_owned
  if [ -n "$REMAIN" ]; then
    say owned_hdr
    printf '%s' "$REMAIN" | sed 's/^\([^ ]\)/  - \1/'
  else
    say owned_none
  fi
  exit 0
fi

# ---- versions ----
# re <text>: <text> as a literal inside a sed basic regular expression
re() { printf '%s' "$1" | sed 's/[][\.*^$|/]/\\&/g'; }
VER='[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'

# The gateway's version: `image: <GW_IMAGE>:X.Y.Z` in the compose file (quotes and a trailing comment allowed).
pinned_gateway() {
  [ -f "$COMPOSE" ] || return 0
  sed 's/[[:space:]]#.*$//' "$COMPOSE" |
    sed -n "s|^[[:space:]]*image:[[:space:]]*[\"']\{0,1\}$(re "$GW_IMAGE"):\($VER\)[\"']\{0,1\}[[:space:]]*\$|\1|p" | sed -n 1p
}
# The base's version: `FROM [--flag ...] <BASE_IMAGE>:X.Y.Z [AS name]` in the Dockerfile.
pinned_base() {
  [ -f "$DOCKERFILE" ] || return 0
  sed -n "s|^FROM[[:space:]][[:space:]]*\(--[^[:space:]]*[[:space:]][[:space:]]*\)*$(re "$BASE_IMAGE"):\($VER\)\([[:space:]].*\)\{0,1\}\$|\2|p" "$DOCKERFILE" | sed -n 1p
}

vsort() { sort -t. -k1,1n -k2,2n -k3,3n; }
# ver_lt a b: a is an older version than b
ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | vsort | sed -n 1p)" = "$1" ]; }

# newest <image>: the highest X.Y.Z tag the registry has for it.
# The tag list can come in pages (a Link header names the next one), and the tags are in text order,
# so the newest version can sit on a later page than the first: follow every page.
newest() {
  local img=$1 host name tok url page=0
  host=${img%%/*}; name=${img#*/}
  [ "$host" = ghcr.io ] || die registry "$img"
  tok=$(curl -fsSL "https://$host/token?scope=repository:$name:pull" 2>/dev/null |
    sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') || true
  [ -n "$tok" ] || return 1
  : > "$TMP/tags"
  url="https://$host/v2/$name/tags/list?n=1000"
  while [ -n "$url" ] && [ "$page" -lt 50 ]; do
    curl -fsSL -D "$TMP/tags.hdr" -o "$TMP/tags.page" -H "Authorization: Bearer $tok" "$url" 2>/dev/null || return 1
    # one tag per line: split at the commas, then keep a line only if it holds a whole "X.Y.Z"
    # (a page need not end in a newline, and without one its last tag would run into the next page's first)
    { tr ',' '\n' < "$TMP/tags.page"; echo; } | sed -n "s/.*\"\($VER\)\".*/\1/p" >> "$TMP/tags"
    url=$(tr -d '\r' < "$TMP/tags.hdr" | sed -n 's/^[Ll]ink:[[:space:]]*<\([^>]*\)>.*rel="next".*/\1/p' | sed -n 1p)
    # the token goes with every page, so only ever to this registry
    case $url in
      /*) url="https://$host$url" ;;
      "https://$host/"*) ;;
      *) url= ;;
    esac
    page=$((page + 1))
  done
  vsort < "$TMP/tags" | tail -1
}

# ---- the distributed files ----
# url_of <file> <base> <gateway> <lang>
url_of() {
  case $1 in
    tasks.mise.toml) echo "$RAW/$BASE_REPO/v$2/share/sgw/tasks.mise.$4.toml" ;;
    gateway.mise.toml) echo "$RAW/$GW_REPO/v$3/share/gateway.mise.$4.toml" ;;
    *) echo "$RAW/$BASE_REPO/v$2/share/sgw/$1" ;;
  esac
}
fetch() { curl -fsSL -o "$2" "$1" 2>/dev/null; }
# fetch_set <dir> <base> <gateway> <lang>: every distributed file into <dir>; fails on the first miss
fetch_set() {
  local f u
  mkdir -p "$1"
  for f in $FILES; do
    u=$(url_of "$f" "$2" "$3" "$4")
    fetch "$u" "$1/$f" || { say fetch "$u" >&2; return 1; }
  done
}

manifest_get() { [ -f "$MANIFEST" ] && sed -n "s/^$1 //p" "$MANIFEST" | sed -n 1p || true; }
manifest_sha() { [ -f "$MANIFEST" ] && sed -n "s/^file $(re "$1") //p" "$MANIFEST" | sed -n 1p || true; }

# The versions and language the files on disk were written from: MANIFEST when there is one,
# otherwise the pinned versions (the first sync, with only upgrade.sh copied in).
ORIG_BASE= ORIG_GW= ORIG_LANG= ORIG_DIR=$TMP/orig ORIG_FETCHED=
orig_file() {  # orig_file <file>: path to the file as it was written, or nothing when it cannot be fetched
  if [ -z "$ORIG_FETCHED" ]; then
    ORIG_FETCHED=1
    fetch_set "$ORIG_DIR" "$ORIG_BASE" "$ORIG_GW" "$ORIG_LANG" 2>/dev/null || true
  fi
  [ -f "$ORIG_DIR/$1" ] && echo "$ORIG_DIR/$1" || true
}

# edited <file>: the file on disk would lose something if overwritten — it matches neither what
# MANIFEST says was written, nor the file as written, nor the file about to replace it.
edited() {
  local f=$1 cur h o
  cur=$SGW_DIR/$f
  [ -f "$cur" ] || return 1
  h=$(sha "$cur")
  [ "$h" = "$(sha "$NEW/$f")" ] && return 1
  [ "$h" = "$(manifest_sha "$f")" ] && return 1
  o=$(orig_file "$f")
  [ -n "$o" ] && [ "$h" = "$(sha "$o")" ] && return 1
  return 0
}

# ---- UPGRADING ----
# sections <file> <cur_gw> <new_gw> <cur_base> <new_base> <body>: the sections a move between the two
# pairs of versions crosses. Headings are "## X.Y.Z title" (a gateway version) or "## base X.Y.Z title".
# body=1 prints them whole; otherwise only the heading. Headings inside code fences are text, not sections.
sections() {
  awk -v cg="$2" -v ng="$3" -v cb="$4" -v nb="$5" -v body="$6" '
    function n(v,  a) { split(v, a, "."); return a[1] * 1000000 + a[2] * 1000 + a[3] }
    /^```/ { fence = !fence }
    !fence && /^## / {
      on = 0
      v = $2; lo = cg; hi = ng
      if ($2 == "base") { v = $3; lo = cb; hi = nb }
      if (v ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ && lo != "" && n(v) > n(lo) && n(v) <= n(hi)) {
        on = 1
        if (!body) { sub(/^## /, ""); print; next }
      }
    }
    on && body { print }
  ' "$1"
}

# ---- what is pinned, what it moves to ----
CUR_GW=$(pinned_gateway)
CUR_BASE=$(pinned_base)
[ -n "$CUR_GW" ] || die unpinned "$GW_IMAGE" "${COMPOSE#$ROOT/}"
[ -n "$CUR_BASE" ] || die unpinned "$BASE_IMAGE" "${DOCKERFILE#$ROOT/}"

if [ "$MODE" = sync ]; then
  NEW_GW=$CUR_GW NEW_BASE=$CUR_BASE
else
  NEW_GW=$(newest "$GW_IMAGE" || true); [ -n "$NEW_GW" ] || die no_newest "$GW_IMAGE"
  NEW_BASE=$(newest "$BASE_IMAGE" || true); [ -n "$NEW_BASE" ] || die no_newest "$BASE_IMAGE"
  # a registry that only has older tags must not walk a project backwards
  ver_lt "$NEW_GW" "$CUR_GW" && NEW_GW=$CUR_GW
  ver_lt "$NEW_BASE" "$CUR_BASE" && NEW_BASE=$CUR_BASE
fi

ORIG_BASE=$(manifest_get base); ORIG_BASE=${ORIG_BASE:-$CUR_BASE}
ORIG_GW=$(manifest_get gateway); ORIG_GW=${ORIG_GW:-$CUR_GW}
ORIG_LANG=$(manifest_get lang); ORIG_LANG=${ORIG_LANG:-$L}

UPG_NAME=UPGRADING.md
[ "$L" != ja ] || UPG_NAME=UPGRADING.ja.md
UPG_URL="$RAW/$BASE_REPO/v$NEW_BASE/$UPG_NAME"
UPG_PAGE="https://github.com/$BASE_REPO/blob/v$NEW_BASE/$UPG_NAME"
UPG=
if fetch "$UPG_URL" "$TMP/UPGRADING.md"; then UPG=$TMP/UPGRADING.md; fi

if [ "$MODE" = notes ]; then
  [ -n "$UPG" ] || die notes_unavail "$UPG_URL"
  out=$(sections "$UPG" "$CUR_GW" "$NEW_GW" "$CUR_BASE" "$NEW_BASE" 1)
  if [ -n "$out" ]; then printf '%s\n' "$out"; else say notes_none; fi
  exit 0
fi

NEW=$TMP/new
fetch_set "$NEW" "$NEW_BASE" "$NEW_GW" "$L" || { say unchanged >&2; exit 1; }

# ---- the report (every mode but notes starts with it) ----
row() { printf "$(msg hdr) %s\n" "$1" "$2" "$3" "$4"; }
state() { if [ "$1" = "$2" ]; then msg up_to_date; else msg update; fi; }
row "" "$(msg col_pinned)" "$(msg col_newest)" ""
row gateway "$CUR_GW" "$NEW_GW" "$(state "$CUR_GW" "$NEW_GW")"
row base "$CUR_BASE" "$NEW_BASE" "$(state "$CUR_BASE" "$NEW_BASE")"
echo

if [ "$MODE" = sync ]; then at=$(msg at_pinned); else at=$(msg at_newest); fi
say files_at "$at"
[ "$ORIG_LANG" = "$L" ] || { printf '  '; say lang_changed "$ORIG_LANG" "$L"; }
EDITED= CHANGED=
for f in $FILES; do
  if [ ! -f "$SGW_DIR/$f" ]; then s=$(msg f_new); CHANGED="$CHANGED $f"
  elif edited "$f"; then s=$(msg f_edited); EDITED="$EDITED $f"
  elif [ "$(sha "$SGW_DIR/$f")" = "$(sha "$NEW/$f")" ]; then s=$(msg f_same)
  else s=$(msg f_changes); CHANGED="$CHANGED $f"
  fi
  printf '  %-20s %s\n' "$f" "$s"
done
echo

NOTES=
if [ -z "$UPG" ]; then
  say notes_unavail "$UPG_URL"
else
  NOTES=$(sections "$UPG" "$CUR_GW" "$NEW_GW" "$CUR_BASE" "$NEW_BASE" 0)
  if [ -n "$NOTES" ]; then
    say notes_hdr
    printf '%s\n' "$NOTES" | sed 's/^/  /'
  else
    say notes_none
  fi
fi
echo

# The manifest the files about to be written would get. Writing it is part of "something changed".
new_manifest() {
  echo "# Written by upgrade.sh: what it last put in this directory, so an edit by hand can be told"
  echo "# apart from a file it wrote. Do not edit."
  echo "base $NEW_BASE"
  echo "gateway $NEW_GW"
  echo "lang $L"
  for f in $FILES; do echo "file $f $(sha "$NEW/$f")"; done
}
new_manifest > "$TMP/MANIFEST"
UP_TO_DATE=0
if [ "$CUR_GW" = "$NEW_GW" ] && [ "$CUR_BASE" = "$NEW_BASE" ] && [ -z "$CHANGED" ] && [ -z "$EDITED" ] &&
   [ -f "$MANIFEST" ] && cmp -s "$MANIFEST" "$TMP/MANIFEST"; then
  UP_TO_DATE=1
fi


# #53: when this run replaces upgrade.sh itself, the new one reports this part at the end instead —
# it may know of changes to your files that this one, written for an older release, does not.
SELF_REPLACED=0
if [ "$MODE" != check ]; then
  case " $CHANGED " in *" upgrade.sh "*) SELF_REPLACED=1 ;; esac
fi
[ "$SELF_REPLACED" = 1 ] || collect_owned

if [ "$MODE" = check ]; then
  # What the project's own files need is said here too, not only after an apply: a check is where
  # a person looks first, and these do not wait for a new version.
  if [ -n "$REMAIN" ]; then
    say owned_hdr
    printf '%s' "$REMAIN" | sed 's/^\([^ ]\)/  - \1/'
    echo
  fi
  if [ "$UP_TO_DATE" = 1 ]; then say all_current
  elif [ -n "$EDITED" ]; then say next_edited
  else say next_apply
  fi
  exit 0
fi

# ---- apply / sync ----
if [ -n "$EDITED" ]; then
  for f in $EDITED; do
    say edited_stop ".devcontainer/sgw/$f" >&2
    o=$(orig_file "$f")
    if [ -n "$o" ]; then diff -u "$o" "$SGW_DIR/$f" | sed "1,2s|$(re "$o")|$f (as written)|" >&2 || true; fi
  done
  say edited_how >&2
  say unchanged >&2
  exit 1
fi

if [ "$UP_TO_DATE" = 1 ]; then
  say all_current
else
  # the tags. Written in place (cat >), which keeps the file's owner and mode.
  retag() {  # retag <file> <image> <from> <to>
    local tmp=$TMP/retag img
    img=$(re "$2")
    # the version must end where the tag ends: moving 0.2.1 → 0.2.10 leaves an "0.2.19" alone
    sed -e "s|$img:$(re "$3")\([^0-9.]\)|$2:$4\1|g" -e "s|$img:$(re "$3")\$|$2:$4|" "$1" > "$tmp"
    cat "$tmp" > "$1"
  }
  if [ "$CUR_GW" != "$NEW_GW" ]; then
    retag "$COMPOSE" "$GW_IMAGE" "$CUR_GW" "$NEW_GW"
    say tag gateway "$CUR_GW" "$NEW_GW" "${COMPOSE#$ROOT/}"
  fi
  if [ "$CUR_BASE" != "$NEW_BASE" ]; then
    retag "$DOCKERFILE" "$BASE_IMAGE" "$CUR_BASE" "$NEW_BASE"
    say tag base "$CUR_BASE" "$NEW_BASE" "${DOCKERFILE#$ROOT/}"
  fi

  # The files. Each goes to a temporary name beside it and is renamed over the old one: a rename is
  # atomic, and it leaves this very script's old inode to the bash that is still reading it.
  for f in $FILES; do
    if [ -f "$SGW_DIR/$f" ] && [ "$(sha "$SGW_DIR/$f")" = "$(sha "$NEW/$f")" ]; then continue; fi
    cp "$NEW/$f" "$SGW_DIR/.$f.new"
    case $f in *.sh) chmod 755 "$SGW_DIR/.$f.new" ;; *) chmod 644 "$SGW_DIR/.$f.new" ;; esac
    mv "$SGW_DIR/.$f.new" "$SGW_DIR/$f"
    say wrote "$f"
  done
  cp "$TMP/MANIFEST" "$SGW_DIR/.MANIFEST.new" && chmod 644 "$SGW_DIR/.MANIFEST.new" && mv "$SGW_DIR/.MANIFEST.new" "$MANIFEST"
fi
echo

SGW=$SGW_DIR/sgw.sh
if [ "$MODE" = apply ] && [ "$CUR_GW" != "$NEW_GW" ]; then
  if bash "$SGW" id sekimore-gw >/dev/null 2>&1; then
    go=$YES
    if [ "$go" = 0 ] && [ -t 0 ]; then
      f=$(msg ask_recreate); printf "$f" "$NEW_GW"
      read -r ans || ans=
      case $ans in y|Y|yes|YES) go=1 ;; esac
    fi
    if [ "$go" = 1 ]; then
      bash "$SGW" recreate
      st=$(bash "$SGW" gw sekimore-relay store-status 2>/dev/null | head -n1 || echo unavailable); [ -n "$st" ] || st=unavailable
      if [ "$st" != unlocked ] && grep -q '"gw:unlock-auto"' "$SGW_DIR/gateway.mise.toml" && command -v mise >/dev/null 2>&1; then
        say unlock_try "$st"
        (cd "$ROOT" && mise run gw:unlock-auto) || true
        st=$(bash "$SGW" gw sekimore-relay store-status 2>/dev/null | head -n1 || echo unavailable); [ -n "$st" ] || st=unavailable
      fi
      [ "$st" = unlocked ] || remain "$(msg r_unlock)"
    else
      remain "$(msg r_recreate)"
      remain "$(msg r_unlock)"
    fi
  else
    remain "$(say r_gw_down "$NEW_GW")"
  fi
fi
if [ "$MODE" = apply ] && [ "$CUR_BASE" != "$NEW_BASE" ]; then
  remain "$(say r_rebuild "$NEW_BASE")"
fi
[ -z "$NOTES" ] || remain "$(say r_notes "$UPG_PAGE")"
[ "$UP_TO_DATE" = 1 ] || remain "$(msg r_commit)"

say remain
if [ -n "$REMAIN" ]; then
  printf '%s' "$REMAIN" | sed 's/^\([^ ]\)/  - \1/'
else
  echo "  $(msg r_none)"
fi
# This run replaced upgrade.sh: ask the new one what your files need (#53). exec, because nothing
# of this run is left to do, and the old code should not have the last word.
if [ "$SELF_REPLACED" = 1 ]; then
  echo
  exec bash "$SGW_DIR/upgrade.sh" --owned
fi
