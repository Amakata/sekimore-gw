#!/bin/sh
# The Debian packages a built language needs at run time that the base image does not have, one
# per line: every shared library its ELF files load (ldd), traced to the package that ships it
# (dpkg -S). Libraries it ships itself (under <dir>) are not counted.
#
#   runtime-packages.sh <dir> <the base image's packages, one per line>
set -eu
dir=$1
base=$2
need=$(mktemp)
find "$dir" -type f | while read -r f; do
  [ "$(head -c 4 "$f" 2>/dev/null | od -An -c | tr -d ' ')" = '177ELF' ] || continue
  ldd "$f" 2>/dev/null | awk '/=> \// {print $3}'
done | sort -u | while read -r lib; do
  case "$lib" in "$dir"/*) continue ;; esac
  dpkg -S "$lib" 2>/dev/null || dpkg -S "$(readlink -f "$lib")" 2>/dev/null || true
done | cut -d: -f1 | sed 's/,.*//' | sort -u > "$need"
sort -u "$base" | comm -13 - "$need"
rm -f "$need"
