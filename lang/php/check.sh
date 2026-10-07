#!/bin/sh
# Run as the user, with no network, in an image that has only the base, the runtime packages and
# this PHP: the extensions a project counts on have to be there.
set -eu
php --version
mods=$(php -m)
for m in gd sodium xsl openssl curl mbstring intl zip pdo_sqlite bcmath; do
  printf '%s\n' "$mods" | grep -qix "$m" || { echo "FAIL: php has no $m"; printf '%s\n' "$mods"; exit 1; }
done
php -r 'exit(function_exists("imagecreatetruecolor") && function_exists("imagewebp") ? 0 : 1);' ||
  { echo "FAIL: gd lacks truecolor or webp"; exit 1; }
echo "php: every extension present"
