#!/bin/sh
# Run as the user, with no network, in an image that has only the base, the runtime packages and
# this Python: the standard modules that are built against system libraries have to import.
set -eu
python --version
python -c 'import ssl, sqlite3, zlib, bz2, readline, ctypes, hashlib, json; print(ssl.OPENSSL_VERSION)'
echo "python: the native modules import"
