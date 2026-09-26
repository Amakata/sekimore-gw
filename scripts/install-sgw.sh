#!/usr/bin/env sh
# Install `sgw`, the operator's tool for a sekimore-gw project, on this host (macOS or Linux).
#
#   curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
#   curl -fsSL … | sh -s -- --version 0.2.47        a particular release
#   curl -fsSL … | sh -s -- --to /usr/local/bin      somewhere other than ~/.local/bin
#
# It downloads the release asset for this machine, checks its sha256 against the one published
# beside it, and puts one file, `sgw`, in the directory. Nothing else is written. Run it again to
# move to a newer release.
set -eu

REPO=${SGW_REPO:-Amakata/sekimore-gw}
BASE=${SGW_RELEASES_URL:-https://github.com/$REPO/releases}
VERSION=""
TO="${SGW_INSTALL_DIR:-$HOME/.local/bin}"
while [ $# -gt 0 ]; do
  case $1 in
    --version) VERSION=$2; shift ;;
    --to) TO=$2; shift ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install-sgw: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

os=$(uname -s); arch=$(uname -m)
case "$os/$arch" in
  Darwin/arm64) target=aarch64-apple-darwin ;;
  Linux/x86_64) target=x86_64-unknown-linux-musl ;;
  Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "install-sgw: no build for $os/$arch (macOS on Apple silicon, Linux x86_64 or arm64)" >&2; exit 1 ;;
esac
asset="sgw-$target.tar.gz"
if [ -n "$VERSION" ]; then url="$BASE/download/v${VERSION#v}/$asset"; else url="$BASE/latest/download/$asset"; fi

command -v curl >/dev/null 2>&1 || { echo "install-sgw: curl is needed" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM
echo "install-sgw: $url"
curl -fsSL -o "$tmp/$asset" "$url"
curl -fsSL -o "$tmp/$asset.sha256" "$url.sha256"
# the published sum names the file the way `shasum` wrote it; compare the digest only
want=$(cut -d' ' -f1 "$tmp/$asset.sha256")
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1); fi
[ "$want" = "$got" ] || { echo "install-sgw: sha256 mismatch for $asset (want $want, got $got)" >&2; exit 1; }
tar -C "$tmp" -xzf "$tmp/$asset" sgw
mkdir -p "$TO"
install -m 0755 "$tmp/sgw" "$TO/sgw"
echo "install-sgw: $("$TO/sgw" --version) → $TO/sgw"
case ":${PATH}:" in
  *":$TO:"*) ;;
  *) echo "install-sgw: $TO is not on your PATH; add it, e.g.  export PATH=\"$TO:\$PATH\"" ;;
esac
