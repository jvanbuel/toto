#!/bin/sh
# Installs the latest toto release (toto plus the OpenShell it is pinned to), after checking the
# archive against the release's SHA256SUMS. The binaries go into a directory of their own
# (~/.local/share/toto/<version>) and only `toto` is linked into ~/.local/bin, so an OpenShell
# you installed yourself is never replaced.
#
#   curl -fsSL https://raw.githubusercontent.com/jvanbuel/togra/main/scripts/install.sh | sh
#
# TOTO_VERSION=v0.2.0 picks a release; TOTO_BIN_DIR and TOTO_HOME other directories. Needs curl
# and tar, and Docker (OpenShell runs sandboxes on it).
set -eu
REPO="${TOTO_REPO:-jvanbuel/togra}"
BIN_DIR="${TOTO_BIN_DIR:-$HOME/.local/bin}"
TOTO_HOME="${TOTO_HOME:-$HOME/.local/share/toto}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=x86_64-linux ;;
  Linux-aarch64 | Linux-arm64) platform=aarch64-linux ;;
  Darwin-arm64) platform=aarch64-macos ;;
  *) echo "toto has no build for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

version="${TOTO_VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$version" ] || { echo "could not find the latest toto release" >&2; exit 1; }
fi

name="toto-$version-$platform"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
base="https://github.com/$REPO/releases/download/$version"
curl -fsSL "$base/$name.tar.gz" -o "$work/$name.tar.gz"
curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"

want="$(grep " $name.tar.gz\$" "$work/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$work/$name.tar.gz" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$work/$name.tar.gz" | cut -d' ' -f1)"; fi
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum mismatch for $name.tar.gz" >&2; exit 1; }

tar -C "$work" -xzf "$work/$name.tar.gz"
dest="$TOTO_HOME/$version"
mkdir -p "$TOTO_HOME"
rm -rf "$dest.partial"
mv "$work/$name" "$dest.partial"
rm -rf "$dest"
mv "$dest.partial" "$dest"
mkdir -p "$BIN_DIR"
ln -sf "$dest/toto" "$BIN_DIR/toto"
echo "installed toto $version (with OpenShell) into $dest; linked $BIN_DIR/toto"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "add $BIN_DIR to your PATH" ;; esac
echo "next: toto init && toto doctor"
