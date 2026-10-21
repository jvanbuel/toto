#!/usr/bin/env bash
# Pins toto to an OpenShell release: fills openshell.lock.toml with the release's archive
# checksums and the digests of its supervisor and sandbox-runtime images.
#
#   scripts/pin-openshell.sh 0.1.5          # writes openshell.lock.toml
#   scripts/pin-openshell.sh --check        # fails if anything in the lock is unpinned
#
# Needs curl and python3, and access to github.com release downloads and ghcr.io.
set -euo pipefail
cd "$(dirname "$0")/.."
LOCK=openshell.lock.toml

if [[ "${1:-}" == "--check" ]]; then
  if grep -qE 'sha256 = ""' "$LOCK"; then
    echo "openshell.lock.toml has unpinned binaries; run scripts/pin-openshell.sh <version>" >&2
    exit 1
  fi
  echo "openshell.lock.toml is fully pinned"
  exit 0
fi

VERSION="${1:?usage: pin-openshell.sh <version, e.g. 0.1.5> | --check}"
VERSION="${VERSION#v}"
BASE="https://github.com/NVIDIA/OpenShell/releases/download/v${VERSION}"
WORK="$(mktemp -d)"
trap 'rm -r "$WORK"' EXIT

for f in openshell-checksums-sha256.txt openshell-gateway-checksums-sha256.txt; do
  curl -fsSL "$BASE/$f" -o "$WORK/$f"
done
cat "$WORK"/*.txt > "$WORK/all.txt"

digest() {
  local repo=$1
  local token
  token=$(curl -fsSL "https://ghcr.io/token?scope=repository:${repo}:pull" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  curl -fsSI -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://ghcr.io/v2/${repo}/manifests/${VERSION}" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
}
SUP=$(digest nvidia/openshell/supervisor)
SBX=$(digest nvidia/openshell/sandbox)
[[ -n "$SUP" && -n "$SBX" ]] || { echo "could not resolve the image digests for $VERSION" >&2; exit 1; }

python3 - "$LOCK" "$VERSION" "$BASE" "$SUP" "$SBX" "$WORK/all.txt" <<'PY'
import re, sys
lock, version, base, sup, sbx, sums = sys.argv[1:]
checks = {}
for line in open(sums):
    parts = line.split()
    if len(parts) == 2:
        checks[parts[1].lstrip("*")] = parts[0]
text = open(lock).read()
text = re.sub(r'^version = ".*"$', f'version = "{version}"', text, flags=re.M)
text = re.sub(r'^release_url = ".*"$', f'release_url = "{base}"', text, flags=re.M)
text = re.sub(r'^supervisor = ".*"$', f'supervisor = "ghcr.io/nvidia/openshell/supervisor@{sup}"', text, flags=re.M)
text = re.sub(r'^sandbox_runtime = ".*"$', f'sandbox_runtime = "ghcr.io/nvidia/openshell/sandbox@{sbx}"', text, flags=re.M)
missing = []
def fill(m):
    asset = m.group(1)
    if asset not in checks:
        missing.append(asset)
        return m.group(0)
    return f'asset = "{asset}", sha256 = "{checks[asset]}"'
text = re.sub(r'asset = "([^"]+)", sha256 = "[0-9a-f]*"', fill, text)
open(lock, "w").write(text)
if missing:
    sys.exit("not in the release's checksum files: " + ", ".join(missing))
print(f"pinned OpenShell {version}")
PY
