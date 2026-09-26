#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The local multi-arch check of the mkit-server container image: the same
# staging and checks as release.yml's `container` job, without cosign and
# WITHOUT pushing anything. It packs two locally built Linux binaries into
# archives laid out as release.yml's build job lays them out (the binary,
# the licenses, SHA256SUMS; a `.sha256` per archive), then runs
# scripts/stage-server-image.sh and scripts/check-server-image.sh on them:
# both platforms are built and inspected, the host's is run.
#
# Usage: scripts/local-server-image.sh <version> <x86_64-linux-binary> <aarch64-linux-binary>
#
# <version> is what the binaries print (`mkit-server <version>`): the
# workspace version for a tree build. How to cross-build the two binaries:
# docs/RELEASE.md, "Container image".

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <version> <x86_64-linux-binary> <aarch64-linux-binary>" >&2
  exit 2
fi
VERSION="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

pack() {
  local target="$1" bin="$2" stage
  stage="mkit-server-${VERSION}-${target}"
  mkdir -p "${WORK}/${stage}"
  cp "$bin" "${WORK}/${stage}/mkit-server"
  cp "${ROOT}/LICENSE-MIT" "${ROOT}/LICENSE-APACHE" "${WORK}/${stage}/"
  (
    cd "${WORK}/${stage}"
    sha256 ./mkit-server ./LICENSE-APACHE ./LICENSE-MIT > "${WORK}/SHA256SUMS.tmp"
    mv "${WORK}/SHA256SUMS.tmp" SHA256SUMS
  )
  (
    cd "$WORK"
    tar -czf "${stage}.tar.gz" "$stage"
    sha256 "${stage}.tar.gz" > "${stage}.tar.gz.sha256"
  )
}

pack x86_64-unknown-linux-gnu "$2"
pack aarch64-unknown-linux-gnu "$3"
bash "${ROOT}/scripts/stage-server-image.sh" "$WORK" "$VERSION" "${WORK}/context"
bash "${ROOT}/scripts/check-server-image.sh" "${WORK}/context" "$VERSION" linux/amd64 linux/arm64
