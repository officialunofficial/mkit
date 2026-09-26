#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Checks that each platform of a mkit-server image holds exactly the binary
# of the matching release archive: per platform, it creates (never runs) a
# container from <image>, copies /usr/local/bin/mkit-server out (the image
# has no shell), and compares its sha256 with the `./mkit-server` entry of
# that archive's own SHA256SUMS. Fails closed on any mismatch or missing
# piece.
#
# WHY: release.yml's `container` job runs it on the pushed digest, before
# container-sign signs it, so the signature never covers bytes other than
# the cosign-verified archives' (whatever the build step did).
#
# Usage: scripts/verify-server-image-binaries.sh <image-ref> <archives-dir> <version> [<arch>...]
#
# <arch> is amd64 and/or arm64 (default both).
# <image-ref> is normally <name>@sha256:<digest>, pulled per platform.
# MKIT_IMAGE_PULL=missing uses a local image instead (the local check).

set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <image-ref> <archives-dir> <version> [<arch>...]" >&2
  exit 2
fi
REF="$1"
ARCHIVES="$2"
VERSION="$3"
shift 3
if [ "$#" -eq 0 ]; then
  set -- amd64 arm64
fi
PULL="${MKIT_IMAGE_PULL:-always}"

die() { echo "verify-server-image-binaries: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

WORK="$(mktemp -d)"
CID=""
cleanup() {
  if [ -n "$CID" ]; then
    docker rm "$CID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

for ARCH in "$@"; do
  case "$ARCH" in
    amd64) TARGET=x86_64-unknown-linux-gnu ;;
    arm64) TARGET=aarch64-unknown-linux-gnu ;;
    *) die "unknown architecture '${ARCH}'" ;;
  esac
  STAGE="mkit-server-${VERSION}-${TARGET}"
  ARCHIVE="${ARCHIVES}/${STAGE}.tar.gz"
  [ -f "$ARCHIVE" ] || die "missing ${ARCHIVE}"
  WANT="$(tar -xzOf "$ARCHIVE" "${STAGE}/SHA256SUMS" | awk '$2 == "./mkit-server" { print $1 }')"
  [[ "$WANT" =~ ^[0-9a-f]{64}$ ]] || die "${STAGE}/SHA256SUMS has no ./mkit-server entry"

  CID="$(docker create --pull "$PULL" --platform "linux/${ARCH}" "$REF")"
  GOT_ARCH="$(docker image inspect --format '{{.Architecture}}' "$(docker inspect --format '{{.Image}}' "$CID")")"
  [ "$GOT_ARCH" = "$ARCH" ] || die "${REF} gave a ${GOT_ARCH} image for linux/${ARCH}"
  docker cp "${CID}:/usr/local/bin/mkit-server" "${WORK}/mkit-server-${ARCH}"
  docker rm "$CID" >/dev/null
  CID=""

  GOT="$(sha256_of "${WORK}/mkit-server-${ARCH}")"
  [ "$GOT" = "$WANT" ] || die "linux/${ARCH}: the image's mkit-server is ${GOT}, the archive's is ${WANT}"
  echo "linux/${ARCH}: /usr/local/bin/mkit-server = ${STAGE}/mkit-server (${GOT})"
done
