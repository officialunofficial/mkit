#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Builds the mkit-server container image (contrib/docker/mkit-server/
# Dockerfile) from a staged context (scripts/stage-server-image.sh) for each
# platform, loads it into the local Docker daemon WITHOUT pushing, and checks
# it:
#
# - every platform: the image config (numeric non-root user 65532, the
#   `mkit-server serve` entrypoint, `--help` as the default arguments, the
#   architecture, the version label);
# - the host's platform only (every platform with MKIT_IMAGE_CHECK_RUN_ALL=1,
#   given emulation): `mkit-server version` prints `mkit-server <version>`,
#   `serve --help` succeeds and lists no test-only flag, and the image has
#   no shell.
#
# release.yml's `container` job runs it before it pushes anything; run it
# locally the same way (docs/RELEASE.md, "Container image").
#
# Usage: scripts/check-server-image.sh <context-dir> <version> [<platform>...]
# (platforms default to linux/amd64 linux/arm64).

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <context-dir> <version> [<platform>...]" >&2
  exit 2
fi
CONTEXT="$1"
VERSION="$2"
shift 2
if [ "$#" -eq 0 ]; then
  set -- linux/amd64 linux/arm64
fi
DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/contrib/docker/mkit-server/Dockerfile"
HOST="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"

die() { echo "check-server-image: $*" >&2; exit 1; }

TAGS=()
cleanup() {
  if [ "${#TAGS[@]}" -gt 0 ]; then
    docker image rm "${TAGS[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for PLATFORM in "$@"; do
  ARCH="${PLATFORM#linux/}"
  TAG="mkit-server:check-${ARCH}"
  TAGS+=("$TAG")
  docker buildx build --platform "$PLATFORM" --load --provenance=false \
    --file "$DOCKERFILE" --build-arg "VERSION=${VERSION}" --tag "$TAG" "$CONTEXT"

  CONFIG="$(docker image inspect --format \
    '{{.Architecture}}|{{.Config.User}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{index .Config.Labels "org.opencontainers.image.version"}}' "$TAG")"
  WANT="${ARCH}|65532:65532|[\"/usr/local/bin/mkit-server\",\"serve\"]|[\"--help\"]|${VERSION}"
  [ "$CONFIG" = "$WANT" ] || die "${PLATFORM}: image config is ${CONFIG}, want ${WANT}"

  if [ "$PLATFORM" != "$HOST" ] && [ "${MKIT_IMAGE_CHECK_RUN_ALL:-0}" != 1 ]; then
    echo "${PLATFORM}: built and inspected; not run (host is ${HOST})"
    continue
  fi
  RUN=(docker run --rm --network none --platform "$PLATFORM")
  GOT="$("${RUN[@]}" --entrypoint /usr/local/bin/mkit-server "$TAG" version)"
  [ "$GOT" = "mkit-server ${VERSION}" ] || die "${PLATFORM}: version printed '${GOT}', want 'mkit-server ${VERSION}'"
  # The default arguments are `--help`: `serve --help`.
  HELP="$("${RUN[@]}" "$TAG")"
  printf '%s\n' "$HELP" | grep -q -- '--repo-root' || die "${PLATFORM}: serve --help does not list --repo-root"
  if printf '%s\n' "$HELP" | grep -Eiq -- '--[a-z0-9-]*(test|fault)|x-mkit-test'; then
    die "${PLATFORM}: serve --help lists a test-only flag"
  fi
  if "${RUN[@]}" --entrypoint /bin/sh "$TAG" -c true >/dev/null 2>&1; then
    die "${PLATFORM}: the image has a shell"
  fi
  echo "${PLATFORM}: runs mkit-server ${VERSION} (version, serve --help) as 65532:65532, no shell"
done
