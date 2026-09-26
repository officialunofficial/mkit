#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Checks that each platform of a mkit-server image is exactly the base image
# plus the release archive's files, and nothing else. Per platform, from
# containers it creates but never runs (the image has no shell):
#
# - the config: architecture, user 65532:65532, entrypoint
#   `mkit-server serve`, cmd `--help`, exposed ports 8080 and 9418, no
#   volumes, healthcheck or onbuild triggers, and the base's own Env and
#   WorkingDir unchanged;
# - the layers: the base image's layers (from the Dockerfile's pinned
#   FROM), unchanged and in order, plus exactly the Dockerfile's two COPY
#   layers, which hold only the binary, the two licenses and their
#   directories (so an added /etc/ld.so.preload, a whiteout or an
#   overwritten base file fails);
# - the binary: /usr/local/bin/mkit-server hashes to the `./mkit-server`
#   entry of the matching archive's own SHA256SUMS.
#
# WHY: release.yml's `container` job runs it on the pushed digest, before
# container-sign signs it, so the signature never covers anything but the
# pinned base and the cosign-verified archives' bytes. Fails closed.
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

DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/contrib/docker/mkit-server/Dockerfile"
BASE="$(awk '$1 == "FROM" { print $2; exit }' "$DOCKERFILE")"
[[ "$BASE" == *@sha256:* ]] || die "the Dockerfile's FROM is not pinned by digest: ${BASE}"

# What the Dockerfile's COPY layers may contain: these files, and the
# directories leading to them.
ALLOWED_FILES="usr/local/bin/mkit-server usr/share/doc/mkit-server/LICENSE-APACHE usr/share/doc/mkit-server/LICENSE-MIT"
ALLOWED_DIRS=" usr/ usr/local/ usr/local/bin/ usr/share/ usr/share/doc/ usr/share/doc/mkit-server/ "
ADDED_LAYERS=2

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

WORK="$(mktemp -d)"
CIDS=()
cleanup() {
  if [ "${#CIDS[@]}" -gt 0 ]; then
    docker rm "${CIDS[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# Sets IMG_ID to the image ID that <ref> gives for linux/<arch>, through a
# created (never started) container, recorded in CID. A <name>@sha256:
# reference is first resolved to its platform manifest's digest: pulling
# the second platform of the same index reference would clash with the
# first in the classic image store. (Not a $(...) function: CIDS must
# survive for cleanup.)
IMG_ID=""
CID=""
image_id() {
  local ref="$1" arch="$2" pull="$3" digest
  if [[ "$ref" == *@sha256:* ]]; then
    digest="$(docker buildx imagetools inspect --raw "$ref" | jq -r --arg arch "$arch" '
      [.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest]
      | if length == 1 then .[0] else empty end')"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "${ref} has no single linux/${arch} manifest"
    ref="${ref%@*}@${digest}"
  fi
  CID="$(docker create --pull "$pull" --platform "linux/${arch}" "$ref" /nonexistent)"
  CIDS+=("$CID")
  IMG_ID="$(docker inspect --format '{{.Image}}' "$CID")"
}

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

  image_id "$REF" "$ARCH" "$PULL"
  IMG="$IMG_ID"
  IMG_CID="$CID"
  image_id "$BASE" "$ARCH" missing
  BASE_IMG="$IMG_ID"
  docker image inspect "$IMG" > "${WORK}/image.json"
  docker image inspect "$BASE_IMG" > "${WORK}/base.json"

  # The config, against the expected values and the base's Env/WorkingDir.
  DIFF="$(jq -rn --arg arch "$ARCH" --slurpfile img "${WORK}/image.json" --slurpfile base "${WORK}/base.json" '
    def view: {
      Architecture, Os,
      User: .Config.User, Entrypoint: .Config.Entrypoint, Cmd: .Config.Cmd,
      Env: .Config.Env, WorkingDir: .Config.WorkingDir,
      ExposedPorts: (.Config.ExposedPorts // {}), Volumes: (.Config.Volumes // {}),
      Healthcheck: .Config.Healthcheck, OnBuild: (.Config.OnBuild // [])
    };
    ($img[0][0] | view) as $got
    | ($base[0][0] | view) as $b
    | {
        Architecture: $arch, Os: "linux", User: "65532:65532",
        Entrypoint: ["/usr/local/bin/mkit-server", "serve"], Cmd: ["--help"],
        Env: $b.Env, WorkingDir: $b.WorkingDir,
        ExposedPorts: {"8080/tcp": {}, "9418/tcp": {}}, Volumes: {},
        Healthcheck: null, OnBuild: []
      } as $want
    | [$want | keys[] | select($got[.] != $want[.]) | "\(.): got \($got[.] | tojson), want \($want[.] | tojson)"]
    | join("; ")')"
  [ -z "$DIFF" ] || die "linux/${ARCH}: image config differs: ${DIFF}"

  # The layers: the base's, unchanged, then exactly the COPY layers.
  jq -e --slurpfile base "${WORK}/base.json" --argjson added "$ADDED_LAYERS" '
      .[0].RootFS.Layers as $l | $base[0][0].RootFS.Layers as $b
      | ($l | length) == ($b | length) + $added and $l[0:($b | length)] == $b' \
    "${WORK}/image.json" > /dev/null \
    || die "linux/${ARCH}: the layers are not the base's plus ${ADDED_LAYERS} COPY layers"
  docker save "$IMG" -o "${WORK}/image.tar"
  mkdir -p "${WORK}/saved"
  tar -xf "${WORK}/image.tar" -C "${WORK}/saved" manifest.json
  FILES=""
  while IFS= read -r LAYER; do
    while IFS= read -r ENTRY; do
      ENTRY="${ENTRY#./}"
      case "$ENTRY" in
        */)
          case "$ALLOWED_DIRS" in
            *" ${ENTRY} "*) ;;
            *) die "linux/${ARCH}: an added layer holds the unexpected directory /${ENTRY}" ;;
          esac
          ;;
        *) FILES="${FILES} ${ENTRY}" ;;
      esac
    done < <(tar -xOf "${WORK}/image.tar" "$LAYER" | tar -t)
  done < <(jq -r --argjson added "$ADDED_LAYERS" '.[0].Layers[-$added:][]' "${WORK}/saved/manifest.json")
  FILES="$(tr ' ' '\n' <<< "$FILES" | sed '/^$/d' | sort | tr '\n' ' ')"
  [ "$FILES" = "${ALLOWED_FILES} " ] || die "linux/${ARCH}: the added layers hold [${FILES% }], want [${ALLOWED_FILES}]"
  rm -rf "${WORK}/image.tar" "${WORK}/saved"

  # The binary.
  docker cp "${IMG_CID}:/usr/local/bin/mkit-server" "${WORK}/mkit-server-${ARCH}"
  docker rm "${CIDS[@]}" >/dev/null
  CIDS=()
  GOT="$(sha256_of "${WORK}/mkit-server-${ARCH}")"
  [ "$GOT" = "$WANT" ] || die "linux/${ARCH}: the image's mkit-server is ${GOT}, the archive's is ${WANT}"
  echo "linux/${ARCH}: base + [${ALLOWED_FILES}], config as built, /usr/local/bin/mkit-server = ${STAGE}/mkit-server (${GOT})"
done
