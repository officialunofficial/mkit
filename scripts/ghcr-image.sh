#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Registry operations on a ghcr.io image by digest, through the OCI
# distribution API (curl + jq), for release.yml's container-tag job:
#
#   tag <repo> <digest> <tag>...
#       Fetch the manifest at <digest>, check its bytes hash to <digest>, and
#       PUT those exact bytes under each <tag> in order, checking each tag
#       resolves to <digest>; prints `tagged <tag>` for each one applied and
#       stops at the first failure. A tag therefore never names anything but
#       the signed digest (a re-serializing tool could change it). Needs
#       GITHUB_ACTOR and GITHUB_TOKEN (packages: write).
#   check-public <repo> <digest>
#       Resolve <digest> with an anonymous token: exits 0 when anyone can
#       pull the image, 1 when not (the package is still private).
#
# <repo> is the path under ghcr.io, e.g. officialunofficial/mkit-server.

set -euo pipefail

REGISTRY="https://ghcr.io"
ACCEPT="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"

die() { echo "ghcr-image: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Credentials never go on curl's command line, where the process list
# would show them: curl reads them as a config file on stdin (`-K -`;
# printf is a shell builtin, so they are not in any argv either).

# A bearer token for <repo> with <scope>, as GITHUB_ACTOR when <auth> is
# "user", else anonymous.
token() {
  local repo="$1" scope="$2" auth="$3" url
  url="${REGISTRY}/token?service=ghcr.io&scope=repository:${repo}:${scope}"
  if [ "$auth" = user ]; then
    printf 'user = "%s:%s"\n' "${GITHUB_ACTOR:?}" "${GITHUB_TOKEN:?}" | curl -fsS -K - "$url" | jq -er .token
  else
    curl -fsS "$url" | jq -er .token
  fi
}

# curl with `Authorization: Bearer <token>` ($1), then curl's arguments.
curl_bearer() {
  local tok="$1"
  shift
  printf 'header = "Authorization: Bearer %s"\n' "$tok" | curl -K - "$@"
}

# The Docker-Content-Digest a HEAD of manifests/<ref> answers.
resolve() {
  local repo="$1" ref="$2" tok="$3"
  curl_bearer "$tok" -fsSI -H "Accept: ${ACCEPT}" "${REGISTRY}/v2/${repo}/manifests/${ref}" \
    | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }'
}

[ "$#" -ge 3 ] || die "usage: $0 tag <repo> <digest> <tag>... | check-public <repo> <digest>"
CMD="$1" REPO="$2" DIGEST="$3"
shift 3
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "bad digest '${DIGEST}'"

case "$CMD" in
  tag)
    [ "$#" -ge 1 ] || die "tag: no tag given"
    TOK="$(token "$REPO" pull,push user)"
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    curl_bearer "$TOK" -fsS -D "${WORK}/headers" -o "${WORK}/manifest" \
      -H "Accept: ${ACCEPT}" "${REGISTRY}/v2/${REPO}/manifests/${DIGEST}"
    TYPE="$(tr -d '\r' < "${WORK}/headers" | awk 'tolower($1) == "content-type:" { print $2 }')"
    [ -n "$TYPE" ] || die "no Content-Type for ${REPO}@${DIGEST}"
    GOT="sha256:$(sha256_of "${WORK}/manifest")"
    [ "$GOT" = "$DIGEST" ] || die "the manifest fetched for ${DIGEST} hashes to ${GOT}"
    for TAG in "$@"; do
      [[ "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || die "bad tag '${TAG}'"
      curl_bearer "$TOK" -fsS -X PUT -H "Content-Type: ${TYPE}" \
        --data-binary "@${WORK}/manifest" "${REGISTRY}/v2/${REPO}/manifests/${TAG}" > /dev/null
      AT="$(resolve "$REPO" "$TAG" "$TOK")"
      [ "$AT" = "$DIGEST" ] || die "tag ${TAG} resolves to '${AT}', not ${DIGEST}"
      echo "tagged ${TAG}"
    done
    ;;
  check-public)
    if TOK="$(token "$REPO" pull anonymous 2>/dev/null)" \
      && [ "$(resolve "$REPO" "$DIGEST" "$TOK" 2>/dev/null)" = "$DIGEST" ]; then
      echo "ghcr.io/${REPO}@${DIGEST} is publicly pullable"
    else
      echo "ghcr.io/${REPO}@${DIGEST} is NOT publicly pullable"
      exit 1
    fi
    ;;
  *) die "unknown command '${CMD}'" ;;
esac
