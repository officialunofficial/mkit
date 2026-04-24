#!/bin/sh
# mkit installer — downloads the signed release archive matching the
# host OS + architecture from a public GitHub Release, verifies its
# SHA256, and installs the `mkit` binary into $MKIT_INSTALL_DIR
# (default: ~/.local/bin).
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh | sh -s -- --version v0.1.0
#
# Environment overrides:
#   MKIT_VERSION     — explicit tag (e.g. v0.1.2). Default: resolves 'latest' via the GitHub API.
#   MKIT_INSTALL_DIR — install prefix. Default: ~/.local/bin.
#   MKIT_COSIGN      — set to 'verify' to additionally run `cosign verify-blob`
#                      against the published .cosign.bundle (requires cosign in PATH).
#
# Flags:
#   --version <tag>   same as MKIT_VERSION
#   --prefix  <dir>   same as MKIT_INSTALL_DIR
#   --cosign          same as MKIT_COSIGN=verify
#
# For private-repo installs, use `gh release download` instead — it
# handles auth natively:
#   gh release download v0.1.0 --repo officialunofficial/mkit \
#     --pattern 'mkit-*-<target>.tar.gz' --dir .
#
# POSIX sh — runs under dash/ash/bash/zsh without bashisms.

set -eu

owner="officialunofficial"
repo="mkit"
api="https://api.github.com/repos/${owner}/${repo}"
dl="https://github.com/${owner}/${repo}/releases/download"

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

version="${MKIT_VERSION:-}"
install_dir="${MKIT_INSTALL_DIR:-$HOME/.local/bin}"
cosign_verify="${MKIT_COSIGN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --prefix)  install_dir="$2"; shift 2 ;;
    --cosign)  cosign_verify="verify"; shift ;;
    --help|-h) sed -n '3,30p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

fetch() {
  url="$1"; out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "need curl or wget to fetch $url"
  fi
}

fetch_stdout() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    die "need curl or wget"
  fi
}

# ---- host detection ----

uname_os="$(uname -s 2>/dev/null || echo unknown)"
uname_arch="$(uname -m 2>/dev/null || echo unknown)"

case "$uname_os" in
  Darwin)  os_part="apple-darwin" ;;
  Linux)   os_part="unknown-linux-gnu" ;;
  *)       die "unsupported OS: $uname_os (only Darwin and Linux have prebuilt binaries)" ;;
esac

case "$uname_arch" in
  x86_64|amd64)   arch_part="x86_64" ;;
  arm64|aarch64)  arch_part="aarch64" ;;
  *)              die "unsupported arch: $uname_arch" ;;
esac

target="${arch_part}-${os_part}"

# ---- version resolution ----

if [ -z "$version" ]; then
  log "resolving latest release tag"
  version=$(fetch_stdout "${api}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n1)
  [ -n "$version" ] || die "could not parse latest release tag"
fi

# Normalise (accept either 'v0.1.0' or '0.1.0').
case "$version" in
  v*) tag="$version"; bare="${version#v}" ;;
  *)  tag="v$version"; bare="$version" ;;
esac

archive="mkit-${bare}-${target}.tar.gz"
archive_url="${dl}/${tag}/${archive}"
sha_url="${archive_url}.sha256"
bundle_url="${archive_url}.cosign.bundle"

log "installing mkit $tag ($target) into $install_dir"

tmp=$(mktemp -d -t mkit-install.XXXXXXXXXX)
trap 'rm -rf "$tmp"' EXIT INT TERM

# ---- download ----

log "fetching $archive_url"
fetch "$archive_url" "$tmp/$archive" \
  || die "download failed — the release may not include a build for $target"

log "fetching ${archive}.sha256"
fetch "$sha_url" "$tmp/${archive}.sha256"

# ---- verify ----

log "verifying SHA256"
cd "$tmp"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${archive}.sha256" >/dev/null
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${archive}.sha256" >/dev/null
else
  die "need sha256sum or shasum to verify the download"
fi

if [ "$cosign_verify" = "verify" ]; then
  command -v cosign >/dev/null 2>&1 || die "cosign not in PATH — install it or unset MKIT_COSIGN"
  log "fetching cosign bundle"
  fetch "$bundle_url" "$tmp/${archive}.cosign.bundle"
  log "cosign verify-blob"
  cosign verify-blob \
    --certificate-identity-regexp "https://github.com/${owner}/${repo}/.github/workflows/release.yml@refs/tags/v.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle "$tmp/${archive}.cosign.bundle" \
    "$tmp/$archive" \
    || die "cosign verification failed"
fi

# ---- extract + install ----

log "extracting"
tar -xzf "$archive"

stage_dir="mkit-${bare}-${target}"
bin_src="$tmp/$stage_dir/mkit"
[ -x "$bin_src" ] || die "extracted archive missing expected binary at $stage_dir/mkit"

mkdir -p "$install_dir"
install_path="$install_dir/mkit"

# Move into place; cp + mv trick avoids cross-filesystem rename issues
# and leaves the old binary on disk until the new one is ready.
cp "$bin_src" "${install_path}.new"
chmod +x "${install_path}.new"
mv "${install_path}.new" "$install_path"

log "installed $install_path"

# ---- PATH check ----

case ":$PATH:" in
  *":$install_dir:"*)
    "$install_path" version
    ;;
  *)
    warn "$install_dir is not in PATH"
    cat <<EOF
Add it to your shell profile:
  export PATH="$install_dir:\$PATH"

Then re-open the shell, or run directly:
  $install_path version
EOF
    ;;
esac
