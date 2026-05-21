#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# mkit installer — downloads the signed release archive matching the
# host OS + architecture from a public GitHub Release, verifies its
# cosign signature, verifies its SHA256, and installs the `mkit` binary
# atomically into $MKIT_INSTALL_DIR (default: ~/.local/bin).
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh | sh -s -- --version v0.1.0
#
# Trust model:
#   * cosign keyless verification is REQUIRED by default. The script
#     fetches the per-archive `.cosign.bundle`, validates that it was
#     signed by this repo's release.yml workflow at a strict-semver tag,
#     and only then installs. The published .sha256 file is fetched
#     from the same origin as the archive and proves NOTHING about
#     authenticity on its own — it's a defense-in-depth integrity check.
#   * If `cosign` is not in PATH on a release-track install (i.e. you
#     have not passed --insecure-skip-cosign), the script exits non-zero
#     with installation instructions. Use --insecure-skip-cosign to
#     proceed without signature verification at your own risk.
#
# Version pinning:
#   * MKIT_VERSION (or --version) pins the install to a specific tag.
#     RECOMMENDED for production use — it's the only way to get a
#     repeatable install.
#   * Without a version pin the script resolves the GitHub "latest"
#     release. The resolved tag is recorded at
#     ~/.local/state/mkit/installed-tag; subsequent unpinned installs
#     compare against this file and warn loudly on a silent downgrade.
#
# Environment overrides:
#   MKIT_VERSION             explicit tag (e.g. v0.1.0). Default: 'latest'.
#   MKIT_INSTALL_DIR         install prefix. Default: ~/.local/bin.
#   MKIT_STATE_DIR           state dir for installed-tag bookkeeping.
#                            Default: ~/.local/state/mkit.
#   MKIT_SKIP_COSIGN         set to '1' to skip cosign verification
#                            (equivalent to --insecure-skip-cosign).
#
# Flags:
#   --version <tag>          pin to a specific release tag.
#   --prefix  <dir>          install prefix.
#   --insecure-skip-cosign   skip cosign signature verification (DANGEROUS).
#   --cosign                 deprecated; cosign is on by default. No-op.
#   --help, -h               show this help text.
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

# Print the embedded usage block. Reading from $0 breaks under
# `curl … | sh` because $0 there is `sh`. Instead we embed the help
# text here.
print_help() {
  cat <<'EOF'
mkit installer

Usage:
  curl -sSfL https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh | sh
  sh install.sh [--version <tag>] [--prefix <dir>] [--insecure-skip-cosign]

Flags:
  --version <tag>           Pin to a specific release tag (e.g. v0.1.0).
                            RECOMMENDED for production / reproducible installs.
  --prefix <dir>            Install prefix. Default: ~/.local/bin.
  --insecure-skip-cosign    Skip cosign signature verification. DANGEROUS — use
                            only when cosign is unavailable and you have
                            verified the binary by other means.
  --cosign                  Deprecated alias. cosign verification is now ON by
                            default; this flag is a no-op kept for back-compat.
  --help, -h                Show this help.

Environment:
  MKIT_VERSION              Same as --version.
  MKIT_INSTALL_DIR          Same as --prefix.
  MKIT_STATE_DIR            State dir for downgrade bookkeeping.
                            Default: ~/.local/state/mkit.
  MKIT_SKIP_COSIGN=1        Same as --insecure-skip-cosign.

Trust model:
  cosign keyless signature verification is REQUIRED by default. Install cosign
  from https://docs.sigstore.dev/cosign/installation/ before running, or pass
  --insecure-skip-cosign at your own risk.
EOF
}

version="${MKIT_VERSION:-}"
install_dir="${MKIT_INSTALL_DIR:-$HOME/.local/bin}"
state_dir="${MKIT_STATE_DIR:-$HOME/.local/state/mkit}"
skip_cosign="${MKIT_SKIP_COSIGN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)               version="$2"; shift 2 ;;
    --prefix)                install_dir="$2"; shift 2 ;;
    --insecure-skip-cosign)  skip_cosign="1"; shift ;;
    --cosign)                shift ;;  # deprecated; cosign is default-on
    --help|-h)               print_help; exit 0 ;;
    *)                       die "unknown argument: $1 (try --help)" ;;
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

resolved_from_latest=0
if [ -z "$version" ]; then
  log "resolving latest release tag (no --version pinned)"
  warn "for reproducible installs, pin a tag with --version vX.Y.Z or MKIT_VERSION=vX.Y.Z"
  version=$(fetch_stdout "${api}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n1)
  [ -n "$version" ] || die "could not parse latest release tag"
  resolved_from_latest=1
fi

# Normalise (accept either 'v0.1.0' or '0.1.0').
case "$version" in
  v*) tag="$version"; bare="${version#v}" ;;
  *)  tag="v$version"; bare="$version" ;;
esac

# ---- silent-downgrade guard ----
#
# We compare the previously-installed tag against the tag we're about
# to install. POSIX sh has no built-in semver compare, so we use sort
# -V (GNU/BSD coreutils both ship it). If sort -V is missing we just
# warn and continue.
#
# Two records are consulted:
#   1. $state_dir/installed-tag — global per-user record, survives
#      install_dir rotation.
#   2. $install_dir/.mkit-installed-tag — local-to-binary record,
#      survives state-dir clearance and catches the case where a user
#      runs the installer with a different MKIT_STATE_DIR.
# Both are written on every install; on a downgrade attempt, EITHER
# file disagreeing causes the guard to fire.
state_file="${state_dir}/installed-tag"
bin_state_file="${install_dir}/.mkit-installed-tag"

read_state_file() {
  if [ -f "$1" ]; then
    cat "$1" 2>/dev/null || true
  fi
}

prev_tag_global="$(read_state_file "$state_file")"
prev_tag_local="$(read_state_file "$bin_state_file")"

# Pick the higher of the two so a missing/empty file never lets a
# downgrade slip through. sort -V handles the comparison; if either is
# empty we just use the non-empty one.
if [ -n "$prev_tag_global" ] && [ -n "$prev_tag_local" ]; then
  prev_g_bare="${prev_tag_global#v}"
  prev_l_bare="${prev_tag_local#v}"
  if command -v sort >/dev/null 2>&1; then
    prev_higher="$(printf '%s\n%s\n' "$prev_g_bare" "$prev_l_bare" | sort -V | tail -n1)"
    if [ "$prev_higher" = "$prev_l_bare" ]; then
      prev_tag="$prev_tag_local"
    else
      prev_tag="$prev_tag_global"
    fi
  else
    prev_tag="$prev_tag_global"
  fi
elif [ -n "$prev_tag_global" ]; then
  prev_tag="$prev_tag_global"
else
  prev_tag="$prev_tag_local"
fi

if [ -n "$prev_tag" ] && [ "$prev_tag" != "$tag" ]; then
  if command -v sort >/dev/null 2>&1; then
    # Strip leading 'v' for sort -V.
    prev_bare="${prev_tag#v}"
    new_bare="${bare}"
    higher="$(printf '%s\n%s\n' "$prev_bare" "$new_bare" | sort -V | tail -n1)"
    if [ "$higher" = "$prev_bare" ] && [ "$prev_bare" != "$new_bare" ]; then
      warn "you are installing $tag but $prev_tag is already recorded — this is a DOWNGRADE."
      if [ "$resolved_from_latest" = "1" ]; then
        die "refusing to silently downgrade from $prev_tag to $tag via 'latest'. Pin --version $prev_tag or newer, or delete $state_file and $bin_state_file."
      else
        warn "proceeding because --version was passed explicitly."
      fi
    fi
  fi
fi

# Independent check: the two state files MUST agree when both exist.
# A mismatch means one was tampered with (or a parallel installer
# misbehaved). Refuse rather than picking a winner silently.
if [ -n "$prev_tag_global" ] && [ -n "$prev_tag_local" ] \
   && [ "$prev_tag_global" != "$prev_tag_local" ]; then
  die "installed-tag mismatch: $state_file says '$prev_tag_global' but $bin_state_file says '$prev_tag_local'. Refusing to install. Resolve manually."
fi

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

# ---- cosign verification (default-on) ----
#
# This is the AUTHENTICATION step. The .sha256 check below is integrity
# only — it shows nothing about provenance because the file is served
# from the same origin as the archive. Cosign verifies that this archive
# was produced by this repo's release.yml workflow at a strict-semver tag.
if [ "$skip_cosign" = "1" ]; then
  warn "cosign verification SKIPPED (--insecure-skip-cosign / MKIT_SKIP_COSIGN=1)"
  warn "the only authenticity check disabled. SHA256 alone proves nothing."
else
  if ! command -v cosign >/dev/null 2>&1; then
    cat >&2 <<EOF
error: cosign is not in PATH.

cosign keyless signature verification is required by default — without it
the .sha256 file you just downloaded proves nothing about authenticity
(it comes from the same origin as the archive). Install cosign from:

  https://docs.sigstore.dev/cosign/installation/

Or, if you have verified the binary by other means and accept the risk,
re-run with --insecure-skip-cosign (or MKIT_SKIP_COSIGN=1).
EOF
    exit 1
  fi

  log "fetching cosign bundle"
  fetch "$bundle_url" "$tmp/${archive}.cosign.bundle" \
    || die "cosign bundle missing for $tag — refusing to install. Pass --insecure-skip-cosign to override."

  log "cosign verify-blob"
  # Strict-semver regex on the tag, anchored to the exact workflow path.
  # Accepts e.g. v0.1.0 and v1.2.3-rc.1 but rejects v.* glob matches,
  # branch refs, and rogue workflows in the same repo.
  cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle "$tmp/${archive}.cosign.bundle" \
    "$tmp/$archive" \
    || die "cosign verification failed — refusing to install"
fi

# ---- integrity (SHA256) ----
#
# Defense-in-depth integrity check. Comes AFTER cosign because cosign
# is the authenticity check; sha256 only catches transport corruption.
log "verifying SHA256"
cd "$tmp"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${archive}.sha256" >/dev/null
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${archive}.sha256" >/dev/null
else
  die "need sha256sum or shasum to verify the download"
fi

# ---- extract + install (atomic) ----

log "extracting"
tar -xzf "$archive"

stage_dir="mkit-${bare}-${target}"
bin_src="$tmp/$stage_dir/mkit"
[ -x "$bin_src" ] || die "extracted archive missing expected binary at $stage_dir/mkit"

mkdir -p "$install_dir"
install_path="$install_dir/mkit"

# ---- install_dir permission check ----
#
# A group- or world-writable install directory lets anyone on the host
# race a malicious binary into $install_path between our final mv(1)
# and the user's first invocation. Refuse rather than win the race
# unintentionally. Mode is read with BSD stat on Darwin and GNU stat
# on Linux — the rest of the script already keys on $uname_os.
case "$uname_os" in
  Darwin) dir_mode="$(stat -f '%Lp' "$install_dir" 2>/dev/null || echo '')" ;;
  Linux)  dir_mode="$(stat -c '%a' "$install_dir" 2>/dev/null || echo '')" ;;
  *)      dir_mode="" ;;
esac

if [ -n "$dir_mode" ]; then
  # Normalise to three digits so the substring tests below align.
  case "$dir_mode" in
    [0-9])    dir_mode="00${dir_mode}" ;;
    [0-9][0-9]) dir_mode="0${dir_mode}" ;;
  esac
  # Group bit = middle digit, other bit = last digit. Either even-2
  # (write bit set) is the failure case.
  group_digit="$(printf '%s' "$dir_mode" | cut -c2)"
  other_digit="$(printf '%s' "$dir_mode" | cut -c3)"
  case "$group_digit" in
    [2367]) die "install dir $install_dir is group-writable (mode $dir_mode); refusing to install — a malicious local user could race a replacement binary into place between mv and first execution. Tighten permissions: chmod g-w $install_dir" ;;
  esac
  case "$other_digit" in
    [2367]) die "install dir $install_dir is world-writable (mode $dir_mode); refusing to install — anyone on this host could race a replacement binary into place. Tighten permissions: chmod o-w $install_dir" ;;
  esac
fi

# Atomic install: stage the new binary in the SAME directory as the
# final install path (so rename(2) stays within one filesystem),
# chmod +x BEFORE the rename so the final inode is never executable-
# without-content, then rename on top of the old binary. mv on POSIX
# uses rename(2) when src and dst are on the same fs, which is atomic.
staged="$(mktemp "${install_path}.XXXXXX")" \
  || die "could not create temp file in ${install_dir}"
# mktemp creates with restrictive perms; copy contents then mark exec.
cp "$bin_src" "$staged"
chmod 0755 "$staged"
mv "$staged" "$install_path"

# ---- record installed tag for downgrade guard ----
#
# Write BOTH copies. Future installer runs treat either as
# authoritative (the higher of the two wins); a mismatch trips the
# tamper check above. mv-from-staging makes the writes atomic.

mkdir -p "$state_dir"
printf '%s\n' "$tag" > "${state_file}.new"
mv "${state_file}.new" "$state_file"

printf '%s\n' "$tag" > "${bin_state_file}.new"
mv "${bin_state_file}.new" "$bin_state_file"

log "installed $install_path ($tag)"

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
