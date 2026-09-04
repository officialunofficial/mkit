#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Mechanizes docs/RELEASE.md's "Smoke test" checklist for a Linux/macOS
# release archive (`.tar.gz`): verify the cosign signature and the
# SHA256SUMS entry, extract it, check the `mkit version` contract and the
# bundled man page/completions, run a basic init/keygen/add/commit flow,
# and (unless --skip-npm) check the matching npm package.
#
# WHY: this checklist used to be run once per release, by a human, by hand.
# Mechanizing it makes it repeatable: as a pre-flight dry run against a
# locally packaged archive (no cosign bundle / SHA256SUMS yet — those steps
# are skipped with a warning, not a failure) and as the real verification
# pass against a downloaded GitHub Release archive (issue #779 Phase 4).
#
# Usage:
#   scripts/release-smoke.sh --archive <path/to/mkit-X.Y.Z-<triple>.tar.gz> \
#     --version X.Y.Z [--skip-npm] [--skip-cosign] [--skip-sha256sums]
#
# Looks for, alongside <archive> (all optional — a missing sidecar is
# skipped with a warning so this also works against a bare local build):
#   <archive>.cosign.bundle   cosign signature bundle
#   SHA256SUMS                aggregate hash file, same directory as <archive>

set -euo pipefail

archive=""
version=""
skip_npm=0
skip_cosign=0
skip_sha256sums=0

while [ $# -gt 0 ]; do
  case "$1" in
    --archive) archive="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --skip-npm) skip_npm=1; shift ;;
    --skip-cosign) skip_cosign=1; shift ;;
    --skip-sha256sums) skip_sha256sums=1; shift ;;
    *)
      echo "release-smoke: unknown argument '$1'" >&2
      exit 2
      ;;
  esac
done

if [ -z "$archive" ] || [ -z "$version" ]; then
  echo "usage: $0 --archive <path/to/mkit-X.Y.Z-<triple>.tar.gz> --version X.Y.Z [--skip-npm] [--skip-cosign] [--skip-sha256sums]" >&2
  exit 2
fi
if [ ! -f "$archive" ]; then
  echo "release-smoke: archive not found: $archive" >&2
  exit 1
fi
case "$archive" in
  *.tar.gz) ;;
  *)
    echo "release-smoke: only .tar.gz archives are supported here" >&2
    exit 2
    ;;
esac

archive_dir="$(cd "$(dirname "$archive")" && pwd)"
archive_name="$(basename "$archive")"
fail=0

note()  { echo "release-smoke: $*"; }
warn()  { echo "release-smoke: WARN: $*" >&2; }
error() { echo "release-smoke: ERROR: $*" >&2; fail=1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

# ── cosign signature ────────────────────────────────────────────────────
if [ "$skip_cosign" -eq 1 ]; then
  note "skipping cosign verification (--skip-cosign)"
elif [ ! -f "${archive}.cosign.bundle" ]; then
  warn "no ${archive_name}.cosign.bundle found next to the archive — skipping cosign verification (expected for a local pre-flight build)"
elif ! command -v cosign >/dev/null 2>&1; then
  warn "cosign not installed — skipping signature verification. Install: https://docs.sigstore.dev/cosign/installation/"
else
  note "verifying cosign signature for ${archive_name}"
  if cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle "${archive}.cosign.bundle" \
    "$archive"; then
    note "cosign: Verified OK"
  else
    error "cosign signature verification failed for ${archive_name}"
  fi
fi

# ── SHA256SUMS entry ─────────────────────────────────────────────────────
if [ "$skip_sha256sums" -eq 1 ]; then
  note "skipping SHA256SUMS check (--skip-sha256sums)"
elif [ ! -f "${archive_dir}/SHA256SUMS" ]; then
  warn "no SHA256SUMS found in ${archive_dir} — skipping hash check (expected for a local pre-flight build)"
else
  entry="$(grep " ${archive_name}\$" "${archive_dir}/SHA256SUMS" || true)"
  if [ -z "$entry" ]; then
    error "SHA256SUMS has no entry for ${archive_name}"
  else
    expected="$(printf '%s' "$entry" | awk '{print $1}')"
    actual="$(sha256 "$archive" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
      error "SHA256SUMS mismatch for ${archive_name}: expected ${expected}, got ${actual}"
    else
      note "SHA256SUMS matches ${archive_name}"
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "release-smoke: aborting before extraction — signature/hash checks failed" >&2
  exit 1
fi

# ── extract and locate the binary ───────────────────────────────────────
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

note "extracting ${archive_name}"
tar -xzf "$archive" -C "$work_dir"

bin="$(find "$work_dir" -maxdepth 2 -type f -name mkit -perm -u+x | head -n1)"
if [ -z "$bin" ]; then
  error "no 'mkit' executable found in the extracted archive"
  exit 1
fi
archive_root="$(dirname "$bin")"

# ── version contract ────────────────────────────────────────────────────
out="$("$bin" version)"
expected="mkit ${version}"
if [ "$out" != "$expected" ]; then
  error "version contract violated: got [$out], expected [$expected]"
else
  note "version contract OK: ${out}"
fi

# ── man page / completions present ──────────────────────────────────────
for f in \
  "share/man/man1/mkit.1" \
  "share/completions/mkit.bash" \
  "share/completions/_mkit" \
  "share/completions/mkit.fish"
do
  if [ ! -f "${archive_root}/${f}" ]; then
    error "missing ${f} in extracted archive"
  fi
done
[ "$fail" -eq 0 ] && note "man page and completions present"

# ── basic flow: init, keygen, add, commit ───────────────────────────────
repo_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir" "$repo_dir"' EXIT
(
  cd "$repo_dir"
  "$bin" init
  "$bin" keygen
  echo "hello" > README.md
  "$bin" add README.md
  "$bin" commit -m "smoke test commit"
) || error "basic init/keygen/add/commit flow failed"
[ "$fail" -eq 0 ] && note "basic init/keygen/add/commit flow OK"

# ── npm package ──────────────────────────────────────────────────────────
if [ "$skip_npm" -eq 1 ]; then
  note "skipping npm checks (--skip-npm)"
elif ! command -v npm >/dev/null 2>&1; then
  warn "npm not installed — skipping npm checks"
else
  note "checking @officialunofficial/mkit-wasm@${version} on npm"
  if ! npm view "@officialunofficial/mkit-wasm@${version}" >/dev/null; then
    error "npm view @officialunofficial/mkit-wasm@${version} failed"
  fi
  npm_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir" "$repo_dir" "$npm_dir"' EXIT
  (
    cd "$npm_dir"
    npm init -y >/dev/null
    npm install --save-exact "@officialunofficial/mkit-wasm@${version}" >/dev/null
    npm audit signatures
  ) || error "npm audit signatures failed for @officialunofficial/mkit-wasm@${version}"
fi

if [ "$fail" -ne 0 ]; then
  echo "release-smoke: FAILED — see errors above" >&2
  exit 1
fi
echo "release-smoke: all checks passed for ${archive_name} (${version})"
