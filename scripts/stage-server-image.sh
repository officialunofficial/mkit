#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Lays out the build context of the mkit-server container image
# (contrib/docker/mkit-server/Dockerfile) from the Linux release archives:
#
#   <context>/dist/amd64/{mkit-server,LICENSE-MIT,LICENSE-APACHE}
#   <context>/dist/arm64/{mkit-server,LICENSE-MIT,LICENSE-APACHE}
#
# WHY: the image must carry exactly the bytes release.yml signed, not a
# second compile. release.yml's `container` job verifies each archive's
# cosign bundle first; this script then checks every byte it copies back to
# that archive: the archive against its `.sha256`, and each extracted file
# against the archive's own SHA256SUMS. It also refuses a binary the base
# image cannot run: the wrong ELF machine, a shared library distroless `cc`
# lacks, or a glibc symbol newer than its glibc (Debian 13: 2.41).
#
# Usage: scripts/stage-server-image.sh <archives-dir> <version> <context-dir>
#
# <archives-dir> holds mkit-server-<version>-<target>.tar.gz and its
# `.sha256` for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu.
# Needs `readelf` (binutils), or an `objdump` that reads foreign ELF files
# (llvm-objdump, the macOS default).

set -euo pipefail

# glibc of the image's base (gcr.io/distroless/cc-debian13). Dependabot
# bumps the digest within the same tag, so this changes only with the tag.
MAX_GLIBC="2.41"
# What distroless `cc` provides: glibc and libgcc_s.
ALLOWED_LIBS=" libc.so.6 libm.so.6 libgcc_s.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1 "

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <archives-dir> <version> <context-dir>" >&2
  exit 2
fi
ARCHIVES="$1"
VERSION="$2"
CONTEXT="$3"

die() { echo "stage-server-image: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# The dynamic section and version references of an ELF file, as text.
elf_deps() {
  if command -v readelf >/dev/null 2>&1; then
    readelf -dW "$1"
    readelf -VW "$1"
  else
    objdump -p "$1"
  fi
}

# 0 when glibc version $1 (e.g. 2.34) is at most $2.
glibc_le() {
  local a_major a_minor b_major b_minor
  IFS=. read -r a_major a_minor _ <<< "$1"
  IFS=. read -r b_major b_minor _ <<< "$2"
  [ "$a_major" -lt "$b_major" ] || { [ "$a_major" -eq "$b_major" ] && [ "${a_minor:-0}" -le "${b_minor:-0}" ]; }
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

rm -rf "${CONTEXT}/dist"
for PAIR in amd64:x86_64-unknown-linux-gnu:3e arm64:aarch64-unknown-linux-gnu:b7; do
  IFS=: read -r ARCH TARGET MACHINE <<< "$PAIR"
  STAGE="mkit-server-${VERSION}-${TARGET}"
  ARCHIVE="${ARCHIVES}/${STAGE}.tar.gz"
  [ -f "$ARCHIVE" ] || die "missing ${ARCHIVE}"
  [ -f "${ARCHIVE}.sha256" ] || die "missing ${ARCHIVE}.sha256"

  EXPECTED="$(cut -d' ' -f1 < "${ARCHIVE}.sha256")"
  [ "$(sha256_of "$ARCHIVE")" = "$EXPECTED" ] || die "${ARCHIVE} does not match its .sha256"

  # Only the members the image uses, plus the archive's own checksums.
  tar -xzf "$ARCHIVE" -C "$WORK" \
    "${STAGE}/SHA256SUMS" "${STAGE}/mkit-server" "${STAGE}/LICENSE-MIT" "${STAGE}/LICENSE-APACHE"
  OUT="${CONTEXT}/dist/${ARCH}"
  mkdir -p "$OUT"
  for FILE in mkit-server LICENSE-MIT LICENSE-APACHE; do
    SRC="${WORK}/${STAGE}/${FILE}"
    if [ ! -f "$SRC" ] || [ -L "$SRC" ]; then
      die "${STAGE}/${FILE} is not a regular file"
    fi
    LISTED="$(awk -v f="./${FILE}" '$2 == f { print $1 }' "${WORK}/${STAGE}/SHA256SUMS")"
    [ -n "$LISTED" ] || die "${STAGE}/SHA256SUMS does not list ./${FILE}"
    [ "$(sha256_of "$SRC")" = "$LISTED" ] || die "${STAGE}/${FILE} does not match the archive's SHA256SUMS"
    cp "$SRC" "${OUT}/${FILE}"
  done

  BIN="${OUT}/mkit-server"
  # ELF magic, 64-bit, and e_machine (0x3e x86-64, 0xb7 aarch64).
  [ "$(od -An -tx1 -N5 "$BIN" | tr -d ' \n')" = "7f454c4602" ] || die "${STAGE}/mkit-server is not a 64-bit ELF file"
  [ "$(od -An -tx1 -j18 -N1 "$BIN" | tr -d ' \n')" = "$MACHINE" ] || die "${STAGE}/mkit-server is not a ${ARCH} binary"

  DEPS="$(elf_deps "$BIN")"
  LIBS="$(printf '%s\n' "$DEPS" | grep NEEDED | grep -oE 'lib[A-Za-z0-9_+.-]*\.so[.0-9]*|ld-linux[A-Za-z0-9_.-]*' | sort -u)"
  [ -n "$LIBS" ] || die "${STAGE}/mkit-server lists no shared library; cannot read its dynamic section"
  for LIB in $LIBS; do
    case "$ALLOWED_LIBS" in
      *" ${LIB} "*) ;;
      *) die "${STAGE}/mkit-server needs ${LIB}, which the base image does not provide" ;;
    esac
  done
  NEWEST="$(printf '%s\n' "$DEPS" | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/^GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)"
  [ -n "$NEWEST" ] || die "${STAGE}/mkit-server has no glibc version references"
  glibc_le "$NEWEST" "$MAX_GLIBC" || die "${STAGE}/mkit-server needs glibc ${NEWEST}; the base image has ${MAX_GLIBC}"

  echo "staged ${ARCH}: ${STAGE}/mkit-server ($(sha256_of "$BIN")), libs: $(tr '\n' ' ' <<< "$LIBS")newest glibc symbol: ${NEWEST}"
done
