#!/usr/bin/env bash
# Harvest deterministic golden-vector bytes for the Rust port's cross-
# implementation tests (Phase 1: hash + object + serialize).
#
# The Zig implementation on `main` is the source of truth for the on-disk
# object byte layout defined in docs/SPEC-OBJECTS.md. This script
# invokes a tiny Zig harness (scripts/harvest/harvest.zig) which imports
# the Zig `object` / `serialize` / `hash` modules, constructs objects
# with fixed inputs (fixed identity bytes, fixed timestamps, fixed
# messages — no time/random reads), serialises them, and writes the raw
# bytes to stdout. This script captures each vector's stdout into a
# `.bin` file and emits a matching `.json` sidecar with metadata and the
# vector's BLAKE3 hex digest.
#
# Determinism contract:
#   - Re-running this script from a clean checkout produces byte-
#     identical output. If it does not, that is a bug.
#   - Every vector's BLAKE3 is recorded in its .json and in MANIFEST.txt;
#     the downstream Rust tests cross-check both the bytes and the
#     digest.
#
# Dependencies:
#   - Zig matching the repo pin (see .zigversion). The harness uses
#     std.process.Init (0.16+).
#   - macOS or Linux. No extra crates, no network.
#   - A BLAKE3 CLI for the sidecar digests (`b3sum`). If absent we fall
#     back to `python3 -c "import blake3"`, and if neither is present
#     the digest field is omitted (the Rust test still recomputes it).
#
# Usage:
#   bash scripts/harvest-golden-vectors.sh
#
#   or with an explicit output directory:
#   bash scripts/harvest-golden-vectors.sh /path/to/out
#
# Idempotent: clears and recreates the target directory before each
# run. Passes `bash scripts/verify-rename.sh` — no forbidden strings.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-$ROOT_DIR/rust/tests/golden/phase1}"
# Phase 3 fixtures live alongside phase1 under their own subtree so each
# Rust test crate can scope its loader to its own phase.
PHASE3_OUT_DIR="${PHASE3_OUT_DIR:-$ROOT_DIR/rust/tests/golden/phase3}"
HARVEST_SRC="$ROOT_DIR/scripts/harvest/harvest.zig"
BUNDLE_SRC="$ROOT_DIR/src/lib.zig"

if [ ! -f "$HARVEST_SRC" ]; then
  echo "harvest: missing $HARVEST_SRC" >&2
  exit 1
fi
if [ ! -f "$BUNDLE_SRC" ]; then
  echo "harvest: missing $BUNDLE_SRC (expected Zig lib root)" >&2
  exit 1
fi

# Locate a Zig compiler. The repo pins its version via .zigversion; CI
# installs the requested version into PATH. We warn but do not hard-fail
# on mismatch so developers can still run the script locally on a near-
# by version.
if ! command -v zig >/dev/null 2>&1; then
  echo "harvest: 'zig' not found on PATH" >&2
  exit 1
fi
EXPECTED_ZIG="$(cat "$ROOT_DIR/.zigversion" 2>/dev/null || echo unknown)"
ACTUAL_ZIG="$(zig version)"
if [ "$ACTUAL_ZIG" != "$EXPECTED_ZIG" ]; then
  echo "harvest: WARNING zig version $ACTUAL_ZIG != pinned $EXPECTED_ZIG" >&2
fi

# Pick a target triple. On macOS 26 the default target links against
# libc symbols that the bundled SDK cannot resolve, so we pin to macOS
# 14.0 on Darwin. On Linux the default target is fine.
TARGET_FLAGS=()
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) TARGET_FLAGS=(-target aarch64-macos.14.0) ;;
      x86_64)        TARGET_FLAGS=(-target x86_64-macos.14.0) ;;
    esac
    ;;
esac

# Reset output directory so the harvest is idempotent.
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Emit a single vector into <out_dir>/<name>.bin + <name>.json. The Zig
# harness prints raw bytes on stdout and "BLAKE3: <hex>\n" on stderr,
# so we don't need an external hasher.
emit_vector_to() {
  local out_dir="$1"
  local name="$2"
  local description="$3"
  local bin_path="$out_dir/$name.bin"
  local json_path="$out_dir/$name.json"
  local err_path="$out_dir/.$name.err"

  zig run \
    "${TARGET_FLAGS[@]}" \
    --dep mkit_src -Mroot="$HARVEST_SRC" \
    -Mmkit_src="$BUNDLE_SRC" \
    -- "$name" >"$bin_path" 2>"$err_path"

  local size
  size=$(wc -c <"$bin_path" | tr -d ' ')
  local digest=""
  if grep -q '^BLAKE3: ' "$err_path"; then
    digest="$(grep '^BLAKE3: ' "$err_path" | head -n1 | awk '{print $2}')"
  fi
  rm -f "$err_path"

  {
    printf '{\n'
    printf '  "name": "%s",\n' "$name"
    printf '  "description": "%s",\n' "$description"
    printf '  "bin": "%s.bin",\n' "$name"
    printf '  "size": %s' "$size"
    if [ -n "$digest" ]; then
      printf ',\n  "blake3": "%s"' "$digest"
    fi
    printf '\n}\n'
  } >"$json_path"

  printf '%s %s\n' "$name" "${digest:-unknown}"
}

# Backwards-compatible wrapper: emit into the phase1 OUT_DIR.
emit_vector() {
  emit_vector_to "$OUT_DIR" "$1" "$2"
}

# Manifest collects (name, blake3) for all emitted vectors, so the
# Rust test can load it once and assert every digest in one pass.
MANIFEST="$OUT_DIR/MANIFEST.txt"
{
  echo "# Phase 1 golden vectors (deterministic)"
  echo "# Produced by scripts/harvest-golden-vectors.sh"
  echo "# Format: <name> <blake3-hex-of-bin-bytes>"
} >"$MANIFEST"

# Vector list. Order matches docs/SPEC-OBJECTS.md §1-§9.
# Keep in sync with scripts/harvest/harvest.zig::buildByName.
declare -a VECTORS=(
  "identity_ed25519|ed25519 identity, 32-byte pubkey 0xAA*32 (raw wire form)"
  "identity_opaque|opaque 8-byte LE u64=42 identity (raw wire form)"
  "blob|11-byte UTF-8 blob 'hello mkit\\n'"
  "empty_blob|zero-byte blob; SPEC-OBJECTS §13.1 (10 bytes total)"
  "tree|3-entry tree: README.md (blob) + scripts (executable) + src (tree), lex-sorted"
  "empty_tree|zero-entry tree; SPEC-OBJECTS §13.2 (10 bytes total)"
  "tree_single_file|single-entry tree pointing at the empty blob; SPEC-OBJECTS §13.3"
  "commit_0parent|root commit, zero parents, ed25519 identity"
  "commit_1parent|commit with one parent, ed25519 identity"
  "commit_2parent|merge commit with two parents, ed25519 identity"
  "remix_2sources|remix with two sources sorted by (upstream_id, commit_hash)"
  "remix_identical_upstream_distinct_commit|remix with two sources sharing upstream_id; SPEC-OBJECTS §13.6 (secondary-key sort)"
  "commit_0parent_signing_bytes|canonical Ed25519 signing-bytes preimage for commit_0parent (sign domain prefix not included)"
  "remix_2sources_signing_bytes|canonical Ed25519 signing-bytes preimage for remix_2sources"
  "chunked_blob|chunked blob manifest with 4 fixed-size chunks"
  "chunked_blob_cs0_3chunks|chunked blob with chunk_size=0 (CDC) and 3 chunks; SPEC-OBJECTS §13.7 (118 bytes)"
)

for entry in "${VECTORS[@]}"; do
  name="${entry%%|*}"
  desc="${entry#*|}"
  line="$(emit_vector "$name" "$desc")"
  echo "$line" >>"$MANIFEST"
done

echo "harvest: wrote $(printf '%s\n' "${VECTORS[@]}" | wc -l | tr -d ' ') vectors to $OUT_DIR"
echo "harvest: manifest:"
cat "$MANIFEST"

# -----------------------------------------------------------------------
# Phase 3 vectors — additive. Reset and emit into PHASE3_OUT_DIR.
# These are FastCDC chunk-boundary lists harvested from the Zig
# implementation so the Rust port can assert byte-identical cuts.
# pack/delta vectors live in the Rust crate's own pin tests because the
# Zig packfile/delta predate SPEC-PACKFILE / SPEC-DELTA — they don't
# emit the spec wire format.
# -----------------------------------------------------------------------
rm -rf "$PHASE3_OUT_DIR"
mkdir -p "$PHASE3_OUT_DIR"
PHASE3_MANIFEST="$PHASE3_OUT_DIR/MANIFEST.txt"
{
  echo "# Phase 3 golden vectors (deterministic; FastCDC boundaries from Zig)"
  echo "# Produced by scripts/harvest-golden-vectors.sh"
  echo "# Format: <name> <blake3-hex-of-bin-bytes>"
} >"$PHASE3_MANIFEST"

declare -a PHASE3_VECTORS=(
  "fastcdc_boundaries_1mib|1 MiB pseudo-random buffer (i*31+7 mod 256); chunk-end offsets as JSON"
  "fastcdc_boundaries_256k|256 KiB pattern ((i*17)^(i>>3))&0xFF; chunk-end offsets as JSON"
)

for entry in "${PHASE3_VECTORS[@]}"; do
  name="${entry%%|*}"
  desc="${entry#*|}"
  line="$(emit_vector_to "$PHASE3_OUT_DIR" "$name" "$desc")"
  echo "$line" >>"$PHASE3_MANIFEST"
done

echo "harvest: wrote $(printf '%s\n' "${PHASE3_VECTORS[@]}" | wc -l | tr -d ' ') Phase 3 vectors to $PHASE3_OUT_DIR"
echo "harvest: phase3 manifest:"
cat "$PHASE3_MANIFEST"
