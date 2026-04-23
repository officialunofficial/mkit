#!/usr/bin/env bash
# Harvest deterministic golden-vector bytes for the Phase 8 (mkit-attest)
# Rust port. Mirrors scripts/harvest-golden-vectors.sh but emits the
# JCS-canonical statement + DSSE envelope vectors under
# rust/tests/golden/phase8/. See docs/SPEC-ATTESTATIONS.md.
#
# Determinism contract:
#   - Re-running this script from a clean checkout produces byte-
#     identical output. Inputs are fixed constants (ATTEST_*) inside
#     scripts/harvest/harvest.zig.
#
# Dependencies:
#   - Zig matching the repo pin (see .zigversion). The harness uses
#     std.process.Init (0.16+).
#   - macOS or Linux. No extra crates, no network.
#
# Usage:
#   bash scripts/harvest-golden-vectors-phase8.sh
#   bash scripts/harvest-golden-vectors-phase8.sh /path/to/out

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-$ROOT_DIR/rust/tests/golden/phase8}"
HARVEST_SRC="$ROOT_DIR/scripts/harvest/harvest.zig"
BUNDLE_SRC="$ROOT_DIR/src/lib.zig"

if [ ! -f "$HARVEST_SRC" ]; then
  echo "harvest8: missing $HARVEST_SRC" >&2
  exit 1
fi
if [ ! -f "$BUNDLE_SRC" ]; then
  echo "harvest8: missing $BUNDLE_SRC (expected Zig lib root)" >&2
  exit 1
fi

if ! command -v zig >/dev/null 2>&1; then
  echo "harvest8: 'zig' not found on PATH" >&2
  exit 1
fi
EXPECTED_ZIG="$(cat "$ROOT_DIR/.zigversion" 2>/dev/null || echo unknown)"
ACTUAL_ZIG="$(zig version)"
if [ "$ACTUAL_ZIG" != "$EXPECTED_ZIG" ]; then
  echo "harvest8: WARNING zig version $ACTUAL_ZIG != pinned $EXPECTED_ZIG" >&2
fi

TARGET_FLAGS=()
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) TARGET_FLAGS=(-target aarch64-macos.14.0) ;;
      x86_64)        TARGET_FLAGS=(-target x86_64-macos.14.0) ;;
    esac
    ;;
esac

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

emit_vector() {
  local name="$1"
  local description="$2"
  local bin_path="$OUT_DIR/$name.json"   # JCS bytes are JSON; .json is a clearer extension
  local meta_path="$OUT_DIR/$name.meta.json"
  local err_path="$OUT_DIR/.$name.err"

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
    printf '  "bin": "%s.json",\n' "$name"
    printf '  "size": %s' "$size"
    if [ -n "$digest" ]; then
      printf ',\n  "blake3": "%s"' "$digest"
    fi
    printf '\n}\n'
  } >"$meta_path"

  printf '%s %s\n' "$name" "${digest:-unknown}"
}

MANIFEST="$OUT_DIR/MANIFEST.txt"
{
  echo "# Phase 8 golden vectors (deterministic)"
  echo "# Produced by scripts/harvest-golden-vectors-phase8.sh"
  echo "# Format: <name> <blake3-hex-of-bin-bytes>"
} >"$MANIFEST"

# Vector list. Keep in sync with scripts/harvest/harvest.zig::buildByName
# Phase 8 dispatch arms.
declare -a VECTORS=(
  "statement_basic|in-toto v1 Statement; commit subject 0xCC*32, predicate {} (JCS-canonical)"
  "envelope_basic|DSSE envelope wrapping statement_basic; one Ed25519 sig over PAE"
)

for entry in "${VECTORS[@]}"; do
  name="${entry%%|*}"
  desc="${entry#*|}"
  line="$(emit_vector "$name" "$desc")"
  echo "$line" >>"$MANIFEST"
done

echo "harvest8: wrote $(printf '%s\n' "${VECTORS[@]}" | wc -l | tr -d ' ') vectors to $OUT_DIR"
echo "harvest8: manifest:"
cat "$MANIFEST"
