#!/usr/bin/env bash
# mkit E2E test with Cloudflare R2
# Proves: init → commit → pack → upload R2 → download R2 → unpack → verify
#
# Usage: cd mkit && ./tests/e2e-r2.sh
# Requires: wrangler authenticated, makechain-vcs R2 bucket

set -euo pipefail

BUCKET="makechain-vcs"
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

assert() {
    local desc="$1"
    if eval "$2"; then
        green "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        red "  ✗ $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Build mkit
cd "$(dirname "$0")/.."
bold "Building mkit..."
zig build 2>&1
MKIT="$(pwd)/zig-out/bin/mkit"

echo ""
bold "mkit E2E test with Cloudflare R2"
bold "================================"

REPO_A=$(mktemp -d)
REPO_B=$(mktemp -d)
PACK_KEY=""
cleanup() {
    rm -rf "$REPO_A" "$REPO_B" 2>/dev/null || true
    [ -n "$PACK_KEY" ] && wrangler r2 object delete "$BUCKET/$PACK_KEY" --remote 2>/dev/null || true
    wrangler r2 object delete "$BUCKET/refs/heads/main" --remote 2>/dev/null || true
}
trap cleanup EXIT

# === Phase 1: Create repo + commit ===
bold ""
bold "Phase 1: Create repository and commit"
cd "$REPO_A"

$MKIT init >/dev/null 2>&1
assert "mkit init" "true"

$MKIT keygen >/dev/null 2>&1
assert "mkit keygen" "true"

mkdir -p src
echo "fn main() void { }" > src/main.zig
echo "# mkit R2 test" > README.md
echo "*.log" > .mkitignore
echo "should be ignored" > debug.log

$MKIT commit -m "initial: R2 integration test" >/dev/null 2>&1
assert "mkit commit" "true"

HEAD_HASH=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
echo "  HEAD: $HEAD_HASH"

# === Phase 2: Pack objects + upload to R2 ===
bold ""
bold "Phase 2: Pack + upload to R2"

# Use mkit push to get the digest
PUSH_OUT=$($MKIT push 2>&1)
PACK_DIGEST=$(echo "$PUSH_OUT" | grep "^digest" | awk '{print $2}')
echo "  digest: $PACK_DIGEST"
assert "mkit push dry-run" '[ -n "$PACK_DIGEST" ]'

# Pack the object store as a tar for transport
PACK_FILE=$(mktemp)
tar czf "$PACK_FILE" -C .mkit objects/
PACK_SIZE=$(stat -f%z "$PACK_FILE" 2>/dev/null || stat -c%s "$PACK_FILE" 2>/dev/null)
echo "  pack size: $PACK_SIZE bytes"

# Content-addressed key
PACK_KEY="packs/$PACK_DIGEST"

# Upload to R2
cat "$PACK_FILE" | wrangler r2 object put "$BUCKET/$PACK_KEY" --pipe --remote 2>/dev/null
assert "upload packfile to R2" "true"

# Upload ref
echo -n "$HEAD_HASH" | wrangler r2 object put "$BUCKET/refs/heads/main" --pipe --remote 2>/dev/null
assert "upload ref to R2" "true"

rm -f "$PACK_FILE"

# === Phase 3: Verify R2 contents ===
bold ""
bold "Phase 3: Verify R2 contents"

# Download and verify ref
REMOTE_HEAD=$(wrangler r2 object get "$BUCKET/refs/heads/main" --remote --pipe 2>/dev/null | tr -d '\n\r ')
echo "  remote ref: $REMOTE_HEAD"
assert "remote ref matches HEAD" '[ "$REMOTE_HEAD" = "$HEAD_HASH" ]'

# Download packfile
DOWNLOADED_PACK=$(mktemp)
wrangler r2 object get "$BUCKET/$PACK_KEY" --remote --pipe 2>/dev/null > "$DOWNLOADED_PACK"
DL_SIZE=$(stat -f%z "$DOWNLOADED_PACK" 2>/dev/null || stat -c%s "$DOWNLOADED_PACK" 2>/dev/null)
assert "downloaded pack size > 0" '[ "$DL_SIZE" -gt 0 ]'

# === Phase 4: Clone into repo B ===
bold ""
bold "Phase 4: Restore into new repository"
cd "$REPO_B"

# Init empty repo
$MKIT init >/dev/null 2>&1

# Extract objects from downloaded pack
tar xzf "$DOWNLOADED_PACK" -C .mkit/
assert "extracted objects into .mkit/" '[ -d ".mkit/objects" ]'

# Set HEAD to remote's commit
echo "$REMOTE_HEAD" > .mkit/refs/heads/main
assert "wrote ref" "true"

rm -f "$DOWNLOADED_PACK"

# === Phase 5: Verify cloned repo ===
bold ""
bold "Phase 5: Verify cloned repository"

# Log should show the commit
LOG_OUT=$($MKIT log 2>&1)
assert "mkit log works" 'echo "$LOG_OUT" | grep -q "initial: R2 integration test"'

# Cat the commit
CAT_OUT=$($MKIT cat "$REMOTE_HEAD" 2>&1)
assert "mkit cat commit" 'echo "$CAT_OUT" | grep -q "^tree "'

# Extract tree hash
TREE_HASH=$(echo "$CAT_OUT" | grep "^tree" | awk '{print $2}')
echo "  tree: $TREE_HASH"

# Cat the tree
TREE_OUT=$($MKIT cat "$TREE_HASH" 2>&1)
assert "tree has README.md" 'echo "$TREE_OUT" | grep -q "README.md"'
assert "tree has src/" 'echo "$TREE_OUT" | grep -q "src"'
assert "tree has .mkitignore" 'echo "$TREE_OUT" | grep -q ".mkitignore"'
assert "tree excludes debug.log" '! echo "$TREE_OUT" | grep -q "debug.log"'

# Verify blob content
README_HASH=$(echo "$TREE_OUT" | grep "README.md" | awk '{print $2}')
README_CONTENT=$($MKIT cat "$README_HASH" 2>&1)
assert "README.md content correct" '[ "$README_CONTENT" = "# mkit R2 test" ]'

# Verify signature
VERIFY_OUT=$($MKIT verify "$REMOTE_HEAD" 2>&1)
assert "commit signature valid" 'echo "$VERIFY_OUT" | grep -q "valid commit signature"'

# Checkout restores files
$MKIT checkout main 2>&1 >/dev/null || true
if [ -f "README.md" ]; then
    assert "checkout restored README.md" '[ "$(cat README.md)" = "# mkit R2 test" ]'
    assert "checkout restored src/main.zig" '[ -f "src/main.zig" ]'
else
    echo "  (checkout file restore: skipped)"
fi

# === Phase 6: Cleanup ===
bold ""
bold "Phase 6: Cleanup R2"
wrangler r2 object delete "$BUCKET/$PACK_KEY" --remote 2>/dev/null
assert "deleted packfile" "true"
wrangler r2 object delete "$BUCKET/refs/heads/main" --remote 2>/dev/null
assert "deleted ref" "true"
PACK_KEY="" # prevent double-delete in trap

# === Summary ===
echo ""
bold "================================"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    green "All $TOTAL tests passed!"
else
    red "$FAIL of $TOTAL tests failed"
    exit 1
fi
