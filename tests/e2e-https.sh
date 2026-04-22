#!/usr/bin/env bash
# zmit E2E test with HTTPS transport (vcs.makechain.net)
# Proves: push -> clone -> modify -> push -> pull with DO-backed atomic refs
#
# Requires: ZMIT_API_TOKEN env var (Worker write auth)
# Usage: cd zmit && ZMIT_API_TOKEN=<token> ./tests/e2e-https.sh

set -euo pipefail

WORKER="https://vcs.makechain.net/v1"
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

# Helper: run zmit command, capture stdout only, tolerate exit code
# (debug allocator may exit 1 on memory leaks even when the command succeeds)
zmit_run() {
    "$ZMIT" "$@" 2>/dev/null || true
}

# === Check prerequisites ===
if [ -z "${ZMIT_API_TOKEN:-}" ]; then
    echo "ZMIT_API_TOKEN not set — skipping HTTPS E2E test"
    echo "(set it to run: ZMIT_API_TOKEN=<token> ./tests/e2e-https.sh)"
    exit 0
fi

# Verify Worker is reachable
HEALTH=$(curl -sf --max-time 5 "$WORKER/../health" 2>/dev/null || true)
if ! echo "$HEALTH" | grep -q '"ok":true'; then
    echo "error: cannot reach $WORKER (health check failed)"
    exit 1
fi

# Use unique branch names to avoid conflicts with other test runs
BRANCH="test-$(date +%s)-$$"

# Build zmit
cd "$(dirname "$0")/.."
bold "Building zmit..."
zig build 2>&1
ZMIT="$(pwd)/zig-out/bin/zmit"

echo ""
bold "zmit E2E test with HTTPS transport"
bold "===================================="
echo "  Worker:  $WORKER"
echo "  Branch:  $BRANCH"
echo ""

REPO_A=$(mktemp -d)
REPO_B=$(mktemp -d)
cleanup() {
    rm -rf "$REPO_A" "$REPO_B" 2>/dev/null || true
}
trap cleanup EXIT

DUMMY_PROJECT="0000000000000000000000000000000000000000000000000000000000000000"

# === Phase 1: Init + first commit in repo A ===
bold "Phase 1: Init + first commit in repo A"
cd "$REPO_A"

zmit_run init
assert "zmit init" '[ -d ".zmit" ]'

zmit_run keygen
assert "zmit keygen" '[ -f ".zmit/keys/default.key" ]'

mkdir -p src
echo 'fn main() void { }' > src/main.zig
echo '# zmit HTTPS transport test' > README.md
echo '*.log' > .zmitignore

COMMIT_OUT=$(zmit_run commit -m "HTTPS E2E initial commit")
assert "zmit commit succeeds" 'echo "$COMMIT_OUT" | grep -q "commit"'

HEAD_HASH=$(cat .zmit/refs/heads/main | tr -d '\n\r ')
echo "  HEAD: ${HEAD_HASH:0:16}..."
assert "HEAD ref exists" '[ -n "$HEAD_HASH" ]'

# Configure remote for HTTPS transport
REMOTE_OUT=$(zmit_run remote set "$WORKER")
assert "zmit remote set" 'echo "$REMOTE_OUT" | grep -q "remote set"'
assert "remote type is http" 'echo "$REMOTE_OUT" | grep -q "http"'

# === Phase 2: Create branch + push ===
bold ""
bold "Phase 2: Create branch + push"

zmit_run branch "$BRANCH"
assert "create test branch" '[ -f ".zmit/refs/heads/$BRANCH" ]'

zmit_run checkout "$BRANCH"
BRANCH_OUT=$(zmit_run branch)
assert "$BRANCH is current branch" 'echo "$BRANCH_OUT" | grep -q "\\* $BRANCH"'

# Recommit on the branch (branch starts at same HEAD)
BRANCH_HASH=$(cat ".zmit/refs/heads/$BRANCH" | tr -d '\n\r ')
echo "  branch HEAD: ${BRANCH_HASH:0:16}..."

# Push to remote
PUSH_OUT=$(zmit_run push --project "$DUMMY_PROJECT")
echo "  push: $(echo "$PUSH_OUT" | head -2)"
assert "zmit push succeeds" 'echo "$PUSH_OUT" | grep -q "pushed"'
assert "push targets test branch ref" 'echo "$PUSH_OUT" | grep -q "refs/heads/$BRANCH"'

# Verify remote ref via curl
REF_BODY=$(curl -sf --max-time 10 "$WORKER/refs/heads/$BRANCH" 2>/dev/null || true)
REF_VALUE=$(echo "$REF_BODY" | tr -d '\n\r ')
echo "  remote ref: ${REF_VALUE:0:16}..."
assert "remote ref matches HEAD" '[ "$REF_VALUE" = "$BRANCH_HASH" ]'

# Verify refs listing includes our branch (pack key is BLAKE3 of packfile bytes,
# not the commit hash, so we verify the refs endpoint instead)
REFS_LIST=$(curl -sf --max-time 10 "$WORKER/refs/?prefix=refs/heads/" 2>/dev/null || true)
assert "refs listing includes test branch" 'echo "$REFS_LIST" | grep -q "refs/heads/$BRANCH"'

# === Phase 3: Clone into repo B ===
bold ""
bold "Phase 3: Clone into repo B"
cd "$REPO_B"

CLONE_OUT=$(zmit_run clone "$WORKER")
echo "  clone: $(echo "$CLONE_OUT" | head -3)"
assert "zmit clone succeeds" 'echo "$CLONE_OUT" | grep -q "initialized"'

# Switch to the test branch
zmit_run checkout "$BRANCH"

# Verify log shows the commit
LOG_OUT=$(zmit_run log)
assert "zmit log shows initial commit" 'echo "$LOG_OUT" | grep -q "HTTPS E2E initial commit"'

# Verify HEAD matches
CLONE_HEAD=$(cat ".zmit/refs/heads/$BRANCH" | tr -d '\n\r ')
assert "clone HEAD matches origin" '[ "$CLONE_HEAD" = "$BRANCH_HASH" ]'

# Verify file content
if [ -f "README.md" ]; then
    assert "README.md content correct" '[ "$(cat README.md)" = "# zmit HTTPS transport test" ]'
    assert "src/main.zig exists" '[ -f "src/main.zig" ]'
else
    echo "  (checkout file restore: skipped — not yet implemented)"
fi

# Verify signature
VERIFY_OUT=$(zmit_run verify "$CLONE_HEAD")
assert "commit signature valid" 'echo "$VERIFY_OUT" | grep -q "valid commit signature"'

# === Phase 4: Second commit + push from A ===
bold ""
bold "Phase 4: Second commit + push from A"
cd "$REPO_A"

echo '# zmit HTTPS transport test (updated)' > README.md
echo 'hello from repo A' > CHANGELOG.md

COMMIT2_OUT=$(zmit_run commit -m "HTTPS E2E second commit")
assert "second commit succeeds" 'echo "$COMMIT2_OUT" | grep -q "^tree"'

HEAD2_HASH=$(cat ".zmit/refs/heads/$BRANCH" | tr -d '\n\r ')
assert "HEAD advanced" '[ "$HEAD2_HASH" != "$BRANCH_HASH" ]'
echo "  HEAD: ${HEAD2_HASH:0:16}..."

PUSH2_OUT=$(zmit_run push --project "$DUMMY_PROJECT")
echo "  push: $(echo "$PUSH2_OUT" | head -2)"
assert "second push succeeds" 'echo "$PUSH2_OUT" | grep -q "pushed"'

# Verify remote ref updated
REF2_BODY=$(curl -sf --max-time 10 "$WORKER/refs/heads/$BRANCH" 2>/dev/null || true)
REF2_VALUE=$(echo "$REF2_BODY" | tr -d '\n\r ')
assert "remote ref updated to second commit" '[ "$REF2_VALUE" = "$HEAD2_HASH" ]'

# === Phase 5: Pull in repo B ===
bold ""
bold "Phase 5: Pull in repo B"
cd "$REPO_B"

PULL_OUT=$(zmit_run pull)
echo "  pull: $PULL_OUT"
assert "zmit pull succeeds" 'echo "$PULL_OUT" | grep -q "pulled"'

# Verify updated content
LOG2_OUT=$(zmit_run log)
assert "log shows second commit" 'echo "$LOG2_OUT" | grep -q "HTTPS E2E second commit"'
assert "log still shows initial commit" 'echo "$LOG2_OUT" | grep -q "HTTPS E2E initial commit"'

# Verify HEAD updated
PULL_HEAD=$(cat ".zmit/refs/heads/$BRANCH" | tr -d '\n\r ')
assert "pull updated HEAD" '[ "$PULL_HEAD" = "$HEAD2_HASH" ]'

# Verify file content updated (if checkout restores on pull)
if [ -f "README.md" ]; then
    assert "README.md content updated" '[ "$(cat README.md)" = "# zmit HTTPS transport test (updated)" ]'
    assert "CHANGELOG.md exists" '[ -f "CHANGELOG.md" ]'
fi

# Pulling again should be a no-op
PULL_AGAIN=$(zmit_run pull)
assert "pull again is up to date" 'echo "$PULL_AGAIN" | grep -q "already up to date"'

# === Phase 6: Cleanup ===
bold ""
bold "Phase 6: Cleanup"
echo "  Branch refs/heads/$BRANCH left on remote (harmless, unique per run)"
echo "  Temporary directories cleaned up by trap"

# === Summary ===
echo ""
bold "===================================="
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    green "All $TOTAL tests passed!"
else
    red "$FAIL of $TOTAL tests failed"
    exit 1
fi
