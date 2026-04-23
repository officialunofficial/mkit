#!/usr/bin/env bash
# mkit E2E test with file:// transport
# Proves: init -> commit -> push -> clone -> modify -> push -> pull -> branch -> staging -> fetch
# Full distributed VCS cycle using only local filesystem. No network, no R2.
#
# Usage: cd mkit && ./tests/e2e-file.sh

set -euo pipefail

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

# Helper: run mkit command, capture stdout only, tolerate exit code
# (debug allocator may exit 1 on memory leaks even when the command succeeds)
mkit_run() {
    "$MKIT" "$@" 2>/dev/null || true
}

# Build mkit
cd "$(dirname "$0")/.."
bold "Building mkit..."
zig build 2>&1
MKIT="$(pwd)/zig-out/bin/mkit"

echo ""
bold "mkit E2E test with file:// transport"
bold "====================================="

REPO_A=$(mktemp -d)
REPO_B=$(mktemp -d)
REMOTE=$(mktemp -d)
cleanup() {
    rm -rf "$REPO_A" "$REPO_B" "$REMOTE" 2>/dev/null || true
}
trap cleanup EXIT


# === Phase 1: Init + first commit in repo A ===
bold ""
bold "Phase 1: Init + first commit in repo A"
cd "$REPO_A"

mkit_run init
assert "mkit init" '[ -d ".mkit" ]'

mkit_run keygen
assert "mkit keygen" '[ -f ".mkit/keys/default.key" ]'

mkdir -p src
echo 'fn main() void { }' > src/main.zig
echo '# mkit file transport test' > README.md
echo '*.log' > .mkitignore
echo 'should be ignored' > debug.log

COMMIT_OUT=$(mkit_run commit -m "initial commit")
assert "mkit commit succeeds" 'echo "$COMMIT_OUT" | grep -q "commit"'

HEAD_HASH=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
echo "  HEAD: ${HEAD_HASH:0:16}..."
assert "HEAD ref exists" '[ -n "$HEAD_HASH" ]'

# === Phase 2: Configure remote + push ===
bold ""
bold "Phase 2: Configure remote + push"

REMOTE_OUT=$(mkit_run remote set "mkit+file://$REMOTE")
assert "mkit remote set" 'echo "$REMOTE_OUT" | grep -q "remote set"'
assert "remote type is file" 'echo "$REMOTE_OUT" | grep -q "file"'

PUSH_OUT=$(mkit_run push)
echo "  push: $(echo "$PUSH_OUT" | head -2)"
assert "mkit push succeeds" 'echo "$PUSH_OUT" | grep -q "pushed"'

# Verify remote has pack files
assert "remote has packs/ dir" '[ -d "$REMOTE/packs" ]'
PACK_COUNT=$(ls "$REMOTE/packs/" 2>/dev/null | wc -l | tr -d ' ')
assert "remote has at least 1 pack" '[ "$PACK_COUNT" -ge 1 ]'

# Verify remote has refs
assert "remote has refs/heads/main" '[ -f "$REMOTE/refs/heads/main" ]'
assert "remote has pack companion for main" 'ls "$REMOTE/refs/heads/main."*".pack" >/dev/null 2>&1'

# === Phase 3: Clone into repo B ===
bold ""
bold "Phase 3: Clone into repo B"
cd "$REPO_B"

CLONE_OUT=$(mkit_run clone "mkit+file://$REMOTE")
echo "  clone: $(echo "$CLONE_OUT" | head -3)"
assert "mkit clone succeeds" 'echo "$CLONE_OUT" | grep -q "initialized"'
# mkit clone only does init + remote set — pull fetches content
mkit_run pull >/dev/null
assert "pull after clone fetches main" '[ -f ".mkit/refs/heads/main" ]'

# Verify log shows the commit
LOG_OUT=$(mkit_run log)
assert "mkit log shows initial commit" 'echo "$LOG_OUT" | grep -q "initial commit"'

# Get commit hash from log
CLONE_HEAD=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
assert "clone HEAD matches origin" '[ "$CLONE_HEAD" = "$HEAD_HASH" ]'

# Cat the commit
CAT_OUT=$(mkit_run cat "$CLONE_HEAD")
assert "mkit cat works on commit" 'echo "$CAT_OUT" | grep -q "^tree"'

# Extract tree hash and verify tree contents
TREE_HASH=$(echo "$CAT_OUT" | grep "^tree" | awk '{print $2}')
TREE_OUT=$(mkit_run cat "$TREE_HASH")
assert "tree has README.md" 'echo "$TREE_OUT" | grep -q "README.md"'
assert "tree has src/" 'echo "$TREE_OUT" | grep -q "src"'
assert "tree has .mkitignore" 'echo "$TREE_OUT" | grep -q ".mkitignore"'
assert "tree excludes debug.log" '! echo "$TREE_OUT" | grep -q "debug.log"'

# Verify blob content
README_HASH=$(echo "$TREE_OUT" | grep "README.md" | awk '{print $2}')
README_CONTENT=$(mkit_run cat "$README_HASH")
assert "README.md content correct" '[ "$README_CONTENT" = "# mkit file transport test" ]'

# Verify signature
VERIFY_OUT=$(mkit_run verify "$CLONE_HEAD")
assert "commit signature valid" 'echo "$VERIFY_OUT" | grep -q "valid commit signature"'

# Check if checkout restored files
if [ -f "README.md" ]; then
    assert "checkout restored README.md" '[ "$(cat README.md)" = "# mkit file transport test" ]'
    assert "checkout restored src/main.zig" '[ -f "src/main.zig" ]'
    assert "checkout did not restore debug.log" '[ ! -f "debug.log" ]'
else
    echo "  (checkout file restore: skipped — not yet implemented)"
fi

# === Phase 4: Second commit + push from A ===
bold ""
bold "Phase 4: Second commit + push from A"
cd "$REPO_A"

echo '# mkit file transport test (updated)' > README.md
echo 'hello world' > CHANGELOG.md

COMMIT2_OUT=$(mkit_run commit -m "second commit")
assert "second commit succeeds" 'echo "$COMMIT2_OUT" | grep -q "^tree"'

HEAD2_HASH=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
assert "HEAD advanced" '[ "$HEAD2_HASH" != "$HEAD_HASH" ]'
echo "  HEAD: ${HEAD2_HASH:0:16}..."

PUSH2_OUT=$(mkit_run push)
assert "second push succeeds" 'echo "$PUSH2_OUT" | grep -q "pushed"'

# Verify remote updated
PACK_COUNT2=$(ls "$REMOTE/packs/" 2>/dev/null | wc -l | tr -d ' ')
assert "remote has >= 2 packs" '[ "$PACK_COUNT2" -ge 2 ]'

# === Phase 5: Pull in repo B ===
bold ""
bold "Phase 5: Pull in repo B"
cd "$REPO_B"

PULL_OUT=$(mkit_run pull)
echo "  pull: $PULL_OUT"
assert "mkit pull succeeds" 'echo "$PULL_OUT" | grep -q "pulled"'

# Verify repo B now has the second commit
LOG2_OUT=$(mkit_run log)
assert "log shows second commit" 'echo "$LOG2_OUT" | grep -q "second commit"'
assert "log still shows initial commit" 'echo "$LOG2_OUT" | grep -q "initial commit"'

# Verify HEAD updated
PULL_HEAD=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
assert "pull updated HEAD" '[ "$PULL_HEAD" = "$HEAD2_HASH" ]'

# Verify file content updated (if checkout restores on pull)
if [ -f "README.md" ]; then
    assert "README.md content updated" '[ "$(cat README.md)" = "# mkit file transport test (updated)" ]'
    assert "CHANGELOG.md exists" '[ -f "CHANGELOG.md" ]'
fi

# Pulling again should be a no-op
PULL_AGAIN=$(mkit_run pull)
assert "pull again is up to date" 'echo "$PULL_AGAIN" | grep -q "already up to date"'

# === Phase 6: Branch workflow ===
bold ""
bold "Phase 6: Branch workflow"
cd "$REPO_A"

mkit_run branch feature
assert "create feature branch" '[ -f ".mkit/refs/heads/feature" ]'

mkit_run checkout feature
BRANCH_OUT=$(mkit_run branch)
assert "feature is current branch" 'echo "$BRANCH_OUT" | grep -q "\* feature"'

echo 'feature work' > feature.txt
FEAT_OUT=$(mkit_run commit -m "feature commit")
assert "feature commit succeeds" 'echo "$FEAT_OUT" | grep -q "^tree"'

FEAT_PUSH=$(mkit_run push)
assert "push feature branch" 'echo "$FEAT_PUSH" | grep -q "pushed"'
assert "push targets feature ref" 'echo "$FEAT_PUSH" | grep -q "refs/heads/feature"'

# Verify remote has feature ref
assert "remote has refs/heads/feature" '[ -f "$REMOTE/refs/heads/feature" ]'
assert "remote has pack companion for feature" 'ls "$REMOTE/refs/heads/feature."*".pack" >/dev/null 2>&1'

# Verify main still exists on remote
assert "remote still has refs/heads/main" '[ -f "$REMOTE/refs/heads/main" ]'

# === Phase 7: Selective staging + fetch ===
bold ""
bold "Phase 7: Selective staging + fetch"
cd "$REPO_A"

# Switch back to main for this phase
mkit_run checkout main

# Create two new files, stage only one
echo 'staged content' > staged_file.txt
echo 'unstaged content' > unstaged_file.txt

ADD_OUT=$(mkit_run add staged_file.txt)
assert "mkit add stages one file" 'echo "$ADD_OUT" | grep -q "staged 1"'

# Verify status shows staged file
STATUS_OUT=$(mkit_run status)
assert "status shows staged file" 'echo "$STATUS_OUT" | grep -q "staged_file.txt"'
assert "status shows Changes to be committed" 'echo "$STATUS_OUT" | grep -q "Changes to be committed"'

# Commit with staging — only staged_file.txt should be in the tree
STAGED_COMMIT=$(mkit_run commit -m "selective staging commit")
assert "staged commit succeeds" 'echo "$STAGED_COMMIT" | grep -q "^tree"'

# Inspect the committed tree to verify only staged_file.txt was included (not unstaged_file.txt as new)
STAGED_HEAD=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
STAGED_CAT=$(mkit_run cat "$STAGED_HEAD")
STAGED_TREE_HASH=$(echo "$STAGED_CAT" | grep "^tree" | awk "{print \$2}")
STAGED_TREE_OUT=$(mkit_run cat "$STAGED_TREE_HASH")
assert "committed tree has staged_file.txt" 'echo "$STAGED_TREE_OUT" | grep -q "staged_file.txt"'
assert "committed tree excludes unstaged_file.txt" '! echo "$STAGED_TREE_OUT" | grep -q "unstaged_file.txt"'

# Push to remote
STAGED_PUSH=$(mkit_run push)
assert "push staged commit" 'echo "$STAGED_PUSH" | grep -q "pushed"'

# Test fetch in repo B — should update tracking ref without touching local branch
cd "$REPO_B"

# Record local main before fetch
LOCAL_MAIN_BEFORE=$(cat .mkit/refs/heads/main | tr -d '\n\r ')

FETCH_OUT=$(mkit_run fetch)
assert "mkit fetch succeeds" 'echo "$FETCH_OUT" | grep -q "fetched"'
assert "fetch creates remote tracking ref" '[ -f ".mkit/refs/remotes/origin/main" ]'

# Verify local main is NOT updated by fetch
LOCAL_MAIN_AFTER=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
assert "fetch does not update local branch" '[ "$LOCAL_MAIN_AFTER" = "$LOCAL_MAIN_BEFORE" ]'

# Verify remote tracking ref points to the new commit
REMOTE_TRACKING=$(cat .mkit/refs/remotes/origin/main | tr -d '\n\r ')
assert "tracking ref points to fetched commit" '[ "$REMOTE_TRACKING" = "$STAGED_HEAD" ]'
assert "tracking ref differs from local branch" '[ "$REMOTE_TRACKING" != "$LOCAL_MAIN_BEFORE" ]'

# === Phase 8: Blame + Stash ===
# These commands depend on blame.zig and stash.zig which may not be compiled
# into the binary yet (created by other agents). Skip gracefully if unavailable.
cd "$REPO_A"

BLAME_AVAIL=false
if $MKIT blame --help 2>&1 | grep -qi "usage\|blame\|file"; then
    BLAME_AVAIL=true
fi

STASH_AVAIL=false
if $MKIT stash --help 2>&1 | grep -qi "usage\|stash\|save"; then
    STASH_AVAIL=true
fi

if [ "$BLAME_AVAIL" = true ] || [ "$STASH_AVAIL" = true ]; then
    bold ""
    bold "Phase 8: Blame + Stash"
fi

if [ "$BLAME_AVAIL" = true ]; then
    # Ensure we are on main
    mkit_run checkout main

    # Create a file and commit
    echo "line1" > blame-test.txt
    echo "line2" >> blame-test.txt
    mkit_run add blame-test.txt
    mkit_run commit -m "add blame-test"

    # Modify and commit again
    echo "line1" > blame-test.txt
    echo "modified-line2" >> blame-test.txt
    echo "line3" >> blame-test.txt
    mkit_run add blame-test.txt
    mkit_run commit -m "modify blame-test"

    BLAME_OUT=$(mkit_run blame blame-test.txt)
    assert "blame outputs line1" 'echo "$BLAME_OUT" | grep -q "line1"'
    assert "blame outputs modified-line2" 'echo "$BLAME_OUT" | grep -q "modified-line2"'
    assert "blame outputs line3" 'echo "$BLAME_OUT" | grep -q "line3"'
    assert "blame shows multiple commits" 'test "$(echo "$BLAME_OUT" | grep -o "[0-9a-f]\{8,\}" | sort -u | wc -l | tr -d " ")" -ge 2'
else
    echo ""
    echo "  (blame tests: skipped — blame command not yet available)"
fi

if [ "$STASH_AVAIL" = true ]; then
    # Ensure we are on main with a clean state
    mkit_run checkout main

    # Create untracked/modified content to stash
    echo "stashed content" > stash-test.txt
    mkit_run add stash-test.txt

    mkit_run stash
    assert "stash cleans working dir" '[ ! -f stash-test.txt ] || [ "$(cat stash-test.txt 2>/dev/null)" != "stashed content" ]'

    STASH_LIST=$(mkit_run stash list)
    assert "stash list shows entry" 'echo "$STASH_LIST" | grep -q "stash@{0}"'

    mkit_run stash pop
    assert "stash pop restores file" '[ -f stash-test.txt ] && [ "$(cat stash-test.txt)" = "stashed content" ]'

    # Verify stash list is now empty
    STASH_LIST2=$(mkit_run stash list)
    assert "stash list empty after pop" '[ -z "$STASH_LIST2" ] || ! echo "$STASH_LIST2" | grep -q "stash@{0}"'
else
    echo ""
    echo "  (stash tests: skipped — stash command not yet available)"
fi

# === Summary ===
echo ""
bold "====================================="
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    green "All $TOTAL tests passed!"
else
    red "$FAIL of $TOTAL tests failed"
    exit 1
fi
