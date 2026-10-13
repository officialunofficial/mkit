#!/usr/bin/env bash
# Real Git worktrees and Cargo metadata/clean; no dependency builds.
set -euo pipefail
scripts=$(cd "$(dirname "$0")/.." && pwd -P)
fixture=$(mktemp -d)
fixture=$(cd "$fixture" && pwd -P)
trap 'rm -rf "$fixture"' EXIT
export MKIT_BUILD_ROOT="$fixture/cache"
unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_BUILD_DIR
mkdir -p "$fixture/repo/rust/src"
cd "$fixture/repo"
git init -q -b main
git config user.name 'Test'
git config user.email 'test@example.invalid'
printf 'rust/target\n**/.cargo/config.toml\n' > .gitignore
printf '[package]\nname = "cache-fixture"\nversion = "0.1.0"\nedition = "2021"\n' > rust/Cargo.toml
printf 'pub fn fixture() {}\n' > rust/src/lib.rs
(cd rust && cargo generate-lockfile --offline)
git add .
git commit -qm 'test fixture'
for branch in merged dirty untracked active gone locked detached external symlink symlink-build tracked; do
    git worktree add -qb "$branch" "$fixture/$branch tree"
done
git -C "$fixture/detached tree" checkout -q --detach
printf 'changed\n' >> "$fixture/dirty tree/rust/src/lib.rs"
touch "$fixture/untracked tree/untracked"
printf '\n// active\n' >> "$fixture/active tree/rust/src/lib.rs"
git -C "$fixture/active tree" commit -qam 'active work'
printf '\n// abandoned\n' >> "$fixture/gone tree/rust/src/lib.rs"
git -C "$fixture/gone tree" commit -qam 'abandoned work'
git config remote.origin.url "$fixture/unused-remote"
git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
git update-ref refs/remotes/origin/gone gone
git branch --set-upstream-to origin/gone gone >/dev/null
git update-ref -d refs/remotes/origin/gone
git worktree lock "$fixture/locked tree"
# Metadata resolves the same per-worktree directory that real builds use.
eval "$(python3 "$scripts/local-build.py" env)"
for path in "$fixture/repo" "$fixture/"*' tree'; do
    mkdir -p "$path/rust/target"
    printf 'build output\n' > "$path/rust/target/sentinel"
    build=$(cd "$path/rust" && cargo metadata --offline --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["build_directory"])')
    mkdir -p "$build"
    printf 'intermediates\n' > "$build/sentinel"
done
# Configured shared targets and symlinks must not be followed.
mkdir -p "$fixture/shared" "$fixture/external tree/rust/.cargo"
printf 'keep\n' > "$fixture/shared/sentinel"
printf '[build]\ntarget-dir = "%s"\n' "$fixture/shared" > "$fixture/external tree/rust/.cargo/config.toml"
rm -rf "$fixture/symlink tree/rust/target"
ln -s "$fixture/shared" "$fixture/symlink tree/rust/target"
build=$(cd "$fixture/symlink-build tree/rust" && cargo metadata --offline --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["build_directory"])')
mkdir "$fixture/shared-build"
printf 'keep intermediates\n' > "$fixture/shared-build/sentinel"
rm "$build/sentinel"
rmdir "$build"
ln -s "$fixture/shared-build" "$build"
git -C "$fixture/tracked tree" add -f rust/target/sentinel
git -C "$fixture/tracked tree" commit -qm 'tracked output must stay'
git merge -q --no-edit tracked
# Safety skips return nonzero so an operator sees the unsafe configurations.
if python3 "$scripts/local-build.py" gc > "$fixture/dry" 2>&1; then
    echo 'expected unsafe output configurations to fail' >&2; exit 1
fi
cat "$fixture/dry"
grep -Fq "would clean $fixture/merged tree: merged" "$fixture/dry"
grep -Fq "would clean $fixture/gone tree: upstream branch gone" "$fixture/dry"
grep -Fq "skip $fixture/repo: main or current" "$fixture/dry"
grep -Fq "skip $fixture/dirty tree: uncommitted" "$fixture/dry"
grep -Fq "skip $fixture/untracked tree: uncommitted" "$fixture/dry"
grep -Fq "skip $fixture/active tree: branch is not merged" "$fixture/dry"
grep -Fq "skip $fixture/locked tree: locked" "$fixture/dry"
grep -Fq "skip $fixture/detached tree: detached" "$fixture/dry"
grep -Fq "skip $fixture/external tree: target directory is external" "$fixture/dry"
grep -Fq "skip $fixture/symlink tree: target directory is external" "$fixture/dry"
grep -Fq "skip $fixture/symlink-build tree: build directory is symlinked" "$fixture/dry"
grep -Fq "skip $fixture/tracked tree: target directory contains tracked" "$fixture/dry"
test -f "$fixture/merged tree/rust/target/sentinel"
# Ignore inherited shared targets and recheck the current worktree exclusion.
(cd "$fixture/merged tree" && python3 "$scripts/local-build.py" gc > "$fixture/current" 2>&1) || true
grep -Fq "skip $fixture/merged tree: main or current" "$fixture/current"
if CARGO_TARGET_DIR="$fixture/shared" python3 "$scripts/local-build.py" gc --apply > "$fixture/apply" 2>&1; then
    echo 'expected unsafe output configurations to fail' >&2; exit 1
fi
for branch in merged gone; do
    test ! -e "$fixture/$branch tree/rust/target/sentinel"
    build=$(cd "$fixture/$branch tree/rust" && cargo metadata --offline --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["build_directory"])')
    test ! -e "$build/sentinel"
    test -f "$fixture/$branch tree/rust/src/lib.rs"
    git show-ref --verify "refs/heads/$branch" >/dev/null
done
for branch in dirty untracked active locked detached external symlink symlink-build tracked; do
    test -f "$fixture/$branch tree/rust/target/sentinel"
done
test -f "$fixture/repo/rust/target/sentinel"
test -f "$fixture/shared/sentinel"
test -f "$fixture/shared-build/sentinel"
# Export quoting survives whitespace and single quotes.
export MKIT_BUILD_ROOT="$fixture/cache root's"
eval "$(python3 "$scripts/local-build.py" env)"
test "$CARGO_BUILD_BUILD_DIR" = "$MKIT_BUILD_ROOT/{workspace-path-hash}"
python=$(command -v python3)
mkdir "$fixture/empty-path"
if PATH="$fixture/empty-path" "$python" "$scripts/local-build.py" cargo check > "$fixture/missing" 2>&1; then
    echo 'missing sccache should fail' >&2; exit 1
fi
grep -Fq 'sccache is not on PATH' "$fixture/missing"
# Forward Cargo flags verbatim, including --help and arguments containing spaces.
mkdir "$fixture/bin"
cat > "$fixture/bin/cargo" <<'CARGO'
#!/bin/sh
printf '%s\n' "$@"
printf '%s\n' "$CARGO_BUILD_BUILD_DIR" "$RUSTC_WRAPPER" "$CARGO_INCREMENTAL"
pwd -P
CARGO
printf '#!/bin/sh\nexit 0\n' > "$fixture/bin/sccache"
chmod +x "$fixture/bin/cargo" "$fixture/bin/sccache"
PATH="$fixture/bin:$PATH" "$python" "$scripts/local-build.py" cargo check --help 'argument with spaces' > "$fixture/forwarded"
grep -Fxq -- '--help' "$fixture/forwarded"
grep -Fxq 'argument with spaces' "$fixture/forwarded"
grep -Fxq "$MKIT_BUILD_ROOT/{workspace-path-hash}" "$fixture/forwarded"
grep -Fxq "$fixture/bin/sccache" "$fixture/forwarded"
grep -Fxq '0' "$fixture/forwarded"
if PATH="$fixture/bin:$PATH" CARGO_TARGET_DIR="$fixture/shared" "$python" "$scripts/local-build.py" cargo check > "$fixture/target-error" 2>&1; then
    echo 'inherited target override should fail' >&2; exit 1
fi
grep -Fq 'never share targets' "$fixture/target-error"
# Guard coverage includes nested workspaces, legacy config, composite actions,
# quoted/dotted keys, CLI overrides, and environment assignments.
for file in rust/.cargo/config rust/.cargo/config.toml rust/.cargo/included.toml rust/Cargo.toml cloudbuild/Dockerfile.ci apps/test.Dockerfile .github/actions/test/action.yml cloudbuild/test.yaml; do
    for setting in 'build-dir = "cache"' 'build.build-dir="cache"' '"build-dir" = "cache"' 'CARGO_BUILD_BUILD_DIR=cache' 'MKIT_BUILD_ROOT=cache'; do
        mkdir -p "$(dirname "$file")"
        cp "$file" "$fixture/saved" 2>/dev/null || : > "$fixture/saved"
        printf '%s\n' "$setting" > "$file"
        git add -f "$file"
        if python3 "$scripts/check-build-dir-authority.py" --root . > "$fixture/guard" 2>&1; then
            echo "guard missed $file: $setting" >&2; exit 1
        fi
        grep -Fq "$file:1:" "$fixture/guard"
        cp "$fixture/saved" "$file"
        git add -f "$file"
    done
done
python3 "$scripts/check-build-dir-authority.py" --root .
echo 'ok: local build and worktree GC fixtures'
