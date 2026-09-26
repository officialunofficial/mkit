# Local CI parity. Each `ci-*` recipe is a literal extraction of commands
# already run by cloudbuild/ci.yaml / cloudbuild/security.yaml /
# cloudbuild/docs.yaml / cloudbuild/geiger.yaml / .github/workflows/rust.yml
# — no new logic lives here, so keep this file in sync with those when they
# change instead of letting it drift into a second source of truth.
#
# `ci-scripts` bundles script and wasm32 gates. cloudbuild/ci.yaml's
# `mkit-server` block (since WP-M0-20) runs its
# scripts/check-wasm-dep-graph.sh, scripts/check-cli-baseline.sh (the
# server-free CLI check), `cargo check --target wasm32-unknown-unknown` of
# mkit-server and the wasm32 build of mkit-server-worker, and docs-lint.yml
# runs its check-spec-status.sh. Still local-only until WP-REL mirrors them
# into the CI configs: the mkit-wasm wasm32 check, scripts/wasm-ruzstd-check.sh
# (mkit-core's pack-ruzstd decoder run on wasm32 under node via wasm-pack),
# the `pack-ruzstd` nextest run in ci-linux / ci-macos, and `interop-enc`.
# None of this is a 1:1 extract of web.yml (wasm-pack bundler + bun) or of
# workers.yml's worker wasm32 builds.
#
# Not mirrored (CI-infra-specific, not part of the test surface):
#   - cloudbuild/ci.yaml's swtpm/TPM harness (mkit-sign-tpm's real-device
#     test) and sccache/GCS wiring.
#   - cloudbuild/ci.yaml's apps/repo-worker and apps/keys-worker legs
#     (separate Cloudflare Workers builds, own toolchain/workspace,
#     including their wasm32 cargo builds).
#   - rust.yml's keystore-backends matrix (2-OS native keystore backends —
#     stays workflow_dispatch-only by design; run it on GitHub, not here).
#   - web.yml's wasm-pack bundler smoke and bun test/lint/build.
#
# Usage: `just ci` for the host-appropriate subset, or `just ci-linux` /
# `just ci-macos` / `just ci-security` / `just ci-docs` /
# `just ci-geiger` / `just ci-scripts` / `just ci-server` to check one
# gate in isolation.
# Windows is not a supported target (MKIT-6; see docs/INVARIANTS.md), so
# there is no `just ci-windows`.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Run the host-appropriate local CI subset.
ci:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ os() }}" in
      macos) just ci-macos ;;
      *)     just ci-linux ;;
    esac
    just ci-security
    just ci-docs
    just ci-geiger
    just ci-scripts
    just interop-enc

# Mirrors cloudbuild/ci.yaml's rust/ + contrib/signers/ steps.
ci-linux:
    #!/usr/bin/env bash
    set -euo pipefail
    ( cd rust && cargo fmt --check )
    ( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
    ( cd rust && cargo build --locked --workspace )
    ( cd contrib/signers && cargo fmt --check )
    ( cd contrib/signers && cargo clippy --locked --all-targets --all-features -- -D warnings )
    ( cd contrib/signers && cargo build --locked --all-features )
    ( cd contrib/signers && cargo nextest run --locked --all-features )
    ( cd rust && cargo nextest run --locked --workspace --all-features )
    # --all-features decodes through C zstd; this is the pure-Rust path.
    ( cd rust && cargo nextest run --locked -p mkit-core --no-default-features --features pack-ruzstd )
    ( cd rust && cargo nextest run --locked --workspace --all-features \
        --profile ignored-lane --run-ignored ignored-only )
    ( cd rust && cargo test --manifest-path fuzz/Cargo.toml )
    ( cd rust && cargo test --locked --doc --workspace )
    just _version-contract
    ( cd rust && cargo build --locked -p mkit-cli --features enc-transport )
    ( cd rust && cargo test --locked -p mkit-transport-enc --features tcp --no-fail-fast )
    # MSRV gate: cloudbuild/ci.yaml asserts the CI image's rustc matches
    # [workspace.package].rust-version, then runs this as the all-targets
    # check. Locally this just checks against whatever toolchain is active.
    ( cd rust && cargo check --workspace --locked --all-targets )

# Mirrors .github/workflows/rust.yml's `build-and-test` job (macOS leg).
ci-macos:
    #!/usr/bin/env bash
    set -euo pipefail
    ( cd rust && cargo fmt --check )
    ( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
    ( cd rust && cargo build --locked --workspace )
    ( cd contrib/signers && cargo fmt --check )
    ( cd contrib/signers && cargo clippy --locked --all-targets --all-features -- -D warnings )
    ( cd contrib/signers && cargo build --locked --all-features )
    ( cd contrib/signers && cargo nextest run --locked --all-features )
    # macOS runners always have `git` on PATH — MKIT_TEST_STRICT=1 makes
    # git-dependent tests fail loudly instead of silently skipping if it's
    # missing here too. See rust.yml's "Test (nextest)" step comment.
    ( cd rust && MKIT_TEST_STRICT=1 cargo nextest run --locked --workspace --all-features )
    # --all-features decodes through C zstd; this is the pure-Rust path.
    ( cd rust && cargo nextest run --locked -p mkit-core --no-default-features --features pack-ruzstd )
    ( cd rust && cargo nextest run --locked --workspace --all-features \
        --profile ignored-lane --run-ignored ignored-only )
    ( cd rust && cargo test --manifest-path fuzz/Cargo.toml )
    ( cd rust && cargo test --locked --doc --workspace )
    just _version-contract
    ( cd rust && cargo build --locked -p mkit-cli --features enc-transport )
    ( cd rust && cargo test --locked -p mkit-transport-enc --features tcp --no-fail-fast )

# Mirrors cloudbuild/security.yaml (cargo-audit + cargo-deny). Unlike its
# source (Linux-only, GNU grep), this target also runs on macOS, so the
# deadline extraction below uses `grep -oE` + `sed` instead of `grep -oP`
# (BSD grep has no -P) — same result, portable.
ci-security:
    #!/usr/bin/env bash
    set -euo pipefail
    deadline=$(grep -oE 'TODO\([0-9]{4}-[0-9]{2}-[0-9]{2}\)' rust/deny.toml | head -n1 | sed -E 's/TODO\(([0-9-]+)\)/\1/')
    if [ -z "$deadline" ]; then
      echo "ERROR: could not find a TODO(YYYY-MM-DD) deadline in rust/deny.toml for RUSTSEC-2023-0071" >&2
      exit 1
    fi
    today=$(date -u +%Y-%m-%d)
    if [[ "$today" > "$deadline" || "$today" == "$deadline" ]]; then
      echo "ERROR: RUSTSEC-2023-0071 ignore in rust/deny.toml expired on $deadline (today: $today)." >&2
      exit 1
    fi
    echo "RUSTSEC-2023-0071 ignore still valid until $deadline (today: $today)."
    run_audit() {
      cargo audit --deny warnings \
        --ignore RUSTSEC-2023-0071 \
        --ignore RUSTSEC-2024-0436 \
        --ignore RUSTSEC-2025-0055
    }
    ( cd rust && run_audit )
    ( cd contrib/signers && run_audit )
    ( cd contrib/interop/enc-client-0.4 && run_audit )
    cargo deny --manifest-path rust/Cargo.toml --all-features check
    cargo deny --manifest-path contrib/interop/enc-client-0.4/Cargo.toml --all-features \
      check --config rust/deny.toml

# Spec-status, wasm dep-graph, mkit-wasm / mkit-server wasm32 checks, and
# the pack-ruzstd wasm32 test run.
ci-scripts:
    #!/usr/bin/env bash
    set -euo pipefail
    bash scripts/check-spec-status.sh
    bash scripts/check-wasm-dep-graph.sh
    bash scripts/check-cli-baseline.sh
    if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
      echo "error: wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown" >&2
      exit 1
    fi
    ( cd rust && cargo check -p mkit-wasm --target wasm32-unknown-unknown )
    ( cd rust && cargo check --locked -p mkit-server --target wasm32-unknown-unknown )
    ( cd rust && cargo build --locked -p mkit-server-worker --target wasm32-unknown-unknown )
    bash scripts/wasm-ruzstd-check.sh

# The MKIT-29 M0 exit gate in one command (WP-M0-20): the mkit-server
# crates' tests (storage suite per backend, wire suite in-process and over
# the real binary), the wasm32 builds of the runtime-agnostic core and the
# Workers adapter, and the server-free CLI check. `just ci` already covers
# every step (the nextest run is a subset of ci-linux / ci-macos's
# workspace run; the rest is in ci-scripts), so `ci` does not call this
# recipe and run the server suites twice. In CI: cloudbuild/ci.yaml's
# workspace nextest and its mkit-server block (main and PRs to main only).
ci-server:
    #!/usr/bin/env bash
    set -euo pipefail
    ( cd rust && cargo nextest run --locked -p mkit-server -p mkit-server-native \
        -p mkit-server-conformance -p mkit-server-worker --all-features )
    ( cd rust && cargo check --locked -p mkit-server --target wasm32-unknown-unknown \
        && cargo build --locked -p mkit-server-worker --target wasm32-unknown-unknown )
    bash scripts/check-cli-baseline.sh

# The published mkit-transport-enc 0.4 client (crates.io) against this
# tree's `mkit-server serve --listen-enc` (contrib/interop/enc-client-0.4).
interop-enc:
    #!/usr/bin/env bash
    set -euo pipefail
    ( cd rust && cargo build --locked -p mkit-server-native --bin mkit-server )
    target="${CARGO_TARGET_DIR:-$PWD/rust/target}"
    ( cd contrib/interop/enc-client-0.4 && MKIT_SERVER_BIN="$target/debug/mkit-server" cargo test --locked )

# Mirrors cloudbuild/docs.yaml (rustdoc -D warnings).
ci-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    RUSTDOCFLAGS="-D warnings" bash -c '( cd rust && cargo doc --locked --all-features --workspace --no-deps )'
    RUSTDOCFLAGS="-D warnings" bash -c '( cd contrib/signers && cargo doc --locked --all-features --no-deps )'

# Mirrors cloudbuild/geiger.yaml (unsafe-code ceiling).
ci-geiger:
    bash scripts/check-geiger-baseline.sh

_version-contract:
    #!/usr/bin/env bash
    set -euo pipefail
    cd rust
    cargo build --release --locked -p mkit-cli
    out=$(./target/release/mkit version)
    expected="mkit $(awk -F\" '/^version/ {print $2; exit}' Cargo.toml)"
    echo "stdout:   [$out]"
    echo "expected: [$expected]"
    if [ "$out" != "$expected" ]; then
      echo "mkit version contract violated — stdout is not exactly 'mkit <X.Y.Z>'" >&2
      exit 1
    fi
