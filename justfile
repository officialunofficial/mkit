# Local CI parity. Each `ci-*` recipe is a literal extraction of commands
# already run by cloudbuild/ci.yaml / cloudbuild/security.yaml /
# cloudbuild/docs.yaml / cloudbuild/geiger.yaml / .github/workflows/rust.yml /
# .github/workflows/buf.yml
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
# ci-proto mirrors buf.yml's buf-action lint and breaking gates as CLI
# commands, followed by the same server-hook JSON script. Its baseline
# parameter reproduces the action's event-dependent comparison target.
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

# Mirrors .github/workflows/buf.yml: buf-action lint/breaking and its JSON step.
# Use the event's PR base or pre-push commit as baseline to match the action;
# origin/main is the local default, and the feature-branch gate overrides it.
ci-proto baseline="origin/main":
    buf lint
    buf breaking --against '.git#branch={{ baseline }}'
    bash scripts/check-server-hooks-goldens.sh
    python3 scripts/check-redaction-goldens.py
    bash scripts/check-server-admin-goldens.sh

# Spec-status, proto schema, wasm dep-graph, mkit-wasm / mkit-server wasm32 checks, and
# the pack-ruzstd wasm32 test run.
ci-scripts:
    #!/usr/bin/env bash
    set -euo pipefail
    bash scripts/check-spec-status.sh
    just ci-proto
    python3 scripts/golden/url_token_ref.py rust/tests/golden/url-token --no-b3sum
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

# ---------------------------------------------------------------------------
# Formal verification (docs/FORMAL.md, epic MKIT-17). Unlike the ci-*
# recipes above, these are the source: .github/workflows/formal.yml (nightly
# + workflow_dispatch) calls them, so change them here, not there. Every
# script prints one "<check> <expected outcome>" line per check and exits 1
# on any unexpected outcome (a holding invariant that should be violated
# counts, so a vacuous property fails the run).
#
#   just formal              PR-sized subset: formal-quint + formal-lean +
#                            formal-conformance
#   just formal-quint        every formal/quint/*/check.sh in its default
#                            mode (quint typecheck/test/run, plus TLC where
#                            the script runs it by default); `all` adds
#                            gc's TLC=1 runs
#   just formal-apalache     the bounded Apalache runs (APALACHE=1)
#   just formal-lean         lake build + both Lean difftests
#   just formal-kani         every Kani harness, one at a time (~1.5 h)
#   just formal-conformance  the MKIT-22 ITF replay (cargo test, offline)
#   just formal-fixtures     re-derive the MKIT-22 fixtures from the model
#                            and diff them (needs quint + jq)
#   just formal-setup-apalache  fetch + verify the pinned Apalache
#
# Tool pins (MKIT-17). Java 21 is also what TLC runs on: TLC is the
# tlc2.TLC class inside the Apalache jar, so formal-quint needs the
# Apalache install too. Lean comes from formal/lean/lean-toolchain via elan.
formal_quint_version := "0.32.0"
formal_apalache_version := "0.62.2"
formal_apalache_tgz_sha256 := "765f610537281a0f25b8c30f2554f19523e2859c824e80e62276653ee23c10e2"
formal_apalache_jar_sha256 := "079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8"
formal_java_version := "21"
formal_lean_toolchain_file := "formal/lean/lean-toolchain"
formal_kani_version := "0.68.0"

# PR-sized formal subset: Quint default mode, Lean, conformance replay.
formal: formal-quint formal-lean formal-conformance

# Fail early, with the fix, when a pinned tool is missing or off-pin.
_formal-pins *layers:
    #!/usr/bin/env bash
    set -euo pipefail
    fv=${FV_HOME:-$HOME/.local/share/mkit-fv}
    jar=${APALACHE_MC:-$fv/apalache-{{ formal_apalache_version }}/bin/apalache-mc}
    jar=$(dirname "$jar")/../lib/apalache.jar
    sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
    for layer in {{ layers }}; do
      case $layer in
        quint)
          qv=$(quint --version 2>/dev/null) || { echo "error: quint not on PATH (npm i -g @informalsystems/quint@{{ formal_quint_version }})" >&2; exit 2; }
          [[ $qv == {{ formal_quint_version }} ]] || { echo "error: quint $qv, pin is {{ formal_quint_version }}" >&2; exit 2; } ;;
        apalache)
          [[ -f $jar ]] || { echo "error: no Apalache at $jar (just formal-setup-apalache, or set FV_HOME / APALACHE_MC)" >&2; exit 2; }
          [[ $(sha256 "$jar") == {{ formal_apalache_jar_sha256 }} ]] ||
            { echo "error: $jar is not Apalache {{ formal_apalache_version }} (sha256 mismatch)" >&2; exit 2; } ;;
        lean)
          command -v lake >/dev/null || { echo "error: lake not on PATH (install elan; it reads {{ formal_lean_toolchain_file }})" >&2; exit 2; } ;;
        kani)
          kv=$(cargo kani --version 2>/dev/null) || { echo "error: cargo kani missing (cargo install --locked kani-verifier --version {{ formal_kani_version }} && cargo kani setup)" >&2; exit 2; }
          kv=${kv%%$'\n'*}
          [[ $kv == *" {{ formal_kani_version }} "* ]] || { echo "error: $kv, pin is Kani {{ formal_kani_version }}" >&2; exit 2; } ;;
      esac
    done
    # Java {{ formal_java_version }}: each check.sh finds it (JAVA_HOME, java_home -v 21,
    # Homebrew's openjdk@21) and exits 2 when it cannot.

# Checks both the release tarball's and the jar's sha256; a no-op when the
# verified jar is already there.
# Download the pinned Apalache into $FV_HOME.
formal-setup-apalache:
    #!/usr/bin/env bash
    set -euo pipefail
    fv=${FV_HOME:-$HOME/.local/share/mkit-fv}
    v={{ formal_apalache_version }}
    sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
    jar=$fv/apalache-$v/lib/apalache.jar
    if [[ -f $jar && $(sha256 "$jar") == {{ formal_apalache_jar_sha256 }} ]]; then
      echo "Apalache $v already at $fv/apalache-$v"; exit 0
    fi
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    curl -sSfL -o "$tmp/a.tgz" "https://github.com/apalache-mc/apalache/releases/download/v$v/apalache-$v.tgz"
    [[ $(sha256 "$tmp/a.tgz") == {{ formal_apalache_tgz_sha256 }} ]] ||
      { echo "error: apalache-$v.tgz sha256 mismatch" >&2; exit 1; }
    tar -xzf "$tmp/a.tgz" -C "$tmp"
    [[ $(sha256 "$tmp/apalache-$v/lib/apalache.jar") == {{ formal_apalache_jar_sha256 }} ]] ||
      { echo "error: apalache.jar sha256 mismatch" >&2; exit 1; }
    mkdir -p "$fv"; rm -rf "$fv/apalache-$v"; mv "$tmp/apalache-$v" "$fv/"
    echo "Apalache $v installed at $fv/apalache-$v"

# Runs every model even after a failure, then fails if any did. `just
# formal-quint all` also turns on the TLC runs a script leaves off by
# default (gc's exhaustive instances, ~50 min).
# Every formal/quint/*/check.sh in its default mode (quint, plus TLC where default).
formal-quint tlc="default": (_formal-pins "quint" "apalache")
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ tlc }}" in
      default) tlc= ;;
      all) tlc=TLC=1 ;;
      *) echo "formal-quint: tlc must be default or all" >&2; exit 2 ;;
    esac
    failed=()
    log=$(mktemp); trap 'rm -f "$log"' EXIT
    # A check.sh ends with "all checks as expected" or "<n> unexpected". A
    # non-zero exit without either line is an abort (set -e inside a helper
    # function, e.g. a failed `quint compile`), which the script cannot
    # report itself; say so instead of failing silently.
    _verdict() {
      if [[ $2 == 0 ]]; then return 0; fi
      if ! tail -n 1 "$log" | grep -Eq '^(all checks as expected|[0-9]+ unexpected)$'; then
        echo "=== $1 aborted (exit $2) before its verdict; last lines above" >&2
      fi
      return 1
    }
    for s in formal/quint/*/check.sh; do
      echo "=== $s (default mode${tlc:+, $tlc})"
      t0=$SECONDS
      rc=0; env -u APALACHE -u TLC -u QUINT -u ONLY -u SEL $tlc bash "$s" | tee "$log" || rc=$?
      _verdict "$s" "$rc" || failed+=("$s")
      echo "=== $s: $((SECONDS - t0)) s"
    done
    if (( ${#failed[@]} )); then echo "formal-quint: FAILED: ${failed[*]}" >&2; exit 1; fi

# Lengths are each script's defaults, overridable per script (GC_DEPTH,
# HISTORY_DEPTH, REFS_DEPTH, ...). QUINT=0 TLC=0 skip what formal-quint
# already covers where a script allows it (gc and history always re-run
# their quint tests; history also re-runs its TLC checks).
# Bounded Apalache runs of every Quint model (APALACHE=1).
formal-apalache: (_formal-pins "quint" "apalache")
    #!/usr/bin/env bash
    set -euo pipefail
    failed=()
    log=$(mktemp); trap 'rm -f "$log"' EXIT
    # A check.sh ends with "all checks as expected" or "<n> unexpected". A
    # non-zero exit without either line is an abort (set -e inside a helper
    # function, e.g. a failed `quint compile`), which the script cannot
    # report itself; say so instead of failing silently.
    _verdict() {
      if [[ $2 == 0 ]]; then return 0; fi
      if ! tail -n 1 "$log" | grep -Eq '^(all checks as expected|[0-9]+ unexpected)$'; then
        echo "=== $1 aborted (exit $2) before its verdict; last lines above" >&2
      fi
      return 1
    }
    for s in formal/quint/*/check.sh; do
      echo "=== $s (APALACHE=1)"
      t0=$SECONDS
      rc=0; APALACHE=1 QUINT=0 TLC=0 bash "$s" | tee "$log" || rc=$?
      _verdict "$s" "$rc" || failed+=("$s")
      echo "=== $s: $((SECONDS - t0)) s"
    done
    if (( ${#failed[@]} )); then echo "formal-apalache: FAILED: ${failed[*]}" >&2; exit 1; fi

# Each difftest re-runs the axiom audit and its canaries against
# Rust-exported vectors.
# Lean: lake build (proofs, canaries, #guard replays), then both difftests.
formal-lean: (_formal-pins "lean")
    #!/usr/bin/env bash
    set -euo pipefail
    want=$(cat {{ formal_lean_toolchain_file }})
    ( cd formal/lean && have=$(elan show active-toolchain 2>/dev/null | cut -d' ' -f1 || true) &&
      if [[ -n $have && $have != "$want" ]]; then echo "warning: elan reports $have, pin is $want" >&2; fi &&
      lake build )
    bash formal/lean/scripts/difftest-merkle.sh
    bash formal/lean/scripts/difftest-delta.sh

# One CBMC run at a time (peak ~5.4 GB). Harnesses are discovered from the
# #[kani::proof] items in the files formal/kani/README.md lists, so a new
# harness in one of them runs automatically; flags per that README's
# "Running". KANI_FILTER=regex restricts the run to matching harness names.
# Every Kani harness with its pinned flags (about 1.5 h).
formal-kani: (_formal-pins "kani")
    #!/usr/bin/env bash
    set -euo pipefail
    cd rust
    files="crates/mkit-core/src/delta.rs crates/mkit-core/src/merkle.rs crates/mkit-core/src/pack.rs
      crates/mkit-core/src/serialize.rs crates/mkit-keystore/src/encrypted_record.rs crates/mkit-rpc/src/framing.rs"
    harnesses() { awk '/#\[kani::proof\]/{p=1} p && /fn [a-z0-9_]+/{match($0,/fn [a-z0-9_]+/); print substr($0,RSTART+3,RLENGTH-3); p=0}' "$1"; }
    failed=() n=0
    run() { # label, then the cargo kani arguments
      local label=$1 t0=$SECONDS out; shift
      n=$((n + 1))
      if out=$(cargo kani "$@" 2>&1) && grep -q 'VERIFICATION:- SUCCESSFUL' <<<"$out" &&
         ! grep -q 'VERIFICATION:- FAILED' <<<"$out"; then
        printf '%-64s ok %ss\n' "$label" "$((SECONDS - t0))"
      else
        printf '%-64s UNEXPECTED %ss\n' "$label" "$((SECONDS - t0))"
        tail -n 40 <<<"$out"; failed+=("$label")
      fi
    }
    for f in $files; do
      crate=$(cut -d/ -f2 <<<"$f")
      for h in $(harnesses "$f"); do
        [[ -n ${KANI_FILTER:-} && ! $h =~ $KANI_FILTER ]] && continue
        case $crate:$h in
          mkit-core:merkle_verify_*|mkit-core:merkle_roundtrip_*|mkit-core:merkle_canary_*|mkit-core:pack_*)
            run "$crate::$h" -p "$crate" --no-default-features -Z stubbing --harness "$h" \
              -Z unstable-options --cbmc-args --unwindset memcmp.0:33 ;;
          mkit-core:*) run "$crate::$h" -p "$crate" --no-default-features -Z stubbing --harness "$h" ;;
          mkit-keystore:software_key_record_rejects_algorithm_4)
            run "$crate::$h" -p "$crate" -Z stubbing --harness "$h"
            run "$crate::$h (bls-threshold)" -p "$crate" --features bls-threshold -Z stubbing --harness "$h" ;;
          mkit-keystore:*) run "$crate::$h" -p "$crate" -Z stubbing --harness "$h" ;;
          *) run "$crate::$h" -p "$crate" --harness "$h" ;;
        esac
      done
    done
    echo "formal-kani: $n runs, ${#failed[@]} unexpected"
    if (( ${#failed[@]} )); then printf '  %s\n' "${failed[@]}" >&2; exit 1; fi

# Targets: mkit_core::refs, ops::recovery, FileTransport, MemoryTransport.
# MKIT-22: replay the checked-in refs_mbt.qnt ITF traces against the code.
formal-conformance:
    ( cd rust && cargo test --locked -p mkit-formal-conformance )

# A quint upgrade that reshuffles its RNG shows up here, not as a
# conformance failure.
# Re-derive the MKIT-22 fixtures with the pinned quint and diff them.
formal-fixtures: (_formal-pins "quint")
    CHECK=1 bash formal/scripts/gen-refs-traces.sh
