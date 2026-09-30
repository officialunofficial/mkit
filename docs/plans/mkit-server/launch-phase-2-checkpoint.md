# WP-4.18 phase 2 implementation checkpoint

Status: **implementation checkpoint; sandbox access restored;
complete launch matrix UNRUN; no PR opened**. This is a retained work record,
not a passing gate or permission waiver.

Last committed launch head: `7a2d1bf039e0853fb53d5e8e78d4d449782196ca`.
It merges `origin/feat/mkit-server` with physical timer-alarm repair #1247 at
`e45def2fe1855a531d0149727bf6678fc8145c3c` and native timer-conformance repair
#1248 at `12e4ce4998145a959c4fc400e02b6ad546812090`.
No old native timer flake exception applies to the pending rerun.

## Implemented in the worktree

- Combined `NsObjectBuilder` configuration, published snapshots, custom
  Outcome factory and actual `PurgeSink`/`LocalInvalidation` registration.
  Verification uses the same explicit configuration and blob binding.
- Programmatic ref-policy validation, takedown denial, custom-purge parsing
  before startup validation, host-only admin placement and authenticated
  `serve_admin_with`. Custom purge delivery requires Paid alarm capacity.
- `durable_objects!` exports all five classes with a scoped workers-rs
  wasm-bindgen import. The reference Worker and embedded example use it.
- Streamed in-process example with custom service-binding hooks, a local
  release Wrangler probe, its lockfile and explicit wasm CI check.
- Supported 0.x embedding documentation, reserved prefixes, audience/resource
  contracts, #1246 ref-file headers and updated timer prerequisite records.
  The size table remains unmeasured. The current platform limit is linked
  to official Cloudflare documentation; gzip is informational.

Preservation startup refusal remains. Complete preservation/admin/takedown
integration, the integrated native/release runtime matrix, measured wasm/bundle
sizes, final full gates and two independent final reviews remain required.

## Checks at the dirty source checkpoint (2026-09-30)

All Cargo invocations use debug level zero, the worktree's own target and
`TMPDIR=$HOME/.cache/mkit-test-tmp/wp-4-18`, as mandated by the executor rules.
`ulimit -n 4096` applies to compilation commands. These are targeted checks,
not the final workspace gates.

| Directory | Exact command | Result |
|---|---|---|
| `rust/` | `cargo fmt --all --check` | PASS |
| `rust/` | `cargo clippy --locked --offline -p mkit-server-worker -p mkit-server --all-targets --all-features --no-deps -- -D warnings` | PASS; includes compilation of new host regression tests |
| `rust/` | `cargo clippy --locked --offline -p mkit-server-worker --features http-objects,published-view,signed-http-hooks --no-deps --target wasm32-unknown-unknown -- -D warnings` | PASS |
| `apps/vcs-worker/` | `cargo clippy --locked --offline --target wasm32-unknown-unknown --features launch -- -D warnings` | PASS; generated DO classes expand across crates |
| `apps/embedded-worker/` | `cargo metadata --offline --format-version 1` | PASS; generated dedicated lockfile |
| `apps/embedded-worker/` | `cargo fmt --check` | PASS |
| `apps/embedded-worker/` | `cargo clippy --locked --offline --target wasm32-unknown-unknown -- -D warnings` | PASS; custom factory macro expansion |
| Repository | `git diff --check` | PASS |
| Repository | `python3 scripts/vcs-worker-launch.py validate` | PASS; 23-case inventory, no runtime PASS implied |
| Repository | `bash -n scripts/embedded-worker-conformance.sh` | PASS |
| Repository | Python AST parse of `scripts/embedded-worker-conformance.py` | PASS |
| Repository | `node --check apps/embedded-worker/tests/hook/worker.mjs` | PASS |

The new owned Rust diff has a conservative upper bound of 2,065 added tracked
Rust lines including tests, plus the small new embedded app. This is below the
3,500 non-test production-line cap; finalize the exact production count at
the final candidate.

## Historical blocked execution, without flake classification

The requested focused rerun was attempted from `rust/`:

```sh
cargo nextest run --locked --offline \
  -p mkit-server -p mkit-server-native -p mkit-server-worker \
  --all-features --lib \
  -E 'test(timers::) | test(alarm::) | test(publication_recheck) | test(timer_window)' \
  --test-threads 1
```

It exited 101 while linking core/native/Worker test binaries. No tests ran.
The linker reported `clang: error: unable to make temporary file: Operation
not permitted`. A separate release-feature embedding test attempt also exited
101 with the same linker denial. No timer assertion failure was observed and
no failure is classified as a flake. Native timer integration and wire timer
checks still require execution, followed by actual release Worker alarm checks.

The sandbox also denied Git staging with:

```text
fatal: Unable to create '.../mkit/.git/worktrees/wp-4-18/index.lock': Operation not permitted
```

Some earlier edits were staged before this denial; later edits and new files
remain unstaged. Preserve both. The branch cannot be committed/pushed under
the current permissions. Required scratch logs cannot be created in their
mandated cache path; command diagnostics are retained in the execution
transcript. Restore Git and scratch-directory writes, then commit this
checkpoint, rerun the blocked checks and continue phase 2. Do not relocate
mandated scratch files, apply old timer exceptions or open a PR with an
incomplete local matrix.

## Permission restoration

The user restored unrestricted filesystem/network access. A real scratch-file
write/delete and Git staging succeeded. The previously blocked timer/alarm
rerun and native embedding tests are being repeated at the saved implementation
checkpoint. Historical linker failures above are environment failures, not
accepted timer exceptions. Fresh results must replace the UNRUN matrix slots
only after actual execution.
