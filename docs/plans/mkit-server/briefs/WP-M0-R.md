> **DROPPED (adopted default Q11 = no).** The PRD's rollout keeps the demo stack (`repo-worker`, `keys-worker`,
> `workspace-worker`, `spammer-worker`) unchanged, so `apps/repo-worker`'s copies stay. This brief is kept for the
> record only; it is not in `registry.json` and must not be scheduled.

# WP-M0-R (conditional): Switch `apps/repo-worker`'s duplicated pure logic to `mkit-server`

- **Run only if** the user answers "yes" to overview **Q11**. The PRD §8 rollout says the demo stack (`repo-worker`,
  `keys-worker`, `workspace-worker`, `spammer-worker`) keeps using `mkit-worker-common` unchanged, while §8 M0 says
  to merge the duplicated quota and envelope code, which today exists only in `repo-worker` and `vcs-worker`.
- **Milestone/track:** M0 (optional)
- **Base:** `feat/mkit-server`; **branch:** `mkit-server/wp-m0-r-repo-worker-dedupe`
- **Depends on:** M0-04
- **Size:** S (~150–300 changed, mostly deletions)

## Conventions

Same as WP-M0-01. Worker gate:
`(cd apps/repo-worker && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --lib)`,
plus the wasm32 build (the codegen-freshness check builds it; also run `cargo build --target wasm32-unknown-unknown`).

## Goal

Replace `apps/repo-worker`'s copies of pure logic with the canonical `mkit-server` modules. Behavior and the
`mkit.repo.v1` wire don't change.

## Scope

**IN:** `apps/repo-worker/src/envelope.rs` (identical to vcs-worker's; use `mkit_server::auth_v2`),
`src/refs.rs` (the CAS decision and ref validation, keeping repo-worker-specific room validation local),
`src/write_quota.rs` (use `mkit_server::quota::evaluate_quota` with repo-worker's **own** limits, since its constants
may differ; `diff` shows ~95 differing lines, so read them first), `src/hashing.rs` (use `mkit_core::hash`), and
`src/storage_error.rs` (use `mkit_server::storage_error`, adding repo-worker-specific `StorageOp` variants only if
the generalized enum lacks them).

**OUT:** anything touching `mkit-worker-common`'s replay ledger or the repo-worker DO; keys-worker,
workspace-worker and spammer-worker.

## Files

- `apps/repo-worker/Cargo.toml`: `mkit-server = { path = "../../rust/crates/mkit-server", default-features = false }`
  (no `connect`: repo-worker has its own `mkit.repo.v1` codegen)
- Edit the five modules to be thin re-exports or adapters, and delete the duplicated tests (they live in
  `mkit-server` now). Keep any test that pins repo-worker-specific behavior (room rules, its quota constants).
- `scripts/check-wasm-dep-graph.sh`: the `apps/repo-worker` check already exists and must still pass.

## Tests to write first

- A test in repo-worker asserting its quota limits equal its previous constants (`WRITE_QUOTA_*` from the old
  `write_quota.rs`), so switching to the parameterized `evaluate_quota` can't silently change the numbers.
- Keep the existing repo-worker lib tests green.

## Acceptance criteria

- [ ] No duplicated CAS, quota, envelope or storage-error logic remains in repo-worker.
- [ ] The repo-worker wire and behavior are unchanged. Its lib tests pass, the wasm32 build passes, and the wasm
      dep-graph check passes.
- [ ] `mkit-worker-common` is untouched.

## Risks / gotchas

- repo-worker's quota is keyed per (room, author) and its limits may differ from vcs-worker's. Keep the keying local;
  only the arithmetic is shared.
