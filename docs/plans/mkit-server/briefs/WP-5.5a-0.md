## Purpose

Build the storage pieces of 5.5a's hold authority, tested but **not wired** into the pipeline or the read surfaces.
5.5a then only integrates them.

## A. Fixed

- SPEC-SERVER §11.2 and §11.3;
- the 100-op / 1 MiB batch limits;
- `NamespaceStore` semantics: `get_many` and `scan_many` are sequential by default, and only `apply` is atomic;
- Single and D34 must have identical semantics;
- no pre-launch compatibility.

## B. Decided

1. **Durable inspection mode marker**, modeled exactly on the sharding and addressing markers (`sm`/`am`):
   - the Worker side mirrors `mkit-server-worker/src/sharding_guard.rs` (`check_mode`, `Settled`, the cached
     settled outcome, `public_message`);
   - the native side mirrors native's sharding marker check; restore and export handling mirror
     `store/restore.rs`'s `sharding_marker`.

   Rules:
   - The marker is set on first start when the configuration enables inspection **and** the store is empty.
   - Enabling inspection on a non-empty store without the marker refuses startup.
   - Once the marker is set, a configuration with inspection off refuses startup.
   - Mode on with zero inspectors is valid.
   - A corrupt marker fails closed.

   **Default off:** no configuration surface changes behavior until 5.5a adds the switch. Expose the guard API and a
   config field that defaults to off.
2. **Repository flagged-id registry:**
   - It lives in the repository's RepoIndex partition under D34, and the Namespace partition under Single. Resolve it
     through the existing `ShardMap`.
   - Each record holds the flagged object id plus a strict versioned value: reason, source inspection/advance
     identity, and a state of `flagged` or `released`.
   - A per-repository monotonic **registry version** counter is bumped by every flag install or release, in the same
     apply.
   - API:
     - `install_flags`: bounded and idempotent. A re-install doesn't bump the version twice.
     - `release_flag`: the audited caller comes in 5.5a.
     - `lookup(ids)`: a bounded batch, returning the flagged subset plus the version read.
     - `version()`.
   - All writes are guarded, with CAS on the version and records.
3. **Hold records per (content id, advance):**
   - They live in the ref shard, beside the advance, keyed so that "is this content held by any advance" is a bounded
     prefix probe with limit 1.
   - Release deletes only the caller's own (content, advance) records.
   - API: `plan_holds(advance, ids)`, which returns effects to fold into the caller's apply, `plan_release(advance)`
     and `is_held(ids)`.
   - Record the op cost per id. 5.5a must fit these into the seven-ticket 100-op budget, so report the counts.
4. **Keys.**
   - Choose key tags that are unused in `store/keys.rs` on the base **and** on the active branches (`git show` their
     `keys.rs`):
     - `mkit-server/wp-5-4-published-view`;
     - `mkit-server/wp-4-10b-worker-extraction` (uses `gp` and `ct`);
     - `mkit-server/wp-5-10-5-11a-purge-admin`;
     - `mkit-server/wp-4-14b-1-http-proofs`.
   - `pv` is freed by R-198, but don't use it.
   - Add them to `parse`, the goldens and the restore/export classification.
   - No new timer kinds.
5. **Docs:**
   - Add row **R-199** (WP-5.5a-0, the inspection storage prerequisite per R-198 B3) to `00-plan.md`.
   - Add a registry row for 5.5a-0 with deps on the merged base only, and make 5.5a depend on it.
   - Add a CHANGELOG line.
   - Add INVARIANTS entries for the marker's one-way rule and the version monotonicity.

## C. Your decisions

Codecs, module layout, exact key layouts and API signatures. Record them in the PR body.

## D. Escalate (stop, commit, report)

- A clean design needs a cross-partition transaction or a new `NamespaceStore` primitive.
- The hold-record op cost per id makes seven-ticket advances exceed 100 ops in any plausible 5.5a integration. Report
  the arithmetic.
- You'd pass 1,200 production lines.

## Tests (required)

- **Marker, on native, Memory and Worker:**
  - an empty store sets it;
  - a non-empty store without the marker refuses;
  - turning it off after it's set refuses;
  - a corrupt marker fails closed;
  - the settled cache;
  - restore and export round-trip.
- **Registry:**
  - install is idempotent and bumps the version exactly once;
  - release;
  - bounded lookup with version;
  - concurrent install/release CAS losers retry correctly;
  - Single and D34 partitions.
- **Holds:**
  - two advances on the same content: releasing one leaves it held (the logic of
    `releasing_one_advance_must_preserve_another_hold_on_the_same_pack`, at storage level);
  - the prefix probe is limited to 1;
  - the op-count assertion.
- Default-off identity: existing suites are unchanged.

## Gates

- the common gates;
- `just ci-server`;
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`;
- wasm32 clippy.

Do the mandatory self-review, then open the PR.
