## Purpose

Built-in ref policy per SPEC-SERVER §9.7 and SPEC-WRITE-GRANTS §8.2:
- per-ref allowed operation signers;
- deployment fast-forward-only rules;
- the indexed-mode ancestry check that lets `u`-only grants fast-forward (R-148's TODO);
- ticketless head-membership enforcement in indexed mode.

It stays inert in Stage 1.

## A. Fixed (do not change)

1. **SPEC-SERVER §9.7:** the signer is the **authenticated operation signer**, never commit signers; ff-only binds
   every principal; startup is refused if ff-only is configured without indexed mode.
2. **SPEC-WRITE-GRANTS §8.2:** `u`-only `MATCH` is allowed only as a proven fast-forward.
3. **Opaque mode is unchanged byte for byte:** `update without force needs indexed mode`. The pin test at
   `ref_scopes.rs:182` stays.
4. **§9.4 isolation:** only same-repository membership. The global object store is never read.
5. **R-148 and R-154:** programmatic only, and inert in Stage 1.

## B. Decided (do not change)

- **B1 (D1).** A built-in `PipelineConfig.ref_policy: Option<RefPolicy>` (`RefPattern` → `{allowed_signers,
  fast_forward_only}`), run at stage 5 **before** the user's `hooks.pre_receive()`. `HookSet` and the `PreReceive`
  signature are unchanged.
- **B2. Signer rules:**
  - they apply to every ref-moving change: `UpdateRef` (create, update, delete) and the `AdvanceRefs` head;
  - a missing auth v2 signer → deny;
  - **packmap refs are covered through `packmap_head` (D5)**;
  - error: `permission_denied` `signer not allowed for this ref`;
  - overlapping rules intersect (D8);
  - they are enforced in both modes.
- **B3 (D6).** Amend §9.7 so a server MAY check the signer before verification and at `BeginUpload`. Implement both
  (DoS mitigation).
- **B4. Ff-only rules:**
  - the new value must descend from the current value;
  - delete is refused with `non-fast-forward update not allowed on this ref`;
  - create is allowed;
  - **`ANY` on a present ff-only ref is rewritten to `MATCH(observed)` (D2)**, and denied if the value can't be
    observed.
- **B5. `u`-only grants in indexed mode:**
  - `ref_scopes` returns a `FastForward` requirement, checked at stage 5 after verification;
  - failure is the existing `write grant rejected: ref scope`;
  - remove R-148's TODO and carry-forward.
- **B6. The ancestry engine** (`policy/ff.rs`, D7):
  - it walks Commit and Remix `parents` only;
  - `to == from` counts as a fast-forward;
  - staged commits come first: change `verify_ticketed` to return a parent map for staged commits instead of the
    unused `Vec<Hash>`;
  - member commits are walked breadth-first with `locate_split` and `member_object`;
  - **cap (D3):** `max_ancestry_commits` defaults to 256, plus the decode budget. Capped or exhausted is the policy
    denial (`permission_denied`), with a log and a metric;
  - **the lag window:** inside it, `unavailable` `repository membership not yet visible` (not stored); after it,
    permanent.
- **B7. Ticketless head membership** (a spec amendment to §9.3 or §9.7):
  - in indexed mode, a non-delete ticketless `AdvanceRefs` or `UpdateRef` head must be a member Commit, Remix or Tag
    of **this** repository;
  - otherwise `invalid_argument` `open closure`, byte-identical regardless of other repositories;
  - a capped lookup → `object index limit exceeded`;
  - factor the helper out of `verify.rs:743-800` and share it;
  - **the lag proxy (D4):** a new `VerifiedAuth.created_at_ms` from the envelope, clamped to now.
- **B8 (D9).** Siblings inherit `ref_policy`. A non-auth-v2 sibling denies on signer rules.
- **B9. Docs:**
  - the SPEC-SERVER §9.7 clarifications, the ticketless rule and D6 MAY, with a version-history row;
  - a SPEC-WRITE-GRANTS §6 rollout note;
  - **R-170:** B1–B8, and the 4.8 carry-forward (a Worker ancestry cap of at most 64, run after async verification);
  - a CHANGELOG line.

## C. Your decisions

Config struct shapes, metric names, and walk internals.

## D. Escalate (stop and report) if

- A rule can't be enforced without changing `HookSet`.
- The replay or `in_flight` handling for lag answers would need new replay states.
- Production code passes 1,400 lines.

## Tests (required)

The fact sheet's §11 list, in full, including isolation (repository A vs B) and the inertness checks.

## Gates

- The common gate set, plus `just ci-server` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`.
- The wasm32 clippy for `mkit-server`.
