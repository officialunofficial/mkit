## Purpose

This completes server-side write grants:
- **2.6b:** the two `0x` owner schemes get wire conformance.
- **2.7:** grants are enforced per ref and per change, exactly as §8.2/§8.3 say, with the apply-time precondition for
  `ANY`.
- **2.8:** owners can revoke grants by raising the namespace epoch through the two unsigned RPCs. Completion is
  reported only once every leased ref shard is fenced (1.25).

## A. Fixed (do not change)

1. **SPEC-WRITE-GRANTS:**
   - §3.3: flags;
   - §5, §5.2 checks 1–6: the epoch statement; §5.3–5.4: RPCs, completion, `Retry-After`;
   - §6, §7 steps 1–11: verification;
   - **§8.2 and §8.3: ref scopes**;
   - §9.3: writes are not an oracle;
   - §11: error codes;
   - §12: epochs are per deployment.
   - STC §7.5.
2. **The apply-time epoch guards already exist** (2.6a / 1.25): an `e` guard on Single, an `el` guard on D34, and a
   creation guard. **Don't re-implement them.**
3. **`mkit-attest` needs no changes.** It already provides `verify_epoch_statement` (never cache it),
   `epoch_transition`, `effective_flags` (empty for packmap refs), `head_packmap` and `packmap_head`.
4. **The epoch RPCs are unsigned, forever.** They stay outside `Procedure`, never read `X-Repository`, and ignore
   auth headers.
5. **R-135:** the interim gate is replaced by 2.7. BeginUpload's §8.2 scope moves here.

## B. Decided (do not change)

### Part 1: WP-2.6b

- **B1. Restore the five removed cases.** Revert the test-only removal in commit `359ebdb` (its parent is `4ddd3d9c`
  on the #1199 branch). The cases are:
  - `valid_secp256k1_eip191`
  - `valid_webauthn_p256`
  - `zero_x_without_grant_denied`
  - `ed25519_scheme_on_0x_denied`
  - `webauthn_unconfigured_rp_denied`

  Restore with them the `Owner::{K1,Web}` builders, `owner_namespaces()`, the Multi allowlist extension and the
  Single/D34 case list.
- **B2. Dependencies:** `k256` and `p256` (`ecdsa`), and `sha2` non-optional again, in `mkit-server-conformance`. Keep
  `check-wasm-dep-graph.sh` and `cargo deny` green.
- **B3. Plan:**
  - Add a `2.6b` registry row (deps 2.6, tests only).
  - Record the 2.6a/2.6b split in R-149.
  - In R-149 and the fixture doc, state that the fixed test seeds own real `0x` namespaces and must never be
    allowlisted on a shared or staging deployment.

### Part 2: WP-2.7

- **B4. A new `policy/ref_scopes.rs` replaces `interim_ref_gate`.** The required flag per change:

  | Change | Required flag | When |
  |---|---|---|
  | Delete (always `MATCH`) | `d` | authorize |
  | `MISSING` | `c` | authorize |
  | `MATCH`, non-delete, **opaque** server | `f` | authorize. A grant with `u` but not `f` is `permission_denied`, "update without force needs indexed mode" |
  | `ANY` | `c` if the ref is absent at apply, `f` if present | authorize **and** apply |

  **`ANY`:**
  - neither `c` nor `f` → deny;
  - both → no guard;
  - `c` only → a `Precondition::Absent(ref)` requirement;
  - `f` only → `Precondition::Present(ref)`.

  **Evaluation is per change, not per grant.** A `cu` grant can still create (`MISSING`) and delete with `d`.
- **B5. Carrying the requirement to apply.**
  - Extend `GrantRef` with a server-local presence requirement per ref (an enum, not an `mkit-attest` type), and
    thread it through `WriteRequest.grant`.
  - `decide_refs` adds the guard, and re-evaluates it against the snapshot on each plan.
  - A failed guard re-plans. The re-plan answers `permission_denied`, with nothing committed: no replay, quota or ref
    row.
- **B6. §8.3.**
  - `AdvanceRefs` flags are evaluated on the head only.
  - The exact `refs/heads/<x>` ↔ `refs/mkit/packmap/<x>` pairing is required.
  - A direct packmap `UpdateRef` is denied even under `refs/*`.
- **B7. BeginUpload:** "matching entry, any flag". That is `!effective_flags.is_empty()`; move it unchanged.
- **B8. Indexed mode.**
  - Add one `indexed_mode()` seam used by both `pipeline/info.rs` and `ref_scopes.rs`, with a `TODO(WP-4.7)` for the
    fast-forward check. The WP-4.6+4.7 bundle may add `IndexedConfig`; if it has merged, use it.
  - Until then, the opaque rule applies.
- **B9. Owner and authority writes are untouched by scopes.**
- **B10. Docs.**
  - Remove the interim-gate text from the SPEC-WRITE-GRANTS status paragraph and §6 "Rollout".
  - Remove "full §8.2 not yet implemented" from STC §7.5 rule 2.
  - **R-150:**
    - B4–B9;
    - the four places where the breakdown disagreed with the spec (per-change evaluation; `ANY` needs `c`/`f` by
      presence; the BeginUpload rule; the reframed test);
    - the client divergence for WP-2.13: the client ranks a `u`-only grant valid for `Match`, but an opaque server
      now denies it, so 2.13 must prefer `f` when `indexed_mode = false`.

### Part 3: WP-2.8

- **B11. A new `pipeline/epoch.rs` plus the `service.rs` handlers.**
- **B12. `GetGrantEpoch`.**
  - Parse the namespace grammar before anything else; a bad namespace is `invalid_argument` (R-125).
  - **An unserved namespace** (not allowlisted; see B14) answers 0 without a store read.
  - Otherwise read the coordinator `e`; absent means 0.
  - It never creates state, and never depends on whether a repository exists.
- **B13. `SetGrantEpoch`.**
  1. Check `len ≤ 8192` **before** decoding. Too long, or failing to decode, is **`permission_denied`** (§5.2 check 1,
     §11). This amends R-125's `invalid_argument` note; update R-125 to say so, and to carry the same rule to 2.9's
     statements.
  2. `verify_epoch_statement` with the deployment's grant verifier and the business clock.
  3. The namespace-policy check (B14).
  4. A CAS loop on `e` using `epoch_transition`:
     - Advance → put;
     - Retry → no write;
     - Reject → `permission_denied`;
     - a lost CAS → re-read and re-classify.

     Refactor `bump_epoch` to share this, and alias its `MAX_EPOCH_STEP` to `mkit_attest::grant::MAX_EPOCH_STEP`.
  5. Loop `revoke_step` within a per-request budget of at most 5 slices or 5 s:
     - `Complete` → `{epoch}`;
     - otherwise → `unavailable` with `Retry-After: 1`.

  A retry is **any** statement passing checks 1–6 with `new == stored`, not only identical bytes.

  Errors are `permission_denied("epoch statement rejected: <reason>")`. Only the statement id is logged. No grant
  configuration → `permission_denied` ("scheme not advertised").
- **B14. §5.2 check 6, "served namespace" (orchestrator decision).**
  - Under Allowlist: listed only, and `0x` is served only under Allowlist (mirroring 2.6a).
  - Under `Any`: **require an existing namespace record**, created by an admitted write. Without one, answer
    `permission_denied`. This closes a state-creation vector with no admission.
  - Add an informative sentence to SPEC-WRITE-GRANTS §5.2.
- **B15. Single addressing:** both RPCs are `unimplemented` ("grant epochs require multi-repository addressing").
- **B16. The reserved-BeginUpload `Aborted` row is deferred to WP-3.3.** It falls under 3.3's generic "any apply
  failure after `Allow{reservation}`" rule. Add a test asserting nothing is committed, a `TODO(WP-3.3)`, and record the
  move in R-151.
- **B17. Race cases are native pipeline tests,** not wire (the wire harness can't pause). Extend
  `mkit-server-native/tests/epoch_leases.rs` with real signed statements, on memory and SQLite.
- **B18. Docs.**
  - The SPEC-WRITE-GRANTS status paragraph: the epoch RPCs are implemented. Update the STC §7.5 informative note.
  - **R-151:**
    - B11–B17;
    - the breakdown/spec disagreements: retry semantics, check 6, file paths, and races as native tests;
    - carry-forwards:
      - 2.9's Worker config cache must hook into completion (§5.4, last bullet), and uses the same statement-size rule;
      - 2.12 decides the ticketless-UploadPack epoch source, keeps `GrantConfig`'s constructors stable, and must be
        brief-gated on the 1.15+1.30 bundle;
      - 2.14 uses the client RPCs.
  - A CHANGELOG line per WP.

## C. Your decisions

- The shape of the presence-requirement enum and its field name.
- The exact revoke-loop budget within B13.5, documented.
- Module and test layout.

## D. Escalate (stop and report) if

- The `ANY` apply-time guard can't be added without growing the advance batch past its budget. Today it is 86 on D34,
  becoming 88 with 1.28b.
- `mkit-attest` would need a change.
- Production code passes 3,000 lines. Then open the PR with 2.6b and 2.7, and list 2.8 as not done.

## Tests (required)

**2.6b:** the five restored cases pass on Single and D34 in `pipeline_grants_single_and_d34`, with the allowlist
extended.

**2.7:**

*Unit:*
- the full required-flag table: every condition × presence × flag subset, on the opaque server;
- the `u`-without-`f` message;
- BeginUpload any flag vs no match;
- a packmap `UpdateRef` denied even under `refs/*`;
- the pairing: a wrong packmap, or a non-heads head, is denied.

*Pipeline:*
- `ANY` with `c` only, on an absent ref, commits.
- `ANY` with `c` only, when the ref appears between plan and apply (a `BeforeFinalApply` write hook): the answer is
  `permission_denied`, with no replay, quota or ref row.
- `ANY` with `f` only, on an absent ref, is denied.
- Every authorize-time denial allocates nothing.
- Owner and authority writes are unaffected.
- The same nonce succeeds after a corrected grant.

*Wire* (Single and D34), in a new `wire/cases/ref_scopes.rs` or appended to `grants.rs`:
- `create_only_rejects_update`
- `cu_grant_creates_but_match_update_denied_opaque`
- `force_allows_non_ff`
- `delete_needs_d`
- `any_on_absent_needs_c`
- `any_on_present_needs_f`
- `direct_packmap_update_denied`
- `head_only_update_ok`
- `advance_wrong_packmap_denied`
- `rebaseline_push_under_head_scope`
- `begin_upload_any_flag`
- `begin_upload_unmatched_denied`

**2.8:**

*Unit / pipeline:*
- the transition table, including the `u64::MAX` edge;
- a retry still runs checks 1–6;
- a lost CAS re-classifies;
- the B12–B15 mappings;
- `Retry-After` on pending;
- no replay or quota rows;
- the business clock;
- Single → `unimplemented`.

*Native races* (memory and SQLite):
- **(a)** Revoke during an in-flight write: pause at `AfterAuthorize`, let `SetGrantEpoch` complete, resume. The
  write gets `permission_denied`, and nothing is committed.
- **(b) R-63.**
  1. Pause at `BeforeFinalApply`.
  2. Fail the push to that shard.
  3. Advance past lease expiry plus skew.
  4. `SetGrantEpoch` completes.
  5. Resume: `NotAfter` fails, the re-plan answers `permission_denied`, and nothing is committed.
- **(c)** An idle shard woken after revocation rejects the old grant.
- **(d)** Lease expiry racing an ack.
- **(e)** A pending answer is `unavailable` with `Retry-After`. The same statement retried later returns `{epoch}`.
- **(f)** A reserved BeginUpload hitting an epoch mismatch commits nothing.

*Wire* (a new `wire/cases/epochs.rs`, M2, `[Grants, MultiRepo]`, Single and D34):
- `get_unsigned_zero`
- `get_ignores_auth_headers`
- `get_bad_namespace_invalid_argument`
- `set_advances_and_get_reflects`
- `set_retry_same_epoch`
- `set_over_step_denied`
- `set_decrease_denied`
- `wrong_audience`
- `expired`
- `not_yet_valid`
- `scheme_not_advertised`
- `namespace_not_served`
- `oversize_statement`
- `zero_x_secp256k1_statement`
- `zero_x_webauthn_statement`
- `old_grant_denied_new_grant_works_after_set`

## Gates

- `just ci-server`, `just ci-scripts` and `just ci-security`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-attest --all-features`
- the wasm32 check and the worker build
- `scripts/check-wasm-dep-graph.sh`
- `cargo deny check`
- `scripts/vcs-worker-conformance.sh` (default phase)
