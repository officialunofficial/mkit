# WP-1.9a executor stop: Section D

WP-1.25 is merged: `89ed8fd0` (#1150). Work started from feature tip
`80106e31` in `.claude/worktrees/wp-1-9a`.

## Exact blocker

B.7 requires exactly its listed edits, including a BeginUpload cap-error
carve-out. STC §5 currently also says (lines 371–374):

> `failed_precondition` is a CAS conflict only on `UpdateRef`. Except
> for the indexed delta-base case above, it is a ticket failure on the
> other RPCs listed here and on an `UploadPack` that needed a ticket and
> carried none (§7.6).

That later paragraph contradicts the required new cap carve-out. Section D
explicitly requires stopping when B.7 conflicts with other §5 text.
No STC changes have been made. Proposed amendment: permit that later
paragraph's exception to name both the indexed delta-base and BeginUpload
cap cases above, in addition to the edits already listed in B.7.

## Saved partial work (not ready to review or merge)

- Brief copied verbatim from Purpose onward in the first commit.
- Draft Procedure/OpKind, replay result/codec, unary write integration,
  pre-admission decisions, ticket-open fragment and lease reuse.
- Token module, parsing/configuration and token tests drafted; the golden
  test's generator exists, but its JSON fixture and MANIFEST entry do not.
- Native/Worker key configuration and authenticated Connect handler drafted.
- Legacy UploadPack session callers renamed to `open_upload`.
- Adapter configuration tests and native wire key setup drafted.

No flow integration tests, race-barrier tests, wire ticket cases, conformance
Rpc changes, STC/plan/invariant/changelog edits or gate evidence are complete.
The changes are incomplete and may not compile. The token test command with
`--locked` stopped before compilation because the added dependencies require
lockfile refresh. No tests passed and no lockfile refresh was performed.

## Continuation notes

- Executor choices so far: `upload/token.rs` owns MAC encoding/config parsing;
  `pipeline/begin.rs` owns ticket decisions/fragments; a local `Allowance`
  struct preserves admission charges/reservation; ticket reads use Snapshot.
  Record reasons and final decisions in the eventual PR body.
- Refresh rust/Cargo.lock and affected app lockfiles before compilation.
- Existing core upload-golden regeneration rewrites uploads/MANIFEST; retain
  the new token entry when adding the fixture and verify existing bytes.
- Tiny-quota wire baselines need a cap-case strategy. TestFaults clock-skew can
  roll quota windows without expiring a 24h ticket, but native in-process
  baselines do not currently advertise that feature.
- Continue auditing the draft planner, especially race results, replay on
  cap races and the common D34 stage order; all required gates remain.

The branch is committed locally and has not been pushed. No PR was opened,
under the common rules' explicit Section D exception. The worktree remains.
