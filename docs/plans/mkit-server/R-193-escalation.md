# R-193: lifetime authority escalation

Status: stopped under [brief](briefs/R-193.md) B3 / D, before retrieval implementation.
Base: `bc114103` (`origin/feat/mkit-server`, including #1240 and #1242).

## The blocker

The required private route must return `not_found` once its advance has applied
or aborted, even if its capability is unexpired. Existing ticket/advance state
proves successful consumption, but does not distinguish an active synchronous
inspection from its completed fail-closed attempt.

A concrete counterexample is an Inspect call that returns `unavailable` before
its capability expires. The advance returns without apply or replay storage,
while its upload tickets, Ticketed reservations, refs and publication remain
unchanged. Pack bytes remain addressable. A separate scanner retrieval request
observes the same lifetime inputs while Inspect is active and after it returns.

This is a lifetime gap, not evidence that any existing retrieval endpoint leaks:
the R-193 endpoint has not been implemented.

## Source evidence

- Ticketed advances skip admission (`pipeline/mod.rs:2379`) and therefore create
  no pending advance reservation (`2393`). Error settlement runs only when such
  a pending reservation exists (`2497`).
- `Pipeline::inspect_advance` returns `unavailable` on a fail-closed outcome
  (`pipeline/inspection.rs:134`). `plan_and_apply` propagates this error before
  `apply_atomic` (`pipeline/mod.rs:3425–3457`).
- Inspection rejection stores only replay denial, without ticket/admission
  effects (`pipeline/ref_policy.rs:21–63`). Replay can distinguish this deliberate
  rejection, but cannot cover the unavailable case; §11.2 requires no replay there.
- `plan_replay` uses `InFlight` only for `UploadReserve`; advance replay is
  committed with its result (`pipeline/plan.rs:803–808`).
- Successful consumption closes tickets in the apply fragment
  (`pipeline/advance.rs:126–185`), deleting the exact observed ticket
  (`store/tickets.rs:377–378`). This solves after-apply, not all after-abort cases.
- Worker pipelines and inspectors are built per request
  (`mkit-server-worker/src/adapter.rs:1991–2005,2268–2300`). A pipeline-local
  registry is invisible to a separate retrieval request. An isolate-local map
  supplies no existing guarantee that advance and retrieval reach the same
  isolate; introducing such routing would be a new foundation under R-198.

Unless explicitly prefixed `mkit-server-worker/src/`, source paths above and
below are relative to `rust/crates/mkit-server/src/`; Worker paths are relative
to `rust/crates/`. They refer to the unchanged base's production sources.

## Reproduction

`pipeline::tests::indexed::inspection::unavailable_inspection_leaves_active_lifetime_rows_unchanged`
uses real ticketed pack verification and stage-5 inspection for both Single and
D34 placement. An inspector reads ticket rows, their Ticketed reservations, the
advance replay key, publication, refs and pack membership during its active call,
then returns unavailable. The test asserts byte-identical lifecycle rows after
the advance returns, absent replay, unmoved refs/publication and surviving pack
bytes. This is escalation evidence; it pins the existing retry semantics rather
than claiming to implement the endpoint's after-abort behavior.

The existing `unavailable_has_no_replay_and_retry_reuses_inspection_id` additionally
proves that the same tickets and logical inspection id succeed on retry.

## What is available

Native and Worker staged-byte addressing are sufficient:

- Ticketed upload commits `BlobKey::pack` before writing its completion marker
  (`pipeline/upload.rs:483–522`); multipart completion does likewise
  (`pipeline/parts.rs:417–460`). Advance validates the pack before apply
  (`pipeline/advance.rs:269–282`).
- Native `FsBlobStore` reads the final pack key with range support
  (`fs/blob.rs:344–373`); Worker R2 streams ranges from the same pack key
  (`mkit-server-worker/src/r2.rs:499–526`).
- `takedown::denial::require_pack_clear` supplies global-denial checking without
  retrieval-specific pack decoding (`takedown/denial.rs:593–615`). Verified
  inventory is sealed before Inspect on native (`indexed/verify.rs:1156`) and
  scheduled Worker verification (`indexed/job.rs:1559`). The helper currently
  allocates 9,000 metadata calls; a resumed implementation must account for
  that proof and retrieval reads in the route's complete budget.

## Ruling needed to resume

Authorize a minimal shared lifetime mechanism for synchronous attempts, including
its storage/routing ownership and cancellation semantics, or clarify that B3's
“abort” means terminal ticket closure only and permits retrieval after a failed
advance attempt until capability expiry. The latter changes the current prompt's
completed-advance lifetime requirement and cannot be assumed by the executor.

No durable record, key tag, routing protocol, endpoint, capability codec or
configuration contract has been introduced. No spec or completion/registry row
is marked finished. No push or PR is made, as brief D and the common executor
rules require for escalation. Full implementation gates are deferred because
there is no retrieval implementation to gate.

## Verification and self-review

- `cargo fmt --all --check` and `git diff --check`: passed.
- `cargo clippy --locked -p mkit-server --all-targets --all-features -- -D warnings`:
  passed. Initial probe returned a literal under a trait's non-static return
  signature; the test now stores its name and returns a borrow, resolving Clippy.
- `cargo nextest run --locked -p mkit-server --all-features` with the two focused
  lifetime/retry tests selected: 2 passed. The new test covers both placements.
- Independent correctness/security and spec/brief reviews found no blocking
  issues. The source-path qualification in this report was corrected.
- Logs: `~/.cache/mkit-test-tmp/wp-r193/lifetime-{test,clippy}.log`.
- Changed production Rust: 0 lines. Tests: 84 added lines. Brief and evidence
  report are documentation. Full workspace/Worker/conformance gates are unrun
  because this is the explicitly required Section D stop, not a completed WP.
