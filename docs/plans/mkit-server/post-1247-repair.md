# Post-#1247 inherited failure repair

Base: `e8164870170ac0dcedd1512fde25d3c0063ee6d0`. Evidence directory:
`~/.cache/mkit-test-tmp/chore-post-1247/`.

The strict frozen-parent controls are `named-parent-frozen.log` (13 failures)
and `wasm-parent-frozen.log` (one failure). Every Rust source and the advance
golden was restored to the base while those binaries were built and run.
The initial broad `before-server.log` reproduced seven failures before later
rebuilds replaced some binary paths; it is retained as diagnostic evidence, not
as a complete unchanged-parent verdict. The initial wasm failure is also
recorded in `before-wasm-named.log`. The earlier independent parent
controls are listed in `~/.cache/mkit-test-tmp/wp-zstd-bound-review/baseline-findings.md`.
The cold-alarm ruling requires failed/unknown rows to retain their identity and
payload while their physical due time advances with capped exponential backoff.

## Classification of every named failure

| Test | Class | Before / after | Verified cause and retained invariant |
| --- | --- | --- | --- |
| `interrupted_closure_and_recheck_slices_shrink_then_end_terminal` | (a) | FAIL / PASS (full server) | Twelve fixed 5-second ticks do not attempt twelve failed slices under 5/10/20/40/... second backoff. Drive actual wakes; assert one exact retry row, original due, unchanged payload and capped delay after each interruption. Keep caps `{1,2,4}`, terminal `ClosureCapped`, and no rejection. |
| `killed_slices_shrink_the_entry_cap_and_end_in_a_terminal_outcome_not_a_rejection` | (a) | FAIL / PASS (full server) | The fixed 3,000-second clock horizon is shorter than repeated capped retries required to shrink 4096 entries to one. Keep the 3,000-alarm bound and all terminal/cap/no-rejection assertions, follow returned wakes, and assert retained job timer payloads. |
| `golden_two_ticket_advance_batch_keys` | (a) | FAIL / PASS (full server) | The two timer keys omit the attempt/original-due fields added by #1247. Regenerate with the existing planner; operation count, guards and writes remain checked in full. |
| `same_millisecond_writer_during_fire_cannot_lose_wakeup` | (a) | FAIL / PASS (full server) | The writer changes `os`; the final handler guard races. #1247 moves the unchanged timer to 5100 rather than retaining its 100 key. Assert exact payload/identity, retention before 5100, successful later drain and no timer left. |
| `sqlite_crash_after_target_commit_retries_without_another_target_apply` | (a) | FAIL / PASS (full server) | Source cleanup fails after target commit, so physical retry is 5100, not 101. Assert the retained retry row, then retry at its wake; target apply count remains exactly one. |
| `sqlite_full_source_relay_timer_reschedules_immediately_after_progress` | (a) | FAIL / PASS (full server) | A one-commit tick budget requests a conservative alarm at 5100 without a future scan; the successful relay continuation itself is persisted at 5101. Assert one exact 5101 row, fired=1/failed=0, alarm no later than that row, healthy delivery and retained blocked work. |
| `sqlite_scan_state_guard_conflict_retries_without_deleting_rows` | (a) | FAIL / PASS (full server) | Backoff consumes the one-commit budget, yielding a conservative immediate wake. That alarm precedes the persisted retry. Assert exact retained 5100 timer and all three queued rows at the early alarm, then retry at 5100 and retain ordered-delivery assertions. |
| `sql_soft_limit_reserves_space_for_guarded_relay_timer_reschedule` | (a) | FAIL / PASS (full server) | #1247 requires both source Equals and destination Absent guards for the reserve exception. The test builds the obsolete source-only batch. Add the destination guard; preserve wrong-kind/nonempty-payload rejection cases. Existing strict reserve tests reject missing guards and unrelated puts. |
| `etag_conflict_crash_and_relay_during_upload_preserve_dirty_work` | (a) | FAIL / PASS (full server) | The interleaved relay changes generation; the snapshot CAS races and its unchanged 4000 timer moves to 9000. Assert dirty generation 2 and unchanged retry payload at 5000, successful clean empty snapshot at 9000, and consumed retry row. |
| `rollup_config_failure_retries_the_stored_timer` | (a) | FAIL / PASS (full server) | Configuration failure retains the same payload under a physical retry key. Check ten retries through the 600-second cap and successful firing after configuration repair. |
| `rollup_is_registered_on_the_classes_that_hold_quota_rows_only` | (a) | FAIL / PASS (full server) | Unknown kinds retain their payload under retry keys. Check exact single-row retention through the cap, then fire with an owning registry. |
| `relay_config_failure_retries_the_stored_timer` | (a) | FAIL / PASS (full server) | Configuration failure retains an empty relay payload under retry keys. Check ten capped retries, then successful firing and complete timer removal with repaired configuration. |
| `relay_is_registered_only_on_ref_shards` | (a) | FAIL / PASS (full server) | Unregistered classes back off the timer rather than deleting it. Check ten capped retries and successful firing after registration; no target transport calls are added for the empty source. |
| `golden_http_object_spans_via_wasm` | (c) | FAIL / PASS (full wasm) | `content-headers.json` is a filename/media/disposition table, not a proof sidecar. `fixture_files()` emits only this JSON and its manifest digest; it never emits `content-headers.bin`. Match the core golden verifier's table exclusion in the wasm span verifier. Genuine span acceptance/rejection checks stay unchanged. |

## Adjacent product regression

`retried_relay_progress_reschedules_after_its_physical_wake` demonstrates (b):
a relay retried at 5100 still carries semantic due=100. After successful delivery
with more work, the handler used `max(now, original_due+1)`, producing 5100.
The regression fails before the fix with `Some(5100)` instead of `Some(5101)`
(`relay-progress-red.log`). The fix changes the successful continuation to
`now+1`, preserving normal immediate progress, failed-target backoff, row
retention and eventual drain. The new regression passes in the full server
gate. No protocol, key, kind or budget changes.

## Additional inherited property-test failure

The first full server gate found
`http_objects::route::tests::the_first_dash_segment_delimits_the_ref`, with
`branch="a", rest=["con"]` (`ci-server.log`). The unchanged parser and
`TreeEntry::validate_name` correctly reject reserved Windows device names;
the property wrongly assumed every generated lowercase segment was valid.
This is **(c), a generated-fixture artifact unrelated to the timer layout**.
The unchanged test fails again in isolation with its persisted seed
(`route-property-red.log`, zero successes); route/parser and core name-validation
sources were identical to the base. A direct existing-binary control also fails
(`route-existing-binary-red.log`). The repair retains invalid generated inputs
and asserts `BadUrl`; valid cases now compare every path segment's exact bytes.
Both the repaired property and deterministic case pass in the full server
gate. A deterministic test covers `con/nul/prn/aux` rejection, the valid ref
`refs/heads/con`, and an ordinary dash within the file path. The proptest seed is checked in
under `proptest-regressions/http_objects/route.txt`. No parser code changed.

## Fixture instruction correction

Restoring a binary for the content-header table would invent a proof and hide
an incorrect reader assumption. The source generator and manifest establish
that the table is JSON-only. Regenerate/check the existing table and repair
its classification in the wasm reader instead. This follows the user's correction citing external review 12-1; no proof
fixture is omitted or weakened.

## Gates and Worker diagnosis

- Focused repaired server tests: `named-after.log`, 14/14 passed (13 named
  originals plus the added relay regression). This run explicitly regenerated
  the advance golden; the full gate checks it without update variables.
- Wasm: `wasm-after-full.log`, all 59 tests passed, including the original failure.
- HTTP fixture generation and verification: `golden-regenerate.log` and
  `golden-check.log`, passed; regeneration produced no HTTP fixture diff.
- Default Worker conformance: `worker-default-final.log`, **84 passed, zero
  failed, 131 profile skips**, including `refs.many_refs_one_repository` and
  the 1,000-ref paging fixture, on newly allocated free port 58716. This successful
  unchanged-harness run does not resolve the intermittent failures below.
- Security: `ci-security.log`, passed.
- Formatting: `fmt-final.log`, passed.
- Workspace clippy, all targets/all features with warnings denied:
  `clippy-workspace-final.log`, passed.
- Wasm32 clippy for server/Worker/wasm, no deps and warnings denied:
  `clippy-wasm-final.log`, passed with supported/default features.
- All-feature doctests for server/native/Worker/conformance/wasm/CLI:
  `doctests.log`, passed. Rustdoc with warnings denied: `rustdoc.log`, passed.
- `just ci-scripts`: `ci-scripts.log`, passed, including wasm graph/builds and
  the server-free CLI baseline. Signer fixture build: passed.
- Full `just ci-server`: `ci-server-final.log`, **2,833 passed, zero failed,
  12 skipped**, followed by all wasm checks/build and CLI-baseline check passed.
  Includes complete all-feature suites: server 1,475; native 474; Worker 351;
  conformance 533.
  All-feature CLI reverse-dependency suite:
  `cli-reverse-tests.log`, 1,534 passed, nine skipped.
- Self-review: independent correctness/security and brief/spec passes found
  no actionable product defect; identified and completed frozen-parent evidence
  and golden inclusion checks. The final route-test delta was also independently
  reviewed with no actionable findings. The gate results above include the final lint fixes.

The user explicitly chose to keep the many-refs diagnosis and carry its gate
failure diagnosis forward, without adding a local client option. The final
full default gate passed, while the earlier intermittent failures remain
unresolved. The original harness and its concurrency/response assertions remain
unchanged. The controlled runtime results are below.

The initial combined four-crate all-features test command failed at compile
because the wasm BLS feature enables an attest enum variant without also enabling
the CLI dev-dependency's BLS feature. Server/native/Worker and wasm full suites
therefore run separately. An extra wasm all-features clippy attempt also failed
in blst's C build because Apple's clang lacks a wasm backend; the required
supported/default-feature wasm32 clippy passes. These are tooling/feature-matrix
limitations, not new production changes.

## Worker `refs.many_refs_one_repository`

Classification: **(c), local HTTP transport/tooling artifact**, with the exact
socket-close mechanism unresolved. This is an inference from controlled local
workerd runs, not a claim about production Workers limits. All probes retain
64 concurrent writes, each step's readbacks and the exact final ordered list.

| Controlled group | Passed / failed | Evidence |
| --- | --- | --- |
| Original pooled client, direct and public listeners | 1 / 2 | `many-refs-direct-{1,2}.log`, `many-refs-public-1.log`; a direct `SendRequest` failure means the public proxy is not the only possible failing hop. |
| Temporary `Connection: close`, same Worker/state | 6 / 0 | Three direct and three public controls in `many-refs-close-{direct,public}-{1,2,3}.log`. |
| Restored original client after those successful runs | 1 / 2 | `many-refs-original-warm-public-{1,2,3}.log`; warming alone does not explain the improvement. |
| Original client, inherited shell FD limit 256 | 0 / 3 | `many-refs-fd256-public-{1,2,3}.log`; workerd already permits more descriptors than that shell limit. |
| Original client and restarted Worker, FD limit 4096 | 0 / 3 | `many-refs-fd4096-public-{1,2,3}.log`; raising the descriptor limit does not resolve the failure. |

The public HTTP 500 is Miniflare's plain-text exception response after
Wrangler's ProxyWorker fails its internal UserWorker fetch. Direct calls can
instead expose a connectrpc/hyper `SendRequest` failure. These failures occur
below the typed RPC response. Failed refs vary; sequential `ReadRef` requests
also fail after all 64 initial writes committed. The runtime remains healthy.

The initial runtime recorded 1,538 successful UpdateRef, 1,152 successful
ReadRef and eight successful ListRefs service outcomes. The raised-limit
runtime recorded 161 successful UpdateRef outcomes; failing reads produced no
service outcome. No panic, memory, CPU, subrequest-limit or EMFILE message was
observed. The maximum sampled raised-limit UserWorker descriptor count was
618, with runners at 70, well below 4096. Completed alarm traces were successful.
Absence of an error trace does not exclude every runtime fault, but changing
connection reuse while preserving the full workload is the strongest evidence
against a deterministic timer or many-ref product regression.

The temporary header was removed byte-for-byte and the normal runner rebuilt
before final gates. No client, retry, script or assertion change remains.
Manual probe runtimes were stopped by their own PIDs. The structured 18-run
record is `many-refs-probe-results.json`; full local diagnosis is
`many-refs-diagnosis.md`. Investigating the lower-level close behavior and a
separately authorized local workaround remain follow-up work.

## Final scope

One production Rust line changed (`relay/deliver.rs`: one addition, one removal),
well below the 600 non-test-line cap. All other Rust changes are tests. No
client/harness, dependency, protocol, key, timer-kind or budget changes. All
required gates pass; the historical many-refs transport failure remains a
diagnosis-only carry-forward at the user's direction.
