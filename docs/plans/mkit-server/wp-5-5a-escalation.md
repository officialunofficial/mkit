# WP-5.5a Section D escalation: synchronous inspection resource bounds

Base: `e99e2b241959932150febb8a3bc4957b08134864` (WP-5.4 and WP-5.10/5.11a merged).
Branch: `mkit-server/wp-5-5a-sync-inspection`.

## Stop condition

The brief requires the complete inspected set, default batches of at most 10,000,
every batch for every inspector, the existing request resource bounds, and no
rejection merely for surplus pack entries. Those requirements do not fit the
current launch request contract at supported input cardinalities. Section D
requires stopping, committing coherent work and reporting rather than inventing
an additional durable foundation or silently narrowing the set.

This is a source-backed resource lower bound, not a reproduced production
Worker timeout. Local workerd does not enforce the production platform limits.

## Evidence

- `rust/crates/mkit-core/src/pack.rs:95`: the format permits 10,000,000 entries.
  Raw entries add 5 framing bytes; the pack header and trailer add 44 bytes
  (`HEADER_LEN`, `ENTRY_FRAME_LEN`, `TRAILER_LEN`).
- `rust/crates/mkit-core/src/serialize.rs:71`: a Blob with a 16-byte distinct
  counter payload serializes to 26 bytes (6-byte prologue, 4-byte length,
  16-byte payload). Two million such surplus entries therefore occupy
  62,000,044 bytes, before a small signed commit/tree closure. This fits even
  64 MiB. Ten million occupy 310,000,044 bytes and fit the Worker default
  1 GiB ticketed-pack limit (`server-worker/src/adapter.rs:105`) and 2 GiB
  indexed decode budget (`server/src/indexed/mod.rs`, IndexedConfig default).
  Reserve a few entries for the closure when using the exact format maximum.
- `rust/crates/mkit-server-worker/src/ns_object.rs:487`: Scan and ScanMany return
  at most 1,000 total rows. Enumerating two million existing VC_FRAME rows
  needs at least 2,000 calls. Ten million need 10,000. Six large data packs plus their MKPL ticket need
  almost 60,000 calls. `ns_client.rs` routes each method through a DO POST;
  the request Pipeline uses DoNamespaceStore, with no local-store shortcut.
- `rust/crates/mkit-server/src/indexed/scheduled.rs:46`: the scheduled advance
  allocates 600 calls to verification and reserves 256 for ancestry plus 144
  for other stages. The publication pair verifier separately caps its full
  closure walk at 256 calls (`indexed/publication.rs`, verify). Adding either
  enumeration or inspection budgets on top is not a valid resource proof.
- Even ideal streaming enumeration avoids only the scan cost. Six distinct
  data packs of approximately ten million files plus their MKPL ticket, at 10,000 objects per batch,
  require approximately 6,000 Inspect calls per inspector. Two inspectors
  require approximately 12,000 hook calls, before any reads or apply. This
  already exceeds the current Paid default of 10,000 platform subrequests.
  Smaller inspect_batch_max_objects values increase the bound.

Cloudflare's current limits permit explicitly increasing Paid subrequests up
to ten million; 1,000 is the repository's conservative accounting contract,
not the current hard Paid platform maximum. Neither raising a platform limit
nor fitting calls alone proves memory, CPU, authentication lifetime and stable
batch/retry bounds. References:
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/),
[2026 limit change](https://developers.cloudflare.com/changelog/post/2026-02-11-subrequests-limit/).
No deployment configuration or external account was changed.

## Why existing cursors are insufficient

`VerifyJobV1` belongs to one (repository, pack) and one ticket
(`indexed/checkpoint.rs:106`). Its cursor belongs to verification phases, not
an advance/inspector/batch inspection. A different ticket replaces the job
(`indexed/scheduled.rs:303`); removal of the owning ticket allows deletion of
its entire vc prefix (`indexed/job.rs:369`, cleanup at 598). It stores no
logical inspection assignments or successful PRE_RECEIVE batch verdicts.

An operation-specific synchronous inspection continuation would need defined
ownership, immutable set/batch identity, persisted results, concurrent retry
rules and cleanup. It cannot safely borrow the current producer's cursor
unchanged. That is additional durable machinery requiring an orchestrator
ruling under R-198, even if encoded inside an existing key namespace.

## Committed partial result

- The required brief was the first commit.
- A transport-only RemoteInspector adapter uses the existing HookClient,
  public hooks.v1 messages, bounded responses and fresh signed envelopes.
- PRE_RECEIVE pass/reject/quarantine are validated; quarantine becomes reject.
  Invalid verdicts/flagged ids and defer return unavailable. Byte retrieval is
  documented as the authorized private-channel seam for R-193.
- No deployment enables it. No enumeration, startup wiring, stage-5 integration,
  replay behavior, publication behavior or durable inspection state changed.
- Incomplete adapter configuration edits were removed; a scratch patch remains
  under ~/.cache/mkit-test-tmp/wp-5-5a-adapter/config.partial.patch.

## Partial verification and self-review

- Correct-environment focused nextest: 3/3 pass, covering deliberate verdicts,
  sanitation, invalid answers and signed retries with stable body/id and fresh
  nonce. Logs: ~/.cache/mkit-test-tmp/wp-5-5a/remote-inspection-nextest.log.
- cargo clippy --locked -p mkit-server --all-targets --all-features -- -D warnings:
  passed. cargo fmt --all --check and git diff --check: passed.
- Two independent read-only reviews (correctness/security and spec/brief): no
  behavioral findings in the partial adapter. Fixed misleading module docs
  suggesting HookSet/stage-5 integration; distinguished the repository's 1,000
  allocation from the current Paid platform limit in this report.
- Approximately 170 Rust production lines, below the 2,000-line cap.
- The common full-workspace, server-wide nextest/doc, just ci-server/scripts/
  security, wasm32 and actual Worker conformance gates were not run: Section D
  stopped the package before a complete implementation or PR candidate existed.

## Required ruling and remaining work

Authorize a concrete resource contract: either a bounded, durable synchronous
inspection continuation, or explicit accepted-input/inspector/batch limits and
platform budgets consistent with the complete-set rule. No new R-row, key tag,
timer, wire version or storage primitive has been allocated by this work.

Then implement enumeration and kind precedence, stable batch ids, every-inspector
aggregation and reject dominance, stage-5/replay/startup integration, Worker and
native configuration, R-200 spec/plan/registry/changelog amendments, full acceptance
tests, all required gates, adversarial self-review, and the PR.

No PR is opened or branch pushed under the Section D stop instruction.

## Resolved by the R-200 input-limit ruling

The user authorized one whole-advance batch (default 10,000 objects), at most
four inspectors and server-info advertisement. Preflight added-pack header/job
entry counts plus newly reachable files outside additions; oversize uses the
existing index-limit error/replay before hooks/apply. Full multi-batch inspection
is deferred to WP-5.5c. No durable continuation, tag, timer or marker is added.

The launch advance allocates 300 calls to verification, 256 to ancestry,
256 shared by the resulting-pair closure, added-pack enumeration and publication
dependency reads, four to Inspect and 144 to remaining stages: **960 <= 1,000**.
Scans return at most 1,000 rows per call; 10,000 entries across at most seven
ticketed packs need at most 10 + 6 = 16 pages (independent pack rounding),
included in the shared 256-call pair allocation, not added to verification.
`pipeline::inspection` asserts the allocations; the pair stages share one
`SliceBudget`, and inspection lowers the old verification allocation from 600
to 300. The historical stop/check record above
describes the pre-ruling tree; integration and the PR proceed under this ruling
without increasing the platform limit.

## Second escalation: role classification is not covered by the row-page bound

The explicit 10,000-object / four-inspector ruling resolves the original
checkpoint-page-count problem. The final independent budget review found a
different cost that the implementation and its initial budget explanation
underestimated: Worker inspection must reconstruct each added `Tree` and
`ChunkedBlob` to classify blobs used as chunks, including references from
surplus entries. Native verification already has these decoded facts; the
Worker's frame checkpoints currently retain locations, sizes and object types,
without the role references.

`indexed::inspection::scheduled_entries` first scans checkpoint rows in
1,000-row pages, then calls `indexed::resolve::member_object` for every
structural role source. A raw, non-delta role source requires two R2 reads
(prefix and frame). These calls are charged to the shared 256-call
publication/inspection allocation. Consequently, row scans are bounded but
are not the complete enumeration cost.

A small valid counterexample is one added pack with 200 distinct one-byte
blobs and 200 one-chunk manifests referencing those blobs. All 400 entries
may be surplus beside an unchanged, already published head. This is below
the configured 10,000-entry limit and ordinary size limits, yet role
classification alone needs 400 R2 reads, plus its checkpoint scan. The
shared allocation refuses it before any Inspect call. That refusal is safe
and does not apply the advance, but it is an additional input refusal not
established by the two explicit launch limits. Increasing the allocation
does not solve the general case: 5,000 such pairs still fit the 10,000-entry
cap and need 10,000 role reads.

This triggers the prompt's Section D: the complete inspected set cannot be
enumerated within the stated call bounds using the current checkpoint
metadata. No new key tag, timer, durable role/inspection state, platform
limit increase, narrowed inspected set or additional input limit has been
introduced to conceal the problem. The branch is committed locally; no PR
is opened while this ruling remains unresolved.

The focused regression
`indexed::inspection::tests::small_valid_manifest_pack_exceeds_worker_role_enumeration_budget`
passes and measures the counterexample: **15,044 bytes, 400 entries, 401
calls** (400 R2 reads plus one checkpoint scan). Native collection and a
Worker allocation of 1,000 produce the same 400-object set; the launch
allocation refuses exactly at 256 calls. The test intentionally records
this limitation rather than claiming launch acceptance. Publication's
exhausted-budget wrapper converts the refusal to the existing
`invalid_argument` index-limit error before hooks or apply.

Options requiring a ruling include retaining verified role facts in existing
indexed checkpoint metadata, or adding an explicit structural-role/input-
complexity bound. Raw frame-window coalescing can reduce reads for clustered
non-delta objects, but does not by itself prove the bound for arbitrary frame
placement and external delta bases.

### Gate status at the second escalation

- Formatting, whole-workspace all-target/all-feature clippy, touched/reverse-
  dependency doctests and rustdoc, default and all-feature wasm32 clippy,
  `just ci-scripts`, `just ci-security`, and feature-base proto checks pass.
- Reverse-dependency nextest: 1,664 pass, nine skips. The initial parallel
  run timed out five existing CLI cases; all five pass individually and on
  unchanged parent `8e72df1d`; the full lower-concurrency rerun passes.
- Worker default conformance: 84 pass, zero failures, 131 skips, including
  30/30 cold-start checks. Signed runtime probes cover pass, quarantine
  rejection, invalid defer, stable request ids and fresh nonces.
- Focused complete-set/pipeline filter: 19 pass; shared dependency-budget
  regression passes; six native/channel/schema tests pass; new role-cost
  reproduction passes.
- `just ci-server` remains incomplete: its later run passed 2,153 tests,
  failed existing `wire_binary::binary_fs_sqlite_auth_v2_d34` at conformance
  `timers.redelivery_is_idempotent` (test timer tick returned unavailable),
  and left 332 tests unrun due to fail-fast. No isolated retry or parent
  comparison of that wire failure is claimed; Section D stops further gates.
- Production additions: 1,615 handwritten Rust lines; 1,760 including
  regenerated Rust and proto additions, excluding test-only artifacts and
  documentation. No production-cap escalation is needed.
