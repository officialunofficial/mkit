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
