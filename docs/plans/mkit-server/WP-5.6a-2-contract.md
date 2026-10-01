# WP-5.6a-2 preservation core contract (R-190)

**Status: core implemented, locally checked with recorded baseline exceptions; activation off.** The current
reported production Rust count is 3,298 against merged base `cd680351`, below
PR2's 3,300 cap (64 production lines removed). Tests/docs/generated code do not
count. This records the source contract. The [verification report](WP-5.6a-2-verification.md)
distinguishes full-suite failures, isolated passes and unchanged-parent results.
It does not establish launch readiness.
The [PR2 brief](briefs/WP-5.6a-2.md) remains binding. All three parts are required
for launch; [PR3](briefs/WP-5.6a-3.md) supplies the restricted admin catalog.

## Durable layout and ownership

All rows use existing `b` subkeys; exact V1 `b 00 object:32` denial is unchanged.
Root work keys are `b 00 ff preservation 00 kind 00 request:32 tail`.

| Kind / tail | Meaning |
|---|---|
| `state` / empty | Strict V1 phase, retention, hold, purge/copy ownership, verification and discovery cursors. |
| `todo`, `object`, `discover` / object:32 | Acquisition queue, verified object facts and discovery candidates/progress. |
| `known-ns` / object:32 namespace UTF-8 | Provable namespace candidate for an object. |
| `pack-todo`, `pack-seen` / pack:32 | Whole-pack inventory traversal and restart-safe visitation. |
| `source` / object:32 | Exact source-selection checkpoint, candidate counters/cursor and delta-chain position. |
| `source-frame` / object:32 level:u32BE | Selected id:32, pack:32 and canonical index bytes; strict 95/127-byte rows. |
| `piece` / object:32 offset:u64BE | Immutable copy intent: content hash, object, offset and length. Kept after purge. |
| `closure` / manifest:32 | Ordered reassembly cursor, total bytes and bounded Merkle frontier. |
| `known-holder` / object:32 namespace UTF-8 00 name UTF-8 | Known holder facts with explicitly incomplete context/signer metadata. |

Discovery context uses `b 00 ff discovery-context 00 request:32 object:32`
followed by `namespace UTF-8 00 name UTF-8 00 pack:32`. Late provenance uses
`b 00 ff late-source 00 request:32`. Existing ct/timer-13 transfers only after
exact provenance, owning request, audit and timer-15 responsibility are durable.
No new tag, wire version, storage primitive or catalog protocol is introduced.
Timer-15 local access uses `TimerCtx.store`; adapters wire the real owner/work
handlers while production activation remains fixed false.

Preservation uses a separately provisioned existing BlobStore. Each immutable
piece hashes `request:32 || object:32 || offset:u64BE || canonical slice`; the
72-byte owner header is stored with it. A piece plus header is at most the
existing 1 MiB blob-piece bound (payload at most 1 MiB minus 72 bytes).
Intent commits before PUT; stored bytes and
header are verified before acquisition progress commits. Purging first owns the
request under CAS, refuses a new hold, verifies each piece's owner before DELETE,
and audits progress. Retained intents permit later passes to remove delayed PUTs.
One request's deletion cannot target another request's preserved copy.

## Verification and bounds

Source selection persists exact frame rows with its checkpoint CAS, inspecting
at most eight candidates per step. Final reconstruction freshly checks selected
index/membership rows; changed/deleted middle frames fail closed. The five
focused source tests pass: formerly 773/26,723-call dense fixtures now checkpoint
selection at at most 12 counted backend calls per source step, and 50-hop final
decode uses 357 calls within its 700-call allowance. Coverage includes 511 empty
continuations plus a partial 128-row group and all 4,096 candidates. These are
source-step counts, not a claim that an entire alarm uses only 12 calls.

Manifest closure retains ordering/duplicates, sums canonical Blob lengths and
checks the manifest root using a bounded frontier. It relies on historical
verified acquisition of every child payload and freshly verified preserved
header pieces; it does not reread every child payload during closure. PR3 MUST
freshly verify every piece actually emitted by ReadPreserved.

The Worker allowance is conservative arithmetic for valid admitted geometry:
1 MiB decoded entries, 16 MiB frame/read windows, 50 hops, 51 MiB retained chain and a
96 MiB acquisition allowance. Allocator fixture measurements are separate from
that arithmetic and do not establish whole-Worker RSS. R-203 bounds pure-Rust decoding with an 8 MiB zstd window and RFC per-block
preflight before materialization. Allocator regressions enforce output claim
plus a fixed 28 MiB working allowance, including transient ring growth.
Decoded corruption of a selected member is terminal and audited, with source
provenance retained and discovery/preservation completeness left unresolved.
Resource exhaustion and unavailable storage remain retryable. Denial stays in
force in every case.

Native profiles retain at most the configured decode budget and validate
configured chain-depth caps through 65,535. Their checked resident allowance
is eight times that budget plus 128 MiB; the logical slice-call allowance is the greater of 700 and
`8 * (depth + 1) + 256`. Worker work uses 700 logical calls and shares the actual
1,000-call alarm counter across remote metadata and R2. Each acquisition step
copies at most eight pieces; closure advances at most 64 ordered chunks (196
counted calls for its full slice). Initial object seeding advances at most 32
targets and whole-pack inventory pages at most eight entries per step.

Finite namespace sweeps wait for the safety cut and relay watermarks. Any
supports named-repo preservation and provable named/known-holder namespace
sweeps, never exhaustive discovery or takedown completion. Missing final signer
context stays incomplete. Verified preservation is never real takedown completion.

## Remaining launch work

PR3 must expose signed moderation-role Get/List/ReadPreserved/SetLegalHold with
byte-free nonce descriptors and fresh audited verified streams. Its SetLegalHold
must commit `plan_legal_hold` with the operator's audit and replay result in the
same batch; the core planner alone supplies no signed admin operation.
ReadPreserved remains unexposed. Local gates and independent reviews are recorded
in the [verification report](WP-5.6a-2-verification.md), including the native timer
and Worker transport baseline exceptions. Activation/readiness work remains
required. Storage provisioning and external staging are user work. The exhaustive Any catalog and full-profile rewrite,
notices/reinstatement/completion remain the approved post-launch scope.
