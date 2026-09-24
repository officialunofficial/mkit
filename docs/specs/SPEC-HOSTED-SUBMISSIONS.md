---
spec: SPEC-HOSTED-SUBMISSIONS
version: 1
status: draft-normative
audience: implementers of optional managed mkit hosting
---

# SPEC-HOSTED-SUBMISSIONS — durable private staged-update validation

Status: **Draft, normative** for the optional managed hosting profile. This
service protocol admits and validates a signed MKWU update against an existing
certified complete Snapshot without publishing a ref, packmap, or accepted
receipt. Core Commit, MKWU, MKWB, MKPL and full-clone bytes are unchanged.
Reference implementation: `apps/vcs-worker/src/{submission_wire,submission_frontier}.rs`
and `apps/vcs-worker/src/worker_impl/submission_*.rs`.

## 1. Authentication and routes

All routes use auth-v2 over the exact HTTP method, route, raw body digest,
audience and repository. Requests are uncompressed. JSON is exactly one object
with no duplicate or unknown fields; field order and whitespace are not
canonical. IDs are 64 lowercase hexadecimal characters. Full-width u64
generation/revision/counter fields are canonical decimal strings; leading
zeros, signs, exponents and overflow are invalid.

The configured repository owner alone calls `POST
/mkit/host/v1/CleanupSubmissions`. A freshly authenticated registered grant
subject alone calls:

| Route | Complete request fields after `version:1` |
|---|---|
| `/mkit/partial/v1/BeginSubmission` | `operation_id,workspace_id,grant_id,grant_generation,expected_ref,expected_base,update_digest,update_len,selected_paths` |
| `/mkit/partial/v1/UploadSubmission` | binary MKSU v1 carrier described below |
| `/mkit/partial/v1/ContinueSubmission` | `operation_id,submission_id,submission_generation,expected_revision` |
| `/mkit/partial/v1/GetStagedSubmission` | `operation_id` |
| `/mkit/host/v1/CleanupSubmissions` | `expected_cleanup_revision,max_rows` |

Begin is at most 256 KiB of raw JSON; other JSON is at most 64 KiB. `max_rows`
is an integer in 1..64. A selected path is an ordered UTF-8 component array
under the core partial-path rules. The exact declared selection is immutable.
`GetStagedSubmission` is an effect-free original-subject recovery lookup: it
requires a fresh valid request signature and healthy configured identity and
policy, but does not require an unexpired original grant. Foreign and missing
operation IDs receive the same opaque 403. Get never returns hidden object,
path, grant, or bundle content.

## 2. Immutable operation identity and upload carrier

The operation ID is repository-global and never reused. Begin binds exact
bytes, not merely equal JSON values: BLAKE3 of the bytes
`mkit/hosted-submission-binding/v1\0`, then u32-LE byte-length plus UTF-8
audience, u32-LE byte-length plus UTF-8 repository, raw 32-byte authenticated
subject key, u32-LE hosted profile version 1, u32-LE validator version 1,
and raw 32-byte BLAKE3 of the exact Begin body. A changed-byte retry under
the same operation ID conflicts. Auth nonce, request time, random submission
ID, mutable revision and policy epoch are not fingerprint inputs. A successful
new Begin atomically inserts identity, reserves quotas, captures exact current
ref/packmap/certificate/index, and charges one grant operation. A completed
retry charges nothing. No R2 I/O happens in Begin.

MKSU v1 has exactly 85 prefix bytes followed by the complete MKWU:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII `MKSU` |
| 4 | 1 | version `01` |
| 5 | 32 | raw operation ID |
| 37 | 32 | raw random submission ID |
| 69 | 8 | immutable admission generation, u64 little-endian |
| 77 | 8 | complete MKWU length, u64 little-endian |
| 85 | declared length | exact MKWU, no trailing bytes |

The entire binary body is auth-signed. The length is 1..4 MiB. A mismatched
operation/submission/generation/length/digest is rejected before modifying
the operation. A correctly bound carrier that fails complete MKWU profile
validation becomes a charged, saved terminal refusal. Intake uses exactly one
private key per operation, `BLAKE3("mkit.host.submission.quarantine.v1\0" +
ASCII admission generation + "\0" + ASCII operation ID + "\0" + ASCII MKWU
digest)`, under `quarantine/submissions/`. PUT is create-only; an existing
object must be read with exact declared length/digest before it can count as
an identical retry. The authenticated carrier is reread and sealed before
its bounded header facts or raw-pack locators become trusted local state.

## 3. Replies, replay and lifecycle

Normal replies have producer field order `version,operation_id,submission_id,
submission_generation,revision,state,progress`, with optional final `code`.
`progress` has decimal strings in order `inventory_entries,base_objects,
changed_pairs,required_objects,candidate_objects,attempts,reserved_io_bytes,
r2_operations`. Begin starts revision `"0"` and state `awaiting_upload`.
Successful semantic Upload/Continue pages and terminal refusal/expiry state
transitions increment revision; claims, reads and nonce replay do not. States
are `awaiting_upload`, `validating`, `validated`, `refused`, `expired`.
`validated` means staged source and declared selected content fit; it is not
accepted or published. A terminal summary preserves its original subject,
immutable binding, result and bounded progress even after bulky cleanup.

Live policy, grant, ref, packmap, certificate, profile, and request expiry
fence every effect and every Begin/Upload/Continue nonce replay. An exact
completed auth nonce returns its saved response; pending returns 202 without
new I/O or a heavy permit. A new effects request requires its current
revision. Get's historical exception does not authorize progress. A grant
charge and identity insert occur in the same short SQL transaction. No SQL
transaction spans R2 awaits. Each attempt has a monotone claim sequence,
two-minute claim lease, fresh at-most-five-minute structural read lease and
longer-lived exact certificate/index retention pin; the pin does not grant
current authority. A stale R2 result cannot apply after policy, grant,
ref/packmap, certificate, request-time, generation or claim drift.

Two active jobs per repository and one per ref include awaiting-upload.
Validation releases that active slot but retains its carrier, logical ledger,
pin and reserved terminal slot for seven days. Active bulky state expires
after 24 hours of inactivity. Get/replay does not extend terminal retention.
Before terminal reclamation, validated state is fenced to opaque `expired`.
Permanent operation identities/results are never evicted automatically:
maximum 1,024 per subject and 100,000 per repository, with no reset API.

## 4. Validation and independent resource bounds

The complete quarantine carrier is at most 4 MiB; its raw-v1 pack is at most
3 MiB and has at most 2,048 inventory entries. Each object ID is verified
against its canonical bytes. The host stores bounded inspected facts, not a
portable `Verified*` checkpoint. Complete base and candidate graphs may each
have 100,000 distinct objects, 256 MiB distinct canonical bytes, depth 128
and one million work units, independent of the small submitted update.

Independent v1 ceilings, in addition to the graph and fit bounds below:

| Resource | Ceiling |
|---|---:|
| Begin JSON / inspected MKWU header | 256 KiB / 128 KiB |
| Pending carriers per subject / repository | 4 and 16 MiB / 8 and 32 MiB |
| Reserved terminal summary slots per repository | 128, including active jobs |
| Durable frontier | 100,000 rows, 32 MiB encoded, 8 KiB per record |
| Inventory work / supplied payload | 4,096 units / 3 MiB |
| Required supplied set | 2,048 unique IDs / 3 MiB canonical bytes |
| Changed Tree-pair visits / diff work / origin work | 8,193 / 1,000,000 / 1,000,000 |
| Inspected Tree / manifest | 2 MiB and 65,536 entries / 32,768 chunks |

The permanent lifetime row retains only bounded identity/result metadata,
not the full Begin or header; bulky Begin data is capped separately at 256 KiB
and the sealed header separately at 128 KiB before encoding in job storage.
The exact authenticated base certificate index is the only source for base
objects; candidate reads use supplied bytes or that certified source. The
host checks full graph walks and changed-pair/file provenance using core
staged APIs, durable ≤64-record pages and exact source/required/supplied
ledgers. Every changed file/chunk representation must be supplied even when
an equal hidden object already exists. Required IDs must equal supplied IDs.
Promotion follows a paged exact coverage audit, not an unbounded graph scan.

The full declared selection, including unchanged files, is checked with the
same hosted C2 selected-builder limits: 4 MiB MKWB, 1 MiB total Tree
witnesses, 1 MiB selected content, 256 KiB per selected file. The fit builder
is one ephemeral attempt; timeout/retry discards it and pays its read budget
again. An ordinary Continue reserves at most 8 MiB and 66 R2 operations;
per-job caps are 8,192 attempts, 2 GiB reserved I/O and 540,672 operations.
Fit separately permits at most eight attempts, 4 MiB/2,048 operations each,
32 MiB/16,384 operations cumulative. Every known read size and operation is
pessimistically durably reserved before I/O, even failed/repeated reads.
Cooperative 20-second checks do not guarantee an interruptible R2 call or
synchronous decode. Caps are independent: not every logical maximum is
jointly reachable.

## 5. Bounded physical cleanup

Cleanup is owner-only and asynchronous. It first fences idle jobs in short
SQL transactions, preserving physical reservations. For one eligible key
per call it performs at most three HEAD/conditional PUT/confirmation cycles,
12 R2 operations, 4 KiB pessimistically reserved marker payload and a
20-second cooperative budget under a two-minute durable claim. Every I/O
attempt is charged before await. A failure retains quota for retry; a
completed nonce replay never repeats R2. `max_rows` counts 1..64 actual
business row transitions/deletions, including idle fencing. The 200 reply is
`version,cleanup_revision,affected_rows,has_more`, with decimal-string
counters and Boolean `has_more`; each successful call advances revision.

Reclamation never DELETEs the carrier key. It installs exactly 37 bytes:
ASCII `MKST`, version `01`, then BLAKE3 of
`mkit.host.submission.retired.v1\0` + ASCII operation ID + ASCII admission
generation + ASCII carrier key. It conditionally creates if absent or
replaces only the observed ETag, then boundedly GETs and compares the exact
marker before refunding carrier slots/bytes. A crashed cleanup repeats this
same key and marker. A late create-only intake cannot replace it, and the
stale SQL result cannot revive a job. The marker is never a repository pack
or a valid MKWU. Paged bulky child rows and the terminal slot are reclaimed
separately; immutable lifetime identity/outcome remains.

## 6. Errors and privacy

Nonterminal request, busy and transient error bodies expose only a bounded
`code`; saved terminal validation refusal additionally retains the bounded
SubmissionReply with progress and final `code`. Codes/statuses are 400 `invalid_argument`, 401
`unauthenticated`, 403 `permission_denied`, 409 `conflict`, 413
`resource_exhausted` for body bytes, 415 `unsupported_media_type`, 422
`invalid_candidate` or `unsupported_profile` for a correctly bound terminal
validation refusal, 429 `resource_exhausted` for quota/profile/busy, and
503 `unavailable` for transient storage, deadline or corrupt local state.
Responses use `Cache-Control: private, no-store`. Progress counters reveal
some aggregate graph size to the authorized original subject; the route
does not reveal hidden paths, object bytes or an acceptance decision.

Committed producer/consumer vectors are in
`rust/tests/golden/hosted-submissions/`. This service performs no
publication, accepted receipt, native push journal or default public Worker
route change.
