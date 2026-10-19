# mkit-primitives

Bounded sans-IO pack framing, all-entry verification, and evidence codecs, with
repository closure and guarded write decisions.
Version **0.1.0** is independent of the workspace release train. All public
APIs are **ALPHA**. The crate also provides guarded fork acceptance and
bounded direct-child closure with authenticated local evidence pages, auth-v2
validation, replay classification, and acceptance-evidence envelopes. The reference
server depends on this crate; publish its required version independently before
publishing a workspace release that uses it.

Callers acquire immutable byte ranges, retain evidence, supply observations,
and commit effects. The crate has no storage callbacks, runtime, HTTP client,
or server dependency. It supports `std`, including `wasm32-unknown-unknown`,
and forbids unsafe code. Core retains existing codecs, hashes, and signatures.

## Frame an immutable source

`FramingDriver` first checks the header, then authenticates the complete pack
and trailer, and finally decodes frames in wire order. Its borrowed frame
payloads remain provisional. `FramedPack` establishes integrity and framing;
canonical objects, delta resolution, and signatures require all-entry
verification.

```rust
use mkit_primitives::{
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::framing::{FramingDriver, FramingStep},
};

let source = PackSource {
    id: [1; 32],
    len: 128,
    binding: SourceBinding([2; 32]),
};
let profile = IndexedProfile {
    pack_bytes: 4 << 30,
    decoded_bytes: 4 << 30,
    delta_depth: 32,
};
let mut driver = FramingDriver::new(
    source, RepositoryId([3; 32]), profile, VerifyLimits::indexed(), 1,
)?;
assert!(matches!(driver.step()?, FramingStep::Request(_)));
# Ok::<(), mkit_primitives::error::Failure>(())
```

For `Request`, supply the exact requested range and bindings through `Response`.
`Frame` borrows decoded bytes until the next mutable driver call. For
`RetainEvidence`, retain the exact page bytes before calling
`acknowledge_retention` with its commitment. Repeated steps return the same
retention event until acknowledgment. `Progress` yields cooperatively;
`Complete` returns framing-only evidence. Missing input never means success.

`VerifyLimits` bounds acquisitions, simultaneous primitive-owned memory,
checkpoint size, cumulative evidence, and work. `IndexedProfile` separately
names content ceilings. Decoder reservations include window buffers, carried
frames, decoded output, and scratch. Hosts budget their own source buffers and
external retained-page storage separately.

## Verify every entry

`pack_verify::verify::VerifyDriver` hashes the pack while decoding each
canonical object in wire order. It acquires each source range once on a
successful uninterrupted run; canonical delta bases may require separate
requests. It resolves deltas from earlier
entries or repository-scoped `MemberFact` bases and verifies each applicable
signature individually. Construction uses the same source, repository, profile,
limits, and fresh run generation as framing. Drive it through `Step`, supply
the requested `Response`, and acknowledge retained pages before advancing.

`ObjectFragment` bytes remain provisional until `Step::Complete` returns a
privately constructed `VerifiedPack`. The artifact exposes exact counts,
including `delta_entries`, and authenticated object, occurrence, ordinal,
dependency, and head roots. Read `DependencyRecord` values to distinguish graph
edges from external base facts. Missing retained evidence is unavailable input;
it cannot establish absence or completion. Repository closure and live write
authorization remain separate checks.

Entry failures, including authenticated external-base absence, remain deferred
until the trailer and whole-pack identity verify. The first entry failure wins
in wire order; integrity failure takes precedence. Unavailable acquisition
returns immediately and never manufactures absence. Signature failures remain
deferred behind integrity and decode failures.

## Schedule pure compute

`VerifyDriver::new` executes serially. Opt in with
`driver.with_compute(ComputeConfig::new(3))?`. The finite capacity is
one through sixteen outstanding jobs, including completed outputs awaiting
merge. Raw entries smaller than 64 KiB decode inline by default; this avoids
worker wakeups for cheap work. Set the canonical-byte threshold with
`ComputeConfig::new(3).with_min_job_bytes(bytes)`. Zero dispatches every entry;
deltas still use jobs. This changes execution scheduling only: evidence,
refusals, work charges, and checkpoint encoding remain the same.
When `Request::Compute { job }` appears, call `take_compute(job)` once,
move the returned `ComputeJob` to your worker, execute `run()`, and return its
opaque `ComputeOutput` through `supply_compute`. The crate starts no threads.
Repeated polling preserves an untaken request; a taken job remains outstanding
until its output returns. Retrying a lost job requires restarting the run.

Each descriptor binds the immutable source, repository, generation, request
sequence, frame ordinal and placement, validated delta base, operation, and
memory/work permits. The requested whole-pack identity and provisional frame
placement bind the input. Only terminal `Complete` authenticates the pack. Jobs
are local state with no serialized format. Current-run
mismatches refuse without advancing. Stale generations and retired or duplicate
outputs are ignored without budget changes. Results, fragments, and evidence
merge in ordinal order, preserving the serial artifact and refusal precedence.

Independent raw Blob entries can overlap within the current acquisition window.
Other objects, deltas, new windows, parser refusals, and completion form barriers.
A delta resolves its eligible predecessor before its job is issued. Admission
reserves input, scratch, and output ownership until ordinal commit, protects
bounded Blob index-commit headroom, and escrows worst-case work. Tight budgets
drain the queue instead of refusing optional overlap. Completed outputs retain
their charge while an earlier job is outstanding. Signature checks remain
individual. No checkpoint can contain an outstanding job or read-ahead frame.
A fully committed entry boundary can be checkpointed while later jobs remain
in flight; the snapshot contains only that committed prefix. Batches stop before
replacing the window needed to bind that boundary.

Retire or drop all jobs and outputs before replacing a driver's resource
envelope. A new generation rejects old completions but does not free memory
still owned by your old workers. Resume uses the same checkpoint format and
starts serially; opt in again after `VerifyDriver::resume` if desired.

## Decode bounded evidence

`encode_leaf` and `encode_internal` construct canonical pages; `BranchChild`
names an internal separator and child commitment. Page decoding checks
structure and exact context. A proof additionally checks
each page against a trusted root and the routed query interval. A missing path
cannot prove absence. Every nested page shares the proof's cumulative budget.

```rust
use mkit_primitives::{
    evidence::{
        PackSource, PageKind, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
        pages::{EvidenceBinding, INDEXED_RULESET, PageView, encode_leaf},
    },
    limits::EvidenceLimits,
};

let binding = EvidenceBinding {
    source: PackSource { id: [1; 32], len: 44, binding: SourceBinding([2; 32]) },
    repository: RepositoryId([3; 32]),
    ruleset: RulesetBinding { ruleset: INDEXED_RULESET, profile: ProfileId::Indexed },
};
let limits = EvidenceLimits::indexed();
let page = encode_leaf(binding, PageKind::Objects, &[], limits)?;
let view = PageView::from_bytes(page.bytes(), binding, limits)?;
assert_eq!(view.items(), 0);
assert_eq!(view.commitment(), page.commitment());
# Ok::<(), mkit_primitives::error::Failure>(())
```

`VerifiedPack`, `ClosureProof`, and `Guarded<D>` have private construction.
Checkpoint and page decoders cannot create them. Host-supplied facts are trusted
observations, not remote attestations. Only a successful host atomic comparison
and effect commit accepts a write. The verifier, closure walker, and decision
implementations have separate entry points. Framing completion establishes none
of their object, closure, or acceptance checks.

## Features and state formats

The default `pack-ruzstd` feature selects pure-Rust decoding. `pack-zstd` enables
the native backend. Raw-only and both-backend builds are supported. A raw-only
build refuses compressed frames as an unsupported capability. Native decoding
is not a wasm configuration.

Crate API version, normative ruleset, semantic profile, and encoded format
versions are separate contracts. The initial indexed ruleset is 1. Page,
proof, pair-coverage checkpoint, and ordered framing-record formats use version
1. Framing checkpoints use envelope version 1; all-entry verification
checkpoints use version 4 and bind six evidence roots, cumulative verification
counters, the external-base commitment, and any deferred refusal.
Unsupported disposable state versions require restart from the immutable
source; historical readers are not promised. Existing pack and object bytes
remain unchanged.

`Checkpoint::from_bytes` checks envelope syntax and bounds. Its checksum detects
corruption and does not authenticate hostile state or authorize resume. Hosts
must trust retained checkpoints or authenticate the complete envelope and its
bindings. Resume must validate expected context, cursor consistency, and
retained evidence before advancing. Active decoder and hash-library memory is
never a persisted checkpoint format. All-entry verification checkpoints at
acknowledged entry boundaries under a fresh generation. A refused
`checkpoint()` arms the request; at the next drained entry boundary the driver
flushes buffered records and retains every page the host does not yet hold,
then reports readiness with `Progress`. Call `checkpoint()` again before the
next mutable call, and persist the result before stepping on: pages only the
previous checkpoint reached are released afterwards (`Step::ReleasePage`).
Evidence pages belong to the run; an ephemeral run
(`VerifyDriver::new_with_retention`) never checkpoints and leaves the host only
the pages its cache evicts. Resume compares core
cursor metadata with every outer binding and audits retained evidence. Its
explicit hash-tree frontiers include the already-acquired window; a commitment
binds the remaining suffix. Resume fetches only that suffix, starting at the
entry boundary, and authenticates it without hashing it into the frontiers
twice. It never reacquires the consumed prefix. Framing-only checkpoints retain
their existing current-window prefix check. Cumulative budgets survive restart.

## Module and decoder inventory

Every public item inherits ALPHA from its enclosing module, including fields,
variants, associated items, trait members, and re-exports.

`FailureCode::as_str` values stay stable within a ruleset. Existing codes must
not be renamed, removed, or repurposed. The single semantic code registry pins
the full set; diagnostic `Display` text is not a code parser.

| Module | Contract |
|---|---|
| `error` | Stable `FailureCode::as_str`, `Failure`, numeric location, bounded detail |
| `limits` | Finite execution and evidence budgets; explicit indexed content ceilings |
| `evidence` | Repository/source/revision/ruleset bindings and repository-scoped facts |
| `evidence::pages` | Canonical bounded leaves/internal pages and commitments |
| `evidence::proof` | Authenticated inclusion and absence against an expected root |
| `evidence::checkpoint` | Strict current-version untrusted checkpoint envelope |
| `pack_verify` | Request/response contracts, resource usage, opaque `VerifiedPack` accessors |
| `pack_verify::framing` | Two-pass pull driver, provisional frames, retention, `FramedPack` |
| `pack_verify::verify` | All-entry canonical/delta/signature verification, paged evidence, cold resume, sealed `VerifiedPack` |
| `pack_verify::verify::records` | Strict fixed-size object, occurrence, ordinal, head, and dependency codecs |
| `closure` | `ClosureWalker`, finite `ClosureLimits`, batched facts, authenticated local pages and opaque closure/missing results |
| `fork` | Bounded full-inventory plans, final source fences, guarded acceptance and exact terminal replay |
| `auth` | Portable envelope verification and host-authenticated claims binding |
| `replay` | Pure replay classification and exact saved results |
| `evidence::acceptance` | Bounded canonical acceptance-evidence envelope |
| `decision` | Snapshots, guards, source fences, effects, decisions, opaque `Guarded<D>` |

In-memory bindings and decision facts have no invented serializer. Acceptance
evidence uses its own strict version-one envelope; closure pages retain their
separate version-one formats.

| Encoded input | Decoder | Bounds |
|---|---|---|
| Pack frames | `FramingDriver::supply` and `step`, through core `WindowReader` | `VerifyLimits`, `IndexedProfile`, fixed frame/output caps |
| Page v1 | `PageView::from_bytes` | `EvidenceLimits`, 16 items, 1 MiB format cap |
| Proof v1 | `proof::verify_path` | One shared `EvidenceLimits` budget, at most 33 pages |
| Framing record v1 | `FrameRecord::from_bytes` | Fixed 58 bytes, checked frame geometry, no allocation |
| Closure state/witness/missing pages v1 | `closure::output::{validate_state_page, decode_witness, decode_missing}` | `PageDecodeCfg`, fixed 1,024-byte internal journal cap |
| Acceptance evidence v1 | `AcceptanceEvidence::decode` | Explicit `AcceptanceEvidenceDecodeCfg` envelope, operation, head and dependency caps |
| Checkpoint v1 and v4 | `Checkpoint::from_bytes` | `VerifyLimits`, 518 values per frontier, 4096-byte core cursor |

The fixture manifest registers encoded formats, canonical bytes, semantic
sidecars, expected outcomes, decoder names, and fuzz targets. Its read-only
runner rejects missing and orphan files. Stable seed replay exercises the
bounded fuzz entry points. The private cursor and cumulative budget provide
checked reads and fallible allocation without a public generic codec trait.

## Fork acceptance

Use `fork::ForkPlan::seal` with complete authenticated whole-pack inventories,
including transitive external suppliers. Call `fork::decide_fork_acceptance`
with exact typed destination facts and the final source proof. Acceptance saves
the terminal response, replay response, and outcome responsibility and settles
the exact reservation in one atomic unit. It emits no visible membership,
ref, or permission to write. Activation is separate published clearance.

The host compares every returned destination fact and revision atomically.
Its emptiness revision covers phantom additions. The source proof is a separate
ordered fence after the final staged membership effect and before this apply
attempt. A later source change cannot invalidate acceptance or a saved result.
See the [guard matrix and host contract](docs/fork.md) for exact requirements,
resource bounds, replay rules, and verification scope.

Run `cargo run -p mkit-primitives --example fork_acceptance` for a complete
plan-sealing and acceptance example using deterministic host observations.

## Direct-child closure

Drive `closure::ClosureWalker::new` with the complete verified object view, the
sealed `VerifiedPack` that supplies its object-set root and ruleset,
requested heads, repository identity/incarnation, ruleset, finite limits, and a
fresh run generation. Poll `step`; answer exact acquisition requests and retain
and acknowledge every page. Only `Closed` or `Missing` is a complete result.
The API example demonstrates an empty view; real views bind every record and
manifest summary to their sealed pack-verification artifact, and report
retained view memory through `InPackObjectView::retained_bytes`.

The proof's `relied_on_members` points to witness pages exposing exact supplier
packs and membership revisions. Acceptance guards those facts separately from
publication, external delta-base suppliers, denial, inspection, and authority.
Direct-child closure does not establish resulting-pair coverage. Tree/tag kind
hints and cycles are diagnostics; every chunk occurrence requires Blob integrity
and checked manifest totals. Resource exhaustion never returns a truncated set.

Pages are local evidence, not transport messages or remote attestations. After
page loss, replay from the same immutable inputs with a fresh generation.

## Resulting-pair coverage

`closure::pair::PairWalker` verifies the resulting-pair obligation of
SPEC-SERVER section 10.2 without storage access: every packmap-chain pack is
published or added by the advance, the head's reachable closure is contained
in chain packs, and external delta-base suppliers are recorded separately so
an advance's own additions never satisfy them. `closure::pair::pair_requirement`
decides when coverage applies at all: deletion is exempt, and the immediate
path without inspectors, takedown, or custom verification is exempt. The host
owns membership reads, cost accounting, and refusal mapping; every caller
bound is explicit in `PairLimits`.

`PairWalker::checkpoint` encodes local resumable progress; `resume` binds the
bytes to their expected parameters under a fresh generation. A checkpoint is
corruption detection, not authentication, and creates no coverage on its own.
Denial, inspection, publication state, and authorization remain separate host
guards; a `PairCoverage` result never authorizes publication.

## Authentication and replay

`auth::validate_envelope` delegates raw canonical fields, commitments, time
bounds, and strict signatures to `mkit_core::write_auth`. Call
`auth::inspect_headers` on raw header multiplicities first: any field in
`auth::TRIGGER_HEADER_NAMES` marks an envelope. Repository addressing and an
idempotency key alone do not. Partial or duplicate envelopes fail closed. Unary
requests require `x-digest`; upload streams may omit it. Trusted destination
identity comes from configuration and resolved addressing. Verification grants
no permission and reserves no nonce.

Envelope expiry is inclusive at ingress. Current host acceptance deadlines
remain separate; replay never extends envelope validity. Signed reads verify
fully and bypass the replay ledger.

`replay::classify_replay` returns the saved terminal result by reference. Hosts
supply successful durable results through `RecordedResult::success`; permanent
refusals pass the explicit allowlist through `RecordedResult::rejection`.
Challenges, membership lag, pending verification, and unavailable inspection
cannot be constructed through the rejection path. A fresh result requires an
absence guard before reservation or commit. A different fingerprint conflicts;
nonresumable in-flight work is retryable. Hosts atomically guard replay and
commit its transitions with their effects.

Claims validation takes borrowed principal and pack bindings after the host
has authenticated its token. Token encoding, MAC, keys, rotation, expiry,
current ticket state, and authorization remain host responsibilities. There is
no portable token encoding or new signing domain.

## Acceptance-evidence decoder inventory

`evidence::acceptance::AcceptanceEvidence` is an immutable canonical envelope
for authenticated delivery inside one trust domain. `decode(bytes, cfg)` requires explicit finite envelope, operation,
head count, per-head byte, cumulative head-byte, and dependency bounds, plus an
exact ruleset and profile/limits commitment. There is no unlimited default.

`encode()` borrows the canonical bytes; `encoded_len()` returns their checked
exact length. `digest()` uses `mkit-acceptance-evidence:v1`, one NUL, and the
canonical encoding. `check_binding()` compares the writer's frozen pack and
operation. `recheck_heads()` individually verifies canonical commit, remix,
and tag ids and signatures using core. No method accepts a write or manufactures
a verified pack, closure proof, or guarded decision. Origin authentication and
atomic live guard comparison remain host responsibilities.

The [acceptance-evidence specification](../../../docs/specs/SPEC-ACCEPTANCE-EVIDENCE.md)
defines every field and compatibility rule. The fixture manifest registers 49
portable cases with explicit configurations and stable outcomes, including nine
digest vectors. Tests consume these files read-only. To deliberately regenerate
an approved format change, run **tools/generate-acceptance-fixtures.py** with
the Python `blake3` package installed, inspect every changed vector, and update
the specification and version policy together. The same bounded fuzz body runs
in stable corpus replay and the scheduled `acceptance_decode` target.

## Fork progress and published clearance

`fork::decide_fork_advance` fences each advancing unit against the recorded
authority, applicable grant epoch, and pre-acceptance reservation protection.
`decide_fork_activation` returns membership installation, exact replay, or a
guarded refusal. `decide_fork_completion` authorizes the final owned write-barrier
release only after complete accepted progress. These decisions emit no terminal
outcome or settlement. Like the ref decisions, they return `decision::Guarded<D>`
with owned typed guards, and `decide_clearance` does too; `decision::guards_hold`
compares them against the live guards a host derives with each facts type's
`guards` method.

The [activation contract](docs/fork-activation.md) explains the complete guard
matrix and host proof obligations. Run `cargo run -p mkit-primitives --example
fork_activation` for a bounded membership decision.

## Guarded ref decisions

`decision::ref_write` decides ref updates, paired advances, exact deletions,
and publication metadata from bounded authoritative observations. Preserve the
sealed `Guarded<WriteDecision>` through lowering and atomically compare every
returned dependency with all composed effects. See the [guard matrix and host
contract](docs/guarded-refs.md) for refusal, replay, source-fence, and completeness
rules. No physical storage representation enters the decision.

Run `cargo run -p mkit-primitives --example ref_decision` for a complete
acquired-absence decision and guard-completeness check.

The in-process `from_verified` export additionally accepts bounded caller-supplied
canonical heads and streamed authenticated closure witnesses. See the
[export contract and resource model](docs/acceptance-evidence.md). It preserves
format 1 and does not add a wire form for either sealed artifact.

## Measure entry cost

Run `cargo bench -p mkit-primitives --bench entry_cost` from **rust/**. The
benchmark uses a reused worker set and collects each batch before supplying
outputs. It reports wall and process CPU microseconds per entry, plus each
run's largest outstanding batch and active-worker peak. CPU includes user and
system time across all threads. Each mode uses a 16 MiB acquisition window and
256 MiB resident envelope, enough for eight large-entry jobs. Pack generation
and worker startup are outside timing.

The fixtures include tiny blobs, 3,000 files of 4 KiB with a tree and three
signed commits, and 150 blobs of 1 MiB. Read-back decodes occurrence pages and
walks every record. Pass a fixture-name substring to select a pack. Set
`ENTRY_COST_RUNS` to choose the sample count or `ENTRY_COST_JOBS` to select one
job count (zero is serial). `ENTRY_COST_MIN_BYTES=0` measures all-entry job
dispatch. `ENTRY_COST_HOST_PROFILE=1` adds a separate replay of page copying and
`HashMap` storage; those timings estimate host costs and are outside run samples.
