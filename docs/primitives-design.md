# Sans-IO protocol primitives

The primitive boundary consumes explicit input and produces requests, evidence,
or guarded decisions. The host acquires bytes, retains evidence, supplies clocks
and authority facts, executes work, and commits effects. A primitive does not
open files, start threads, query storage, or publish repository state.

## Crate boundary

`mkit-primitives` has an independent API version, initially `0.1.0`, and an
ALPHA public surface. Its normal dependencies are core protocol arithmetic,
stability macros, and error support. Existing object codecs, type-dependent
identity, individual signatures, deltas, pack decoding, and subtree arithmetic
remain in `mkit-core`. Native and wasm32 builds use the same public contracts.

The default decoder is pure Rust. An optional native backend selects the core
native decoder; a raw-only build refuses compressed input as an unsupported
capability. Backend availability never converts undecoded bytes into evidence.

API, ruleset, checkpoint, and evidence format versions are independent.
Unsupported disposable checkpoint formats require a restart from the bound
source. Cargo compatibility alone does not promise checkpoint compatibility.

## Implementation status

The crate implements bounded two-pass framing, all-entry verification,
page and proof codecs, strict checkpoint envelopes, and optional caller-owned
compute. `FramedPack` records integrity and framing only; `VerifiedPack` seals
canonical, delta, and individual signature evidence. Closure and guarded
decisions have separate entry points. Framing completion establishes none of
their semantic checks.

The driver resumes integrity, acknowledged entry, and completion boundaries.
Decode restoration checks the core cursor's validated metadata against every
outer source, window, header, position, payload and entry binding. It recovers
all retained predecessor pages before decoding. Envelope decoding alone does
not provide those checks or authorize resumption.

## Evidence layers

The all-entry `VerifiedPack` contract establishes pack identity, framing, canonical objects, resolved
deltas, and every required individual signature under a ruleset and profile.
It does not establish repository membership or read authority.

`ClosureProof` establishes direct-child closure for the requested heads in a
particular repository view. It retains the exact external observations it uses.

`Guarded<AcceptanceEffects>` describes a decision and its required live
comparisons. Only the host's successful atomic comparison and effect commit
accepts an operation. Published-source pre-apply fences remain separate from
destination atomic guards.

These types have private construction. Checkpoint or page decoding never
constructs them. They support correct composition in a trusted process; they
are not remote attestations against a malicious host.

## Pull execution and framing

An acquisition names a request generation and sequence, immutable source,
offset, and exact byte length. The initial driver has one outstanding request.
Responses distinguish present input, authoritative absence, and unavailable
acquisition. Missing retained bytes cannot establish object absence.

The initial framing strategy checks minimum length, magic, and version, then
authenticates the trailer and whole-pack identity, and finally decodes frames
in wire order. Both passes read the same immutable source binding. The core
window reader supplies frame geometry and decoder behavior. Framing completion
has its own result type and cannot substitute for all-entry verification.

Decoded events remain provisional until their owning verification machine
completes. A host retains them privately or reproduces them from the immutable
source. It must not publish objects or advance heads merely because a frame
decoded successfully.

## Budgets and retention

Content ceilings and execution limits are distinct. The indexed content
profile retains the advertised pack limit, configured cumulative canonical
decode limit, per-object limit, and effective delta depth. Execution limits
bound acquisition size, simultaneous owned memory, decoder scratch, evidence
pages, checkpoint size, cumulative evidence, lookups, edges, and work.

Charges precede allocation and use checked arithmetic. Decoder calls reserve
their conservative window, carried frame, decoded output, and backend scratch
before entry. A borrowed event does not release its backing buffer's charge.
The next mutable transition releases an event only after its borrow ends.
Host-owned source and retained-page storage need an additional host budget.

The page codec supplies bounded pages and authenticated paths rather than an
object-count-sized resident map. Objects are keyed by type-dependent object ID;
the framing driver emits an ordered chain of one occurrence leaf per frame.
Each record commits its predecessor digest and frame geometry. Object indexing
and first-occurrence ownership belong to all-entry verification. A nonmembership result requires
an authenticated path to the correct leaf. A host's missing page is an
acquisition failure.

Retention events apply backpressure. No dependent checkpoint or completion can
refer to a page until the host acknowledges its exact commitment. Page loss
requires recovery or re-verification. Replaced pages still count against
cumulative evidence and work limits.

## Checkpoints

A checkpoint binds the source identity, length and immutable version,
repository, ruleset/profile, effective limits, run generation, phase, consumed
counts, completed integrity subtrees, retained roots, and acknowledgment
position. Only safe boundaries are resumable. An active decoder or hasher's
private memory is never serialized.

The integrity pass retains completed 8 MiB subtree commitments for the trailer
digest and whole-pack digest. A partial subtree is replayed after restart.
Small sources replay a bounded span using the ordinary incremental hash API.
The decode pass retains a validated core entry-boundary cursor and rereads the
current window's authenticated prefix on cold resume.

A corruption checksum is not host authentication. A host receiving checkpoints
from an untrusted client must authenticate the complete envelope and bindings,
or discard it and restart. Strict decoding refuses unsupported versions,
duplicate or noncanonical records, inconsistent counts and offsets, overflow,
trailing bytes, and missing retained evidence.

## All-entry verification and optional compute

All-entry verification validates canonical encoding, type-dependent identity,
eligible delta bases, effective chain depth, and individual signatures. Earlier
reconstructed in-pack objects are eligible bases. External bases require
repository-scoped verified-member facts and immutable canonical-byte bindings.
Objects from another repository or a later pack entry do not satisfy that rule.

Initial header checks precede integrity; integrity precedes structural and
canonical decoding in ordinal order. Signature failure selection waits until
the required decode work finishes. Worker completion order must never select
a different refusal. Reference-path parity fixtures pin existing public codes
and attribution before integration.

Serial computation remains the default. Optional jobs bind run generation,
ordinal, operation, input commitments, and byte/work permits. The library
supplies the pure worker and creates opaque outputs. Results merge by ordinal;
stale completions are ignored. Worker input, scratch, and output count against
the same simultaneous memory ceiling.

`VerifyDriver::with_compute` enables a finite queue of at most sixteen jobs.
The driver emits descriptors through `Request::Compute`; the caller takes each
owned job once, runs the pure worker, and returns its opaque output. Raw Blob
entries may overlap inside an acquired window. Other object kinds and deltas
are barriers, as are input acquisition and later parser failures. This avoids a
second dependency graph and keeps every authenticated index mutation serial.
Deltas enter compute only after their eligible base is resolved.

Optional lookahead protects a conservative complete Blob-commit allowance and
worker input/scratch/output ownership before dispatch. Insufficient room drains
the queue; it does not add a content refusal. A completed later output retains
its permits until all earlier ordinals commit. No job is persisted: checkpoints
require a drained queue and reader position, and resume may choose serial or
caller-owned execution without changing evidence formats.

## Validation and integration

Every encoded type requires a decoder inventory entry, portable byte fixtures,
semantic descriptions, bounded fuzz targets, and deterministic seed replay.
Fixture checks are read-only and reject missing or orphan files. Native tests
cover default and native-only backends; raw-only and both-backend builds have
targeted capability and differential checks. Selected fixtures execute on
wasm32. Compiler-derived stability inventories and minimum-level builds cover
the public graph, including re-exports and inherited annotations.

The implementation sequence establishes shared types, then framing and durable
evidence, then all-entry verification, and finally optional compute. Closure,
authorization, acceptance decisions, fork activation, and acceptance-evidence
encoding have their own owners. The independent release gate precedes registry
publication; the workspace release train excludes this crate.

The [retained-state specification](specs/SPEC-PRIMITIVE-EVIDENCE.md) defines the
exact page, proof, checkpoint, and ordered framing-record bytes, including the
distinct length-prefixed page and checkpoint hashing domains. These are
reconstructible state formats and grant no repository authority.
