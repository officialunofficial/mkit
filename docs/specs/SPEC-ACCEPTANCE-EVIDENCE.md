---
spec: SPEC-ACCEPTANCE-EVIDENCE
version: 1
status: stable-normative
audience: implementers of verifier and acceptance hosts
---

# SPEC-ACCEPTANCE-EVIDENCE &mdash; cross-process acceptance facts

Status: **Normative** for acceptance evidence format 1.
Scope: the bounded library byte contract between a trusted verifier and an
acceptance writer, including binding, digest framing, and host obligations.
Endianness: **little-endian** throughout.

External implementations MUST be able to produce and consume this envelope
from this document and its referenced object and signing specifications.

## 1. Scope and trust boundary

An acceptance writer MAY delegate pack verification to a stateless verifier in
the same trust domain. The verifier supplies the following bounded envelope.
This is an optional library byte contract. Its requirements apply when this
envelope is used. It is not a remotely verifiable attestation.
Decoding or hashing the envelope MUST NOT construct a verified pack, closure
proof, or guarded decision. The host MUST authenticate the complete envelope's
origin and integrity before relying on its assertions. A digest alone does not
provide that authentication.

Repository identity resolution and replay retention MUST follow
[SPEC-PRIMITIVE-EVIDENCE §1.1](SPEC-PRIMITIVE-EVIDENCE.md#11-repository-identity).

Before acceptance, the writer MUST compare the pack id and exact length with
its own immutable frozen record, and compare repository, operation, and epoch
with the intended operation. Replay protection binds the tuple (repository,
pack id, operation, epoch). The writer MUST run its pure acceptance decisions
and atomically compare all resulting live guards when committing effects.
Every mutable fact relied on by verification or decisions MUST be guarded in
that atomic unit, as required by [SPEC-SERVER](SPEC-SERVER.md) §3.
Membership and denial versions in this envelope are observations, not authority
to skip live guards. A writer that decides over this envelope derives them as the
typed guards of an acceptance basis ([SPEC-PRIMITIVE-EVIDENCE](SPEC-PRIMITIVE-EVIDENCE.md)
§4.4): the witness pair and the denial version are compared exactly and
atomically, and the envelope digest is the root binding for every other field. Head rechecking does not establish closure or authorization.

## 2. Canonical binary encoding

Integers are unsigned little-endian. Hashes and keys are raw 32-byte values.
The following fields occur exactly once in the listed order. There is no
padding, optional extension area, or digest field. Counts include exactly the
records that follow. Unknown versions and tags MUST be rejected.

| Field | Encoding | Bound or rule |
|---|---|---|
| Magic | 4 bytes, ASCII `MKAE` | Exact literal |
| Evidence version | u16 | 1 |
| Ruleset id | u32 | Must equal the explicitly supported ruleset |
| Profile/limits digest | 32 bytes | Must equal the configured profile and effective-limits commitment |
| Repository id | 32 bytes | Opaque logical repository identity, independent of storage routing |
| Operation id | u32 length, then opaque bytes | Configured maximum; empty is permitted |
| Epoch | u64 | Host-supplied replay epoch |
| Pack id | 32 bytes | Whole-pack content address |
| Exact pack length | u64 | Includes the complete pack |
| Object count | u64 | Entry occurrences, including duplicates |
| Delta count | u64 | Must not exceed object count |
| Object-set root | 32 bytes | Commitment from completed pack verification |
| Head count | u32 | Configured maximum |
| Heads | Repeated head records below | Strictly ascending unique object ids |
| External dependency count | u32 | Configured maximum |
| External dependencies | Repeated 32-byte member pack ids | Strictly ascending unique byte order |
| Membership generation | u64 | Membership incarnation observed during verification |
| Removal version | u64 | Removal witness observed during verification |
| Denial version | u64 | Denial witness observed during verification |

Each head record contains, in order:

| Field | Encoding | Bound or rule |
|---|---|---|
| Object id | 32 bytes | Canonical type-dependent identity |
| Kind | u8 | Commit = 3, Remix = 4, Tag = 7 |
| Signer key | 32 bytes | Embedded Ed25519 public key |
| Signature result | u8 | 1 = valid individual signature; no other tag is supported |
| Canonical head bytes | u32 length, then bytes | Per-head and aggregate configured caps; first byte must equal kind |

Heads contain every distinct object an effect will set as a head. Repeated use
of one object by multiple effects needs one record. Dependencies contain only
resolved member pack ids actually relied on. Neither list contains pack pages
or the pack's complete object set. Envelope size depends on heads and external
dependencies, never on object count. Every canonical head object follows
[SPEC-OBJECTS](SPEC-OBJECTS.md); signatures follow
[SPEC-SIGNING](SPEC-SIGNING.md).

## 3. Strict bounded decoding and rechecking

Decode requires an explicit finite configuration: maximum envelope bytes,
operation-id bytes, head count, bytes per head, aggregate head bytes, external
dependency count, supported ruleset, and expected profile/limits digest.
There is no implicit unlimited configuration. These execution budgets do not
introduce new invalid-pack rules. Exhaustion is a resource refusal.

The decoder MUST check lengths and counts before copying or allocating. Nested
head bytes share one cumulative head-byte budget. It MUST reject truncation,
arithmetic overflow, duplicate or unordered records, contradictory delta counts,
unknown tags or versions, profile mismatch, and trailing bytes. A valid envelope
contains at least 206 bytes (empty operation and lists). Its exact length is
`206 + operation_bytes + sum(70 + head_bytes) + 32 * dependency_count`.
The host accounts for its acquired input separately. Implementations MUST bound
retained output and temporary decoding state using finite caller budgets.
Decoder work is linear in envelope bytes and record counts. No nested or
recursive envelope exists.

Envelope decoding checks head framing and kind prefixes. It does not establish
the truth of head metadata or validate the nested canonical object grammar;
those checks belong to head rechecking and the authenticated verifier.

A head recheck MUST recompute each id from canonical bytes, confirm kind and
embedded signer, and individually verify the signature. It MUST reject malformed
canonical bytes, differing facts, and invalid signatures. Temporary object and
signature inputs MUST remain within finite caller budgets in addition to the
retained envelope. Rechecking never parses a pack.

Decoder refusal codes are stable within this format and ruleset:

| Condition | Code |
|---|---|
| Configured cap or fallible allocation exhausted | `ResourceLimit` |
| Required bytes unavailable | `UnexpectedEof` |
| Evidence version differs from 1 | `UnsupportedEvidenceVersion` |
| Ruleset or profile/limits differs from configuration | `EvidenceProfileMismatch` |
| Magic, ordering, duplicates, tags, contradictory counts, or trailing data | `NonCanonicalEvidence` |
| Frozen pack or replay binding differs | `EvidenceBindingMismatch` |
| Nested canonical head grammar is invalid | `NonCanonicalObject` |
| Head object id differs | `ObjectHashMismatch` |
| Head kind or signer metadata differs | `EvidenceHeadMismatch` |
| Head's individual signature fails | `BadSignature` |

Decode checks the envelope cap first, then reads fields in wire order. It checks
each configured count or length cap before consuming that field's body. The
ruleset/profile comparison precedes operation and pack parsing. The trailing-byte
check follows all witness fields. Head rechecks proceed in envelope order, with
canonical grammar and metadata checks before individual signature verification.

## 4. Digest domain

The permanent domain is ASCII `mkit-acceptance-evidence:v1`. The digest is
`BLAKE3(domain || 0x00 || canonical_encoding)`, with exactly one explicit NUL
between domain and encoding, no domain-length prefix, and no terminating NUL
after the encoding. It commits every field including the evidence version.
It is computed outside the encoding; there is no self-referential digest field.
This domain is distinct from object, page, checkpoint, and signing domains.

## 5. Compatibility and fixtures

Evidence version, ruleset, profile/limits digest, and library API version are
separate contracts. This format supports only version 1. A future incompatible
schema MUST use a new evidence version and a separately specified digest domain;
unknown evidence requires rejection and fresh verification rather than fallback.
No existing object or pack bytes change.

| Evidence version | Change |
|---|---|
| 1 | Initial bounded trusted-host envelope. |

Portable fixtures under **rust/crates/mkit-primitives/fixtures/acceptance/** pin
canonical bytes, decode configurations, refusal codes, and digest vectors. The
fixture manifest registers each case. Semantic JSON descriptions encode u64
values as decimal strings, preserving exact values in every language; configured
u32 bounds remain JSON numbers. Fixture regeneration is an explicit reviewed
operation; CI only reads them.

## 6. Invariants

| Invariant | Enforcement |
|---|---|
| Decoding does not confer verification or acceptance authority | Authenticated host origin and atomic live guards, §1 |
| Evidence binds the writer's exact frozen operation | Pack id/length, repository, operation, and epoch comparison, §1 |
| Every accepted envelope has one canonical representation | Exact field order, tags, sorted unique records, and no trailing bytes, §2 |
| Size and work depend on heads and dependencies, not object count | Explicit finite byte/count caps and cumulative head-byte checks, §3 |
| Head rechecks preserve individual object/signature rules | Canonical id, kind, signer, and individual signature validation, §3 |
| Every encoded field contributes to the digest | Fixed domain, explicit NUL, and the entire canonical encoding, §4 |
| Format, ruleset, profile, and API compatibility remain separate | Explicit version rejection and profile equality, §5 |
