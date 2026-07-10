---
spec: SPEC-CONVENTIONS
version: 1
status: stable
audience: authors and reviewers of every docs/specs/SPEC-*.md document
---

# SPEC-CONVENTIONS — shared conventions for the mkit spec corpus

Status: **Normative** for every other `docs/specs/SPEC-*.md` document.
Scope: normative-language boilerplate, the status/version vocabulary,
numeric encoding conventions, the domain-separation-string registry, the
error-taxonomy mapping contract, and the rule governing how a spec may
(and may not) cite an implementation.

This document does not define any wire or on-disk format itself. It exists
so the other 22 documents can say "see SPEC-CONVENTIONS §N" instead of each
silently restating, or silently omitting, the same convention — and so a
divergence from one of these rules is a one-line spec bug instead of an
undetected drift.

---

## 1. Normative language

Every other spec's use of **MUST**, **MUST NOT**, **SHOULD**, **SHOULD
NOT**, and **MAY** is to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and clarified by
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) — i.e. only the
ALL-CAPS forms carry normative weight; the same words in lowercase prose
are descriptive, not a requirement. Every `docs/specs/SPEC-*.md` document
MUST carry (or reference, via this document) that sentence before its first
normative use of one of these keywords.

## 2. Status vocabulary

A spec's frontmatter carries two independent axes, not one:

- **Maturity** — how settled the design is: `draft` → `stable`. A `draft`
  spec's byte layouts and algorithms MAY still change without a version
  bump; a `stable` spec's MUST NOT.
- **Bindingness** — whether conformance is required at all: `advisory`
  (local-only, informative, e.g. SPEC-INDEX) vs. `normative` (implementers
  of compatible tools MUST conform, e.g. SPEC-OBJECTS).

Frontmatter `status:` MUST be one of exactly these four values:
`draft-normative`, `draft-advisory`, `stable-normative`, `stable-advisory`.
The body's own "Status: **X** for mkit vN" line MUST restate the
bindingness half in prose (`Normative` / `Advisory`) and MUST NOT
contradict the frontmatter. Existing values in the corpus (`draft`,
`normative`, `implemented`, `stable`, `transport-delivery-shipped`, and
combinations like `draft (journaled persistence shipped)`) are non-
conforming and MUST be migrated to one of the four values above; an
"implemented" or "shipped" claim belongs in prose (e.g. an
Implementation-status table, as SPEC-KEYSTORE and SPEC-RELEASE-THRESHOLD
already do well), never in the frontmatter `status:` field.

## 3. Numeric encoding

**Default: little-endian**, for every multi-byte integer field in every
on-disk or wire format defined by this corpus, unless a section explicitly
invokes one of the carve-outs below.

Carve-outs (each MUST be called out at its point of use as "big-endian,
per SPEC-CONVENTIONS §3 carve-out N," not left silent):

1. **SPEC-MERKLE-OBJECTS' Binary Merkle Tree fold** uses big-endian `be32`
   for the leaf-position and finalization counters. Rationale: matches the
   reference tree-construction literature's convention (RFC 6962-style
   trees are typically specified index-first, big-endian); changing it now
   would break every existing merkle object id.
2. **SPEC-FASTCDC's gear-table seed** is interpreted as a big-endian u64.
   Rationale: the seed is consumed once, at table-generation time, not on
   any hot path or wire format; big-endian was simply the paper-adjacent
   convention the original implementation used.

No third carve-out may be added without also stating, in the spec that
needs it, why little-endian was rejected — "big-endian, no reason given" is
exactly the drift this section exists to stop.

## 4. Domain-separation strings

Every hash construction in this corpus that needs to distinguish "this is
an X" from "this is a Y" over otherwise-identical bytes uses a
domain-separation string as an unambiguous, length-prefixed prefix to the
hashed input. There MUST be exactly one notation, with no version suffix
(mkit does not number its formats against a compatibility timeline — see
the note on versioning below):

```
mkit-<name>
```

lowercase, hyphen-separated, no trailing NUL (the length prefix that
precedes it in every hashed input already delimits it — a NUL terminator
would be redundant and has, in practice, been applied inconsistently).
Every domain string currently in the corpus MUST be normalized to this one
notation — there is no dual-support period and no "legacy" form to
preserve: a domain string is renamed outright wherever it doesn't match,
the object-id computation and its golden vectors are regenerated to match,
and the change ships as one atomic edit to spec + code + fixtures. (Note:
renaming a domain string changes the object ids it produces. This is a
one-time normalization pass, tracked separately from this document, not a
standing policy of periodically renaming domains.)

**Registry** (every domain string in the corpus MUST have an entry here
before it ships):

| String | Owner |
|---|---|
| `mkit-tree` | SPEC-MERKLE-OBJECTS |
| `mkit-chunked` | SPEC-MERKLE-OBJECTS |
| `mkit-tag` | SPEC-OBJECTS |
| `mkit-cblob-meta` | SPEC-MERKLE-OBJECTS |
| `mkit-tree-entry` | SPEC-MERKLE-OBJECTS |

**A note on versioning generally:** this corpus does not use `v1`/`v2`-style
suffixes to name formats, domain strings, or migration eras. mkit has not
shipped a public release; there is no installed base whose old bytes must
keep parsing, so there is nothing to version against yet. A format has
*one* current definition, described in the present tense. When mkit
eventually needs real compatibility guarantees (after a real release with
real external consumers), that's a deliberate future decision with its own
policy — not something to pre-build now. Existing "v1 read-compat" and
similar migration-shim language elsewhere in the corpus (e.g. SPEC-INDEX's
dual v1/v2 index-file support, SPEC-HISTORY-PROOF's rebuild-from-empty-
journal mechanism) is being simplified under this same principle; see each
document's own changes.

**Disjointness invariant (MUST hold, not just "currently holds"):** no two
domain strings in the registry may be a prefix of one another, and no
domain string may have a length equal to the first byte(s) of any flat
(non-domain-wrapped) object's type-tag encoding — the existing flat-vs-
merkle id disjointness (SPEC-OBJECTS type tags `0x01`–`0x07` vs.
domain-wrapped ids) depends on no domain string ever reaching length 1–7.
A spec adding a new domain string MUST check both conditions against the
full registry above and reject any string shorter than 8 bytes.

## 5. Error taxonomy

Each spec that defines wire- or storage-level errors MUST provide a table
mapping every named error condition it defines to exactly one
implementation error type (e.g. a Rust enum variant), 1:1. A single
implementation error type standing in for multiple spec-distinguished
conditions (as, historically, `MkitError::TrailingData` has covered six
distinct `DeltaCorrupt` conditions) is non-conforming: either the spec's
conditions get merged into one (if a conforming implementation truly
cannot or need not distinguish them), or the implementation gets a new
variant. The table is what a conformance test suite checks against; a
spec without one cannot be conformance-tested for error behavior.

## 6. No vendor references in normative text

**A normative statement MUST NOT be "this is defined by `<crate>`."**
Every algorithm, format, and cryptographic construction MUST be specified
in this corpus in implementation-independent terms — the same standard an
RFC, an academic paper, or a published standard (e.g. the Noise Protocol
Framework, DSSE, in-toto, TUF) is held to. Concretely:

- Citing a **public specification, RFC, or paper** by name and section
  (e.g. "RFC 8032 §5.1.7," "the Noise Protocol Framework §4," "FastCDC,
  Xia et al., USENIX ATC 2016 §4.2") is required and encouraged wherever
  the corpus adopts or deviates from prior art. A deviation MUST be
  justified in the spec's own text, not left implicit.
- Citing a **crate, crate version, or language-specific API method** as
  the definition of a format or a security property (e.g. "provided
  verbatim by `commonware_stream::encrypted`," "codec-serialised
  commonware `Chunk`, in its native form," "`ed25519-dalek`'s
  `verify_strict`") is non-conforming. A crate name MAY appear **at most
  once** per spec, in a clearly labeled, non-normative "Reference
  implementation" aside — never inside a MUST/SHOULD sentence, and never
  as the sole definition of a byte layout, algorithm, or acceptance
  predicate.

The test for whether a spec passes this rule: could a reader who has never
heard of mkit's Rust workspace, and has no access to it, implement a
conforming peer from the document text and its cited public standards
alone? If the answer depends on reading a specific crate's source at a
specific pinned version, the spec fails this section and MUST be rewritten
before it ships.

## 7. Test vectors

A "Test vectors" section is not satisfied by an instruction to produce a
vector ("record the resulting hex digest") or by naming a Rust test
function. Each numbered vector MUST include the literal input and expected
output bytes (as hex) inline in the document text, generated from real
code and never hand-derived, in addition to (not instead of) a pointer to
the golden fixture under `rust/tests/golden/` that pins the same value in
CI. The document is the artifact an external implementer checks against;
a fixture path they cannot open is not a substitute.

---

## Invariants

| Invariant | Enforced by |
|---|---|
| Normative keywords carry consistent meaning across all 22 specs | §1 boilerplate reference, checked at spec-review time |
| A spec's maturity and bindingness are both legible from frontmatter alone | §2's four-value enum, checked at spec-review time |
| A multi-byte field's byte order is never silently ambiguous | §3's default + enumerated, justified carve-out list |
| No domain-separation string can collide with another or with a flat object type tag | §4's registry + disjointness invariant, checked before any new string ships |
| Every spec-level error condition maps to exactly one implementation type | §5's 1:1 mapping table, one per spec |
| A conforming peer is implementable from public standards + spec text alone, with no access to mkit's own source | §6's vendor-reference prohibition |
| A test vector is checkable by a reader with no access to `rust/tests/golden/` | §7's inline-value requirement |

## Non-goals

- This document does not itself define any wire or on-disk format — it has
  no bytes to be conformant with, only conventions other specs must follow.
- Migrating every existing violation of §2–§4 in the 22 other documents in
  one pass is out of scope for this document; each violation is tracked
  and fixed in its owning spec, citing this document as the reason.
