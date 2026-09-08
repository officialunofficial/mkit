---
spec: SPEC-CONVENTIONS
version: 1
status: stable-normative
audience: authors and reviewers of any docs/specs/SPEC-*.md document
---

# SPEC-CONVENTIONS &mdash; shared vocabulary for the SPEC-*.md corpus

Status: **Normative** for how every other `docs/specs/SPEC-*.md`
document is written and read. This document does not itself specify
any on-disk or wire format; it fixes the small set of conventions
those documents lean on so each one doesn't have to restate them.

Scope: RFC 2119/8174 keyword usage (§1), the frontmatter status
vocabulary and versioning posture (§2), shared wire-encoding notation
(§3), domain-separator/namespace naming (§4), golden-vector citation
conventions (§5), and the no-vendor-references rule (§6).

---

## 1. Normative keywords

MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and REQUIRED are used per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) as clarified by
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) (the keywords carry
their defined meaning only when written in this specific
upper-case form). A spec that uses lower-case "must"/"should" in
ordinary prose is making a descriptive statement, not a normative one.

## 2. Status vocabulary and versioning

### 2.1 Frontmatter `status`

Two independent axes, written as a single hyphenated token
`<maturity>-<bindingness>`:

| Axis | Values | Meaning |
|---|---|---|
| Maturity | `draft` | The described behavior is incomplete, still changing, or has a known open gap the document itself calls out. |
| | `stable` | The described behavior is settled; a conforming implementation can rely on it not changing without a version bump. |
| Bindingness | `normative` | Peers/implementations that don't conform are non-conformant &mdash; cross-process or cross-repo interop depends on this document. |
| | `advisory` | Describes local, non-exchanged behavior (for example, a reconstructible cache file no other peer ever reads); an implementation MAY diverge without breaking interop, though it still shouldn't. |

Bare `draft` or `stable` (no bindingness suffix) is permitted where a
document predates this convention or bindingness genuinely doesn't
apply (for example, this document itself). New or heavily-revised specs
SHOULD use the full `<maturity>-<bindingness>` form.

Some existing `SPEC-*.md` documents in this corpus predate this
convention and use ad hoc status strings. That is a known,
non-urgent inconsistency &mdash; retrofitting them is left as a documentation
cleanup, not a normative requirement of this section.

### 2.2 Versioning and migration shims

Whether a format change needs a migration shim (dual-version read
support, a `FORMAT_VERSION_V1`-style fallback) follows directly from
§2.1's bindingness axis:

- **`normative`** documents describe compatibility or durable-state contracts,
  including authoritative local-only state. A version bump MUST provide a
  migration path or explicitly document a deliberate breaking change.
- **`advisory`** documents may describe disposable, reconstructible caches.
  Whether state can be rebuilt is determined by its contents and source of
  truth, not whether it crosses a network. Staged paths, selected object hashes,
  mode choices and deletion tombstones in `.mkit/index` are authoritative:
  neither HEAD nor current working files can recreate them. SPEC-INDEX therefore
  rejects unsupported versions without rewriting those selections. The current
  pre-release index format deliberately provides no legacy reader or migration
  shim; only stat observations may be discarded.

## 3. Wire-encoding notation

Where a `SPEC-*.md` document specifies byte layout:

- Every multi-byte integer is **little-endian** unless the document
  says otherwise (the one exception in this corpus is network-facing
  wire formats that inherit a big-endian convention from the protocol
  they implement &mdash; for example, AWS SigV4 in SPEC-TRANSPORT &mdash; those documents
  say so explicitly).
- A **length-prefixed field** means `[u32 LE length][length bytes]`
  unless a document specifies a different integer width for that
  field. This applies even to fixed-size fields (for example, a 24-byte nonce
  still carries its own 4-byte length prefix) for uniformity across a
  format's field list, not because the length is ever in doubt.

## 4. Domain-separator and namespace naming

mkit's signing and hashing domain separators (for example, `mkit.tag\0`,
BLS namespace strings like `dsse/v1`) are permanent, literal byte
strings baked into the signing/hashing contract &mdash; not a version field
and not a compatibility-era label that gets bumped in place. A
distinct new application of an existing key MUST mint its own,
distinctly-named domain/namespace constant rather than repurpose an
existing one for a second meaning; there is no in-place migration path
for a domain separator's bytes.

A registry (informative, not itself normative) of the domain
separators and namespace strings currently in use is maintained inline
in each format's own spec (SPEC-OBJECTS §10 for object-hash domains,
SPEC-SIGNING for the commit/remix signing domain, SPEC-RELEASE-THRESHOLD
§3 for the BLS namespace); this document does not duplicate that list,
only the naming rule.

## 5. Golden vectors and conformance tests

Where a `SPEC-*.md` document lists numbered test vectors, the
corresponding fixtures live under `rust/tests/golden/<area>/`
(one directory per format) and are the authoritative pinned bytes &mdash;
the prose vector description is a human-readable label for a fixture
that already exists, not a promise of one that will exist later. A
spec revision that changes wire bytes MUST update the golden fixtures
in the same change (CONTRIBUTING.md's "spec + golden vector updated"
checklist item); a stale "TO BE FIXED IN IMPLEMENTATION" marker left
after the fixtures already ship is a documentation bug, not a
disclaimer.

## 6. No vendor references

A `SPEC-*.md` document specifies behavior as an implementation-independent
contract &mdash; a wire format, an algorithm, a predicate a verifier
evaluates &mdash; not as a reference to a specific library function or crate
API. Where a document needs to describe *how mkit happens to implement*
a requirement, that belongs in a doc comment on the code itself
(cross-referenced by file/function name, not restated), not in the
spec's normative text. This keeps a spec usable by an independent,
non-Rust implementation and keeps it from silently going stale the
moment mkit's own internal factoring changes without the contract
changing.
