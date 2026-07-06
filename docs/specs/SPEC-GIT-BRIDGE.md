---
spec: SPEC-GIT-BRIDGE
version: 1
status: draft
audience: implementers of the mkit→git export bridge and its verifiers
---

# SPEC-GIT-BRIDGE — deterministic mkit→git translation (v1)

Status: **Normative** for the mkit→git export direction.
Scope: the byte-level mapping from mkit v1 objects (SPEC-OBJECTS) to
git objects, the carrier encoding for mkit-only fields, ref-name
mapping, the verification model for carried signatures, mirror update
semantics, and the `git-bridge/v1` provenance attestation.

This spec covers the **export direction**; the import direction is
specified separately in [SPEC-GIT-IMPORT](SPEC-GIT-IMPORT.md) and is
*not* this mapping's inverse (import is a signed translation, not a
carrier round-trip). The translation is designed so that any two
implementations translating the same mkit history produce **byte- and
SHA-identical** git objects, with no shared state. The blake3↔sha1
mapping is therefore always a rebuildable local cache, never a source
of truth.

---

## 1. Model

### 1.1 Direction and fidelity

The bridge translates the mkit object DAG into a git object DAG:

```
mkit blob (0x01)          → git blob
mkit chunked_blob (0x05)  → git blob (flattened; §4)
mkit tree (0x02)          → git tree (re-sorted; §5)
mkit commit (0x03)        → git commit + mkit-* headers (§6)
mkit tag (0x07)           → git tag + mkit-* headers (§7)
mkit remix (0x04)         → REFUSED in v1 (§8)
mkit delta (0x06)         → never translated (pack-only; cannot occur)
```

The mapping is **lossless**: every field of the source mkit object is
either natively represented in the git object or carried in an
`mkit-*` header, such that the original mkit object bytes can be
reconstructed bit-exactly (§9) and the original Ed25519 signature
re-verifies.

### 1.2 Version keying

The mapping in this document is defined for mkit objects whose
prologue carries `schema_version = 0x01` (SPEC-OBJECTS §2). The
emitted `mkit-schema` header records that version. A bridge
encountering an object with any other `schema_version` MUST refuse
that object (and therefore every ref whose closure contains it) with
an actionable error. Future mkit schema versions extend this spec
with a new mapping section; they do not alter the v1 mapping.

### 1.3 Non-goals (v1)

- Treating §9 reconstruction as an import path: it is defined only on
  bridge-emitted objects and fails closed on everything else. Actual
  import (arbitrary git history, importer-signed) is
  [SPEC-GIT-IMPORT](SPEC-GIT-IMPORT.md).
- SHA-256 git repositories. The bridge emits SHA-1 object ids only.
- Remix translation (§8 reserves the carrier).
- Translating attestations themselves (the bridge *mints* a new
  provenance attestation, §11; it does not translate existing ones).

### 1.4 Determinism requirement

Every choice in this mapping is a pure function of the source object
bytes — except in **fork (passthrough) mode** (§14), where the output
is a pure function of *(mkit store, import map)*: the import map is
itself deterministic given the importer key and upstream bytes
(SPEC-GIT-IMPORT §1.2), but exporters without that import state MUST
refuse fork-mode export rather than silently produce a divergent
pure-bridge translation. Implementations MUST NOT consult wall-clock
time, locale, configuration, or local key material when producing
translated objects. (The provenance attestation §11 is signed and
therefore machine-specific; it is *not* part of the translated object
graph.)

---

## 2. git object encoding (recap, normative for this spec)

A git object id is `SHA1("<type> <len>\0" || body)` where `<type>` is
one of `blob`, `tree`, `commit`, `tag` and `<len>` is the decimal
byte length of `body`. Loose objects are stored zlib-compressed at
`.git/objects/<2hex>/<38hex>`. The bridge emits objects with these
exact rules; it does not depend on git pack formats.

The SHA-1 here is git's object-naming function, not a security
boundary: integrity and authorship continue to ride on the carried
BLAKE3 hashes and Ed25519 signatures (§10), and the provenance
attestation binds the two id spaces together (§11).

---

## 3. Blob (`0x01`) → git blob

git blob body = the mkit blob's `data` bytes, verbatim.

A plain blob whose `data` exceeds the 1 MiB chunking threshold MUST
be refused: a conformant writer stores such content chunked, and §9's
reconstruction would re-chunk it into a manifest — the round trip
would not be bit-exact. (This is the plain-blob mirror of §4 item 2;
non-default-threshold writers are out of v1 scope.)

Reconstruction: mkit blob prologue + `u32 LE len` + bytes (§9).

---

## 4. Chunked blob (`0x05`) → git blob

git blob body = the concatenation of every chunk blob's data, in
manifest order. The concatenated length MUST equal the manifest's
`total_size` (this is already a SPEC-OBJECTS §7 invariant).

**Only canonical writer output translates.** Reconstruction (§9)
re-chunks the flattened bytes with the pinned FastCDC parameters
(SPEC-FASTCDC: seed `MKITFCDC`, 16/64/256 KiB, threshold 1 MiB); that
round-trips bit-exactly **iff** the source manifest is exactly what a
conformant mkit writer produces. A bridge MUST therefore refuse, with
an actionable error naming the object, any manifest that:

1. has `chunk_size != 0` (fixed-size chunking — legal under
   SPEC-OBJECTS §7, never emitted by mkit writers, no general
   inverse);
2. has `total_size` at or below the 1 MiB chunking threshold (a
   conformant writer stores such content as a plain blob; the
   round-trip would change the object graph); or
3. has chunk boundaries that differ from the pinned FastCDC output
   over the flattened bytes (verified by re-running the chunker
   during translation).

These refusals are what make the §1.1 lossless guarantee
unconditional for everything the bridge actually emits.

Reconstruction: bytes > 1 MiB re-chunk via pinned FastCDC into chunk
blobs + a `chunk_size = 0` manifest; bytes ≤ 1 MiB reconstruct as a
plain blob. This reproduces the writer-side decision rule, so the
round-trip is exact for any store produced by mkit writers.

---

## 5. Tree (`0x02`) → git tree

Each mkit tree entry maps to one git tree entry:

| mkit mode | git mode |
|-----------|----------|
| `0x01` blob | `100644` |
| `0x02` tree | `40000` |
| `0x03` symlink | `120000` |
| `0x04` executable | `100755` |

Entry name bytes are copied verbatim. mkit's tree-name rules
(SPEC-OBJECTS §4.1) are a strict subset of git's tree-entry legality,
so export never produces a git-illegal entry name. The entry's 20-byte
id is the SHA-1 of the translated child object.

**Sort orders differ and re-sorting is mandatory in both directions.**

- mkit order (SPEC-OBJECTS §4.1): byte-wise ascending on the raw name.
- git order: byte-wise ascending on the *sort key*, where the sort key
  of a directory (`40000`) entry is `name || "/"` and the sort key of
  every other entry is `name`.

For sibling entries `foo` (a directory) and `foo.txt` (a file), mkit
orders `foo` before `foo.txt`; git orders `foo.txt` before `foo`
(`.` = 0x2E sorts below `/` = 0x2F). Translators MUST emit git trees
in git order and MUST re-sort to mkit order on reconstruction. The
two orders are both total and canonical, so re-sorting is a pure
permutation: no information is lost. Implementations MUST NOT skip
the re-sort even when the orders happen to coincide. A golden vector
exercises the divergent case (§13.4).

The empty mkit tree maps to the empty git tree
(`4b825dc642cb6eb9a060e54bf8d69288fbee4904`).

---

## 6. Commit (`0x03`) → git commit

### 6.1 Layout

```
tree <sha1-of-translated-tree>
parent <sha1-of-translated-parent>          (one line per parent, in order)
author <synthesized author line>            (§6.2)
committer <same bytes as author>
mkit-schema 1
mkit-author <identity encoding>             (§6.3)
mkit-signer <64 lowercase hex>
mkit-signature <128 lowercase hex>
mkit-tree <64 lowercase hex>                (mkit tree_hash)
mkit-parent <64 lowercase hex>              (one per mkit parent, in order)
mkit-message-hash <64 lowercase hex>        (only if non-zero)
mkit-content-digest <64 lowercase hex>      (only if non-zero)
<empty line>
<message bytes, verbatim>
```

Header order is exactly as listed and is normative. `mkit-parent`
headers appear in mkit parent order (which always matches the `parent`
line order). `mkit-message-hash` / `mkit-content-digest` are emitted
iff the corresponding 32-byte slot is non-zero (SPEC-OBJECTS §5.1
defines zero as "absent"). All other `mkit-*` headers are always
emitted — including an all-zero `mkit-signature` (the object layer
accepts unsigned commits structurally; the bridge translates what is
stored and never invents or strips signatures).

Header values are lowercase hex or base64 (§6.3) — never raw bytes —
so no value can contain `\n` and header continuation lines are never
produced. Git preserves unknown commit headers through object
transfer, which is the property this carrier relies on; porcelain
that *rewrites* commits (rebase, amend, cherry-pick on the git side)
drops them, which is consistent with the mirror model: the mkit side
is primary, and a git-side rewrite produces commits that are simply
not bridge-translated objects.

The message is the mkit commit's `message` bytes verbatim — no
trailing-newline normalization, no trailer injection. (mkit messages
are length-prefixed, so an empty message is representable; the git
body after the blank separator line is then empty.)

### 6.2 Author line synthesis

git requires `author <name> <<email>> <timestamp> <tz>` where `<name>`
and `<email>` must not contain `<`, `>`, `\n`, or `\0`. The
synthesized line is **display-only**: reconstruction reads the
`mkit-author` header (§6.3), never this line. The synthesis is still
normative because it is part of the hashed git bytes.

- email: the fixed string `bridge@mkit.invalid` (RFC 2606 reserved
  TLD; never routable).
- timestamp: the mkit `u64` timestamp rendered in decimal, timezone
  fixed `+0000`. A timestamp exceeding `i64::MAX` MUST be refused
  (git tooling parses signed 64-bit; no real clock produces this).
- committer line: byte-identical to the author line. mkit has no
  committer concept; inventing a distinct one would add a free
  variable for no information.
- name, by identity kind:
  - `ed25519` (0x01): `mkit:ed25519:` + 64 lowercase hex of the key.
  - `did_key` (0x02): `did:key:` + the payload bytes verbatim
    (conformant readers validate the payload as printable ASCII —
    `Identity::is_valid` in mkit-core — and multibase text cannot
    contain `<` `>`; if a payload nevertheless contains a forbidden
    byte, fall through to the opaque rule below applied to the
    payload).
  - `opaque` (0x03): the payload verbatim **iff** it is valid UTF-8
    and contains no `<` (0x3C), no `>` (0x3E), and no ASCII control
    byte (`< 0x20`, and 0x7F DEL); otherwise `mkit:opaque:` +
    unpadded base64 (RFC 4648 standard alphabet) of the payload.

The verbatim-opaque rule keeps human-readable opaque identities
human-readable in `git log` while remaining a pure function of the
payload bytes.

### 6.3 `mkit-author` header encoding

```
mkit-author <kind-hex2>:<base64-of-payload>
```

`kind-hex2` is the two-digit lowercase hex of the IdentityKind byte
(`01`, `02`, `03`). The payload is unpadded standard base64 of the
raw identity payload bytes. This encodes any legal Identity (payload
1..=4096 bytes) in a single header line with full fidelity.

---

## 7. Tag (`0x07`) → git tag

A lightweight mkit tag (a bare `refs/tags/<name>` ref) maps to a
lightweight git tag: a ref pointing at the translated target. No tag
object is involved.

An annotated/signed mkit tag object maps to a git tag object:

```
object <sha1-of-translated-target>
type <git type of target>                   (§7.1)
tag <name bytes verbatim>
tagger <synthesized line>                   (§6.2 rules, tagger identity)
mkit-schema 1
mkit-tagger <identity encoding>             (§6.3 encoding)
mkit-signer <64 lowercase hex>
mkit-signature <128 lowercase hex>          (all-zero = unsigned, carried as-is)
mkit-target <64 lowercase hex>              (mkit target hash)
mkit-target-type <2 lowercase hex>          (mkit ObjectType byte)
<empty line>
<message bytes, verbatim>
```

### 7.1 Target type and name constraints

`type` is the git type of the *translated* target (`commit`, `tree`,
`blob`, `tag`). A tag whose mkit target is a remix is refused with
the remix policy (§8). A tag whose target is a chunked blob carries
git `type blob` (the flattened translation); `mkit-target-type`
preserves the distinction (`05`) for reconstruction.

The git `tag` header value cannot contain `\n`. mkit tag-object
names only exclude `{0x00, '/', '\\'}` (SPEC-OBJECTS §6a), so the
bridge MUST refuse — for **every** translated tag object, however it
is referenced — a name that is not a single mkit ref *segment*
satisfying all of: the SPEC-REFS §3 segment charset
(`[0-9A-Za-z._-]`), not `.` / `..` / `HEAD`, no `.lock` suffix, and
the git-side dot rules of §12.1. In practice every tag reachable from
`refs/tags/` already satisfies this (ref-write enforces the grammar);
the check exists for tag objects referenced any other way.

---

## 8. Remix (`0x04`) — refused, carrier reserved

Translating remixes is **deliberately out of scope for v1**. The
mapping is tractable (a remix is structurally a commit plus a sorted
`(upstream_id, commit_hash)` source list, which would ride as
headers), but it is excluded to bound v1 review scope and because the
remix signing domain (`mkit.remix\0`) doubles the §10 verification
surface.

Refusal granularity is **per ref**: a ref whose reachable closure
contains a remix is skipped with an actionable warning naming the ref
and the offending object; the export of other refs proceeds. An
export in which *every* requested ref is skipped exits non-zero.

The header names `mkit-remix-source` and `mkit-object-type` are
**reserved** by this spec for the future remix mapping and MUST NOT
be emitted by v1 bridges, so adding remix support is a spec extension
rather than a breaking change to the v1 mapping.

---

## 9. Reconstruction (verification-only inverse)

Reconstruction maps a bridge-emitted git object back to exact mkit v1
object bytes. It exists so verifiers can check the §1.1 lossless
claim and re-verify carried signatures; it is **not an import path**
— it is only defined on objects the §3–§7 mapping can emit, and MUST
fail loudly on anything else (missing `mkit-*` headers, unknown
headers in the `mkit-*` namespace, a `tag`/`commit` without
`mkit-schema`, git modes with no mkit equivalent such as `160000`,
etc.).

- blob: re-wrap bytes ≤ 1 MiB as `blob`; > 1 MiB re-chunk per §4.
- tree: map modes back, re-sort to mkit byte-lex order, replace each
  child SHA-1 with the BLAKE3 of the reconstructed child.
- commit: rebuild SPEC-OBJECTS §5 layout from `mkit-tree`,
  `mkit-parent`*, `mkit-author`, message bytes, the author-line
  timestamp, `mkit-signer`, `mkit-message-hash` / `mkit-content-digest`
  (zero when absent), `mkit-signature`.
- tag: rebuild SPEC-OBJECTS §6a layout from `mkit-target`,
  `mkit-target-type`, the `tag` name bytes, `mkit-tagger`, message,
  timestamp, `mkit-signer`, `mkit-signature`.

A reconstruction is **valid** iff the rebuilt bytes deserialize under
SPEC-OBJECTS and re-serialize to the identical bytes, and their
BLAKE3 equals the value carried in the parent's reference to them
(tree entry, `mkit-tree`, `mkit-parent`, `mkit-target`).

---

## 10. Verification model

Carried signatures never verify over git bytes and git tooling never
verifies them; `gpgsig` is not used (git tooling would attempt to
parse it as OpenPGP/SSH and fail confusingly). Verification of
translated history is mkit-side, in two pinned modes:

**Shallow (default).** For a single git commit/tag, rebuild the mkit
signing bytes (SPEC-SIGNING §3/§4a) directly from the carried
headers + message + timestamp — this requires no other objects — and
check the Ed25519 signature (`verify_strict`) under the appropriate
domain. Shallow verification proves the carried fields are exactly
what the original signer signed; it does *not* prove the surrounding
git tree/parent SHA-1s correspond to those BLAKE3 hashes.

**Deep (audit).** Reconstruct the full closure per §9, checking every
BLAKE3 linkage, then verify signatures on the reconstructed objects.
Deep verification proves the entire translated graph is the signed
original. Cost is proportional to the closure; it is the mode for
mirror audits, not per-commit checks.

An all-zero `mkit-signature` fails both modes (same convention as
unsigned annotated tags, SPEC-SIGNING §4a) and MUST be reported as
"unsigned", not "tampered".

---

## 11. Provenance attestation (`git-bridge/v1`)

At export, the bridge mints one DSSE/in-toto attestation per exported
ref head (SPEC-ATTESTATIONS encoding rules apply):

- `predicateType`:
  `https://github.com/officialunofficial/mkit/spec/predicate/git-bridge/v1`
  (the SPEC-ATTESTATIONS §6.4 project-controlled URI scheme).
- `subject[0]`: `name` = the full mkit ref name; `digest` =
  `{"blake3": "<64hex mkit hash of the ref head — a commit, or a tag
  object for annotated-tag refs>"}`. The git-side id rides in
  the predicate, not the subject: SPEC-ATTESTATIONS's v1 Statement
  encoder is deliberately blake3-only, and the SHA-1 is a locator,
  not an identity (§2). Promoting `gitCommit` into a multi-digest
  subject DigestSet is reserved for a future predicate version,
  gated on SPEC-ATTESTATIONS growing DigestSet support.
- predicate (all fields required; shown in JCS key order, which the
  encoded Statement uses per SPEC-ATTESTATIONS §4):

```json
{
  "gitCommit": "<40hex sha1 of the translated head>",
  "mirror": "<git remote URL as configured>",
  "refName": "<full mkit ref name>",
  "schemaVersion": 1,
  "specVersion": 1
}
```

  Field semantics: `gitCommit` locates the translated head on the
  mirror (locator, never a proof — §2; for annotated-tag refs it is
  the SHA-1 of the translated git *tag object* — the field name stays
  for predicate stability); `mirror` is the git remote
  the head was exported to, as configured (a locator, not an identity
  claim); `refName` is the full mkit ref whose head is attested;
  `schemaVersion` is the mkit object `schema_version` the translated
  history carries (§1.2); `specVersion` is the version of this
  predicate's own shape, i.e. the `git-bridge/v1` definition.

The attestation is signed with the exporter's configured signer
(SPEC-ATTESTATIONS signer plumbing, unchanged). An exporter MAY skip
attestation minting when explicitly requested (no key material is
consulted in that case); a mirror without bridge attestations is
merely unattested, not invalid. Exporters SHOULD also skip re-minting
for a head whose recorded exported state is unchanged and whose claim
is already published — fresh envelopes for old claims add no
information and (with nondeterministic signature schemes) would grow
the published set on every run. **Distinguishability
from author signatures comes from the predicate type and the DSSE
keyid — not from a signing domain.** Verifier guidance: a
`git-bridge/v1` attestation asserts "this exporter translated this
mkit commit to this git commit", never authorship of the content.

git-bridge/v1 attestations are minted **only for heads this bridge
translated** — a fork-mode head whose tip is a passthrough (original
upstream) commit gets no translation claim (its provenance is the
import side's git-import/v1 attestation); a fork-mode head whose tip
is a bridge-translated local commit is attested as usual.

Bridge attestations are stored like any attestation
(`.mkit/attestations/<commit>/…`) and additionally published on the
git mirror under the ref `refs/mkit/attestations` as a flat tree:
one entry per published envelope, name = `<64hex attestation
id>.dsse` (the BLAKE3 of the envelope bytes, matching the local
store's naming — naming by git sha would collide when two refs share
a head), content = the DSSE envelope bytes, committed by a synthetic
commit whose author/committer line is the fixed string
`mkit-git-bridge <bridge@mkit.invalid> <ts> +0000` with `<ts>` = the
newest exported head's timestamp (deterministic; deliberately not
the exporter's identity — the envelopes inside the tree carry the
signed identity claims). Consumers locate a head's attestations by
the `gitCommit` field inside the envelopes' predicates. Note for
consumers: non-standard ref namespaces are not fetched by `git
clone` defaults — document the explicit refspec
(`+refs/mkit/attestations:refs/mkit/attestations`).

**Multi-exporter limitation.** The attestations ref forms a linear
synthetic-commit chain per mirror. Two *machines* exporting to the
same mirror will contend on it: each one's chain diverges from the
other's, and the lease (§12.2) refuses the overwrite. §12.2's
concurrent-exporter safety claim covers translated refs (identical
bytes by determinism); for `refs/mkit/attestations` the v1 posture
is one exporter per mirror, enforced by the lease failing loudly.

A SHA-1 collision would let two git objects claim one `gitCommit`
digest; the binding's integrity rides on the `blake3` digest, and
consumers MUST treat `gitCommit` as a locator, not a proof.

---

## 12. Refs and mirror updates

### 12.1 Ref-name mapping

mkit ref names (SPEC-REFS §3 grammar: segments of `[0-9A-Za-z._-]`)
are *mostly* but not entirely git-legal. The bridge MUST refuse
(per-ref, same granularity as §8) any ref name where a segment:

- begins or ends with `.` (git rejects both; mkit only rejects the
  exact names `.` / `..`), or
- contains `..` anywhere (git rejects; mkit allows `a..b`).

No escaping scheme is defined in v1: escaped names would collide with
the un-escaped namespace and survive round-trips ambiguously. The
refused-name surface is rare by construction and the error is
actionable (rename the branch).

All other mkit ref names map verbatim: `refs/heads/x` → `refs/heads/x`,
`refs/tags/x` → `refs/tags/x`. `HEAD`, remote-tracking refs, and
internal state are never exported.

### 12.2 Update semantics

- Exports are **incremental**: objects already present in the mirror
  (by SHA-1) are not rewritten; ref updates use git's compare-and-swap
  (`--force-with-lease=<ref>:<expected>` against the last value this
  bridge state recorded, or — when no state is recorded for a ref —
  against the mirror's current value observed via `ls-remote`, which
  is what keeps wiped state rebuildable, §12.3). The push is
  `--atomic`: either every ref in the export lands or none does, so
  recorded state can never go stale for a subset of refs.
- Deleting an mkit branch never deletes it on the mirror (export is
  add/update-only); a later re-created branch of the same name
  updates the mirror ref under the observed-value lease.
- An mkit-side history rewrite (amend/rebase/force-push) exports as a
  git force-push. Mapping-cache entries for rewritten-away commits are
  **retained**: determinism makes them permanently correct, and they
  cost only space.
- Recovery-log commits, stash state, and any object not reachable
  from an exported ref are never translated.
- Concurrent exporters are safe: object writes are idempotent (same
  bytes, same SHA-1) and ref updates are CAS; a lost race surfaces as
  a lease failure, never as divergent translation.

### 12.3 Mapping cache

The blake3↔sha1 map and per-ref last-exported state live under
`.mkit/git/<remote>/` (layout is implementation-defined and
explicitly non-normative). Because translation is deterministic, the
cache is disposable: deleting it and re-deriving from the object
store MUST yield identical mappings **for every object still in the
store**. Entries for objects that `mkit gc` has since pruned (e.g.
rewritten-away commits past the recovery window) remain permanently
correct but are not re-derivable; their loss is harmless because
nothing in the store references them. Implementations MUST treat
cache absence or corruption as "rebuild", never as an error state,
and MUST NOT export the cache or rely on its presence for
correctness. Per-ref lease state is equally disposable: with no
recorded expectation the bridge seeds the lease from the mirror's
observed value, so deleting the whole state directory and
re-exporting against the same mirror works. The state directory is
bound to one destination (recorded at first export); pointing the
same `--remote-name` at a different mirror is refused — use one
state name per mirror.

---

## 13. Test vectors (implementer MUST produce)

Pinned under `rust/tests/golden/git-bridge/` with the standard
MANIFEST convention; each vector records the source mkit object bytes,
the emitted git object bytes, and the git SHA-1. Single exception:
vector 9's flattened git bytes (~1.2 MiB) are regenerated
deterministically by the golden test rather than committed; its mkit
manifest bytes and both ids are pinned like every other vector.

1. **Blob**: a small blob; assert git blob bytes + id.
2. **Empty tree**: assert id `4b825dc642cb6eb9a060e54bf8d69288fbee4904`.
3. **Single-entry tree**: one `100644` entry.
4. **Divergent-sort tree**: sibling entries `foo` (tree) and
   `foo.txt` (blob); assert mkit order `foo, foo.txt` and git order
   `foo.txt, foo`.
5. **Root commit**: zero parents, ed25519 identity, zero annotation
   slots (asserts both omitted headers and the author-line shape).
6. **Two-parent commit with annotations**: non-zero `message_hash`
   and `content_digest`; opaque identity that triggers the base64
   fallback.
7. **Unsigned annotated tag**: all-zero signature carried verbatim.
8. **Signed tag**: real signature; shallow verification succeeds.
9. **Chunked blob**: > 1 MiB content; flatten + re-chunk round-trip.

Every vector MUST round-trip through §9 to bit-identical mkit bytes,
and vectors 5–8 MUST shallow-verify (§10) with their original
signatures (vector 7 reporting "unsigned").

---

## 14. Fork (passthrough) mode and the origin guard

### 14.1 Passthrough rule

In a state dir whose direction is `fork` (SPEC-GIT-IMPORT §6), export
applies one per-object rule: **if the object's blake3 is in the
import map, emit nothing and use the original git sha1** (bytes are
served from the import staging mirror); otherwise bridge-translate,
with child resolution consulting `import map ∪ export map`. Each
state dir consults only its OWN maps; on overlap within a fork state
dir the import map wins. The mode is recorded per state dir and
immutable, because the same blake3 resolving to different sha1s
across runs corrupts recorded leases.

Fork-mode pushes target repositories the exporter does NOT own (the
upstream itself or a real fork), so their safety model differs from
plain export, normatively:

- The state dir is not dest-bound: each push records the destination
  informationally only, and the lease expectation comes from a FRESH
  `ls-remote` observation of that destination (an absent ref means
  "must not exist" — recorded leases from other destinations never
  apply).
- An observation-seeded lease passes unconditionally, so fork-mode
  push MUST be fast-forward-only: for every branch, the observed
  value must be an ancestor of the pushed tip (through the staging
  mirror), and an existing tag never moves. Anything else refuses
  with the fetch-and-integrate remediation.

Consequences, all normative:

- A bridge-translated local commit MAY carry `parent` lines naming
  original upstream sha1s (boundary commits). No §6.1 layout variant
  exists; the boundary is detected at verification time by "parent
  object lacks `mkit-*` headers", never by a new header.
- The exported branch shares SHAs with the upstream up to the import
  boundary: it is a true git fork (merge bases exist; PRs work).
- Local trees reuse original sha1s for any imported child object
  (blobs, subtrees) via the same rule, so unchanged content keeps
  upstream ids exactly as plain git would.
- Imported chunked manifests passthrough as the ORIGINAL blob sha1 —
  flattening never runs, so chunk-boundary exactness is structural.

### 14.2 Origin guard

Plain (non-fork) export MUST refuse a destination whose canonical
remote identity (SPEC-GIT-IMPORT §8) matches any recorded import
source in the repository, with an error naming the import state and
the fork-mode alternative. Rationale: lease seeding from `ls-remote`
means a plain re-translation pointed at the upstream would PASS its
lease and force-replace upstream history with a disconnected mirror.
Fork-mode export toward the upstream (or its forks) is the supported
collaboration path. The guard compares canonical identities and is a
safety net, not a security boundary (SPEC-GIT-IMPORT §8's honesty
clause applies).

### 14.3 Fork audit

Fork-mode mirrors are not fully §9-reconstructible (the upstream
segment is not bridge-shaped). The pinned third verification mode,
**fork audit**, walks the closure from a bridge-translated head:

1. deep-verifies (§9) every bridge-shaped object;
2. at each boundary parent: loads the mkit twin from the store,
   checks its importer signature against the pinned importer key
   (SPEC-GIT-IMPORT §4), and checks the retained raw bytes hash to
   the claimed sha1; for imported ref TIPS it additionally requires a
   recorded `git-import/v1` attestation (head-scoped — §5 of
   SPEC-GIT-IMPORT mints per head; per-commit envelope verification
   is `verify-attest`'s job);
3. for imported trees/blobs referenced by bridge objects: re-derives
   the git bytes from the mkit twin (verbatim for blobs ≤ 1 MiB,
   re-sort for trees, flatten for chunked) and compares the sha1.

The SHA-1 collision claim is exactly this and no more: fork audit
detects a swapped object **for every object whose bytes it checks
under steps 2–3**; SHA-1 remains a locator everywhere else (§2).

---

## 15. Version history

| Version | Changes |
|---------|---------|
| 1 | Initial mapping: blob/chunked-blob/tree/commit/tag export, remix refused with reserved carrier, shallow/deep verification, `git-bridge/v1` attestation, ref CAS mirror semantics. Amended in-series (pre-merge): fork/passthrough mode + origin guard + fork audit (§14), §1.4 determinism domain restated, attestation scoping, import direction split out to SPEC-GIT-IMPORT. |

---

## 16. Invariants

| Invariant | Enforced by |
|---|---|
| Two implementations translating the same mkit history emit byte- and SHA-identical git objects, with no shared state | translation is a pure function of source object bytes (fork mode: of *(store, import map)*); no clock, locale, config, or key material consulted (§1.4) |
| Every translated object reconstructs to bit-exact mkit bytes and its original signature re-verifies | the §3/§4/§7.1/§12.1 refusal set (oversize plain blobs, non-canonical manifests, git-illegal names) plus the verification-only inverse (§9), which fails closed on anything not bridge-shaped |
| Only `schema_version = 0x01` objects are ever translated | version keying refuses any other prologue, per ref (§1.2) |
| A carried signature never verifies over git bytes; SHA-1 is a locator, never identity or proof | shallow/deep verification rebuilds mkit signing bytes only (§10); integrity rides on BLAKE3 + Ed25519 (§2, §11) |
| An all-zero signature reports "unsigned", never "tampered" | pinned reporting rule (§10) |
| A translated ref head is bound to its mkit identity, not its git sha | `git-bridge/v1` subject digest is blake3; `gitCommit` is a predicate-side locator (§11) |
| A lost export race never produces divergent translation | idempotent object writes + CAS ref updates + `--atomic` push (§12.2) |
| Wiping bridge state loses nothing | mapping cache and lease state are rebuildable from the store and the mirror's observed values (§12.3) |
| One state dir never serves two mirrors | destination binding recorded at first export (§12.3) |
| Plain export can never force-replace an upstream it was imported from | origin guard compares canonical remote identities and refuses (§14.2) |
| Fork-mode push never rewinds a branch or moves a tag on a repo the exporter doesn't own | fast-forward-only rule against a fresh `ls-remote` observation (§14.1) |
| Adding remix support later cannot break v1 consumers | `mkit-remix-source` / `mkit-object-type` header names reserved, never emitted (§8) |

§10 is the concentrated statement of what verification does and does
not prove per mode (shallow: carried fields; deep: the whole graph;
fork audit §14.3: bridge-shaped objects plus checked boundary bytes);
this table does not extend those claims.
