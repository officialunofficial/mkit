---
spec: SPEC-DISCLOSURE
version: 3
status: draft-normative
audience: implementers of an mkit disclosure-bundle or closure-profile verifier (any language)
---

# SPEC-DISCLOSURE &mdash; partial-disclosure bundle and closure-profile verification

Status: **Draft, normative.** The wire format and verification algorithm
below are pinned by the golden vectors in §6 and §7.7 and are not expected to
change incompatibly, but this document has not yet accumulated the
implementation experience SPEC-CONVENTIONS §2.1 reserves `stable` for.
Scope: proving that a single path, chunk, or byte range of a file belongs
to a specific mkit commit id, with proof bytes on the order of a few KiB
regardless of repository size ("partial disclosure"), **and** proving that
a served object set is the full content that commit id commits to
("closure profile" / full disclosure, §7).

This is issue #1015 (verifier kit). Out of scope, deliberately:
wasm bindings (PR 4), CLI commands (PR 5), the docs guide (PR 6).

## 1. Purpose and trust model

A **disclosure bundle** lets an untrusted party (a data-availability
provider, a light client, an auditor, a browser) hand a verifier three
things &mdash; a trusted commit id, an encoded bundle, and nothing else &mdash; and
receive back a [`Disclosed`](../../rust/crates/mkit-core/src/verify.rs)
result whose `payload` bytes are **exactly** the content that commit id
commits to, at the path the bundle discloses.

A verified disclosure proves:

- **content &harr; commit id.** The disclosed bytes are reachable from
  `commit_id` via an unbroken chain of BLAKE3/BMT checks (§3).

A verified disclosure does **not** prove:

- **completeness.** That the disclosed path is the *only* thing under its
  parent, or that nothing else exists in the repository. A disclosure
  bundle carries a proof of *inclusion*, never of *exclusion* &mdash; see §7's
  note on non-membership.
- **signer identity.** `signer`/`signature_valid` report whether the
  commit's (or remix's) embedded Ed25519 signature verifies against its
  embedded public key (SPEC-SIGNING §3). Binding that public key to a
  person, organization, or trust level is application policy, exactly as
  [`sign::verify_commit`](../../rust/crates/mkit-core/src/sign.rs)
  already documents &mdash; this spec changes nothing about what a commit
  signature covers.

## 2. The authentication chain

```
commit id
  = BLAKE3(commit bytes)                          <- verifier recomputes; reads tree_hash
tree_hash
  = wrap(Tree, BMT(entry leaves))                 <- SPEC-MERKLE-OBJECTS §2/§3.2
    one Step per path component: entry + <= log2(M) siblings
child_id (a Step's disclosed leaf)
  |- Blob            (SPEC-OBJECTS §3):  full canonical bytes, or a Bao
  |                   slice over them (content offset o -> canonical
  |                   offset o + 10)
  \- ChunkedBlob      (SPEC-OBJECTS §7): wrap(ChunkedBlob, BMT([meta, chunks...]))
                       chunk step = chunk id at position (index + 1), via
                       one multi-proof over {0, index + 1} that also
                       authenticates total_size/chunk_size (SPEC-MERKLE-OBJECTS §3.1)
                       chunk bytes, or a Bao slice over the chunk's own
                       canonical bytes
```

Every layer verifies against the layer above and terminates at the
trusted commit id; nothing in this chain is ever compared against a bare
(pre-domain-wrap) BMT root (SPEC-MERKLE-OBJECTS §5.4).

## 3. Wire format

Encoded with `commonware-codec` conventions (SPEC-CONVENTIONS §3
generalizes; this corpus's specific convention, also used by
`transfer::PackListNode`, is: fixed integers **big-endian**, every length
an LEB128 **varint**, arrays raw, `Option<T>` as a bool discriminant
followed by `T` when present):

```
magic   = "MKDP"              (4 raw bytes)
version: u8 = 2
commit_id: [u8; 32]
commit_bytes: Vec<u8>          <= 4 MiB
steps: Vec<Step>               <= MAX_TREE_DEPTH (128), root first
  Step {
    name: Vec<u8> (1..=255)     entry name, SPEC-OBJECTS §4.1 rules
    mode: u8                    EntryMode (SPEC-OBJECTS §4)
    child_id: [u8; 32]
    inner_root: [u8; 32]        bare BMT root of the parent Tree
    position: u32                BMT position (= entry index) in the parent Tree
    proof: Proof (max_items = 1) SPEC-MERKLE-OBJECTS §5.1/§5.2
  }
payload_kind: u8
  0  Object { bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
  1  Chunk  { total_size: u64, chunk_size: u32, index: u32,
              inner_root: [u8; 32], proof: Proof (max_items = 2),
              bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
  2  Range  { chunk: Option<ChunkHdr>,
              offset_in_blob: u64, len: u64, slice: Vec<u8>,
              chunk_len_proofs: Vec<LenProof> <= MAX_CHUNKS }
     ChunkHdr { total_size: u64, chunk_size: u32, index: u32,
                inner_root: [u8; 32], chunk_id: [u8; 32],
                proof: Proof (max_items = 2) }
     LenProof { index: u32, chunk_id: [u8; 32],
                proof: Proof (max_items = 1), slice: Vec<u8> }
```

`Step.inner_root` is the bare BMT root of the **parent** Tree this
step's proof is verified against (the tree whose id is the commit's
`tree_hash` for step 0, or the previous step's `child_id`).
`Chunk`/`ChunkHdr.inner_root` is the bare BMT root of the ChunkedBlob
whose id is the leaf id. `LenProof` entries reuse that same root (same
object) and gain nothing.

The whole bundle MUST be `<= MAX_BUNDLE_BYTES` (64 MiB), checked before
any decode work. Trailing bytes after the declared body MUST be
rejected. `version != 2`, an unrecognized `payload_kind`, and an
unrecognized `mode` byte are typed decode errors, never a bare "invalid".
A version byte of `1` is a typed `UnsupportedBundleVersion(1)` error;
there is no compatibility decoder.

`Step` and `ChunkHdr`/`LenProof`'s `proof` fields decode with
[`merkle::Proof::decode`](../../rust/crates/mkit-core/src/merkle.rs)'s
`max_items` bound (SPEC-MERKLE-OBJECTS §5.2): 1 for a single-leaf proof,
2 for a multi-proof over `{0, position}` (§4.3). Every `Vec` read is
bounded with `read_range` before allocation (§5).

### 3.1 Why `ChunkHdr` carries an explicit `chunk_id`

A Bao `SliceDecoder` always requires its expected root hash **up front**
&mdash; it cannot recover an unknown root from the slice bytes themselves,
by construction (verified streaming's whole point is that the root is
already trusted before decoding starts). For the `Chunk` payload kind the
verifier can compute that hash itself, by hashing the disclosed `bytes`
directly (they *are* the chunk's canonical bytes). For the `Range`
payload kind on a `ChunkedBlob` leaf, only a byte range is disclosed &mdash;
the verifier never sees the chunk's full bytes to hash &mdash; so the
containing chunk's id MUST travel on the wire as its own field.
`ChunkHdr.chunk_id` is exactly the value [`verify_chunk_with_meta`](../../rust/crates/mkit-core/src/verify.rs)'s
multi-proof authenticates against the leaf's `ChunkedBlob` id, so a
forged `chunk_id` simply fails to fold to that id (§4.3) &mdash; carrying it
explicitly costs nothing security-wise and closes an otherwise-unprovable
gap.

## 4. Verification algorithm

A conformant verifier, given a trusted `commit_id: Hash` and an encoded
`bundle: [u8]`:

1. **MUST** reject `bundle` outright if it exceeds `MAX_BUNDLE_BYTES`,
   before decoding anything.
2. **MUST** check the fixed 5-byte header (`"MKDP"` magic + version byte)
   before decoding the codec body; an unrecognized version is a typed
   error, not a fallback to another format.
3. **MUST** decode the codec body with every `Vec` bounded as in §3, and
   **MUST** reject any trailing bytes after the declared body.
4. **MUST** compare the bundle's embedded `commit_id` field against the
   externally trusted id the caller is verifying against, as a fast
   sanity check (a mismatch here is always also a hash mismatch at step
   5, but checking the field first avoids hashing a large `commit_bytes`
   for an obviously-wrong bundle).
5. **MUST** recompute `BLAKE3(commit_bytes)` and reject unless it equals
   the trusted `commit_id` &mdash; this is the one step that binds
   everything else to a value the caller did not have to fetch.
6. **MUST** decode `commit_bytes` and accept only `Commit` or `Remix`
   (SPEC-OBJECTS §5/§6); any other decoded type is a typed error. Take
   `tree_hash` from whichever it is.
7. **MUST** reject `steps.len() > MAX_TREE_DEPTH` (128, SPEC-OBJECTS'
   `store::MAX_TREE_DEPTH`).
8. For each `Step` at index `i` (root first):
   1. **MUST** validate `name` against SPEC-OBJECTS §4.1's entry-name
      rules ([`TreeEntry::validate_name`](../../rust/crates/mkit-core/src/object.rs)) &mdash;
      an invalid name (trailing space, `.mkit`, a reserved Windows device
      name, etc.) is rejected here, before its proof is even checked.
    2. **MUST** check `domain_digest(b"mkit.tree\x00", inner_root) == expected_id`
       first, where `expected_id` is the previous step's `child_id` (step 0
       against `tree_hash` itself). A mismatch is a typed `InnerRootMismatch`.
       The field is never a second trust anchor (wrap-check-first,
       `docs/VERIFY.md` §5). **MUST** then require that the proof folds to
       exactly `inner_root`; a bundle whose proof folds to a different root
       than it declares is rejected even if the wrap of the declared root
       happens to match, and vice versa. **MUST** then wrap the folded
       value and compare to `expected_id` (SPEC-MERKLE-OBJECTS §5.4).
       A commonware-native verifier performs the wrap check itself and
       then runs upstream `bmt::Proof::verify_element_inclusion` against
       `inner_root` unmodified, needing no mkit code beyond the public
       domain constants.
   3. **MUST** reject the whole bundle if `i` is not the last step and
      `mode != Tree` &mdash; every step but the last MUST descend into a
      directory.
9. The **authenticated path** is `steps.map(|s| (s.name, s.mode))`, and
   the **leaf id** is the last step's `child_id` (or `tree_hash` itself
   when `steps` is empty &mdash; disclosing the root tree). A verifier
   compares this authenticated path against whatever path string it
   asked for; **it MUST NOT trust a claimed path** carried any other way.
10. Dispatch on `payload_kind`:
    - **`Object`**: **MUST** deserialize `bytes` and check its
      content-address (BLAKE3, or the BMT root for a `Tree`/`ChunkedBlob`
      &mdash; SPEC-MERKLE-OBJECTS §2) equals the leaf id.
    - **`Chunk`**: **MUST** first check
       `domain_digest(b"mkit.chunked\x00", inner_root) == leaf_id`, else
       reject with `InnerRootMismatch`. **MUST** then require that the
       multi-proof folds to exactly `inner_root`. **MUST** hash `bytes`
       (its BLAKE3 IS the chunk's Blob id, SPEC-OBJECTS §3) and verify, in
       one multi-proof over BMT positions `{0, index + 1}` against the
       leaf id, that (a) the metadata leaf the verifier computes
       **itself** from `total_size`/`chunk_size` and (b) that chunk hash
       at position `index + 1` both fold to the leaf id
       (SPEC-MERKLE-OBJECTS §3.1, §5.5). The metadata leaf is **never**
       accepted as an externally supplied value at position 0 &mdash; only
       ever recomputed from the very fields being authenticated. A
       commonware-native verifier runs the wrap check and then upstream
       `bmt::Proof::verify_multi_inclusion` against `inner_root`
       unmodified.
    - **`Range`**, `chunk = None` (the leaf is a plain `Blob`): **MUST**
      reject `len == 0`. **MUST** verify a Bao slice proving `len` bytes
      at content offset `offset_in_blob` (Bao offset `offset_in_blob +
      10`, SPEC-OBJECTS §3's prologue) against the leaf id. `absolute_offset`
      is `offset_in_blob` itself &mdash; nothing further to prove.
      `chunk_len_proofs` MUST be empty; a non-empty set here is a typed
      error (it has no target chunk to describe).
    - **`Range`**, `chunk = Some(hdr)` (the leaf is a `ChunkedBlob`):
       **MUST** reject `len == 0`. **MUST** apply the same wrap-check-first
       and fold-equals-declared rules as `Chunk` to `hdr.inner_root`.
       **MUST** run the same `{0, index + 1}` multi-proof as `Chunk` above
       (using `hdr.chunk_id` as the second leaf) against the leaf id.
       **MUST** verify a Bao slice proving
      `len` bytes at content offset `offset_in_blob` (Bao offset
      `offset_in_blob + 10`) against `hdr.chunk_id`. If `hdr.index == 0`,
      `chunk_len_proofs` **MUST** be empty &mdash; nothing precedes the
      first chunk for an entry to describe, so a non-empty set here is a
      typed error, exactly like the plain-`Blob` case above, **never**
      silently ignored; `absolute_offset` is then
      `Some(offset_in_blob)` (already absolute). Otherwise, if
      `chunk_len_proofs` is empty, `absolute_offset` is `None` (not
      requested). Otherwise, `chunk_len_proofs` **MUST** cover exactly
      the index set `0..hdr.index`, with no gaps and no duplicates &mdash; an
      incomplete or malformed set **MUST** be rejected as a typed error,
      **never** silently treated as "absent". When it does cover
      `0..hdr.index` completely, each entry's chunk id **MUST** verify
      (single-leaf proof, `verify_chunk`) against the leaf id at position
      `index + 1`, and each entry's `slice` **MUST** verify as a length
      proof (§4.1 below) against that chunk id; `absolute_offset` is then
      `Some(sum of every proven length + offset_in_blob)`.

### 4.1 Length proofs

A length proof authenticates one chunk's declared content length without
disclosing its bytes: a Bao slice over canonical bytes `0..10` (the fixed
6-byte prologue plus the 4-byte `le32` length field, SPEC-OBJECTS §2/§3)
against that chunk's own id, at Bao offset 0 (not `+10` &mdash; this slice
covers the header itself, not post-header content). The authenticated
value is the `le32` at bytes `6..10`. **Bao's own encoding header is not
what is trusted here** &mdash; only the canonical prologue bytes it wraps,
which is exactly why the slice's target is the chunk's real content
id, not a value Bao invents.

## 5. Bounds

| Field | Bound | Rationale |
|---|---|---|
| whole bundle | `MAX_BUNDLE_BYTES` = 64 MiB | checked before any decode |
| `commit_bytes` | 4 MiB | comfortably above any real commit/remix |
| `steps` | `MAX_TREE_DEPTH` = 128 | SPEC-OBJECTS' existing tree-depth cap |
| `Step.name` | 1..=255 bytes | SPEC-OBJECTS §4.1 |
| `Object.bytes` / `Chunk.bytes` | `MAX_RAW_OBJECT_SIZE` = 1 GiB | the store's existing object-size cap |
| `Step`/`Chunk`/`ChunkHdr` proof siblings | `max_items * MAX_LEVELS` (32) | SPEC-MERKLE-OBJECTS §5.2, before any sibling is read |
| `chunk_len_proofs` | `MAX_CHUNKS` = 1,000,000 | the store's existing per-manifest chunk-count cap |
| a single `LenProof.slice` | 8 KiB | proving 10 bytes needs one 1 KiB Bao leaf chunk plus at most `MAX_LEVELS` 64-byte parent hashes plus an 8-byte header &mdash; comfortably under 4 KiB; 8 KiB leaves headroom |

A malicious `leaf_count` inside any embedded `Proof` cannot force a large
allocation: sibling count is bounded by `max_items * MAX_LEVELS` before
any sibling digest is read (SPEC-MERKLE-OBJECTS §5.2), and `leaf_count`
itself is compared, never used to size an allocation.

## 6. Golden vectors

`rust/tests/golden/disclosure/` (SPEC-CONVENTIONS §5) carries the
authoritative pinned bytes: a deterministic fixture repo (fixed signer
seed, fixed timestamp, fixed file bytes; a large file of a fixed PRNG
stream so FastCDC yields several chunks), each `<name>.bin` disclosure
bundle paired with a `<name>.json` sidecar recording the commit id, the
requested path/selector, the expected `Disclosed` summary (path, leaf id,
payload kind, offsets, disclosed bytes' BLAKE3), and the expected
accept/reject outcome (with a reason for every reject). `MANIFEST.txt`
pins every vector's BLAKE3 digest.

Accept vectors: the root tree; a shallow file; a 3-level-nested file; an
executable-mode file; one chunk of a chunked file; a range inside a chunk
(with and without `chunk_len_proofs`, the latter's `absolute_offset`
checked against the fixture's known plaintext offset); a range covering
a whole small blob (the first Bao block, and a last partial block).

Reject vectors: a non-`Tree` intermediate step mode; a step's proof
checked against the wrong parent (two steps swapped); an invalid entry
name (trailing space); a payload whose id does not equal the leaf id; a
`Chunk`/`Range` chunk header with a forged `total_size`; a Bao slice at
the wrong offset; a zero-length range; an incomplete `chunk_len_proofs`
set; a `chunk_len_proofs` entry present on a chunk-index-0 range
(`neg_len_proofs_on_chunk0`); `steps.len() = 129`; `version = 3`;
`version = 1` (`neg_bundle_version_1`); a declared inner root that does
not wrap to the parent id (`neg_inner_root_forged`); a declared inner
root that wraps correctly but whose proof was built for a different
tree (`neg_inner_root_fold_mismatch`); a trailing byte after the
declared body; and `commit_bytes` that decode to a `Tag` (a valid,
signed object &mdash; just not one with a `tree_hash`). Accept sidecars
record `step_inner_roots_hex` and `chunk_inner_root_hex`.

`rust/crates/mkit-core/tests/golden_disclosure.rs` reads only the
committed files, runs `verify::verify_disclosure`, and compares the
result against each sidecar; it never calls the fixture generator.

## 7. Closure profile (full disclosure)

Purpose: given a trusted commit (or remix, or tag) id and a set of
object bytes &mdash; optionally wrapped in raw-only v1 packs plus a
convenience manifest &mdash; a verifier checks that every object reachable
from that id is present and re-hashes to the id it was supplied under.
This is full disclosure against a commit id, for a DA provider, a light
client, or an auditor. The root id is the **only** trust anchor. The
manifest is an index of pack hashes; it does not authenticate the
objects.

### 7.1 Modes and `children`

Two walk modes, because the on-chain anchor is per commit:

| Mode | Byte | What is included |
|---|---|---|
| snapshot (default) | `0` | the root object and its tree closure (trees, blobs, chunked-blob manifests, chunks); tag &rarr; target; remix &rarr; tree. Parents are referenced but not included. |
| history | `1` | today's `reachable_objects` semantics: every ancestor, identical to what push/fetch ship |

`children(obj, mode)` is the single source of truth for "what does this
object reference":

- `Commit`: `tree_hash`, plus `parents` only in history.
- `Remix`: `tree_hash`, plus `parents` only in history; never `sources`
  (foreign-repo pointers, SPEC-OBJECTS §6).
- `Tree`: every entry `object_hash`.
- `ChunkedBlob`: every chunk.
- `Tag`: `target`.
- `Blob` / `Delta`: none (`Delta.base_hash` is not followed).

The root, when present, MUST deserialize as a `Commit`, `Remix`, or
`Tag`. A typed error is raised otherwise.

### 7.2 Raw-only pack rule

A closure pack is a [SPEC-PACKFILE](SPEC-PACKFILE.md) v1 pack of `0x00`
(raw) entries only. The writer MUST NOT compress and MUST NOT emit
deltas. This is so a wasm verifier, which is built without `pack-zstd`,
can consume the profile: `0x03`/`0x04` entries error in that build via
the existing stub, and a delta would require a store to resolve.

A verifier that sees a delta entry or a compressed entry MUST fail with
a profile-violation error naming the pack index and entry index. It MUST
NOT decompress in order to decide this &mdash; scan entry types first.

### 7.3 Manifest bytes

Encoded with commonware-codec conventions (fixed integers big-endian,
lengths LEB128 varint, arrays raw), matching §3:

```
magic "MKCL"            (4 raw bytes)
version: u8 = 1
root: [u8; 32]
mode: u8                0 = snapshot, 1 = history
packs: Vec<[u8; 32]>    pack_key of each pack, in order; length <= 65_536
```

Decoders MUST reject trailing bytes, an unknown version, and an unknown
mode. `pack_key` is BLAKE3 of the entire pack including its trailer
(SPEC-PACKFILE §7).

The manifest is a convenience index. The root id remains the only trust
anchor: a verifier that already has the packs MAY call the pack-set
entry point directly and ignore the manifest.

### 7.4 Verifier MUSTs

1. Re-hash every supplied object (`deserialize` then `id_from_object`).
   In the store-less map path, a deserialize failure is `corrupt` under
   the BLAKE3 of those bytes. A bit-flipped object that still deserializes
   is content-addressed under a *different* id and surfaces as `missing`
   (the referenced id) plus `unreferenced` (the supplied one), not
   `corrupt`. A verifier that fetches by id MAY report a hash mismatch as
   `corrupt` under the requested id; this is the useful classification when
   a store returns bytes from the requested object slot.
2. Walk from the root with `children(obj, mode)` over the resulting
   `id → bytes` map or pull-based source (BFS, visited set). The map walk
   is store-less; a pull-based source fetches only requested ids.
3. Anything referenced and absent is `missing`. Anything supplied and
   never visited is `unreferenced` when the verifier can enumerate the
   supplied set. Completeness fails on `missing` or `corrupt`;
   `unreferenced` is reported, not an error &mdash; a DA provider MAY serve
   a superset. A report that cannot enumerate the supplied set MUST set
   `unreferenced_checked` to `false` and leave `unreferenced` empty.
4. The root itself missing is `missing = [root]`, `verified = 0`.
5. Delta or compressed pack entries are a profile violation (§7.2).
6. The verifier MUST be given the trusted root by its caller and MUST
   reject a manifest whose `root` differs; the manifest is a locator,
   never a trust anchor.
7. Manifest pack hashes MUST equal `pack_key` of the supplied packs, in
   order, and the counts MUST match.
8. Object count MUST NOT exceed SPEC-PACKFILE `MAX_ENTRIES`
   (10,000,000). Pack payload sum and entry count reuse SPEC-PACKFILE
   caps. Tree depth, tree entries, chunks, and parents reuse
   `store::MAX_TREE_DEPTH`, `serialize::MAX_TREE_ENTRIES`,
   `serialize::MAX_CHUNKS`, `serialize::MAX_PARENTS`.

### 7.5 Bounds

| Bound | Value | Applied to |
|---|---|---|
| pack entries | 10,000,000 | each pack, and the supplied object set |
| pack payload sum | 4 GiB | each pack (SPEC-PACKFILE §5) |
| raw object size | 1 GiB | each object (store cap) |
| manifest packs | 65,536 | `packs` vector |
| tree depth | 128 | inherited from object decode |
| tree entries / chunks | 1,000,000 | inherited from object decode |
| parents | 1,000 | inherited from object decode |

### 7.6 Vectors

`rust/tests/golden/closure/` pins the bytes. Accept vectors: `snapshot`
(fixture head commit), `history` (a second commit so history &ne;
snapshot; the parent's tree objects are present only in history),
`tag_root` (tag &rarr; commit, snapshot). Sidecars record the root, mode,
pack hashes, expected `verified` count, and the sorted id list.

Reject / incomplete vectors: missing chunk; corrupt blob; unreferenced
extra (still complete); a delta entry; a compressed entry; a manifest
pack-hash mismatch; the wrong root id; a manifest whose `root` differs
from the caller's trusted root; manifest version 2; a trailing byte on
the manifest.

`rust/crates/mkit-core/tests/golden_closure.rs` reads only the committed
files.

## 8. Later (out of scope for this document)

- **Non-membership.** `payload_kind 3` is reserved for a future proof
  that a name is *absent* from a `Tree` (a range proof over the two
  lex-adjacent entries). Not implemented here.

## 9. Invariants

| Mutation | Detected because |
|---|---|
| any disclosed byte tampered | the Bao slice / BLAKE3 check against the authenticated id fails |
| a step's `(name, mode, child_id)` tampered | that step's inclusion proof no longer folds to the expected parent id |
| declared inner root does not wrap to the parent id | wrap-check-first (`domain_digest(TYPE_DOMAIN, inner_root) == expected_id`) fails with `InnerRootMismatch` |
| proof fold does not equal the declared inner root | rejected even if the wrap of the declared root happens to match |
| step order/parent tampered (steps swapped) | each step verifies against the *previous* step's `child_id`, not an independent root |
| a non-final step's mode misreported as non-`Tree` | rejected outright (§4 step 8.3), before its proof is even checked |
| `ChunkedBlob` `total_size`/`chunk_size` forged | the multi-proof's metadata leaf (computed by the verifier, never accepted as input) no longer folds to the leaf id |
| a `Range` payload's offset/length claim tampered | the Bao slice fails to verify at the claimed offset |
| an incomplete/malformed `chunk_len_proofs` set | rejected as a typed error, never silently treated as "no offset available" |
| a `chunk_len_proofs` entry present on a chunk-index-0 range | rejected outright (`UnexpectedLengthProofs`), the same as the plain-`Blob` case &mdash; index 0 has nothing preceding it to describe |
| oversize bundle / proof sibling count / chunk-length-proof count | bounded before any decode allocation (§5) |
| checked against a bare inner root instead of the object id | every check here goes through the id-based `merkle::verify_*` (SPEC-MERKLE-OBJECTS §5.4) |
| a claimed path not matching what was actually authenticated | callers compare the returned authenticated `path`, never a path string the bundle merely asserts |
| a closure object omitted | the walk from the root reports it in `missing`; completeness fails |
| a closure object's bytes tampered | map verification reports a deserialize failure as `corrupt` and a still-deserializable bit flip as `missing` plus `unreferenced`; a verifier that fetches by id MAY report a hash mismatch as `corrupt` under the requested id |
| a delta or compressed pack in a closure | profile violation, before any decompress |
| a closure manifest pack hash swapped | `pack_key` mismatch against the supplied pack |
| a closure verified against the wrong root | the requested root is `missing`; the supplied set is `unreferenced` |
| a closure manifest whose `root` differs from the caller's trusted root | typed `ClosureRootMismatch`; the manifest is a locator, never a trust anchor |

## Cross-references

- [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §2 (identity), §3.1/§3.2
  (leaf schemes), §5 (inclusion proofs, wire bytes, verification-against-id
  rule).
- [SPEC-OBJECTS](SPEC-OBJECTS.md) §3 (Blob), §4 (Tree, entry-name rules),
  §6 (Remix sources), §6a (Tag), §7 (ChunkedBlob).
- [SPEC-PACKFILE](SPEC-PACKFILE.md) &mdash; v1 raw (`0x00`) packs are the
  closure-profile carrier.
- [SPEC-SIGNING](SPEC-SIGNING.md) §3 (what a commit signature covers).
