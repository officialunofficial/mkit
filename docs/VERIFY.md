# VERIFY &mdash; verifying an mkit commit hash

Audience: someone building a verifier or a data-availability (DA) provider
who has an mkit commit id from an external anchor (a chain, a signed
release, a timestamp) and bytes served by a party they do not trust. This
guide stands alone with the specs and the golden vectors; it links to the
specs for normative detail rather than restating it, and every command and
code snippet on this page has been run against a real repository as part of
writing it.

This is issue [#1015](https://github.com/officialunofficial/mkit/issues/1015)
(the "verifier kit"), PR 6 of 6. The kit itself &mdash; proofs, the disclosure
module, closure export, the CLI, the wasm exports &mdash; is scoped and
delivered in PRs 1&ndash;5; this document explains how to *use* it.

## Contents

1. [What a commit id commits to](#1-what-a-commit-id-commits-to)
2. [Trust model](#2-trust-model)
3. [Full disclosure (closure profile)](#3-full-disclosure-closure-profile)
4. [Partial disclosure (bundle)](#4-partial-disclosure-bundle)
5. [Interop for commonware-based verifiers](#5-interop-for-commonware-based-verifiers)
6. [Implementing a verifier from scratch](#6-implementing-a-verifier-from-scratch-no-rust)
7. [Limits and non-goals](#7-limits-and-non-goals)
8. [Reference table](#8-reference-table)

## 1. What a commit id commits to

An mkit commit id is a 32-byte BLAKE3 digest of a small (~250 byte)
canonical commit object. Everything else &mdash; every file, every directory,
every chunk of every large file in the repository at that commit &mdash; is
reachable from that one id through an unbroken chain of content-addressed
hashes. This is the property the whole verifier kit rests on: hold the id,
and you can authenticate any byte anyone claims belongs to it, without
having to fetch or trust anything else first.

```
commit id  (~250 B object; BLAKE3 of canonical commit bytes)
  = BLAKE3(commit bytes)
                                    verifier recomputes this; reads tree_hash
                                    out of the now-authenticated bytes
  |
  v
tree_hash                          the commit's root Tree id
  = wrap(Tree, BMT(entry leaves))  domain-wrapped Binary Merkle Tree root
                                    over the root directory's entries
                                    (SPEC-MERKLE-OBJECTS §2 / §3.2)
  |
  |   one Step per path component: an entry (name, mode, child_id) plus
  |   <= ceil(log2(M)) sibling digests, M = that directory's entry count
  v
child_id  (a Step's disclosed leaf; itself a Tree id if there's another
           path component to descend into)
  |
  +-- Blob              (SPEC-OBJECTS §3, files <= 1 MiB)
  |     id = BLAKE3(prologue || le32(len) || data)
  |     disclosed as: the full canonical bytes, or a Bao slice over them
  |     (content offset o maps to canonical Bao offset o + 10, the fixed
  |     6-byte prologue plus the 4-byte length field)
  |
  \-- ChunkedBlob        (SPEC-OBJECTS §7, files > 1 MiB)
        id = wrap(ChunkedBlob, BMT([meta_leaf, chunk_0, chunk_1, ...]))
        chunk i lives at BMT position i + 1 (position 0 is the metadata
        leaf binding total_size/chunk_size); reached via one multi-proof
        over positions {0, i + 1} (SPEC-MERKLE-OBJECTS §3.1)
        each chunk is itself a Blob: disclosed as full bytes, or a Bao
        slice over the chunk's own canonical bytes
```

Every layer verifies against the layer directly above it, and the whole
chain terminates at the one id the caller already trusted going in. The
rule this enforces is narrower than "never touch a bare root": **the
comparison against a trusted value is always on the wrapped id**, never a
bare, pre-domain-wrap BMT root accepted as trustworthy on its own. A bare
inner root MAY appear as an *input* alongside a proof (§5 covers exactly
this case, for a commonware-based verifier) &mdash; but only after that input
itself has been checked against the trusted id via the domain wrap, never
before. See [§5.4 of SPEC-MERKLE-OBJECTS](specs/SPEC-MERKLE-OBJECTS.md#54-verification)
for why that ordering is load-bearing, not cosmetic.

### Proof sizes

| Component | Size |
|---|---|
| Commit (or Remix) object | ~250 B (a few hundred more for a Remix, which carries `sources`) |
| One tree-entry step | one entry (`name` + mode + 32-byte child id) plus `32 * ceil(log2(M))` sibling bytes, `M` = that directory's entry count |
| One chunk step | `32 * ceil(log2(N + 1))` sibling bytes, `N` = the file's chunk count (`+1` for the metadata leaf) |
| A Bao slice of `len` content bytes | roughly one 1 KiB Bao leaf block per 1 KiB of `len`, plus `~64 * log2(blocks)` bytes of Bao tree-hash overhead |

A concrete example, captured from a real v2-bundle run against a small
demo repo (commit `64ccb22…`, a two-level path `src/lib.rs`, a 40-byte
range at offset 100): the whole disclosure bundle &mdash; commit bytes, two
tree-entry steps, and a Bao-slice range payload &mdash; was **684 bytes**. A single file
directly under the root instead of two levels deep would be smaller still;
a 1 GiB chunked file's chunk step costs about 14 sibling digests (`log2` of
~16,384 chunks), regardless of how large the file itself is. Proof size
scales with **tree depth and file chunk count**, never with total
repository size.

## 2. Trust model

A verified proof (partial or full) establishes exactly one thing precisely,
and nothing more: **the disclosed bytes are reachable from the trusted
commit id through the chain in §1.** Read that narrowly. There are two
further claims a verifier might care about, and this kit deliberately keeps
them separate:

| Claim | What proves it | Who establishes it |
|---|---|---|
| **content &harr; commit id** | the BLAKE3/BMT chain in §1 | the verifier, from the disclosed bytes alone &mdash; this is what `verify_disclosure` / `verify_closure*` check |
| **commit &harr; signer** | an Ed25519 signature over the commit's signing bytes (SPEC-SIGNING §3) | the verifier, via `signature_valid` &mdash; still just cryptography, no external input needed |
| **signer &harr; identity** | nothing in this kit | the caller's own policy: a trust-roots registry, an attestation, an out-of-band agreement |

`Disclosed.signer` / `Disclosed.signature_valid` (and the closure
manifest's equivalent, since a closure's root can itself be a signed
`Commit`/`Remix`/`Tag`) report whether the commit's *embedded* public key
produced its *embedded* signature. That is real cryptographic work, but it
says nothing about who that public key belongs to &mdash; binding a key to a
person or an organization is exactly what `mkit verify --trust-roots` (and
`verify-proof --trusted --trust-roots`) layers on top, and it is the
caller's responsibility to apply the same policy at the DA/verifier layer
if identity matters there.

One structural detail worth internalizing: `Commit`'s `message_hash` and
`content_digest` fields are **inside** the commit id (they're part of the
canonical bytes BLAKE3'd to produce it) but **outside** the signature (the
signing bytes explicitly exclude them, SPEC-SIGNING §3, red-team item
R-45 &mdash; otherwise a downstream re-computation of either annotation would
silently shift the commit hash). Practically: those two fields are
authenticated by the id check, not by the signature check. A verifier that
cares about them should compare the commit-id-authenticated values, not
assume a valid signature says anything about them.

**A verifier never trusts prover-supplied paths, offsets, positions, or
lengths.** Every function in this kit returns *what it actually proved* &mdash;
an authenticated `path: Vec<(name, mode)>`, an authenticated
`offset_in_blob`, an authenticated chunk `index` &mdash; and it is the caller's
job to compare that returned value against whatever it originally asked
for. A bundle that claims to disclose `secrets.env` but whose authenticated
path says `README.md` is not a verification failure; it is the caller
failing to check the one field this entire exercise exists to produce. See
[`mkit verify-proof --expect-path`](CLI.md) for the CLI's version of that
check.

## 3. Full disclosure (closure profile)

Full disclosure proves that a served object set is **exactly** the content
a commit (or remix, or tag) id commits to: every reachable object present,
every id re-derived from bytes, nothing missing and nothing corrupt. This
is the shape a DA provider, a light client mirroring a repository, or an
`fsck`-style auditor wants.

### Modes

The walk has two modes, because the natural anchor is a single commit, not
a whole history:

| Mode | Included |
|---|---|
| **snapshot** (default) | the root object and its tree closure: every `Tree`, `Blob`, `ChunkedBlob` (manifest + chunks) reachable from the root's tree. Parents are *referenced*, not *included*. |
| **history** | everything `snapshot` includes, plus every ancestor commit and *its* tree closure &mdash; identical to what `push`/`fetch` already ship |

Both modes share one function, `children(obj, mode)` (`mkit_core::ops::graph`),
as their single source of truth for "what does this object reference" &mdash; a
`Commit`/`Remix`'s `parents` are followed only in history mode, a
`Remix`'s `sources` (foreign-repo pointers) are **never** followed by
either mode, and `Delta.base_hash` is never followed (deltas are a
pack-internal encoding detail, not part of object identity).

### The raw-only pack rule

A closure is carried as one or more [SPEC-PACKFILE](specs/SPEC-PACKFILE.md)
v1 packs containing **only raw (`0x00`) entries** &mdash; no compression, no
deltas. This is deliberate: `mkit-wasm` is built with `default-features =
false` (no `pack-zstd`, keeping the wasm build blst/zstd-free per
SPEC-MERKLE-OBJECTS' constraint), so a wasm-based verifier has no way to
decompress a `0x03`/`0x04` entry and no store to resolve a delta base
against. A verifier MUST scan entry *types* before doing any decompression
work, and reject a delta or compressed entry outright as a profile
violation naming the pack and entry index &mdash; never attempt to decompress
first and fail there.

### `missing`, `corrupt`, `unreferenced`

A closure check (`verify_closure` / `verify_closure_packs` /
`verify_closure_manifest`, or `mkit closure verify`) returns a report with
three lists, not a single pass/fail bit, plus `unreferenced_checked`:

- **`missing`** &mdash; an id the walk reached but nobody supplied bytes for.
- **`corrupt`** &mdash; supplied bytes that failed to *deserialize* at all,
  or whose derived id did not match a fetch-by-id request. Map-path decode
  failures are keyed by the BLAKE3 of those bytes; streaming mismatches are
  keyed by the requested id.
- **`unreferenced`** &mdash; bytes that were supplied, deserialized fine, and
  got a real id, but the walk from the root never reached that id.

There are two verifier shapes. The store-less map path (`verify_closure`) and
the raw-pack path (`verify_closure_packs` and `verify_closure_manifest`) have
the complete supplied set available, so they set `unreferenced_checked` to
`true`. A pull-based source (`verify_closure_streaming`, including the native
`verify_closure_store` path) fetches only ids reached by the walk; it sets the
flag to `false` and leaves `unreferenced` empty because it cannot know what it
was never asked to fetch.

Completeness is `missing.is_empty() && corrupt.is_empty()`. An
`unreferenced` extra is reported but is **not** a failure &mdash; a DA
provider legitimately may serve a superset of what one commit needs (a
second unrelated commit's blobs stored alongside it, say).

One subtlety worth knowing: a **bit-flipped-but-still-parsable** object
(one byte flipped inside otherwise well-formed canonical bytes) does not
land in `corrupt`. It deserializes fine, gets content-addressed under a
*different* id than whatever filename or slot it was served under, and
surfaces as **`missing`** (the id the walk actually wanted, still absent)
**plus `unreferenced`** (the id the tampered bytes actually hash to, never
visited). `corrupt` is reserved for bytes that don't even parse as an mkit
object. The local CLI's default (no `--from`, without
`--show-unreferenced`) uses the pull-based store path, so a byte flip is
reported directly as `corrupt` under the requested id; passing
`--show-unreferenced` selects the enumerate-everything map path and retains
the map classification above.

### Worked example

**CLI.** Export a snapshot closure, then verify it against a trusted id
from a separate directory (standing in for "downloaded from an untrusted
party"):

```console
$ mkit closure export HEAD -o snap.closure
closure: snapshot, 4 objects in 1 pack(s), 3169 B -> snap.closure

$ ls snap.closure
495fe4e5dfda894cc4007402999261f7c7e7a36fe8164cef3f4befb46df88ab9.pack
MANIFEST.mkcl

$ mkit closure verify 767a2e0c226ae58d6534d454825e8c739e05b09560b4b0e1003c14a02ae91519 \
    --from snap.closure
ok: closure complete (4 objects, snapshot)

$ mkit closure verify 767a2e0c226ae58d6534d454825e8c739e05b09560b4b0e1003c14a02ae91519 \
    --from snap.closure --format=json
{"root":"767a2e0c226ae58d6534d454825e8c739e05b09560b4b0e1003c14a02ae91519","mode":"snapshot","verified":4,"complete":true,"unreferenced_checked":true,"missing":[],"corrupt":[],"unreferenced":[]}
```

`<commit-id>` with `--from` is **always** a trusted 64-hex id, never
resolved as a revision (`HEAD`, a branch name, a short prefix) &mdash; that
resolution would have to trust the very store whose output is being
checked. Without `--from`, `mkit closure verify HEAD` checks the local
repository instead and *does* accept a revision, since there the store is
trusted by construction; the default local check is pull-based, while
`--show-unreferenced` deliberately selects the enumerate-everything map path.

**Rust**, given the manifest and pack bytes from the export above:

```rust
use mkit_core::hash::from_hex;
use mkit_core::verify::verify_closure_manifest;

let expected_root = from_hex("767a2e0c226ae58d6534d454825e8c739e05b09560b4b0e1003c14a02ae91519")?;
let manifest = std::fs::read("snap.closure/MANIFEST.mkcl")?;
let pack = std::fs::read("snap.closure/495fe4e5dfda894cc4007402999261f7c7e7a36fe8164cef3f4befb46df88ab9.pack")?;

let report = verify_closure_manifest(&expected_root, &manifest, &[&pack])?;
assert!(report.is_complete());
assert_eq!(report.verified, 4);
```

`verify_closure_manifest` takes the **trusted root from the caller**, not
from the manifest &mdash; a manifest whose embedded `root` disagrees with
`expected_root` is rejected (`ClosureRootMismatch`) before any pack is even
touched. The manifest is a locator (which packs to fetch), never a trust
anchor.

**TypeScript**, with `@officialunofficial/mkit-wasm`. Packs travel as one
concatenated buffer plus a JSON array of their individual lengths, since
`js_sys::Array<Uint8Array>` doesn't cross the wasm boundary as cheaply as a
flat buffer:

```ts
import { verify_closure_manifest } from "@officialunofficial/mkit-wasm";

const commitId =
  "767a2e0c226ae58d6534d454825e8c739e05b09560b4b0e1003c14a02ae91519";
const manifest: Uint8Array = /* MANIFEST.mkcl bytes */;
const packs: Uint8Array[] = [/* one Uint8Array per .pack file, export order */];

const concat = new Uint8Array(packs.reduce((n, p) => n + p.byteLength, 0));
let offset = 0;
for (const p of packs) {
  concat.set(p, offset);
  offset += p.byteLength;
}

const report = JSON.parse(
  verify_closure_manifest(
    commitId,
    manifest,
    concat,
    JSON.stringify(packs.map((p) => p.byteLength)),
  ),
);
if (!report.complete) {
  throw new Error(`closure incomplete: ${report.missing.length} missing, ${report.corrupt.length} corrupt`);
}
```

Concatenated packs are capped independently of a disclosure bundle, at
1 GiB (`MAX_CLOSURE_INPUT_BYTES`, matching the native store's per-object
cap) &mdash; a closure is every object reachable from a commit, a
realistically much larger shape than a handful of disclosure proofs, so it
gets its own, much larger ceiling (see §7).

## 4. Partial disclosure (bundle)

Partial disclosure proves that **one** path, chunk, or byte range belongs
to a commit id, with a proof on the order of a few KiB regardless of
repository size &mdash; the shape a browser fetching one file, or a light
client sampling one byte range, wants.

### The bundle at a glance

```
magic   = "MKDP"              (4 raw bytes)
version: u8 = 2
commit_id: [u8; 32]
commit_bytes: Vec<u8>          <= 4 MiB; verifier: BLAKE3(commit_bytes) == commit_id
steps: Vec<Step>               <= MAX_TREE_DEPTH (128), root first
  Step { name, mode, child_id, inner_root, position, proof: Proof (max_items = 1) }
payload_kind: u8
  0  Object { bytes }                       full canonical object bytes
  1  Chunk  { total_size, chunk_size, index, inner_root,
              proof: Proof (max_items = 2), bytes }
  2  Range  { chunk: Option<ChunkHdr>, offset_in_blob, len, slice,
              chunk_len_proofs: Vec<LenProof> }
     ChunkHdr { total_size, chunk_size, index, inner_root, chunk_id,
                proof: Proof (max_items = 2) }
```

Every integer is big-endian, every length an LEB128 varint, arrays are raw
&mdash; `commonware-codec` conventions, the same house style
`mkit_core::transfer`'s packlist node already uses. Full byte-level detail,
every `Vec` bound, and the exact verification algorithm are normative in
[SPEC-DISCLOSURE](specs/SPEC-DISCLOSURE.md) §3&ndash;§5; this section is the
map, not the territory.

### What each payload kind proves

- **`Object`** discloses the leaf's full canonical bytes (a file, or a
  whole directory's `Tree` object when `path` is empty). The verifier
  checks the payload's own content-address (BLAKE3, or the BMT root for a
  `Tree`/`ChunkedBlob`) against the authenticated leaf id.
- **`Chunk`** discloses one whole chunk of a `ChunkedBlob` leaf, by index.
  The chunk's own bytes hash directly to its id (it's a plain `Blob`), and
  that id &mdash; together with the `ChunkedBlob`'s `total_size`/`chunk_size`,
  which the verifier **recomputes itself**, never accepts as input &mdash;
  is proven with one multi-proof over BMT positions `{0, index + 1}`
  (position 0 is the metadata leaf; SPEC-MERKLE-OBJECTS §3.1). This is
  `verify_chunk_with_meta` in `mkit_core::verify`.
- **`Range`** discloses a byte range, over a plain `Blob` leaf directly, or
  over one chunk of a `ChunkedBlob` leaf (`chunk: Some(hdr)`, same
  `{0, index + 1}` multi-proof as `Chunk` first, then the range within
  that chunk). Either way the range itself is proven with a **Bao**
  (BLAKE3 verified streaming) slice over the object's **canonical** bytes
  &mdash; encoding the header-prefixed bytes rather than raw content makes the
  Bao root equal the object's own id, so a content offset `o` maps to Bao
  offset `o + 10` with no format change needed. Ranges MUST NOT cross a
  chunk boundary in this (v1) profile &mdash; see §7.

### Absolute offsets inside a chunked file

A `Range` payload's `offset_in_blob` is only relative to its *containing*
chunk. For chunk index 0 that's already the file's absolute offset
(nothing precedes it). For any later chunk, the verifier needs the sum of
every preceding chunk's *content length* to turn a chunk-relative offset
into a file-absolute one &mdash; and per-chunk lengths are deliberately **not**
bound into a `ChunkedBlob`'s leaves (issue #1015 decision 1), so they have
to be proven separately when wanted. A **length proof**
(`chunk_len_proofs`, `--with-offsets` on the CLI) is a tiny Bao slice over
just the canonical prologue (bytes `0..10`, at Bao offset `0`, not `+10`)
of one preceding chunk, authenticating its `le32` content-length field
without disclosing any of its actual content.

The set is all-or-nothing by design: `chunk_len_proofs` is either empty
(no absolute offset requested/available, `absolute_offset: None`) or
covers **exactly** `0..index` with no gaps and no duplicates
(`absolute_offset: Some(sum + offset_in_blob)`) &mdash; a partial or malformed
set is a typed rejection (`IncompleteLengthProofSet`), never silently
treated as "absent." And **chunk index 0 never carries any length
proofs at all**: there is nothing before it to describe, so a non-empty
set there is rejected the same way as on a plain `Blob` leaf
(`UnexpectedLengthProofs`) &mdash; a rule tightened in this same PR (see
`rust/tests/golden/disclosure/neg_len_proofs_on_chunk0.*`).

### Worked example

**CLI.** Prove a 40-byte range of a file, write it to a bundle, verify it
against a trusted commit id, and recover exactly the disclosed bytes:

```console
$ mkit prove HEAD src/lib.rs --range 100:40 -o p.bin
proof: 684 B for src/lib.rs @ 64ccb22 (range)

$ mkit verify-proof 64ccb22bf4134972fdcbce8c330407d0e15a5c80d8af3bb43ab7c09eb9592e93 \
    p.bin --expect-path src/lib.rs --payload-out slice.bin
ok: range src/lib.rs @ 64ccb22, 40 B, signer 0a486e59affe8fb5… (valid signature)

$ cat slice.bin
tuvwxyz
abcdefghijklmnopqrstuvwxyz
abcde
```

`--expect-path` is the CLI's version of §2's "never trust a claimed path"
rule: it compares the **authenticated** path the bundle actually proved
against the string you pass, and fails closed (`65`, `DATAERR`) on a
mismatch &mdash; it is not merely an informational filter.

**JSON output**, from the same bundle:

```console
$ mkit verify-proof 64ccb22bf4134972fdcbce8c330407d0e15a5c80d8af3bb43ab7c09eb9592e93 \
    p.bin --expect-path src/lib.rs --format=json
{"commit_id":"64ccb22bf4134972fdcbce8c330407d0e15a5c80d8af3bb43ab7c09eb9592e93","tree_hash":"15fa3e247b96d89c9504a8125be55b3de930ccc9e3a2f750fff0a25098cd7cf8","path":[{"name":"src","name_hex":"737263","mode":"tree"},{"name":"lib.rs","name_hex":"6c69622e7273","mode":"blob"}],"leaf_id":"0ef9636d9ce0ef6750be391a909d70ac673d6390ba512f37dcb1b972d525a6a0","signer":"0a486e59affe8fb54af5fa3e31b3b49663970da1cba4140d538a72ffb12e2077","signature_valid":true,"payload":{"kind":"range","bytes_len":40,"bytes_blake3":"0b9523ef4483e7a5a1651f25553c85294f0bf872b689c840df3c9f4a494c5cf1","blob_id":"0ef9636d9ce0ef6750be391a909d70ac673d6390ba512f37dcb1b972d525a6a0","chunk":null,"offset_in_blob":100,"absolute_offset":100},"step_inner_roots":["36b9b63b57ac62c1b0afee72d739e0d8aece1b17d0229b7a3d580b9e2c4cf955","7e837a5798b77529da077b0475cd370a2114c7c5dc99a654eecdc3559ac89ff4"],"chunk_inner_root":null,"signer_trusted":null}
```

This is the same shape `mkit-wasm`'s `verify_disclosure` produces
(`signer_trusted` is the CLI's own trust-roots addition on top).

**Rust:**

```rust
use mkit_core::hash::from_hex;
use mkit_core::verify::verify_disclosure;

let commit_id = from_hex("64ccb22bf4134972fdcbce8c330407d0e15a5c80d8af3bb43ab7c09eb9592e93")?;
let bundle = std::fs::read("p.bin")?;

let disclosed = verify_disclosure(&commit_id, &bundle)?;
assert_eq!(disclosed.path, vec![
    (b"src".to_vec(), mkit_core::object::EntryMode::Tree),
    (b"lib.rs".to_vec(), mkit_core::object::EntryMode::Blob),
]);
assert!(disclosed.signature_valid);
```

**TypeScript**, with `@officialunofficial/mkit-wasm`:

```ts
import {
  verify_disclosure,
  disclosure_payload_bytes,
} from "@officialunofficial/mkit-wasm";

const commitId =
  "64ccb22bf4134972fdcbce8c330407d0e15a5c80d8af3bb43ab7c09eb9592e93";
const bundle: Uint8Array = /* p.bin bytes */;

const disclosed = JSON.parse(verify_disclosure(commitId, bundle));
if (
  disclosed.path.map((p: { name: string }) => p.name).join("/") !==
  "src/lib.rs"
) {
  throw new Error("unexpected path");
}

// Payload bytes travel out-of-band; this call re-verifies independently.
const slice = disclosure_payload_bytes(commitId, bundle);
```

`verify_disclosure` deliberately never returns payload bytes inline (they
could be arbitrarily large relative to the summary); call
`disclosure_payload_bytes` for them, and treat a failure of either call as
a failure of the whole disclosure &mdash; both independently re-verify.

## 5. Interop for commonware-based verifiers

mkit's Binary Merkle Tree proofs (`mkit_core::merkle::Proof`) are,
deliberately, **byte-identical** to `commonware_storage::bmt::Proof` at the
release train mkit pins (`2026.9.0`, `rust/Cargo.toml`): same wire framing
(`be32(leaf_count) || varint(n) || n * 32-byte digest`), same sibling
selection algorithm, for single, range, and multi-leaf proofs alike (issue
#1015 Decision 2). A verifier already built against the upstream
`commonware-storage` crate (makechain, for instance) can decode an mkit
proof directly with the upstream type and run upstream's own
`verify_*_inclusion` **unchanged** &mdash; no mkit-specific decoder, and no
mkit dependency, needed for the proof-checking step itself. One thing sits
outside that byte-identity, though: `Proof::verify_element_inclusion(leaf,
position, root)` checks against an already-known *bare* inner root, not an
mkit id (it doesn't recover or return the folded value, only accept/reject
against a `root` the caller supplies), and an mkit repository never
publishes a bare inner root anywhere &mdash; only the domain-wrapped id. A
commonware-native verifier therefore needs exactly one extra step around
upstream's unmodified check: verify the wrap.

### Primary case: the prover supplies the inner root alongside the proof

The most direct shape, and the one this section leads with because it
needs no mkit code at all on the verifier's side: the prover hands the
verifier the proof **and** the bare inner root it was built against. The
verifier, in order:

1. **Checks the wrap first, before trusting `inner_root` for anything else:**
   `domain_digest(TYPE_DOMAIN, inner_root) == trusted_id`, where
   `TYPE_DOMAIN` is `"mkit.tree\x00"` for a `Tree` or `"mkit.chunked\x00"`
   for a `ChunkedBlob`, and `domain_digest(d, b) = BLAKE3(le16(len(d)) ||
   d || b)` &mdash; both normative, public spec constants (SPEC-MERKLE-OBJECTS
   §2, SPEC-OBJECTS §9), not merely a detail of `mkit_core`'s own Rust
   types. Because `domain_digest` is collision-resistant, a match proves
   `inner_root` is *exactly* the root `trusted_id` commits to &mdash; the
   prover cannot substitute a different tree/chunk set and still pass this
   check, even though it supplied `inner_root` itself.
2. **Only then** runs upstream's `Proof::verify_element_inclusion`
   (or `verify_range_inclusion` / `verify_multi_inclusion`) **unmodified**,
   against that now-trusted `inner_root`.

```rust
use commonware_codec::Read as _;
use commonware_cryptography::blake3::{Blake3, Digest};
use commonware_storage::bmt::Proof as UpstreamProof;
use mkit_core::hash::domain_digest;

// `trusted_tree_id` is the id the caller already trusts (a commit's
// `tree_hash`, or the previous step's `child_id`). `prover_inner_root`,
// `leaf`, `position`, and `proof_bytes` all came from the prover — none
// of them are trusted yet.

// Step 1: the wrap check. Reject before step 2 even runs on a mismatch.
assert_eq!(
    domain_digest(b"mkit.tree\x00", &prover_inner_root), // or b"mkit.chunked\x00"
    trusted_tree_id,
);
// A verifier with no mkit dependency at all computes the same check by
// hand: BLAKE3(le16(9) || b"mkit.tree\x00" || prover_inner_root) — 9 is
// len(b"mkit.tree\x00"); le16/le32 are 2/4-byte little-endian integers.

// Step 2: upstream's own check, unmodified, against the now-trusted root.
let mut r: &[u8] = proof_bytes;
let proof = UpstreamProof::<Digest>::read_cfg(&mut r, &1usize)?;
proof.verify_element_inclusion::<Blake3>(&Digest(leaf), position, &Digest(prover_inner_root))?;
```

(Verified by compiling and running this exact two-step sequence, including
a negative case for a forged `prover_inner_root` failing step 1, against a
real `Tree` while writing this document.)

A v2 disclosure bundle carries that inner root on every `Step` and
chunk header, so a commonware-native verifier reads it from the decoded
bundle and runs the two-step sequence above with no out-of-band channel:

```rust
// After decoding a v2 `Step` (SPEC-DISCLOSURE §3):
let trusted_tree_id = /* commit.tree_hash, or the previous step's child_id */;
assert_eq!(
    domain_digest(b"mkit.tree\x00", &step.inner_root),
    trusted_tree_id,
);
let mut r: &[u8] = &step.proof.encode();
let proof = UpstreamProof::<Digest>::read_cfg(&mut r, &1usize)?;
proof.verify_element_inclusion::<Blake3>(
    &Digest(leaf),
    step.position,
    &Digest(step.inner_root),
)?;
```

The field is mandatory (bundle version 2; a version byte of 1 is
rejected with no compatibility decoder). It is wrap-checked against the
trusted id before use and cross-checked against the proof fold, so it
adds no trust surface.

### Secondary case: the verifier already holds the full object

When the caller instead holds the full `Tree`/`ChunkedBlob` object &mdash; an
`Object`-kind disclosure payload, or an object re-derived while walking a
closure &mdash; it can compute the bare inner root itself, from that object's
leaves, with `mkit_core::merkle::tree_inner_root` / `chunked_inner_root`.
These are byte-identical to building the same tree with
`commonware_storage::bmt::Builder`
(`merkle::tests::proofs_match_commonware` pins this cross-check), so the
same two-step pattern above applies with `prover_inner_root` replaced by
this self-computed value &mdash; trivially "step 1" here, since the caller
derived the root itself rather than received it as a claim.

### Neither: only a proof, no inner root, no full object

A caller that has *only* `(leaf, position, proof)` against a trusted id,
with no inner root available from anywhere, needs the same fold-up
upstream's `verify_element_inclusion` performs internally before it can
even begin &mdash; precisely the algorithm SPEC-MERKLE-OBJECTS §5.4 specifies
in prose. `mkit_core::merkle`'s own id-based verifiers (`verify_tree_entry`,
`verify_chunk`, and their range/multi counterparts) already do exactly
that fold-then-wrap-then-compare, tested and golden-vector-pinned; reach
for those directly (`merkle::wrap_id` / wasm's `wrap_object_id` apply the
same wrap step) rather than hand-rolling the fold loop.

### Leaf digest formulas

The leaf digest formulas themselves are mkit-specific (they're what makes
an mkit tree entry or chunked-blob metadata leaf what it is, not a generic
BMT property) and are normative in
[SPEC-MERKLE-OBJECTS](specs/SPEC-MERKLE-OBJECTS.md) §3:

- **Tree entry leaf**: `domain_digest("mkit-tree-entry-v1", le32(len(name)) || name || u8(mode) || object_hash)`.
- **ChunkedBlob metadata leaf** (position 0): `domain_digest("mkit-cblob-meta-v1", le64(total_size) || le32(chunk_size))`.
- **ChunkedBlob chunk leaf** (position `i + 1`): the chunk's own 32-byte
  `Blob` id, raw &mdash; no further wrapping.

`domain_digest` itself, `"mkit.tree\x00"` / `"mkit.chunked\x00"` (the
outer wrap, §2), and `"mkit-tree-entry-v1"` / `"mkit-cblob-meta-v1"` (the
leaf domains, §3) are all normative spec byte strings &mdash; any independent
implementation may hardcode them. What's private is only
`mkit_core::merkle`'s own Rust `const`s for these same strings (so they
never become a de facto *Rust* ABI commitment, i.e. so the crate stays
free to restructure how it stores them internally); that privacy says
nothing about the byte strings' own status, which is public and pinned by
the golden vectors regardless of which language reads them.

## 6. Implementing a verifier from scratch (no Rust)

A conformant verifier needs exactly four primitives, all widely available
outside Rust:

1. **BLAKE3** &mdash; for commit/blob/tag ids, domain-wrapped digests, and the
   BMT's own internal hashing.
2. **Ed25519 signature verification** &mdash; for `signature_valid`.
3. **LEB128 unsigned varint decode** &mdash; for every length-prefixed field
   in a bundle, manifest, or proof.
4. **Bao slice decode** (BLAKE3 verified streaming) &mdash; for any `Range`
   payload or length proof. The [`bao` reference implementation's
   format](https://github.com/oconnor663/bao) is public and has ports in
   several languages; the encoding is exactly "outboard tree hashes plus
   1 KiB content leaves," nothing mkit-specific.

### Order of checks

Follow [SPEC-DISCLOSURE](specs/SPEC-DISCLOSURE.md) §4 (bundle) and §7.4
(closure) exactly &mdash; they are numbered MUSTs precisely so an independent
implementation can be checked step-by-step against them. The load-bearing
shape, common to both:

1. Reject on size **before decoding anything** (whole bundle vs.
   `MAX_BUNDLE_BYTES`; whole closure input vs. its own cap).
2. Check the fixed magic + version header as raw bytes, before touching the
   codec body.
3. Decode with every length **bounded** (see below) and reject any trailing
   bytes after the declared body.
4. Recompute the one hash that binds everything else to the value the
   caller already trusted (`BLAKE3(commit_bytes) == commit_id` for a
   bundle; re-derive every supplied object's id for a closure) &mdash; this is
   the step that actually does the authenticating; everything before it is
   bookkeeping.
5. Walk/verify structure (tree steps, in order, each against the
   *previous* step's output, never an independently-supplied root; for a
   closure, `children(obj, mode)` from the root).
6. Only then interpret the payload/leaf content, and always **against the
   authenticated id**, never a caller-supplied path/offset/length that
    wasn't itself part of what got verified. A v2 disclosure bundle
    carries a bare inner root on each `Step` and chunk header, but that
    field is wrap-checked against the trusted id **before** it is used
    for anything (§5); the comparison against a trusted value remains
    the wrapped id (SPEC-MERKLE-OBJECTS §5.4). The closure profile does
    not carry inner roots.

### Bounds to enforce before allocation

A hostile prover controls every length field in a bundle or closure input.
None of them may be used to size an allocation before that length is
itself checked against a fixed cap:

| Field | Bound |
|---|---|
| whole disclosure bundle | `MAX_BUNDLE_BYTES` = 64 MiB |
| `commit_bytes` inside a bundle | 4 MiB |
| `steps` (tree depth) | `MAX_TREE_DEPTH` = 128 |
| a proof's sibling count | `max_items * MAX_LEVELS` (32), checked *before* reading any sibling digest |
| `Object`/`Chunk` payload bytes | `MAX_RAW_OBJECT_SIZE` = 1 GiB |
| `chunk_len_proofs` count | `MAX_CHUNKS` = 1,000,000 |
| one length-proof's Bao slice | 8 KiB |
| closure manifest's pack list | `MAX_CLOSURE_PACKS` = 65,536 |
| closure object count | `pack::MAX_ENTRIES` = 10,000,000 |
| closure pack payload sum | `pack::MAX_TOTAL_PAYLOAD` = 4 GiB |
| tree entries / chunks per object | `MAX_TREE_ENTRIES` / `MAX_CHUNKS` = 1,000,000 each |
| parents per commit | `MAX_PARENTS` = 1,000 |

A `leaf_count` embedded in any proof is **compared**, never used to size an
allocation &mdash; it's bound into the finalized BMT root (so a forged
`leaf_count` fails verification on its own), and the sibling-count bound
above already caps the actual bytes read regardless of what `leaf_count`
claims.

### Conformance

The authoritative test suite for an independent implementation is the
golden-vector corpus, not this document's prose:
`rust/tests/golden/{objects,tags,proofs,disclosure,closure}/`. Each
directory has a `MANIFEST.txt` (`<name> <blake3-of-the-.bin-file>` lines,
so tampering with a committed vector is itself detectable) and, per
vector, a `<name>.bin` (the exact bytes to feed your decoder) paired with
a `<name>.json` sidecar. Every sidecar shares a common shape:

```json
{
  "name": "...",
  "description": "... plain-English what this vector is ...",
  "bin": "<name>.bin",
  "size": 123,
  "blake3": "<64-hex, matches MANIFEST.txt>",
  "expect": "accept" | "reject"
}
```

`objects/` and `tags/` sidecars stop there (they pin canonical byte
layout, SPEC-OBJECTS/SPEC-SIGNING territory). `proofs/`, `disclosure/`,
and `closure/` sidecars add vector-specific fields on top &mdash; a proof
vector's `object_id_hex`/`position`/`max_items`/`proof_kind`; a disclosure
vector's `commit_id_hex`/`path_hex`/`selector`/`disclosed` (the full
expected `Disclosed` summary for an accept vector); a closure vector's
`root`/`mode`/pack hashes/expected `verified` count. Every **reject**
vector's sidecar additionally carries `reject_reason`, a short
human-readable note on *why* &mdash; useful for triage, but conformance only
requires that your verifier reject it, not that it reject it for the
identical reason mkit's own implementation does.

The procedure: for every vector, decode `<name>.bin` with your
implementation, and check its outcome against `expect` (an accept vector's
result must additionally match the sidecar's recorded summary fields; a
reject vector just needs to fail, any typed way). This is exactly what
`rust/crates/mkit-core/tests/golden_{proofs,disclosure,closure}.rs` do,
and they are written to read **only** the committed `.bin`/`.json` files,
never the fixture generator &mdash; the same posture an independent verifier's
own test harness should take.

## 7. Limits and non-goals

- **Ranges cannot cross a chunk boundary**, in this (v1) profile of the
  disclosure bundle. `mkit prove --range` rejects such a request outright
  (`RangeCrossesChunkBoundary`) rather than silently splitting it into
  multiple chunk proofs.
- **git SHA-1 hashes support full disclosure only.** A git blob is a flat
  SHA-1 digest with no sub-file structure to build a partial proof over; a
  client that already trusts a git SHA-1 verifies it with git's own
  hashing, not this kit. Partial disclosure is an mkit-id-only capability.
- **Ancestry (history MMB) proofs and pack-shard DA sampling are not part
  of this kit.** Both are real, separately-scoped capabilities (see issue
  #1015 §"Later") that need a chain-side anchor beyond a single commit id
  to be useful &mdash; "branch tip at block B extends tip at block A" and
  "this shard is part of that committed erasure-coded set," respectively.
  Neither is implemented here.
- **Non-membership proofs** (proving a name is *absent* from a `Tree`) are
  reserved as disclosure `payload_kind 3` (`Absent`); see
  [#1027](https://github.com/officialunofficial/mkit/issues/1027). A
  disclosure bundle only ever proves inclusion.
- **wasm caps**, independent of the native crate's own bounds (`mkit_core::verify`,
  which mkit-wasm builds on top of): objects 16 MiB
  (`MAX_WORKSPACE_OBJECT_BYTES`, `mkit-wasm/src/objects.rs`); a disclosure
  bundle 64 MiB (`verify::MAX_BUNDLE_BYTES`, shared with the native crate);
  concatenated closure packs 1 GiB (`MAX_CLOSURE_INPUT_BYTES`,
  `mkit-wasm/src/verify.rs`, independent of the bundle cap &mdash; see §3).

## 8. Reference table

| Surface | Purpose | Spec |
|---|---|---|
| **CLI** | | |
| `mkit prove <rev> [<path>] [--chunk N \| --range OFF:LEN] [--with-offsets] [-o FILE] [--format=json]` | build a disclosure bundle | SPEC-DISCLOSURE §3 |
| `mkit verify-proof <commit-id> <bundle\|-> [--expect-path P] [--trusted] [--trust-roots PATH] [--payload-out FILE] [--format=json]` | verify a disclosure bundle | SPEC-DISCLOSURE §4 |
| `mkit closure export <rev> [--history] [-o DIR] [--force] [--format=json]` | write a closure (manifest + raw-only packs) | SPEC-DISCLOSURE §7.2/§7.3 |
| `mkit closure verify <commit-id> [--from DIR] [--history] [--show-unreferenced] [--format=json]` | verify a closure, remote (`--from`) or local | SPEC-DISCLOSURE §7.4 |
| **mkit-core (`mkit_core::verify`, `mkit_core::merkle`)** | | |
| `verify_object_id(bytes, expected) -> Object` | check one object's content-address | SPEC-OBJECTS §10 |
| `verify_path(commit_id, commit_bytes, steps) -> PathVerified` | walk and verify a tree-entry step chain | SPEC-DISCLOSURE §4 steps 6&ndash;9 |
| `verify_chunk_with_meta(chunked_id, total_size, chunk_size, chunk_hash, index, proof)` | verify one chunk + its manifest metadata | SPEC-MERKLE-OBJECTS §3.1 |
| `verify_blob_slice(blob_id, content_offset, len, slice) -> bytes` | verify a Bao range slice | SPEC-DISCLOSURE §4 (Range) |
| `verify_blob_len_proof(blob_id, slice) -> u32` | verify a chunk's declared content length | SPEC-DISCLOSURE §4.1 |
| `verify_disclosure(commit_id, bundle) -> Disclosed` | decode + fully verify a bundle | SPEC-DISCLOSURE §3&ndash;§4 |
| `build_disclosure(store, commit_id, path, selector) -> Vec<u8>` (native) | producer side of a bundle | SPEC-DISCLOSURE §3 |
| `verify_closure(root, mode, objects) -> ClosureReport` | store-less closure check over an id&rarr;bytes map | SPEC-DISCLOSURE §7.4 |
| `verify_closure_streaming(root, mode, source) -> ClosureReport` | pull-based closure check over an `ObjectSource` | SPEC-DISCLOSURE §7.4 |
| `verify_closure_store(store, root, mode) -> ClosureReport` (native) | on-demand closure check against a local object store | SPEC-DISCLOSURE §7.4 |
| `verify_closure_packs(root, mode, packs) -> ClosureReport` | closure check over raw-only packs | SPEC-DISCLOSURE §7.2/§7.4 |
| `verify_closure_manifest(expected_root, manifest, packs) -> ClosureReport` | closure check + manifest-root binding | SPEC-DISCLOSURE §7.3/§7.4 |
| `export_closure(store, root, mode) -> ClosureExport` (native) | producer side of a closure | SPEC-DISCLOSURE §7.2/§7.3 |
| `merkle::wrap_id(kind, inner_root) -> Hash` | apply the outer type-domain wrap (§5's step 1); a v2 `Step.inner_root` is wrap-checked with this before upstream BMT verify | SPEC-MERKLE-OBJECTS §2 |
| `merkle::verify_tree_entry` / `verify_chunk` (+ `*_range` / `*_multi`) | single/range/multi-leaf BMT inclusion proofs, against the object id | SPEC-MERKLE-OBJECTS §5.4 |
| **mkit-wasm** | | |
| `verify_disclosure(commit_id_hex, bundle) -> json` | JS-facing bundle verify (no payload bytes) | SPEC-DISCLOSURE §3&ndash;§4 |
| `disclosure_payload_bytes(commit_id_hex, bundle) -> bytes` | verified payload bytes (re-verifies) | SPEC-DISCLOSURE §4 |
| `verify_closure_packs` / `verify_closure_manifest` | JS-facing closure verify | SPEC-DISCLOSURE §7 |
| `verify_tree_entry` / `verify_chunk` | JS-facing single-leaf proof verify | SPEC-MERKLE-OBJECTS §5.4 |
| `chunked_blob_decode` | decode a `ChunkedBlob`'s manifest to JSON | SPEC-OBJECTS §7 |
| `blob_bao_encode` / `blob_bao_slice` / `blob_bao_verify_slice` | Bao over **canonical** blob bytes | SPEC-DISCLOSURE §4 (Range) |
| `wrap_object_id(kind, inner_root_hex) -> hex` | JS-facing `wrap_id`; v2 bundles carry `step_inner_roots` / `chunk_inner_root` on the `verify_disclosure` JSON | SPEC-MERKLE-OBJECTS §2 |
| **MCP tools** (`mkit mcp`) | | |
| `mkit_prove` / `mkit_verify_proof` / `mkit_closure_verify` | agent-facing equivalents of the CLI commands above | &mdash; |

---

Cross-references: [SPEC-DISCLOSURE](specs/SPEC-DISCLOSURE.md) (the
normative source for §3&ndash;§4 and §6&ndash;§7 above),
[SPEC-MERKLE-OBJECTS](specs/SPEC-MERKLE-OBJECTS.md) (§1&ndash;§2 identity mirrors
§5 proofs, the normative source for §1 and §5 above),
[SPEC-OBJECTS](specs/SPEC-OBJECTS.md) (Blob/Tree/Commit/ChunkedBlob byte
layout), [SPEC-SIGNING](specs/SPEC-SIGNING.md) (what a commit signature
covers, §2's `signer`/`signature_valid` claim), [`docs/CLI.md`](CLI.md)
(full flag reference for every command in §8), [`docs/INVARIANTS.md`](INVARIANTS.md)
(the enforced-by-test version of the guarantees this document explains in
prose).
