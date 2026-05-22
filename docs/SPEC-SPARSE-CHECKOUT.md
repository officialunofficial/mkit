---
spec: SPEC-SPARSE-CHECKOUT
version: 1-draft
status: draft
audience: implementers of verifiable server-side sparse-checkout for mkit transports (HTTP/S3)
---

# SPEC-SPARSE-CHECKOUT — verifiable server-side sparse delivery

Status: **Draft** (Phase 1 — core module only). Normative for the
`mkit-core::sparse` module's in-memory byte layouts; the
transport-level wire integration is **not yet specified** and will be
added in a Phase 2 revision of this document.

Scope: the `SparseManifest` + `SparseProof` types produced by
`mkit-core::sparse::build_sparse`, and the verifier algorithm in
`mkit-core::sparse::verify_sparse`.

Resolves issue #158.

---

## 1. Motivation

`mkit sparse-checkout` today filters which paths a client materialises
from a tree **on the client side**. The server delivers the full tree
object; the client picks the paths it cares about. That works fine for
the file transport (the server is the local filesystem; there's no
bandwidth to save) but is wasteful on HTTP and S3 transports, where
the server could ship only the requested subtree and save real
bytes-on-the-wire on large monorepos.

The problem with naive server-side sparse delivery: the client has no
way to tell the difference between "the server omitted this path
because I asked it to" and "the server omitted this path because it
was hiding something". For a content-addressed VCS, that's a
correctness hole, not just an annoyance.

This spec defines a **verifiable** server-side sparse-checkout
protocol. The server emits a tree subset plus a Merkleized bitmap
committing to "exactly these leaf indices were included; everything
else was omitted by client request". The client checks the bitmap
against the manifest and rejects any mismatch.

The authenticated bitmap is
[`commonware-storage::AuthenticatedBitMap`](https://docs.rs/commonware-storage)
v`2026.4.0` — an ALPHA-tier std-only crate that provides a Merkleized
bitmap with per-bit inclusion proofs. mkit pins the version and
re-exports its `Proof` type rather than forking the wire format.

---

## 2. Wire format

### 2.1 `SparseManifest`

Fixed-layout, 104 bytes on the wire. Sent once per sparse delivery,
typically as a header before the streamed entries.

```
offset  size  field           value
0       32    tree_hash       BLAKE3 of source Tree (see §2.4)
32      32    bitmap_root     SHA-256 root of the AuthenticatedBitMap
64      32    filter_hash     BLAKE3 of the canonicalised filter (see §2.3)
96      8     leaf_count      u64 LE — total leaves in the source tree
```

All hash fields are 32 bytes raw. Integers are little-endian. Hash
algorithms differ deliberately: BLAKE3 for mkit-side commitments
(matches the rest of the project), SHA-256 for the bitmap root (that's
what `commonware-storage` produces and we don't re-hash to avoid
fork-divergence with upstream).

`leaf_count` MUST be ≤ `MAX_LEAVES` = 1,000,000. Mirrors SPEC-OBJECTS
§4's per-tree entry-count bound. Verifiers MUST reject larger values
before allocating any structure proportional to `leaf_count`.

### 2.2 `SparseProof`

Variable-length. Phase 1 carries:

```
field         size                    encoding
bitmap_bytes  ceil(leaf_count / 8) B  raw little-endian bit packing,
                                      bit i = bits[i / 8] >> (i % 8) & 1
mmr_proof     variable                commonware-storage::merkle::Proof
                                      <mmr::Family, sha256::Digest>
                                      encoded via the upstream codec
```

The bitmap is laid out **little-endian per byte**: bit `i` lives at
`bitmap_bytes[i / 8] >> (i % 8) & 1`. This matches the upstream
`commonware-utils::bitmap::BitMap` byte layout. The verifier MUST
treat the bitmap as opaque bytes — it does *not* decode bits before
checking the root.

`mmr_proof` is the inclusion proof for **bit 0** of the bitmap. For
trees with `leaf_count ≤ 256` (one chunk) this is the partial-chunk
reconstruction proof (single digest); for larger trees it's a
multi-digest MMR-style proof. Phase 1 verifier does not use this
proof — the byte-level reconstruction in §3 is sufficient because the
verifier has the full bitmap. The field exists so Phase 2's streamed
transport can switch to per-bit proofs without a wire-format change.

### 2.3 Filter canonical form

A `filter` is a list of UTF-8 path prefixes the client wants. The
manifest commits to a `filter_hash` so the server can't substitute a
different filter mid-transfer.

Canonical form for `hash_filter`:

1. Drop entries that are not valid UTF-8 or are empty.
2. Sort by byte-wise lex order.
3. Deduplicate (sorted-adjacent identical entries collapse).
4. For each remaining entry: append `len: u32 LE` then the UTF-8
   bytes.
5. BLAKE3 of the resulting buffer is the `filter_hash`.

The empty filter hashes to `BLAKE3([])` and is a valid filter
committing to "no entries delivered".

A filter prefix `P` matches an entry name `N` when either:

* `N == P` (exact match), or
* `N` starts with `P` followed by `/` (subtree prefix).

`P = "foo"` matches `"foo"` and `"foo/bar"` but **not** `"foobar"`.

### 2.4 Tree hash

The Phase 1 module computes `tree_hash` as a sparse-module-internal
commitment over `(name, mode, object_hash)` tuples:

```
h = BLAKE3()
h.update("mkit-sparse-tree-v1")
h.update(entry_count: u32 LE)
for entry in tree.entries:
    h.update(name_len: u32 LE)
    h.update(name bytes)
    h.update(mode: u8)
    h.update(object_hash: [u8; 32])
tree_hash = h.finalize()
```

This is **not** the SPEC-OBJECTS tree hash. Phase 2 will switch this
field to the canonical SPEC-OBJECTS hash once the transport layer
plumbs it. Until then, `tree_hash` is a manifest-internal binding only
and verifiers MUST NOT use it to authenticate the source tree.

---

## 3. Verifier algorithm

`verify_sparse(manifest, delivered_entries, filter, proof) -> bool`
returns true iff **all** of:

1. **Cap check.** `manifest.leaf_count ≤ MAX_LEAVES` and
   `filter.len() ≤ MAX_FILTER_PATHS`. Reject before any allocation
   proportional to either bound.
2. **Filter binding.** `manifest.filter_hash == hash_filter(filter)`.
3. **Bitmap shape.** `proof.bitmap_bytes.len() ==
   ceil(manifest.leaf_count / 8)`. Reject any trailing bytes — they
   would allow an attacker to encode bits the manifest never committed
   to.
4. **Set-bit count.** The number of `1` bits in `proof.bitmap_bytes`
   equals `delivered_entries.len()`. The bitmap commits to *exactly*
   the delivered cardinality.
5. **Filter membership.** Every delivered entry is selected by some
   prefix in `filter`. Protects against a server inserting an entry
   the client didn't ask for, even if the bitmap-bits add up.
6. **Bitmap root.** Reconstruct the bitmap from `proof.bitmap_bytes`
   by feeding the bits one-by-one into a fresh
   `MerkleizedBitMap<_, sha256::Digest, 32>` and compare its root
   against `manifest.bitmap_root` byte-for-byte.

Phase 1 cannot independently verify that
`delivered_entries[i].name` is the canonical name at leaf-index `i` of
the source tree — the verifier doesn't have the source tree (that's
the whole point of sparse delivery). The Phase 2 transport will
cross-check the leaf-index → name mapping once it has assembled
enough of the tree structure to know which leaf-indices exist.

The verifier MUST NOT panic on any caller input; all failures return
`false`.

---

## 4. Limits

| Limit                  | Value     | Rationale                                              |
| ---------------------- | --------- | ------------------------------------------------------ |
| `MAX_LEAVES`           | 1,000,000 | Matches SPEC-OBJECTS §4 tree entry cap.                |
| `MAX_FILTER_PATHS`     | 100,000   | Bounds client→server filter size before allocation.    |
| Bitmap chunk size      | 32 bytes  | One SHA-256 digest, upstream's recommended size.       |
| Filter path encoding   | UTF-8     | Tree entry names are arbitrary bytes; filters are not. |
| `tree_hash` algorithm  | BLAKE3    | Phase 1 internal commitment; Phase 2 promotes to SPEC. |
| `bitmap_root` algorithm| SHA-256   | Upstream `AuthenticatedBitMap` produces SHA-256.       |

A tree with the maximum 1,000,000 leaves produces a bitmap of
`ceil(1_000_000 / 8)` = 125,000 bytes. The MMR proof at that scale is
on the order of `log2(1_000_000 / 256) ≈ 12` digests = ~384 bytes.
Total `SparseProof` size for a worst-case tree: ~125 KB. Acceptable
for Phase 1; Phase 2's streamed transport will only ship the bitmap
chunks the verifier hasn't already cached on disk.

---

## 5. Implementation status

* **Phase 1 (this document):** `mkit-core::sparse` module only.
  In-memory `build_sparse` / `verify_sparse` plus the manifest/proof
  byte layouts. **Feature-gated** as `sparse-checkout`, default off —
  the upstream `commonware-storage` is ALPHA-tier and we don't want
  downstream consumers paying the dep cost unless they opt in.

* **Phase 2 (future PR):** Transport-level wiring.
  - Extend SPEC-TRANSPORT §5 (HTTP) and §6 (S3) with an optional
    `?sparse=<filter-hash>` query param on tree fetches.
  - Server-side reference implementation in `mkit-cli/serve.rs`.
  - On-disk `.mkit/sparse/<tree-hash>.bitmap` cache so re-verification
    on subsequent checkouts is free.
  - Switch `tree_hash` to the canonical SPEC-OBJECTS tree hash and
    drop the Phase 1 manifest-internal hash.
  - Property test: 1000 random filters all round-trip.

* **Phase 3 (further future):** SSH transport extension. Lower
  priority because SSH transport already streams in a structured
  framed protocol where the bitmap fits naturally into a new frame
  type without a query-param hack.

Anti-goals (called out in #158 and preserved here):

* Sparse-checkout MUST NOT become *required* for any transport. The
  client-side filtering path is the fallback for the file transport
  and for clients that don't want to participate in the
  authenticated-bitmap protocol.
* This document does NOT yet specify a server-side reference impl;
  that lives in the Phase 2 PR.
