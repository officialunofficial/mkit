---
spec: SPEC-SPARSE-CHECKOUT
version: 2-draft
status: draft
audience: implementers of verifiable server-side sparse-checkout for mkit transports (HTTP/S3)
---

# SPEC-SPARSE-CHECKOUT — verifiable server-side sparse delivery

Status: **Draft** (wire & transport delivery — core module + wire envelope
+ transport glue). Normative for the `mkit-core::sparse` module's in-memory byte
layouts, the `application/x-mkit-sparse` wire format, the per-tree
on-disk bitmap cache layout, and the HTTP `/<project>/trees/<hex>/sparse`
+ S3 `sparse/<tree>/<filter>` endpoint shapes.

Scope: the `SparseManifest` + `SparseProof` + `SparseResponse` types
produced by `mkit-core::sparse::build_sparse`, the verifier algorithm in
`mkit-core::sparse::verify_sparse`, the encode/decode pair for the
network envelope, the on-disk cache layout under
`.mkit/sparse/<tree-hex>.bitmap`, and the `mkit checkout --sparse` /
`mkit clone --sparse` CLI plumbing.

Resolves issue #158 (the in-process core module and the wire & transport
delivery stages).

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
v`2026.5.0` — an ALPHA-tier std-only crate that provides a Merkleized
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

Variable-length. The in-process core module carries:

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
multi-digest MMR-style proof. The in-process core module's verifier does
not use this proof — the byte-level reconstruction in §3 is sufficient
because the verifier has the full bitmap. The field exists so the wire &
transport delivery stage's streamed transport can switch to per-bit proofs
without a wire-format change.

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

The wire & transport delivery stage swaps the in-process core module's
placeholder for the canonical SPEC-OBJECTS tree hash:

```
tree_hash = BLAKE3(serialize(Object::Tree(t)))
```

where `serialize` is the workspace-canonical
`mkit_core::serialize::serialize` recipe (v1 prologue + length-prefixed
entries — see SPEC-OBJECTS §4). This is the same hash the rest of the
codebase uses to address a tree object: commits' `tree_hash`, remix
roots, and the object store all key trees by this value. The
sparse-module-internal recipe from the in-process core module is removed.

Verifiers MAY now cross-check the manifest's `tree_hash` against any
independently-known commitment to the source tree — a parent commit's
`tree_hash`, a merge-base tree, the local object store — and reject on
mismatch. This was not possible in the in-process core module, when
`tree_hash` was a manifest-private digest with no cross-codebase meaning.

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

The in-process core module cannot independently verify that
`delivered_entries[i].name` is the canonical name at leaf-index `i` of
the source tree — the verifier doesn't have the source tree (that's
the whole point of sparse delivery). The wire & transport delivery stage's
transport will cross-check the leaf-index → name mapping once it has
assembled enough of the tree structure to know which leaf-indices exist.

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
| `tree_hash` algorithm  | BLAKE3    | In-process core module internal commitment; promoted to SPEC by the wire & transport delivery stage. |
| `bitmap_root` algorithm| SHA-256   | Upstream `AuthenticatedBitMap` produces SHA-256.       |

A tree with the maximum 1,000,000 leaves produces a bitmap of
`ceil(1_000_000 / 8)` = 125,000 bytes. The MMR proof at that scale is
on the order of `log2(1_000_000 / 256) ≈ 12` digests = ~384 bytes.
Total `SparseProof` size for a worst-case tree: ~125 KB. Acceptable
for the in-process core module; the wire & transport delivery stage's
streamed transport will only ship the bitmap chunks the verifier hasn't
already cached on disk.

---

## 5. Wire envelope

The HTTP and S3 transports both ship a single
`application/x-mkit-sparse` byte stream that encodes a complete
`SparseResponse = (SparseManifest, Vec<TreeEntry>, SparseProof)`. The
envelope is defined by `mkit-core::sparse::encode_sparse_response` /
`decode_sparse_response`.

Layout (little-endian throughout):

```
offset  size           field
0       4              magic        = b"MSP1"
4       1              version      = 0x01
5       32             tree_hash
37      32             bitmap_root
69      32             filter_hash
101     8              leaf_count   (u64)
109     4              entries_len  (u32)
113     ...            TreeEntry stream, each:
                          u16    name_len    (1..=255)
                          [u8]   name        (name_len bytes)
                          u8     mode        (EntryMode)
                          [u8; 32] object_hash
...     4              bitmap_len   (u32)
...     N              bitmap_bytes
```

Total envelope is capped at `SPARSE_WIRE_MAX_BYTES = 16 MiB`. Refusing
oversized inputs *before* parsing prevents a hostile server from
making the client allocate beyond bounds.

Names use a `u16` length prefix here (vs. the `u32` in SPEC-OBJECTS
§4) because tree entry names are bounded at 255 bytes and the 2-byte
saving per entry adds up over a large tree. The decoder rejects
`name_len == 0` or `> 255`.

The trailing bitmap byte count MUST equal `ceil(leaf_count / 8)`. Any
trailing bytes after the bitmap section are refused (extra trailing
bytes would let an attacker encode bits the manifest never committed
to).

## 6. HTTP transport endpoint

```
POST /<project>/trees/<tree-hex>/sparse?sparse=<filter-hex>
Content-Type:   application/json
Accept:         application/x-mkit-sparse
Body:           {"filter": ["<utf8 path>", "<utf8 path>", ...]}
```

- `<tree-hex>` is the 64-character lowercase hex of
  `BLAKE3(serialize(Object::Tree(t)))`.
- `<filter-hex>` is the 64-character lowercase hex of
  `hash_filter(filter)` — see §2.3. The server MUST recanonicalise the
  body filter and refuse with **HTTP 409** if it disagrees with the
  query, which surfaces client-side as `TransportError::RefConflict`.
- Successful response status is `200 OK` with body
  `application/x-mkit-sparse` (the §5 envelope).
- `404 Not Found` → server does not have the addressed tree; surfaces
  client-side as `TransportError::PackNotFound`.

The transport layer is **trust-thin**: it returns the decoded
`SparseResponse` without verifying anything beyond the envelope shape
and `SPARSE_WIRE_MAX_BYTES`. The caller MUST run `verify_sparse` on
the result before trusting any delivered entries.

## 7. S3 transport endpoint

S3 is a content-addressed key-value store; there is no "POST a
request body, get a computed response" verb. The S3 transport
assumes the server (or a populating Cloudflare Worker) has
pre-computed the sparse delivery and stored it under the canonical
key:

```
sparse/<tree-hex>/<filter-hex>
```

Clients `GET` it with SigV4 signing. The body IS the §5 envelope.
The optional `?sparse=<filter-hex>` URL query is a no-op on S3 (the
key already encodes it); the client builds the URL without the query
to keep the SigV4 canonical request minimal.

Same trust-thin contract as HTTP: decode envelope → return →
`verify_sparse` upstream.

## 8. On-disk cache

The client persists a verified manifest's bitmap under:

```
<repo-root>/.mkit/sparse/<tree-hex>.bitmap
```

One file per source-tree hash. The file body is:

```
offset  size           field
0       4              magic        = b"MSPC"
4       1              version      = 0x01
5       32             bitmap_root
37      32             filter_hash
69      8              leaf_count   (u64)
77      4              bitmap_len   (u32)
81      N              bitmap_bytes
```

The source-tree hash is the *filename*; storing it again in the file
body would be redundant. Re-verifying a cached delivery means
recomputing the bitmap root from `bitmap_bytes` and comparing to
`bitmap_root`.

A cache hit for the same `(tree_hash, filter_hash)` skips the
expensive bitmap-root reconstruction inside the upstream
`MerkleizedBitMap` runtime — the slowest part of `verify_sparse` on
a large tree.

Encoder + decoder live in
`mkit-core::sparse::{encode_sparse_cache, decode_sparse_cache}`. The
CLI helper that owns the file I/O lives in
`mkit_cli::sparse_cache::{store, load, cache_path}`.

A stale cache (cache hit for the same tree but a different filter) is
NOT silently returned: `mkit_cli::sparse_cache::load` returns
`CacheError::FilterMismatch`, and the caller treats it as a cache
miss and re-fetches.

## 9. CLI surface

`mkit checkout --sparse <pattern>...` — switch HEAD with a verifiable
sparse subset. The patterns are interpreted exactly like the existing
`mkit sparse-checkout` config patterns (leading `/` stripped, trailing
`/` directory-only, `!` negation). The CLI:

  1. Resolves the commit's top-level tree.
  2. Runs `build_sparse(tree, filter)` to construct the manifest.
  3. Runs `verify_sparse` against the constructed subset
     (self-consistency check at the seam).
  4. Persists the bitmap to `.mkit/sparse/<tree-hex>.bitmap`.
  5. Materialises only the matching files via the existing
     restore-side sparse-pattern path.

`mkit clone --sparse <pattern>...` — clone, persist the patterns to
`.mkit/sparse-checkout`, then run the same `build_sparse +
verify_sparse + cache + materialise` pipeline against the
freshly-cloned HEAD.

The CLI patterns and the existing `.mkit/sparse-checkout` config file
are kept in sync by `clone --sparse`. `checkout --sparse` does NOT
persist the patterns — by design — so a one-off sparse view doesn't
sticky-write the user's persistent sparse-checkout state. Use `mkit
sparse-checkout set <pattern>...` to persist.

## 10. Implementation status

* **In-process core module (closed):** `mkit-core::sparse` module only.
  In-memory `build_sparse` / `verify_sparse` plus the manifest/proof byte
  layouts. Feature-gated as `sparse-checkout`, default off.

* **Wire & transport delivery (this revision):**
  - `tree_hash` swapped to the canonical SPEC-OBJECTS hash (§2.4).
  - `application/x-mkit-sparse` wire envelope (§5).
  - HTTP transport endpoint (§6) and `HttpTransport::fetch_sparse_tree`.
  - S3 transport endpoint (§7) and `S3Transport::fetch_sparse_tree`.
  - On-disk bitmap cache (§8).
  - `mkit checkout --sparse` / `mkit clone --sparse` (§9).
  - Server-side reference helper:
    `mkit_cli::commands::serve::build_sparse_response_from_tree` and
    `build_sparse_response_from_store`. The HTTP / S3 reference
    servers themselves live outside the workspace (the Cloudflare
    Worker is in `web/`); §6 + §7 document exactly what they need to
    do.

* **SSH transport extension (future):** The SSH transport's
  protobuf-framed protocol fits a new `SparseFetch` frame more
  naturally than a query-param hack; left to a follow-up PR.

Anti-goals (called out in #158 and still preserved):

* Sparse-checkout MUST NOT become *required* for any transport. The
  client-side filtering path remains the fallback for the file
  transport and for clients that don't want to participate in the
  authenticated-bitmap protocol.
* This document does NOT define an HTTP/S3 server reference
  implementation — only the contract such a server MUST honour. The
  Cloudflare Worker in `web/` is the reference deployment.
