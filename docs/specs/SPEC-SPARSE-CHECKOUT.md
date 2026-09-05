---
spec: SPEC-SPARSE-CHECKOUT
version: 3
status: implemented
audience: sparse-checkout transport and cache implementers
---

# SPEC-SPARSE-CHECKOUT — canonical tree witnesses

## 1. Trust boundary

Sparse protocol v2 carries complete canonical Tree metadata, without unselected
file payloads. Only the current witness format is supported. Unsupported formats
MUST be rejected; no compatibility decoder or migration is provided.

The caller MUST obtain the expected Tree ID from an authenticated commit, remix,
or parent Tree. Verification MUST compare that expected ID with both the
manifest ID and the canonical `Object::Tree(tree).id()` of the witness. The
canonical ID is the SPEC-OBJECTS domain-separated Merkle ID, not the BLAKE3 hash
of serialized Tree bytes. Tree ordering and names MUST satisfy SPEC-OBJECTS.

## 2. Filters and selected entries

Filters are lists of UTF-8 repository-relative literal path prefixes. `.`
selects every entry. An empty list selects nothing. Empty paths, leading or
trailing slashes, empty components, `.`/`..` components, backslashes, negation
and glob syntax (`!`, `*`, `?`, `[`, `]`) are unsupported. A filter selects a
local entry when it equals that entry's name. For a directory, a filter starting
with its name followed by `/` also selects that directory for traversal.

A filter permits at most 100,000 paths and 1 MiB total UTF-8 bytes. Its commitment
is BLAKE3 over `mkit-sparse-filter-v2\0`, followed by sorted, deduplicated raw
UTF-8 paths, each preceded by its byte length as u64 little-endian. The NUL in
the domain string is one byte. Invalid filters MUST be rejected before fetching.

The verifier MUST derive the exact selected entries from authenticated witness
metadata. Server-provided selected entries MUST NOT determine membership,
ordering, modes or object hashes. `build_sparse` returns a `SparseResponse`
containing only the manifest and witness. `verify_sparse` returns a
`VerifiedSparseTree` containing the manifest and locally derived entries; it
accepts no parallel server-selected list. HTTP/S3 fetch helpers return that
verified result directly.

## 3. Recursive completeness

For every selected directory the client MUST obtain and authenticate a child
Tree witness against the ID in its parent. An exact directory match or `.`
becomes `.` in the child filter; a longer prefix loses the directory component.
Missing required child witnesses are failures, including for apparently empty
subtrees. No unselected child witness or file payload is required.

`verify_sparse_hierarchy` enforces at most 100,000 tree visits, depth 256,
4,096-byte paths, one million returned entries, and 64 MiB aggregate canonical
witness bytes. Exceeding a bound returns a typed size failure without publishing
a partially verified traversal.

## 4. Wire and cache

All integers are little-endian. The envelope is exactly:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Network magic `MSP1`, or cache magic `MSPC` |
| 4 | 1 | Version 2 |
| 5 | 32 | Canonical Tree ID |
| 37 | 32 | Filter commitment |
| 69 | 4 | Serialized Tree byte length |
| 73 | length | Complete canonical serialized Tree object |

The full envelope MUST be no larger than 16 MiB. The witness MUST contain a
Tree, have strict ordering and valid names, contain at most one million entries,
and reserialize byte-for-byte identically. Declared lengths MUST exactly match
the remaining bytes. Trailing bytes, unsupported versions and noncanonical witnesses
MUST be rejected. The selected-entry list is absent from the envelope.

Cache files are disposable `.mkit/sparse/<tree-hex>.witness` files containing
current Tree metadata. Readers MUST validate the full witness and compare both
Tree ID and filter commitment with caller expectations on every hit. Filename
identity alone is insufficient. Invalid cache entries are misses and may be
overwritten after a verified rebuild. No older cache paths are read or migrated.

## 5. Transport and fallback

HTTP uses `POST /<project>/trees/<tree-hex>/sparse?sparse=<filter-hex>` with JSON
`{"filter":["path",...]}` and `application/x-mkit-sparse` response bytes. S3
uses `sparse/v2/<tree-hex>/<filter-hex>` beneath the configured object prefix.
HTTP/S3 clients validate the requested root and filter and return locally derived
entries. They MUST NOT return a successful fetch for a substituted witness.

Oversized witnesses return a typed size error. Unsupported CLI pattern semantics
and oversized local witnesses use the existing full authenticated metadata path,
subject to its normal resource limits. CLI clone and checkout already possess
that metadata; this protocol does not change their restoration grammar. Clients
MUST NOT approximate negations or glob semantics into a different sparse filter.
Remote callers needing fallback retrieve authenticated Tree objects through the
normal pack path. SSH has no sparse endpoint.

## 6. Conformance

Tests cover independently trusted root binding, changed entry hash or mode,
omitted selected entries, malformed filters and flat names, recursive missing
and substituted children, exact wire lengths, cache identity, and v1 rejection.
The v2 golden response pins canonical bytes and Tree ID. Metadata range proofs
are a possible future protocol; this version makes no metadata bandwidth-saving
claim.
