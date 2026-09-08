---
spec: SPEC-FASTCDC
version: 1
status: stable
audience: implementers of compatible chunkers; anyone reproducing chunked_blob hashes across producers
---

# SPEC-FASTCDC &mdash; mkit v1 content-defined chunking

Status: **Normative** for mkit v1 (content-defined chunking of large
files).
Scope: gear table derivation, chunking parameters, and the determinism
contract that makes chunked_blob hashes stable across producers.

Resolves red-team R-46 (gear-seed determinism gap).

---

## 1. Purpose

For files larger than a fixed threshold, mkit uses FastCDC (Fast
Content-Defined Chunking) to cut the file at content-defined
boundaries, store each chunk as its own blob, and reference them from
a `chunked_blob` object (SPEC-OBJECTS §7).

This lets edits near the end of a large file reuse most of the
prior version's chunks, which is critical for dedup across pack
transfers (see SPEC-PACKFILE §3.2 delta vs. SPEC-OBJECTS §7 chunked
dedup &mdash; these are complementary layers).

---

The 1 MiB writer threshold and the boundary rules here govern newly produced
objects. They do not impose a unique representation on existing file contents:
a large inline Blob or another valid chunk layout remains readable. File
comparison follows SPEC-OBJECTS §7 and preserves an existing staged identity
when bytes are unchanged.

## 2. Determinism contract

Chunk boundaries, and therefore `chunked_blob` hashes, are **fully
determined by**:

1. The input file bytes.
2. The gear table seed (§3).
3. The chunking parameters `(min_size, avg_size, max_size)` (§4).
4. The mask derivation (§5).

**Any change to any of (2), (3), or (4) breaks chunk boundary
reproducibility.** The chunk hashes change, and blob-level dedup
across the change boundary fails for every large file.

This is why (2) through (4) are specified as normative constants in v1
and can only be changed through a format-version bump.

---

## 3. Gear table seed

The gear table is 256 `u64` entries, derived from a splitmix64 initial
state seeded with an 8-byte ASCII literal. mkit does **not** use the
gear table from the FastCDC paper (Xia et al., USENIX ATC '16); the
table is mkit-specific and produced by the procedure below.

```
state = 0x4D4B495446434443        # ASCII "MKITFCDC" interpreted as big-endian u64
for each of 256 entries:
    state = state +% 0x9e3779b97f4a7c15              # wrapping add (splitmix64 gamma)
    z = state
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9        # wrapping mul
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb
    z = z ^ (z >> 31)
    table[i] = z
```

The reference Rust implementation lives in
`mkit-core::chunker::build_gear_table` and uses a `std::sync::OnceLock`
to memoise the 2 KiB table on first use. The exported constant `SEED`
is the same `0x4D4B_4954_4643_4443` value.

### 3.1 Seed decision (v1)

The seed ASCII is **`"MKITFCDC"`**, frozen for the lifetime of v1.
The seed is not user-visible; it is 8 bytes inside the chunker.

Future format versions that want to change chunking MUST bump the
format version and publish a migration path. A future reader that
needs to chunk for a different chunk-family MAY use a different seed
and namespace the result accordingly, but v1 does NOT provide a
mechanism for this.

---

## 4. Chunking parameters

Hard-coded defaults (applied whenever the worktree takes the chunked
path):

```
min_size =  16 * 1024   =   16 KiB
avg_size =  64 * 1024   =   64 KiB
max_size = 256 * 1024   =  256 KiB
```

Normative constraint: `avg_size` MUST be a power of two (the mask
derivation in §5 uses `log2(avg_size)`); `min_size < avg_size <
max_size` MUST hold strictly. mkit's v1 constants satisfy "all three
are powers of two", but the format only requires this of `avg_size`.

Files of size ≤ `min_size` are NOT chunked &mdash; `cut` returns the full
input length, so the caller stores the file as a single `blob`. The
threshold for taking the chunked path is an implementer choice; in
mkit-core the worktree picks `CHUNK_THRESHOLD = 1 MiB`
(`worktree::CHUNK_THRESHOLD`). v1 specifies only that **once a file
is chunked**, the parameters above MUST be used.

Implementation status: end-to-end wiring is in place across the
hashing, staging, commit, and read-back paths (issue #203).

A single helper, `worktree::store_file_object`, is the one place that
decides a regular file's object representation: at or below
`CHUNK_THRESHOLD` it writes a single `Blob`; above it, it splits with
`FastCdc::v1`, stores each chunk as its own `Blob`, and writes a
`ChunkedBlob` manifest (with `chunk_size = 0` to denote content-defined
chunking) whose hash lands in the parent tree. Every caller routes
through it, so a given file produces the same object/hash regardless of
the path that computes it:

- `worktree::{hash_file, build_tree}` &mdash; diff, status, tree, and the
  `rm`/`checkout` dirty-checks;
- `mkit add` (`add_one` / `stage_tracked_changes`) &mdash; staging into the
  index;
- `worktree::build_tree_from_index` &mdash; the commit/index tree build now
  accepts a `ChunkedBlob` under a regular-file (Blob/Executable) entry,
  so committing a > 1 MiB file no longer fails with a "non-blob object"
  error.

Read-back is symmetric: `worktree::read_blob` reassembles a `Blob` or
`ChunkedBlob` into the full byte stream, and backs `mkit cat`,
`mkit diff`, and worktree restore (`mkit checkout`). `mkit cat` on a
`ChunkedBlob` hash streams the reassembled content rather than an object
placeholder.

The byte-level chunk boundaries are pinned by the goldens in §8; the
worktree round-trip is covered by
`worktree::tests::large_file_becomes_chunked_blob`, the index-path
acceptance by `worktree::tests::from_index_accepts_chunked_blob_for_file_entry`,
and the full add → commit → status/diff/rm → checkout → cat round-trip
by the `chunked_blob_roundtrip` unit test in `mkit-core::serialize`.

---

## 5. Mask derivation and cut algorithm

Mask derivation:

```
bits   = log2(avg_size)
mask   = (1 << bits) - 1
mask_s = mask | (mask << 1)      # stricter: fewer boundaries
mask_l = mask >> 1                # looser: more boundaries
```

For `avg_size = 64 KiB = 2^16`, `bits = 16`:

```
mask   = 0x0000_FFFF
mask_s = 0x0001_FFFF
mask_l = 0x0000_7FFF
```

Cut algorithm (normative):

```
cut(data) -> length:
    if len(data) <= min_size: return len(data)
    hash = 0
    # Strict region: min_size .. avg_size
    for i in min_size .. min(avg_size, len(data)):
        hash = (hash << 1) +% gear_table[data[i]]
        if (hash & mask_s) == 0: return i
    # Loose region: avg_size .. max_size
    for i in avg_size .. min(max_size, len(data)):
        hash = (hash << 1) +% gear_table[data[i]]
        if (hash & mask_l) == 0: return i
    # Forced cut at max_size
    return min(max_size, len(data))
```

The result `length` is the number of bytes in the first chunk. The
caller consumes those bytes, then calls `cut` again on the remainder.
The iteration continues until all bytes are consumed.

---

## 6. Chunked_blob composition

See SPEC-OBJECTS §7 for the container. Key points for chunking:

- `total_size` = sum of all chunk byte lengths = file size.
- `chunk_size` = **0** (not the file chunk size; 0 is the sentinel for
  content-defined chunking).
- `chunks` = ordered list of chunk BLAKE3 hashes.
- Each chunk is itself stored as a `blob` object (SPEC-OBJECTS §3)
  under its content hash.

A reader reassembles the file by concatenating `chunks[0].data ||
chunks[1].data || ... || chunks[n-1].data` and verifying the length
equals `total_size`.

---

## 7. Cross-implementation validation

Any two conformant implementations chunking the same file with the
same (seed, parameters, mask) MUST produce:

- The same number of chunks.
- The same chunk boundaries (byte offsets).
- The same chunk hashes.
- The same `chunked_blob` object hash.

Conformance tests SHOULD include at least one 10 MiB pseudo-random
file and one 10 MiB highly-repetitive file, asserting byte-identical
chunk lists across platforms.

---

## 8. Test vectors

The vectors below are exercised by
`rust/crates/mkit-core/tests/golden_pack.rs` (boundaries on disk under
`rust/tests/golden/fastcdc/`) plus the unit tests in
`rust/crates/mkit-core/src/chunker.rs::tests`.

1. **Gear table hash**: `gear_table_digest()` returns
   `BLAKE3` of the 256 `u64` entries little-endian-encoded
   (2 048 bytes total). Any implementation that derives the same table
   for seed `"MKITFCDC"` will produce the same digest. Stability is
   asserted by `gear_table_digest_is_stable`; the table is also checked
   to be all-unique and non-zero by `gear_table_is_unique_and_nonzero`.
2. **Small file fits in single chunk**: short input → `cut` returns
   `data.len()` immediately. No `chunked_blob` produced
   (`small_input_is_single_chunk`).
3. **`min_size`-or-smaller is single chunk**: `data.len() <= min_size`
   → `cut` returns `data.len()` (`cut_at_exactly_min_size_returns_full`).
4. **Pseudo-random 1 MiB file**, splitmix64 stream from seed
   `0xA5A5_F00D_DEAD_BEEF`: chunk boundary offsets are pinned in
   `rust/tests/golden/fastcdc/fastcdc_boundaries_1mib.bin`
   (`fastcdc_boundaries_1mib_match_golden`).
5. **Pseudo-random 256 KiB file**, splitmix64 stream from seed
   `0xCAFE_BABE_1234_5678`: pinned in
   `rust/tests/golden/fastcdc/fastcdc_boundaries_256k.bin`
   (`fastcdc_boundaries_256k_match_golden`).
6. **Repetitive buffer**: all-zero data with a tiny chunker exercises
   the forced-cut-at-`max_size` path
   (`cut_forces_boundary_at_max_size`).
7. **Boundary stability under a 1-byte insert**: insert one byte at
   32 KiB into a 64 KiB pseudo-random file; ≤ 3 chunks differ
   (`boundary_stability_single_byte_insert`). The shifted-chunks
   identity test is subsumed by this regression.
8. **Iterator total covers the input**: chunk lengths sum to the
   input length (`fastcdc_iterator_total_equals_input_length`).
9. **Different `avg_size` yields different boundaries**: a chunker
   with `(8K, 32K, 128K)` does not produce the v1 boundaries
   (`different_avg_size_yields_different_boundaries`).
10. **Seed misuse detector**: if an implementation is accidentally
    built with any seed other than `"MKITFCDC"`, the gear-table-hash
    pin and the boundary goldens both fail loudly at test time.

---

## 9. Future work (non-v1)

- Per-file-type tuning (for example, larger `avg_size` for media files) is
  out of scope.
- A sliding-window gear hash implementation variant would produce
  different boundaries; not a v1 alternative.

---

## 10. Invariants

| Invariant | Enforced by |
|---|---|
| Chunk boundaries &mdash; and therefore `chunked_blob` hashes &mdash; are a pure function of the input bytes | frozen seed (§3), parameters (§4), and mask derivation (§5); any change requires a format-version bump (§2) |
| Every implementation derives the identical gear table | the `"MKITFCDC"` + splitmix64 procedure (§3); gear-table digest pin and uniqueness/non-zero checks (§8.1) |
| `avg_size` is a power of two; `min_size < avg_size < max_size` holds strictly | normative parameter constraint (§4) |
| Input of ≤ `min_size` bytes is a single chunk, never a `chunked_blob` | `cut` returns the full input length (§4, §5) |
| No chunk exceeds `max_size` | forced cut at `max_size` (§5) |
| Chunk lengths sum to the input length; `total_size` equals the file size | iterative consumption until all bytes are cut (§5); reassembly length check against `total_size` (§6); pinned by §8 vector 8 |
| Content-defined manifests are distinguishable from fixed-size ones | `chunk_size = 0` sentinel (§6; SPEC-OBJECTS §7) |
| Any two conformant chunkers agree on chunk count, byte offsets, chunk hashes, and manifest hash | cross-implementation contract (§7); boundary goldens (§8 vectors 4–5) |
| A build with the wrong seed or parameters cannot ship silently | gear-table-hash pin and boundary goldens fail loudly at test time (§8 vectors 9–10) |
