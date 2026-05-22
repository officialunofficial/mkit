---
spec: SPEC-PACK-SHARDS
version: 0
status: draft
audience: implementers of pack producers and consumers; transport implementers
---

# SPEC-PACK-SHARDS — erasure-coded pack delivery

Status: **Draft** for mkit v0.x. Tracks issue
[#159](https://github.com/officialunofficial/mkit/issues/159).
Scope: a wire-level encoding *of* a pack — the on-disk packfile format
(SPEC-PACKFILE) is unchanged.

This spec covers the manifest, per-shard envelope, and encoder/decoder
algorithm. It does **not** cover transport integration; that work
lands in Phase 2 (see §5).

---

## 1. Motivation

Current pack delivery (HTTP, S3, SSH) is all-or-nothing: any byte
missing, the whole transfer fails. Large packs over flaky networks
(mobile, NAT'd home connections, R2-during-incident) re-download from
scratch.

Reed-Solomon erasure coding lets a producer encode `N` data shards
into `N + K` total shards such that **any `N`** of the `N + K` shards
reconstruct the original pack. With `(N, K) = (16, 4)`:

* 20 total shards, each roughly `pack_size / 16` bytes
* Up to 4 shards may be lost (or arrive slowest, and be ignored)
  without affecting reconstruction
* Mirror networks, partial caches, and high-latency clients all
  benefit — a cache holding 18 of 20 shards is still useful

Out of scope: small packs. Below the size threshold in §6, the
fixed-cost overhead exceeds the redundancy benefit.

---

## 2. ShardSet manifest wire shape

The manifest is fetched once, before any shards. It is the
content-addressed root of trust for a sharded pack.

```text
field             type         description
----------------- ------------ ---------------------------------------
pack_hash         [u8; 32]     BLAKE3 of the original pack bytes.
                               Verified after reconstruction.
config            (u16, u16)   (minimum_shards, extra_shards). Both
                               MUST be > 0; (16, 4) is the v0 default.
shard_hashes      [[u8; 32]; T] BLAKE3 of each shard's bytes, indexed
                               by shard index. T = minimum_shards +
                               extra_shards.
commitment        [u8; 32]     Commonware BMT root committing to all
                               T shards. Required by the decoder for
                               per-shard Merkle-proof checks.
```

### 2.1 v0 wire bytes

All multi-byte integers are little-endian. The encoder /
decoder live in `mkit_core::pack_shard::{encode_manifest,
decode_manifest}`.

```text
offset  size   field
------  -----  -----------------------------------------
0       4      magic        = b"MKSH"
4       1      version      = 0x01
5       32     pack_hash
37      2      minimum_shards (u16, non-zero)
39      2      extra_shards   (u16, non-zero)
41      32     commitment
73      4      shard_hashes_len (u32, == minimum + extra)
77      32*T   shard_hashes
```

For the v0 default `(16, 4)` config the manifest is `717` bytes:
`5 + 32 + 2 + 2 + 32 + 4 + 20 * 32`.

Decoders MUST:

* Reject inputs shorter than the 5-byte prologue, or with a magic
  that is not `b"MKSH"`, or with an unrecognised version.
* Reject `minimum_shards == 0` or `extra_shards == 0`.
* Reject a `shard_hashes_len` that does not equal
  `minimum_shards + extra_shards`.
* Reject any input that exceeds `MANIFEST_MAX_BYTES` (1 MiB).
* Reject trailing bytes after the last hash.

The manifest is itself content-addressed by `pack_hash` — i.e. the
publish path is `/packs/<lower-hex(pack_hash)>/shards.manifest`.

---

## 3. Per-Shard envelope

```text
field    type        description
-------- ----------- --------------------------------------------------
index    u16         Shard index in [0, T). The receiver MUST reject
                     a shard whose index ≥ T or whose index does not
                     match the URL it was fetched from.
bytes    Vec<u8>     Codec-serialised commonware `Chunk`. Opaque at
                     the transport layer.
```

The `bytes` field carries the commonware `Chunk` (shard payload +
shard index + Merkle multi-proof) in its native
`commonware_codec::Codec` form. mkit does **not** introduce a second
framing — the codec output is already self-describing.

**Integrity:** before passing a shard to the decoder, the receiver
computes `BLAKE3(bytes)` and compares against
`manifest.shard_hashes[index]`. A mismatch means the shard was
corrupted or substituted in transit. The shard is dropped before it
ever reaches the Reed-Solomon decoder.

This double-check (BLAKE3 envelope hash + commonware's own Merkle
proof) is intentional. The envelope BLAKE3 lets a transport reject
bad shards cheaply, without paying the Merkle-proof cost. The Merkle
proof inside the chunk additionally binds the shard to the manifest's
`commitment`, which prevents a coordinated attacker from substituting
a self-consistent shard set with a different `commitment`.

---

## 4. Encoder/decoder algorithm

The implementation lives in `mkit_core::pack_shard` and wraps
[`commonware-coding`](https://docs.rs/commonware-coding) **v2026.4.0**
(ALPHA stability — pinned exactly in `Cargo.toml`).

The reference scheme is `commonware_coding::ReedSolomon<Sha256>` with
the `Sequential` parallel strategy. Producers and consumers MUST use
the same scheme and digest.

### 4.1 Encode

```text
input:  pack: &[u8], config: Config
output: (Vec<Shard>, ShardSet)

1. (commitment, chunks) := ReedSolomon::encode(config, pack, Sequential)
2. for i in 0..total_shards:
       bytes := codec_encode(chunks[i])
       shards[i] := Shard { index: i, bytes }
       shard_hashes[i] := BLAKE3(bytes)
3. manifest := ShardSet {
       pack_hash:    BLAKE3(pack),
       config,
       shard_hashes,
       commitment:   commitment.as_bytes(),
   }
4. return (shards, manifest)
```

### 4.2 Decode

```text
input:  shards: &[Shard], manifest: &ShardSet
output: Vec<u8>  (the reconstructed pack)

1. validate manifest.shard_hashes.len() == config.total_shards()
2. for each shard in input:
   a. validate shard.index < total_shards
   b. validate shard.index not yet seen (no duplicates)
   c. validate BLAKE3(shard.bytes) == manifest.shard_hashes[shard.index]
      → on mismatch, ShardHashMismatch (do NOT call decoder)
   d. chunk := codec_decode(shard.bytes)
   e. checked := ReedSolomon::check(config, commitment, shard.index, chunk)
3. require checked.len() >= minimum_shards
4. pack := ReedSolomon::decode(config, commitment, checked.iter(), Sequential)
5. require BLAKE3(pack) == manifest.pack_hash
6. return pack
```

A failure at any step short-circuits with a typed `ShardError`. See
the `mkit_core::pack_shard::ShardError` rustdoc for the full taxonomy.

---

## 5. Implementation status

This SPEC ships in two phases.

### Phase 1 (this document, this PR)

* `mkit-core::pack_shard` module behind the `pack-shards` feature
  flag (default off — the commonware dep stack is large)
* `Config`, `Shard`, `ShardSet`, `ShardError`
* `encode_pack_to_shards` / `decode_pack_from_shards`
* Round-trip, lossy round-trip, tamper-detection, and
  insufficient-shards tests

No transport speaks `Pack-Shards` yet. Producers and consumers must
both link `mkit-core` with the feature on.

### Phase 2 (future PRs)

* HTTP transport: `Pack-Shards: N+K` request/response header,
  shard URLs at `/packs/<hash>/shards/<index>`, parallel-fetch
  client
* S3 transport: same shape; shards as separate keys
* SSH transport: explicitly skipped — SSH is a single stream, the
  shard model does not fit
* Producer pipeline: `pack → encode → upload N+K shards → publish
  ShardSet manifest`
* Performance benchmark: 100 MiB pack at 1% simulated packet loss,
  monolithic vs sharded

The manifest wire format will be normatively pinned in Phase 2
alongside the transport spec.

---

## 6. Size thresholds

Shards are **only** justified for packs larger than **1 MiB**.

Rationale:

* Each shard carries a Merkle proof of size O(log₂ T) hashes ≈ 5
  hashes for T = 20. At 32 bytes each, that is 160 bytes of overhead
  per shard, plus codec framing. For a 100 KiB pack split 16 ways,
  per-shard overhead would dominate the payload.
* Small packs already fit in a single HTTP response. The
  round-trip-savings argument does not apply.
* The manifest itself is `~ 32 * (T + 2) = ~ 700 bytes` for T = 20.
  This is a one-time cost regardless of pack size.

Producers SHOULD bypass the shard path entirely for packs ≤ 1 MiB
and serve them monolithically.

Producers MAY tune `(minimum_shards, extra_shards)` for very large
packs. The v0 default `(16, 4)` was picked to balance:

* Shard count low enough that each shard is fetched in O(1) HTTP
  requests (vs. say `(64, 16)` which would be 80 requests per pack)
* Redundancy high enough to absorb the typical mirror-down /
  slow-tail-shard scenario (25% over-provision)
* Total shard count comfortably below `u16::MAX` and below
  commonware's internal `ReedSolomonEncoder` limits
