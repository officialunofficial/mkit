---
spec: SPEC-PACK-SHARDS
version: 0
status: stable-normative
audience: implementers of pack producers and consumers; transport implementers
---

# SPEC-PACK-SHARDS &mdash; erasure-coded pack delivery

Status: **Normative** for mkit v0.x &mdash; the in-process codec and the
wire/transport delivery surface are both implemented. Tracks issue
[#159](https://github.com/officialunofficial/mkit/issues/159).
Scope: a wire-level encoding *of* a pack &mdash; the on-disk packfile format
(SPEC-PACKFILE) is unchanged.

This spec covers the manifest, per-shard envelope, encoder/decoder
algorithm (§§ 2-4), and HTTP/S3 transport wiring + producer pipeline
(§ 5). SSH integration is explicitly out of scope.

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
  benefit &mdash; a cache holding 18 of 20 shards is still useful

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
4       1      version      = 0x02
5       32     pack_hash
37      2      minimum_shards (u16, non-zero)
39      2      extra_shards   (u16, non-zero)
41      32     commitment
73      4      shard_hashes_len (u32, == minimum + extra)
77      32*T   shard_hashes
```

For the v0 default `(16, 4)` config the manifest is `717` bytes:
`5 + 32 + 2 + 2 + 32 + 4 + 20 * 32`.

`version` was bumped `0x01` → `0x02` by issue
[#661](https://github.com/officialunofficial/mkit/issues/661), which
switched the Reed-Solomon hasher from `Sha256` to `Blake3` (§4) &mdash; a
hard cutover, not dual-hasher support. `0x01` (the pre-#661
`ReedSolomon<Sha256>` scheme) is retired **permanently** and MUST NOT
be reused for a different wire meaning: a `0x01` manifest's
`commitment` can never check out against the `Blake3`-based decoder,
so a decoder that sees `0x01` MUST reject it with a version-specific
error rather than the generic unrecognized-version error, so a caller
stuck on an old producer gets an actionable message (re-shard with a
current mkit) instead of an opaque failure.

Decoders MUST:

* Reject inputs shorter than the 5-byte prologue, or with a magic
  that is not `b"MKSH"`, or with an unrecognized version.
* Reject `minimum_shards == 0` or `extra_shards == 0`.
* Reject a `shard_hashes_len` that does not equal
  `minimum_shards + extra_shards`.
* Reject any input that exceeds `MANIFEST_MAX_BYTES` (1 MiB).
* Reject trailing bytes after the last hash.

The manifest is itself content-addressed by `pack_hash` &mdash; that is, the
publish path is `/packs/<lower-hex(pack_hash)>/shards.manifest`.

---

## 3. Per-Shard envelope

```text
field    type        description
-------- ----------- --------------------------------------------------
index    u16         Shard index in [0, T). The receiver MUST reject
                     a shard whose index ≥ T or whose index does not
                     match the URL it was fetched from.
bytes    Vec<u8>     Codec-serialized commonware `Chunk`. Opaque at
                     the transport layer.
```

The `bytes` field carries the commonware `Chunk` (shard payload +
shard index + Merkle multi-proof) in its native
`commonware_codec::Codec` form. mkit does **not** introduce a second
framing &mdash; the codec output is already self-describing.

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
[`commonware-coding`](https://docs.rs/commonware-coding), pinned exactly
to the commonware train fixed in `rust/Cargo.toml` (`=2026.9.0` as of this
revision) (ALPHA stability &mdash; pinned exactly in `Cargo.toml`).

The reference scheme is `commonware_coding::ReedSolomon<Blake3>`.
Producers and consumers MUST use the same scheme and digest. The
`commonware-parallel` execution strategy (`Sequential` vs a `Rayon`
thread pool) is a caller-selectable performance parameter, not part
of the wire contract &mdash; see `encode_pack_to_shards_with_strategy` /
`decode_pack_from_shards_with_strategy` and issue
[#653](https://github.com/officialunofficial/mkit/issues/653).

### 4.1 Encode

```text
input:  pack: &[u8], config: Config, strategy: impl Strategy
output: (Vec<Shard>, ShardSet)

1. (commitment, chunks) := ReedSolomon::encode(config, pack, strategy)
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
input:  shards: &[Shard], manifest: &ShardSet, strategy: impl Strategy
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
4. pack := ReedSolomon::decode(config, commitment, checked.iter(), strategy)
5. require BLAKE3(pack) == manifest.pack_hash
6. return pack
```

A failure at any step short-circuits with a typed `ShardError`. See
the `mkit_core::pack_shard::ShardError` rustdoc for the full taxonomy.

---

## 5. Implementation status

This SPEC ships in two stages.

### In-process codec &mdash; shipped

* `mkit-core::pack_shard` module behind the `pack-shards` feature
  flag (default off &mdash; the commonware dep stack is large)
* `Config`, `Shard`, `ShardSet`, `ShardError`
* `encode_pack_to_shards`/`decode_pack_from_shards`
* Round-trip, lossy round-trip, tamper-detection, and
  insufficient-shards tests

### Wire format and transport delivery &mdash; shipped (this surface)

* **Manifest wire format pinned**: see §2.1.
  `encode_manifest`/`decode_manifest` in `mkit_core::pack_shard`.
* **HTTP transport**: `Accept-Pack-Shards: <N>+<K>` request header;
  `X-Pack-Shards: <N>+<K>` response header signaling shard mode.
  Shard URLs at `/packs/<lower-hex(pack_hash)>/shards/<index>`,
  manifest at `/packs/<hex>/shards.manifest`. Behind
  `--features pack-shards` on `mkit-transport-http`. Parallel-fetch
  client: one std thread per shard URL, collect the first
  `minimum_shards` successful responses, drop stragglers. Up to
  `extra_shards` failures tolerated; `extra_shards + 1` failures
  short-circuit to `PackNotFound`.
* **S3 transport**: same key shape on the bucket
  (`packs/<hex>/shards/<index>`, `packs/<hex>/shards.manifest`).
  Behind `--features pack-shards` on `mkit-transport-s3`. The
  client unconditionally tries the manifest first; only a `404`
  (no manifest published) falls back to the monolithic pack key. A
  present-but-undecodable manifest &mdash; any other error status, or a
  malformed `200` body &mdash; propagates instead of falling back: it is
  indistinguishable from tampering, and silently downgrading to the
  monolithic pack would mask that. This mirrors the HTTP transport's
  posture, whose shard path is entered only after the server
  advertises `X-Pack-Shards`, so a failure once inside it is treated
  as a server-side bug and surfaced rather than downgraded.
* **SSH transport**: explicitly skipped. SSH is a single ordered
  stream; the shard model does not fit and per-shard sigv4-style
  signing is meaningless over an authenticated tunnel.
* **Producer pipeline**: `mkit pack-shard <hash>` reads a stored
  pack from `ObjectStore`, runs the encoder, and writes:
  ```text
  <out>/packs/<hex>/shards.manifest
  <out>/packs/<hex>/shards/<index>
  ```
  Default `<out>` is `<repo>/.mkit/pack-shards/`. Operators publish
  the directory to whichever HTTP / S3 target their clients hit.
  Size gate per §6 enforced; bypass with `--force`.
* **Bench**: `rust/benches/benches/pack_shard_transfer.rs` measures
  monolithic vs parallel-shard vs sequential-shard transfer on a
  100 MiB pack with jittered network sleeps. Not gated on CI.

### Direct-upload negotiation and streaming &mdash; out of scope for this SPEC

* Sharded uploads via the `Transport` trait directly (today, shards
  are published out-of-band by the operator).
* Per-shard streaming download (current implementation buffers each
  shard whole; the per-shard cap is `PACK_BODY_LIMIT`).
* `(N, K)` negotiation between client and server beyond the v0
  default `(16, 4)`.

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

---

## 7. Invariants

| Invariant | Enforced by |
|---|---|
| The reconstructed pack is bit-identical to the original | `BLAKE3(pack) == manifest.pack_hash` after decode (§4.2 step 5) |
| The manifest parses one way or not at all | `b"MKSH"` magic + version check, non-zero `(minimum, extra)`, `shard_hashes_len == minimum + extra`, `MANIFEST_MAX_BYTES` cap, trailing bytes rejected (§2.1) |
| A corrupted or substituted shard never reaches the Reed-Solomon decoder | `BLAKE3(shard.bytes)` checked against `manifest.shard_hashes[index]` first → `ShardHashMismatch` (§3, §4.2 step 2c) |
| A shard cannot claim a foreign index | `index < T`, index-vs-fetch-URL match (§3), duplicate indices rejected (§4.2 step 2b) |
| A self-consistent substitute shard *set* is detected | commonware BMT `commitment` in the manifest; per-shard Merkle proof checked by `ReedSolomon::check` (§2, §3, §4.2 step 2e) |
| Any `minimum_shards` of the `T` shards suffice; fewer fail loudly | `checked.len() >= minimum_shards` requirement, typed `ShardError` short-circuit (§4.2 step 3) |
| The manifest is the content-addressed root of trust | fetched first, published at `/packs/<hex(pack_hash)>/shards.manifest` (§2) |
| A failed sharded fetch degrades, never corrupts; an undecodable manifest never silently downgrades | HTTP: `extra_shards + 1` failures short-circuit to `PackNotFound`; S3: only a manifest `404` falls back to the monolithic pack key &mdash; a present-but-undecodable manifest propagates as `InvalidResponse` on both S3 and HTTP (§5) |
| Per-shard memory is bounded | each shard buffered whole under `PACK_BODY_LIMIT` (§5) |

Sharding is an encoding *of* a pack, not a new pack format (see Scope,
header): once reconstructed, the pack is verified again by the
SPEC-PACKFILE trailer and per-object rules like any monolithic download.
