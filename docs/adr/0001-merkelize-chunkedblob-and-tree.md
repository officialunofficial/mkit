# ADR 0001 — Merkelize ChunkedBlob and Tree (identity = domain-bound BMT root)

- Status: Accepted (pre-1.0, breaking, no migration)
- Date: 2026-06-20
- Supersedes: n/a
- Full design: [docs/MERKELIZATION-PLAN.md](../MERKELIZATION-PLAN.md);
  normative crypto in `docs/SPEC-MERKLE-OBJECTS.md` (created by this work).

## Context

mkit object ids are `BLAKE3(canonical serialized bytes)`, re-verified on every store read. The
"merkelize everything" north star makes a merkelized object's content-address its merkle root, so
inclusion of any chunk/entry is provable and completeness is verifiable for free.

## Decision

- `ChunkedBlob` and `Tree` are content-addressed by a **domain-bound commonware BMT root**:
  `id = domain_digest(TYPE_DOMAIN, Builder::<Blake3>(leaves).build().root().0)`, mirroring
  makechain `transactions_root.rs`. BMT, not MMR (fixed, known-up-front leaf sets).
- ChunkedBlob leaves: a metadata leaf at position 0 (binds `total_size`/`chunk_size`) then the
  chunk hashes. Tree leaves: one `domain_digest` per entry over `name_len‖name‖mode‖object_hash`.
- The store verifies these two types **structurally** (decode → recompute root → compare to key)
  and all other types by byte-hash; dispatch is on the prologue type byte, performed **inside
  `ObjectSink::put_parts`** so every ingest path is correct unchanged.
- Blob/Commit/Remix/Delta/Tag identity, the serialized wire format, and `schema_version = 0x01`
  are unchanged. Cross-format safety is a **mandatory `.mkit/format` repo marker**, not a version
  bump.
- Transfer: legacy per-object path deleted; completeness becomes the chain of root-equals-id
  checks (no merkle proofs on the wire); packmap stays a content-addressed hash chain (not an MMR);
  packlist codec moves to commonware-codec (in PR #401).

## Consequences

- BREAKING: every Tree id → every Commit id → every ref changes; all history is re-addressed. No
  migration (pre-1.0). Old repos are rejected loudly at open via `.mkit/format`.
- `commonware-cryptography`/`-storage`/`-codec` become non-optional in `mkit-core` (the
  "default build pays zero" property is given up for these three; gated on a wasm32 build check).
- Golden vectors for Tree/ChunkedBlob (and git-bridge round-trips) are regenerated.
- Open items requiring human sign-off are tracked in MERKELIZATION-PLAN.md §8 (domain-wrap vs bare
  root, wasm viability of non-optional storage, marker semantics, persisted git↔mkit oid maps).
