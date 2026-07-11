# mkit specifications

The authoritative wire-format, on-disk, and subsystem specifications.
Each spec carries its own `status` (stable / normative / draft) in its
front matter.

- [SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md) — native attestations: in-toto v1 statements in DSSE envelopes.
- [SPEC-CONCURRENCY](SPEC-CONCURRENCY.md) — the total mkit lock order across worktree, ref-history, and CAS locks.
- [SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md) — user-vs-repo config trust boundary and key classification rules.
- [SPEC-CONVENTIONS](SPEC-CONVENTIONS.md) — shared vocabulary (RFC 2119 keywords, status vocabulary, encoding notation) for the SPEC-*.md corpus.
- [SPEC-DELTA](SPEC-DELTA.md) — delta encoding for packfile objects.
- [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md) — subprocess protocol for out-of-process signers (HSM, TPM, WebAuthn, …).
- [SPEC-FASTCDC](SPEC-FASTCDC.md) — deterministic content-defined chunking for chunked blobs.
- [SPEC-GC](SPEC-GC.md) — garbage collection, object pruning, and recovery.
- [SPEC-GIT-BRIDGE](SPEC-GIT-BRIDGE.md) — mkit→git export bridge (fork mode) and its verifiers.
- [SPEC-GIT-IMPORT](SPEC-GIT-IMPORT.md) — git→mkit import bridge (one-way fork) and its verifiers.
- [SPEC-HISTORY-PROOF](SPEC-HISTORY-PROOF.md) — MMR-based history proofs for light-client verification.
- [SPEC-INDEX](SPEC-INDEX.md) — repo-local staging-area index (advisory, not exchanged).
- [SPEC-KEYSTORE](SPEC-KEYSTORE.md) — key vault interface, backends, and `mkit key` CLI surface.
- [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) — merkelized ChunkedBlob and Tree object hashing.
- [SPEC-OBJECTS](SPEC-OBJECTS.md) — on-disk object model and canonical serialization over BLAKE3 IDs.
- [SPEC-PACK-SHARDS](SPEC-PACK-SHARDS.md) — sharded pack production and transport delivery.
- [SPEC-PACKFILE](SPEC-PACKFILE.md) — packfile wire format for object exchange.
- [SPEC-REFS](SPEC-REFS.md) — ref names, storage, and CAS update variants.
- [SPEC-RELEASE-THRESHOLD](SPEC-RELEASE-THRESHOLD.md) — BLS threshold signatures for release-party attestation.
- [SPEC-RPC](SPEC-RPC.md) — shared stdio protobuf framing for subprocess protocols.
- [SPEC-SIGNING](SPEC-SIGNING.md) — commit / remix / tag signing hashes and verification.
- [SPEC-SPARSE-CHECKOUT](SPEC-SPARSE-CHECKOUT.md) — verifiable server-side sparse checkout over HTTP/S3.
- [SPEC-TRANSPORT](SPEC-TRANSPORT.md) — seven-verb transport wire protocol (file, SSH, HTTP, S3, memory).
- [SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) — draft `mkit.transport.v1` Connect service, the canonical remote protocol superseding SPEC-TRANSPORT §5.
- [SPEC-TRANSPORT-ENC](SPEC-TRANSPORT-ENC.md) — self-contained encrypted-stream transport (`mkit+enc://`).
