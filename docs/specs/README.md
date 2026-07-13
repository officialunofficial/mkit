# mkit specifications

The authoritative wire-format, on-disk, and subsystem specifications.
Each spec carries its own `status` (stable / normative / draft) in its
front matter.

- [SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md) &mdash; native attestations: in-toto v1 statements in DSSE envelopes.
- [SPEC-CONCURRENCY](SPEC-CONCURRENCY.md) &mdash; the total mkit lock order across worktree, ref-history, and CAS locks.
- [SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md) &mdash; user-vs-repo config trust boundary and key classification rules.
- [SPEC-CONVENTIONS](SPEC-CONVENTIONS.md) &mdash; shared vocabulary (RFC 2119 keywords, status vocabulary, encoding notation) for the SPEC-*.md corpus.
- [SPEC-DELTA](SPEC-DELTA.md) &mdash; delta encoding for packfile objects.
- [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md) &mdash; subprocess protocol for out-of-process signers (HSM, TPM, WebAuthn, …).
- [SPEC-FASTCDC](SPEC-FASTCDC.md) &mdash; deterministic content-defined chunking for chunked blobs.
- [SPEC-GC](SPEC-GC.md) &mdash; garbage collection, object pruning, and recovery.
- [SPEC-GIT-BRIDGE](SPEC-GIT-BRIDGE.md) &mdash; mkit→git export bridge (fork mode) and its verifiers.
- [SPEC-GIT-IMPORT](SPEC-GIT-IMPORT.md) &mdash; git→mkit import bridge (one-way fork) and its verifiers.
- [SPEC-HISTORY-PROOF](SPEC-HISTORY-PROOF.md) &mdash; MMR-based history proofs for light-client verification.
- [SPEC-INDEX](SPEC-INDEX.md) &mdash; repo-local staging-area index (advisory, not exchanged).
- [SPEC-KEYSTORE](SPEC-KEYSTORE.md) &mdash; key vault interface, backends, and `mkit key` CLI surface.
- [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) &mdash; merkelized ChunkedBlob and Tree object hashing.
- [SPEC-OBJECTS](SPEC-OBJECTS.md) &mdash; on-disk object model and canonical serialization over BLAKE3 IDs.
- [SPEC-PACK-SHARDS](SPEC-PACK-SHARDS.md) &mdash; sharded pack production and transport delivery.
- [SPEC-PACKFILE](SPEC-PACKFILE.md) &mdash; packfile wire format for object exchange.
- [SPEC-REFS](SPEC-REFS.md) &mdash; ref names, storage, and CAS update variants.
- [SPEC-RELEASE-THRESHOLD](SPEC-RELEASE-THRESHOLD.md) &mdash; BLS threshold signatures for release-party attestation.
- [SPEC-RPC](SPEC-RPC.md) &mdash; shared stdio protobuf framing for subprocess protocols.
- [SPEC-SIGNING](SPEC-SIGNING.md) &mdash; commit / remix / tag signing hashes and verification.
- [SPEC-SPARSE-CHECKOUT](SPEC-SPARSE-CHECKOUT.md) &mdash; verifiable server-side sparse checkout over HTTP/S3.
- [SPEC-TRANSPORT](SPEC-TRANSPORT.md) &mdash; seven-verb transport wire protocol (file, SSH, HTTP, S3, memory).
- [SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) &mdash; draft `mkit.transport.v1` Connect service, the canonical remote protocol superseding SPEC-TRANSPORT §5.
- [SPEC-TRANSPORT-ENC](SPEC-TRANSPORT-ENC.md) &mdash; self-contained encrypted-stream transport (`mkit+enc://`).
- [SPEC-WORKTREE](SPEC-WORKTREE.md) &mdash; linked working trees: common-dir/per-tree state split, discovery, and cross-worktree locking.
