# mkit-attest

DSSE + in-toto v1 attestations for mkit, with multi-algorithm signers
(Ed25519, secp256k1, P-256) and an RFC 8785 JCS encoder.

The wire format and on-disk layout this crate produces are defined,
normatively, in `docs/specs/SPEC-ATTESTATIONS.md` — any change here must update the
spec in the same PR.

## Layering

- `jcs` — RFC 8785 JSON Canonicalisation writer for the subset of JSON DSSE
  + in-toto need (string, uint, bool, null, array, pre-sorted ASCII-keyed
  object).
- `statement` — in-toto v1 Statement encoder. Predicate bodies are passed
  through as already-canonical bytes; this crate never parses predicates.
- `envelope` — DSSE envelope encoder + strict decoder, PAE, and
  `attestation_id` derivation.
- `signer` — the common `Signer` trait every backend implements.
- `signer_repo_key` — Ed25519 over the repo key (the default signer).
- `signer_external` — drives an external signer subprocess over the
  length-prefixed `buffa`-generated `SignerFrame` wire (see
  `contrib/signers/README.md` and `docs/specs/SPEC-EXTERNAL-SIGNER.md`).

Attestations are stored under `.mkit/attestations/<commit-hash>/<att-id>.dsse`
and are a first-class object type, not a side-channel — see the top-level
README's "Attestations" section for the end-to-end model.
