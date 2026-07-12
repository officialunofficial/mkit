# ARCHITECTURE — mkit code map

Status: **Informative**. Audience: contributors and integrators who
need to find where something lives and how the pieces connect.

This document is the index. Normative shape lives in `SPEC-*.md`.

---

## 1. Workspace layout

The Rust workspace lives under `rust/`. Crate boundaries match
responsibility boundaries — there is no "common" or "utils" crate.

| Crate                          | Path                                  | Purpose                                                                |
|--------------------------------|---------------------------------------|------------------------------------------------------------------------|
| `mkit-core`                    | `rust/crates/mkit-core/`              | Object store, packs, refs, index, worktree, ignore, repo lock, ops, signing, protocol framing |
| `mkit-attest`                  | `rust/crates/mkit-attest/`            | JCS canonical JSON, in-toto v1 Statement, DSSE envelope, signers, verifiers |
| `mkit-keystore`                | `rust/crates/mkit-keystore/`          | Key vault interface and backends (`specs/SPEC-KEYSTORE.md`)                  |
| `mkit-git-bridge`              | `rust/crates/mkit-git-bridge/`        | Git import/export bridge incl. fork mode (`specs/SPEC-GIT-BRIDGE.md`)        |
| `mkit-rpc`                     | `rust/crates/mkit-rpc/`               | Shared stdio framing for subprocess protocols (`specs/SPEC-RPC.md`)          |
| `mkit-transport-memory`        | `rust/crates/mkit-transport-memory/`  | In-process transport, used by tests                                    |
| `mkit-transport-file`          | `rust/crates/mkit-transport-file/`    | Local-filesystem transport, atomic CAS via `link(2)` on POSIX          |
| `mkit-transport-http`          | `rust/crates/mkit-transport-http/`    | reqwest + rustls transport with bearer auth and `If-Match` CAS         |
| `mkit-transport-s3`            | `rust/crates/mkit-transport-s3/`      | Hand-rolled SigV4 transport (R2 + S3-compatible)                       |
| `mkit-transport-ssh`           | `rust/crates/mkit-transport-ssh/`     | Spawns system `ssh(1)`; framed protocol over stdio                     |
| `mkit-transport-enc`           | `rust/crates/mkit-transport-enc/`     | `mkit+enc://` no-OpenSSH encrypted transport (`specs/SPEC-TRANSPORT-ENC.md`) |
| `mkit-cli`                     | `rust/crates/mkit-cli/`               | The `mkit` binary; thin glue over the library crates                   |
| `mkit-wasm`                    | `rust/crates/mkit-wasm/`              | WASM bindings for browsers and Cloudflare Workers                      |
| `mkit-fuzz`                    | `rust/fuzz/`                          | cargo-fuzz harnesses (`docs/FUZZ.md`)                                  |
| `mkit-sign-file` (contrib)     | `contrib/signers/mkit-sign-file/`     | Reference external signer; protocol conformance baseline               |
| `mkit-sign-se` (contrib)       | `contrib/signers/mkit-sign-se/`       | Apple Secure Enclave signer (Swift / CryptoKit)                        |
| `mkit-sign-tpm` (contrib)      | `contrib/signers/mkit-sign-tpm/`      | TPM 2.0 P-256 signer (Linux/Windows)                                   |
| `mkit-sign-ctap` (contrib)     | `contrib/signers/mkit-sign-ctap/`     | FIDO2/WebAuthn roaming-authenticator signer                            |

The `contrib/signers/*` crates form a separate sibling Cargo
workspace under `contrib/signers/` — they are **not** members of the
`rust/` workspace (out-of-tree members break release-plz publishing).
They share package metadata, lint config, and dependency pins by
inheriting from `contrib/signers/Cargo.toml`, and they are not part of
the `mkit` binary's link graph. They communicate over the protocol
defined in `specs/SPEC-EXTERNAL-SIGNER.md`.

---

## 2. Data flow: object → pack → ref → transport

```
write path                                read path
==========                                =========

bytes                                     transport
  │                                         │
  ▼                                         ▼
chunker (FastCDC)                         pack reader
  │   SPEC-FASTCDC                          │   SPEC-PACKFILE
  ▼                                         ▼
object encoder                            object decoder + verify
  │   SPEC-OBJECTS §2 prologue              │   BLAKE3 verify on read
  ▼                                         ▼
content-addressed store                   refs
  │   .mkit/objects/<dd>/<hex62>            │   SPEC-REFS
  ▼                                         ▼
pack writer                               worktree materialize
  │   SPEC-PACKFILE                          │   symlink containment
  ▼                                         ▼
transport                                 user
  └─── SPEC-TRANSPORT 7-verb wire ──────────┘
```

Every stage validates the previous stage's output. Decoders refuse
oversized allocations; the FastCDC chunker is fully deterministic
(seed `MKITFCDC`); object readers re-hash bytes before returning.

---

## 3. Object identity: the merkelization break

Most object types keep flat content addressing: the object ID is
BLAKE3 of the serialized bytes. `Tree` and `ChunkedBlob` are the
exception. Their ID is the root of a domain-bound Binary Merkle Tree
(BMT) built over their parts &mdash; one leaf per entry for a `Tree`, or a
metadata leaf plus one leaf per chunk for a `ChunkedBlob`. The
construction is normative in `docs/specs/SPEC-MERKLE-OBJECTS.md`; the
decision record is `docs/adr/0001-merkelize-chunkedblob-and-tree.md`.

The payoff is proof, not just storage. Because the ID is a Merkle
root, mkit can prove that one chunk or entry belongs to an object
without shipping the whole object, and it can verify the
completeness of a partial fetch structurally instead of by trust.

The cost is that a `Tree`'s ID feeds its `Commit`'s ID, which feeds
every ref built on top of it. Changing how `Tree` and `ChunkedBlob`
get their IDs re-addresses an entire history, not only the objects
that use the new scheme. mkit shipped this change before 1.0 under a
**no-migration** policy: `ObjectStore::open` checks a mandatory
`.mkit/format` repo marker (`bmt-v1`) and rejects any repository
written under the old flat-hash scheme with `IncompatibleRepoFormat`,
rather than silently mis-reading its trees. mkit ships no tool that
translates a pre-merkle repository forward; the wire format and
`schema_version` did not change, only object identity did.

---

## 4. Attestation flow

Attestations are a separate resource class from objects. A commit
without attestations and a commit with five are indistinguishable
at the commit layer.

```
predicate JSON  ── caller-supplied
       │
       ▼
in-toto v1 Statement   (subject = commit BLAKE3, predicateType = URI)
       │   SPEC-ATTESTATIONS §4.2
       ▼
JCS canonical bytes    (RFC 8785; mkit-attest hand-rolled writer)
       │
       ▼
PAE("application/vnd.in-toto+json", payload)
       │   SPEC-ATTESTATIONS §2.1
       ▼
Signer ────► sig bytes        Signer is one of:
       │                        - repo-key  (Ed25519, .mkit/keys/default.key)
       │                        - external  (subprocess; SPEC-EXTERNAL-SIGNER)
       │                        - sigstore-keyless (Fulcio/Rekor; planned)
       ▼
DSSE envelope ─► JCS ─► BLAKE3 → attestation id
       │
       ▼
.mkit/attestations/<commit-hex>/<att-id>.dsse
       │
       ▼
transport (OP_UPLOAD_ATTESTATION / DOWNLOAD / LIST)
```

`mkit verify-attest` walks the envelope, dispatches each signature
to a verifier keyed on `keyid`, and consults trust roots from
`$XDG_CONFIG_HOME/mkit/trust-roots.toml` (see
`THREAT-MODEL.md` §5).

---

## 5. External signer protocol

The contract is `docs/specs/SPEC-EXTERNAL-SIGNER.md` (Protocol v1, v1.1
adds optional WebAuthn wrapping). Shape:

```
mkit attest ──► spawn binary at attest.external_signer_path
            ──► stdin:  one-line JSON {"pae_base64": …, "algorithm": …}
            ──► stdout: one-line JSON {"keyid": …, "sig_base64": …}
            ──► exit 0 on success
```

Argv comes from `attest.external_signer_args` (user-scoped config —
see `THREAT-MODEL.md` §4) or per-invocation flags. Every reference
signer in `contrib/signers/` is a conformance test for this
contract.

---

## 6. Where to start reading

Pick the closest match.

### "I'm modifying the parser for an on-disk object."
Start at `rust/crates/mkit-core/src/serialize.rs`, then read
`docs/specs/SPEC-OBJECTS.md`. Update the matching golden vector under
`rust/tests/golden/`. If you change the wire shape, version it.

### "I need to understand why `ObjectStore::open` rejects a repository."
Read [§3, Object identity: the merkelization break](#3-object-identity-the-merkelization-break),
then `docs/specs/SPEC-MERKLE-OBJECTS.md` for the exact construction. The
rejection is deliberate: the `.mkit/format` marker gates a pre-1.0,
no-migration break, not a bug.

### "I'm adding a new transport."
Start at `rust/crates/mkit-core/src/protocol.rs` for the `Transport`
trait, then read `docs/specs/SPEC-TRANSPORT.md` for the verb set. Use
`mkit-transport-memory` as the smallest implementation reference.

### "I'm adding a new signer algorithm or implementation."
For an in-tree algorithm, edit `mkit-attest`'s `Algorithm` enum and
the verifier dispatch. For an out-of-tree signer (HSM, KMS, hardware
token), implement `docs/specs/SPEC-EXTERNAL-SIGNER.md` and ship a binary —
see `contrib/signers/mkit-sign-file/` for a minimal example.

### "I'm changing the wire format."
Bump the spec version in the relevant `docs/specs/SPEC-*.md`, write a
new golden vector alongside the old one, and gate the new shape
behind a version field. Do not delete the old vector until a major
release window.

### "I'm changing key handling, signing, or trust roots."
Read `docs/THREAT-MODEL.md` first. Crypto and key-handling changes
require a second reviewer per `CONTRIBUTING.md`, plus a CHANGELOG
entry under `### Security` and a note on which threat-model section
the change affects.

---

## 7. Cross-references

- `specs/SPEC-OBJECTS.md` — on-disk object format
- `specs/SPEC-MERKLE-OBJECTS.md` &mdash; `Tree`/`ChunkedBlob` BMT-root addressing
- `adr/0001-merkelize-chunkedblob-and-tree.md` &mdash; why object identity moved to a Merkle root
- `specs/SPEC-PACKFILE.md` — packfile wire format
- `specs/SPEC-DELTA.md` — delta encoding
- `specs/SPEC-FASTCDC.md` — content-defined chunking
- `specs/SPEC-REFS.md` — ref names, CAS variants
- `specs/SPEC-INDEX.md` — repo-local index
- `specs/SPEC-TRANSPORT.md` — seven-verb wire protocol
- `specs/SPEC-SIGNING.md` — commit / remix signing
- `specs/SPEC-ATTESTATIONS.md` — DSSE + in-toto v1
- `specs/SPEC-EXTERNAL-SIGNER.md` — external signer subprocess protocol
- `SSH-SECURITY.md` — SSH trust model (informative)
- `THREAT-MODEL.md` — security boundaries (informative)
- `FUZZ.md` — fuzz harness conventions
