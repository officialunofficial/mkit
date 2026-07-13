# ARCHITECTURE &mdash; mkit code map

Status: **Informative**. Audience: contributors and integrators who
need to find where something lives and how the pieces connect.

This document is the index. Normative shape lives in `SPEC-*.md`.

---

## 1. Workspace layout

The Rust workspace lives under `rust/`. Crate boundaries match
responsibility boundaries &mdash; there is no "common" or "utils" crate.

| Crate                          | Path                                  | Purpose                                                                |
|--------------------------------|---------------------------------------|------------------------------------------------------------------------|
| `mkit-core`                    | `rust/crates/mkit-core/`              | Object store, packs, refs, index, worktree, ignore, repo lock, ops, signing, protocol framing |
| `mkit-attest`                  | `rust/crates/mkit-attest/`            | JCS canonical JSON, in-toto v1 Statement, DSSE envelope, signers, verifiers |
| `mkit-keystore`                | `rust/crates/mkit-keystore/`          | Key vault interface and backends (`specs/SPEC-KEYSTORE.md`)                  |
| `mkit-git-bridge`              | `rust/crates/mkit-git-bridge/`        | Git import/export bridge incl. fork mode (`specs/SPEC-GIT-BRIDGE.md`)        |
| `mkit-rpc`                     | `rust/crates/mkit-rpc/`               | Shared stdio framing for subprocess protocols (`specs/SPEC-RPC.md`)          |
| `mkit-transport-memory`        | `rust/crates/mkit-transport-memory/`  | In-process transport, used by tests                                    |
| `mkit-transport-file`          | `rust/crates/mkit-transport-file/`    | Local-filesystem transport, atomic CAS via `link(2)` on POSIX          |
| `mkit-transport-http`          | `rust/crates/mkit-transport-http/`    | reqwest plus rustls transport with bearer auth and `If-Match` CAS         |
| `mkit-transport-s3`            | `rust/crates/mkit-transport-s3/`      | Hand-rolled SigV4 transport (R2 plus S3-compatible)                       |
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
workspace under `contrib/signers/` &mdash; they are **not** members of the
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

## 3. Merkle-root object identity

`Blob`, `Commit`, `Remix`, and `Tag` take their object ID from a flat
BLAKE3 digest of their canonical bytes. `Tree` and `ChunkedBlob` do
not: their ID is the domain-bound root of a Binary Merkle Tree (BMT)
built over their parts &mdash; one leaf per entry for a `Tree`, and a
metadata leaf plus one leaf per chunk for a `ChunkedBlob`. The
construction is normative in `docs/specs/SPEC-MERKLE-OBJECTS.md`; the
vendored BMT lives in `rust/crates/mkit-core/src/merkle.rs`.

A flat digest names exact bytes and nothing more. Deriving the ID
from a Merkle root over the object's parts adds two properties.
Inclusion is provable: a caller holding one chunk of a `ChunkedBlob`,
or one entry of a `Tree`, can prove it belongs to the object without
fetching the rest. Completeness is structural: the store verifies
these two types on read by decoding, recomputing the root, and
comparing it to the ID, so "every child is present, unmodified, and
in order" falls out of the check that already runs on each read
&mdash; no trusted manifest involved. The root is also wrapped in a
per-type domain, so identical leaf streams &mdash; an empty `Tree`
and an empty `ChunkedBlob`, for example &mdash; never share an ID.

The guarantee composes up the object graph. A `Tree`'s entry leaves
bind the IDs of its children, a `Commit` binds its root tree, and
every ref resolves to a commit. Verifying a commit against its ID
therefore verifies every tree, entry, and chunk reachable from it.

`ObjectStore::open` enforces addressing consistency through the
`.mkit/format` repository marker. `ObjectStore::init` writes the
marker with the value `bmt-v1`; `open` requires that same value and
rejects the repository with `IncompatibleRepoFormat` when the marker
is missing or different, rather than misreading objects under the
wrong addressing rule. The marker governs object identity only: the
serialized wire format and the `schema_version` field are independent
of it.

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
Signer ────► sig bytes        Signer is one of the two implemented paths:
       │                        - repo-key  (Ed25519, .mkit/keys/default.key)
       │                        - external  (subprocess; SPEC-EXTERNAL-SIGNER)
       │
       │                      Roadmap, not implemented (`SigstoreSigner`
       │                      returns `Error::SigstoreNotImplemented`):
       │                        - sigstore-keyless (Fulcio/Rekor)
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

Argv comes from `attest.external_signer_args` (user-scoped config &mdash;
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

### "I'm adding a new transport."
Start at `rust/crates/mkit-core/src/protocol.rs` for the `Transport`
trait, then read `docs/specs/SPEC-TRANSPORT.md` for the verb set. Use
`mkit-transport-memory` as the smallest implementation reference.

### "I'm adding a new signer algorithm or implementation."
For an in-tree algorithm, edit `mkit-attest`'s `Algorithm` enum and
the verifier dispatch. For an out-of-tree signer (HSM, KMS, hardware
token), implement `docs/specs/SPEC-EXTERNAL-SIGNER.md` and ship a binary &mdash;
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

- `specs/SPEC-OBJECTS.md` &mdash; on-disk object format
- `specs/SPEC-MERKLE-OBJECTS.md` &mdash; `Tree`/`ChunkedBlob` BMT-root addressing
- `specs/SPEC-PACKFILE.md` &mdash; packfile wire format
- `specs/SPEC-DELTA.md` &mdash; delta encoding
- `specs/SPEC-FASTCDC.md` &mdash; content-defined chunking
- `specs/SPEC-REFS.md` &mdash; ref names, CAS variants
- `specs/SPEC-INDEX.md` &mdash; repo-local index
- `specs/SPEC-TRANSPORT.md` &mdash; seven-verb wire protocol
- `specs/SPEC-SIGNING.md` &mdash; commit / remix signing
- `specs/SPEC-ATTESTATIONS.md` &mdash; DSSE plus in-toto v1
- `specs/SPEC-EXTERNAL-SIGNER.md` &mdash; external signer subprocess protocol
- `SSH-SECURITY.md` &mdash; SSH trust model (informative)
- `THREAT-MODEL.md` &mdash; security boundaries (informative)
- `FUZZ.md` &mdash; fuzz harness conventions
