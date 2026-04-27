---
spec: SPEC-ATTESTATIONS
version: 1
status: draft
audience: implementers and integrators producing or verifying native mkit attestations (in-toto v1 + DSSE)
---

# SPEC-ATTESTATIONS — mkit v1 attestation format

Status: **Draft**. This document defines a native attestation primitive
for mkit: the on-disk layout, the wire envelope, the signing contract,
the CLI, and the transport additions. It supersedes `docs/NOTARY.md`
(removed in the same commit series that implements this spec).

Scope: everything about how mkit produces, stores, transports, and
verifies an attestation about a commit. **Not** in scope: what an
attestation *means* — that's the business of the predicate-type URI,
which is chosen by whoever makes the claim (mkit itself, Makechain,
GitHub, a user's build server, etc.).

---

## 1. Design constraints

1. **Content-addressed, same shape as everything else in mkit.** An
   attestation has a stable hash; the hash is the on-disk name; the
   transport carries bytes by hash.
2. **Standards-compliant envelope.** The signed bytes MUST be consumable
   by any off-the-shelf tool that understands the format — today that
   means Sigstore `cosign`, GitHub `gh attestation verify`, the SLSA
   verifier, and any in-toto v1 consumer. No mkit-specific framing
   around the signed bytes.
3. **Multi-signature native.** One attestation envelope MAY carry
   signatures from multiple independent signers (repo-owner,
   reviewer, CI build bot, settlement service). Each signature verifies
   independently against its own trust root.
4. **Predicate-agnostic.** mkit never parses the `predicate` body. It
   only validates that the envelope is well-formed and at least one
   signature verifies.
5. **No external runtime dep.** Canonical JSON + DSSE + base64 +
   BLAKE3/Ed25519 are all in-tree, per the project's zero-deps policy
   (`docs/release/SUPPLY-CHAIN.md`).

---

## 2. Format stack

```
DSSE envelope                 ← signed container (RFC-quality)
  payload = in-toto v1 Statement (JCS-canonical JSON)
                              ← says "I assert <predicate> about <subject>"
  payloadType = "application/vnd.in-toto+json"
  signatures[] = { keyid, sig }
                              ← one or more; each verified independently
```

- **DSSE** is the [Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
  protocol v1. mkit implements it as written, no extensions.
- **in-toto Statement** is [in-toto v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
- **JCS** is [RFC 8785 JSON Canonicalisation Scheme](https://www.rfc-editor.org/rfc/rfc8785).
- **Base64** is standard base64 (RFC 4648 §4), padded.
- **Hash** is BLAKE3, consistent with `SPEC-OBJECTS.md`.
- **Signature** is Ed25519, consistent with `SPEC-SIGNING.md` §1 —
  other algorithms are possible via the `Signer` trait (§6) but the
  built-in repo-key signer is Ed25519.

### 2.1 Pre-Authentication Encoding (PAE)

DSSE signs a canonical encoding of `payloadType` + `payload`, not the
payload alone. Per the DSSE spec:

```
PAE(type, payload) =
    "DSSEv1"
    || SP || ASCII(len(type))   || SP || type
    || SP || ASCII(len(payload)) || SP || payload
```

Where `len(x)` is the decimal-ASCII length of the UTF-8 bytes of `x`
and `SP` is a single ASCII space (0x20). mkit signs `PAE(type, payload)`
directly — no further hashing wrapper. (The Ed25519 code path already
pre-hashes with BLAKE3 at a lower level; see §7.)

---

## 3. On-disk layout

```
.mkit/
  attestations/
    <commit-hash-hex>/                      ← one directory per subject
      <attestation-id-hex>.dsse              ← one DSSE envelope per file
```

- `<commit-hash-hex>` — the 64-char lowercase hex of the commit's
  BLAKE3 hash. Directory is created on first attestation.
- `<attestation-id-hex>` — the 64-char lowercase hex of
  `BLAKE3(envelope-bytes)` where the bytes are the serialised DSSE
  envelope (§4). Makes the filename deterministic from the envelope
  contents, so reposting an identical attestation is idempotent.
- File contents — UTF-8 JSON bytes of the DSSE envelope (§4). **No
  trailing newline.** The attestation file ID is `BLAKE3(file_bytes)`
  hex, so any trailing whitespace would change the ID and break the
  content-addressing invariant. Implementations that want to append `\n`
  for human-readable viewing MUST compute the ID over the unpadded bytes
  first.

There is no index file, no central manifest. `ls .mkit/attestations/<commit-hash>/`
lists every attestation attached to that commit. This is the same
discoverability model as `refs/`.

### 3.1 Relationship to objects/

Attestations are NOT objects in the `objects/` tree. They are a
separate resource class with their own transport verb (§8). Rationale:

- An attestation is *about* a commit; it doesn't participate in the
  DAG. Putting it under `objects/` would imply Merkle-inclusion which
  would be wrong — two repos with the same commit hash should be able
  to carry different attestations.
- Attestations arrive asynchronously (a settlement service attests
  hours after a commit is pushed). Fetching an old commit should not
  require fetching every attestation ever added.

---

## 4. Envelope format

### 4.1 DSSE envelope JSON

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(statement_json)>",
  "signatures": [
    { "keyid": "<signer-identifier>", "sig": "<base64(sig_bytes)>" }
  ]
}
```

- Fields appear in the order above. JCS ensures bit-exactness.
- `payload` is base64-encoded UTF-8 of the in-toto Statement JSON (§4.2).
- `signatures` is a non-empty array. Order is append-only; new
  signatures go at the end.
- `keyid` is an arbitrary string. Conventions in §6.3.

### 4.2 in-toto v1 Statement body

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "<optional-human-readable-string>",
      "digest": { "blake3": "<commit-hash-hex>" }
    }
  ],
  "predicateType": "<uri-identifying-the-predicate>",
  "predicate": { ... arbitrary JSON, predicate-type's own schema ... }
}
```

- `subject[0].digest.blake3` is the commit hash. Additional subjects
  MAY appear (e.g. a file within the commit's tree); implementations
  MUST NOT require them.
- `predicateType` is the URI that tells a consumer how to interpret
  `predicate`. §6.2 lists the known types.
- `predicate` is opaque to mkit. Serialised per the predicate type's
  own spec; mkit pipes bytes through.

### 4.3 Canonicalisation

Both the outer DSSE envelope and the inner Statement are serialised
via RFC 8785 JCS. This makes `<attestation-id>` (hash of envelope
bytes) a stable function of the logical content. Implementation rules:

- UTF-8 throughout.
- Object members sorted by UCS-2 codepoint on the key.
- Numbers serialised per JCS §3.2.2 (no trailing zeros, lowercase
  exponent, no `+` on positive exponents).
- Strings per JCS §3.2.3 (short-form escapes, `\uXXXX` only for
  control chars).
- No trailing whitespace; no trailing newline. The bytes written to disk
  are the bytes hashed for the attestation ID (§3) — no padding is
  appended.

The JCS writer lives in the `mkit-attest` crate. It is restricted to
the JSON subset used by DSSE + in-toto (string, number as integer,
bool, null, object, array) — no floating-point support, no
JSON-number-that-is-really-a-u64-literal shenanigans.

---

## 5. Attestation lifecycle

### 5.1 Create

1. User or service constructs a predicate (arbitrary JSON).
2. mkit builds the in-toto Statement (§4.2) with the commit hash as
   subject and the caller-supplied `predicateType` + `predicate`.
3. Statement is JCS-canonicalised; bytes become the envelope payload.
4. `Signer.signDsse(PAE(payloadType, payload))` is called once per
   configured signer; signatures are collected.
5. Envelope assembled (§4.1), JCS-canonicalised, BLAKE3-hashed for
   the attestation id.
6. Envelope written to `.mkit/attestations/<commit>/<att-id>.dsse`.

### 5.2 Add signature

1. Read existing envelope by `<att-id>`.
2. Decode payload, re-encode via JCS (identity if the envelope was
   well-formed), build PAE.
3. New signer produces its signature over the PAE; append to
   `signatures[]`.
4. Re-serialise envelope, compute new `<att-id-new>`, write new file.
   Old file is NOT removed (two envelopes now differ by signer set).

Co-signing produces a new attestation id because the envelope bytes
differ; this is deliberate — it means "revoke the old one by ignoring
it" is always achievable.

### 5.3 Verify

For each envelope attached to the commit:

1. Parse envelope; reject if not JCS-canonical, if `payloadType` is
   not `application/vnd.in-toto+json`, or if `signatures[]` is empty.
2. Decode payload; parse Statement; reject if `_type` is not the in-toto
   v1 URI, if `subject` is empty, or if no subject's digest matches
   the asked-about commit.
3. For each signature, consult the trust-root registry (§6.3) for the
   `keyid`; if a trust root is known, run its verifier over
   `PAE(payloadType, payload) + sig`. An envelope verifies if **at
   least one** signature verifies against a recognised trust root.
4. Return a per-signer result list to the caller. `mkit attest verify`
   exits 0 iff at least one envelope per commit has at least one
   verifying signature.

There is no revocation list. Revocation is: stop trusting the `keyid`.
Transparency-log-backed signatures (§6.2) solve this differently by
binding signatures to timestamps.

---

## 6. Signers, trust roots, and predicate types

### 6.1 `Signer` trait

The `Signer` trait has two methods:

- `keyid() -> String` — identifies which trust root verifies this
  signer's output.
- `sign_dsse(pae: &[u8]) -> Vec<u8>` — signs the DSSE PAE. Implementation
  may prompt, network-call, subprocess, etc. Returns raw signature bytes.

Verification is symmetric but NOT attached to the same trait, because
the verifier often has no knowledge of how the signature was produced
(e.g. for a Sigstore-keyless signature the verifier is Fulcio's cert
chain, which no signer owns). Verifiers dispatch on `keyid` (§6.3).

### 6.2 Built-in signers

mkit ships three. Each is opt-in; the CLI picks the signer via
`--signer` flag or the `attest.signer` config key.

| Signer name | What it signs with | Where the trust root lives |
|---|---|---|
| `repo-key` (default) | Ed25519, the existing `.mkit/keys/default.key` | The `signer` field already stored on commits. |
| `sigstore-keyless` | Ephemeral Fulcio cert, OIDC identity | Rekor + Fulcio (same as the release workflow). |
| `external` | Subprocess — JSON-over-stdin/stdout to a caller-supplied binary | Whatever the external process's trust model is. |

`external` is the extension point Makechain, a future blockchain
attestor, or an internal tool wraps. The full wire contract —
invocation, request/response JSON, error semantics, size caps,
timeout, determinism, versioning — is specified normatively in
[**`SPEC-EXTERNAL-SIGNER.md`**](./SPEC-EXTERNAL-SIGNER.md). Protocol
version is **v1**; that document is the source of truth for any new
signer implementation, and the multi-algorithm `algorithm` field
added in phase-1 of the Rust port lives there rather than being
re-specified here.

TL;DR for readers who just want the shape:

```
stdin   (one-line JSON):  {"pae_base64": "...", "algorithm": "ed25519|secp256k1|p256"}
stdout  (one-line JSON):  {"keyid": "...", "sig_base64": "..."}
exit 0  on success, non-zero on error (stderr surfaces to the user).
```

The binary path comes from `attest.external_signer_path` in
`.mkit/config`. A reference implementation lives at
`contrib/signers/mkit-sign-file/`.

**Signer argv.** The subprocess is spawned with an optional argv
vector in addition to the stdin JSON. By default that vector is
empty (backward-compatible with pre-argv mkit). There are three
ways to populate it, each overriding the previous:

1. `attest.external_signer_args` in `.mkit/config` — a pipe-separated
   list (`sign|--tag|prod`). Pipe instead of comma because the
   multi-sig spec already uses `,` as its key=value separator.
2. `--external-signer-arg <V>` on `mkit attest`, repeatable. When
   any instance appears, the collected values REPLACE (not append
   to) the config value — per-invocation override for "sign with
   tag X just this once."
3. `args=<a>|<b>|<c>` on `--additional-signer` for the multi-sig
   envelope — see §6.2.1 below.

Every token is passed verbatim to `Command::args` — no shell
interpolation, no splitting on whitespace. This closes the gap
where a signer that wanted subcommand shape (`mkit-sign-se sign
--tag prod`) had to be wrapped in a shell script that hardcoded
the tag, blocking multi-key workflows.

#### 6.2.1 Multi-sig spec: `args=` clause

`mkit attest --additional-signer` takes a comma-separated
`key=value` spec. The recognised keys are:

| Key         | Meaning                                                    |
|-------------|------------------------------------------------------------|
| `algorithm` | `ed25519` / `secp256k1` / `p256`. Required.                |
| `signer`    | `repo-key` / `external`. Required.                         |
| `path`      | Overrides key path (repo-key) or binary path (external).   |
| `args`      | Pipe-separated argv for external signers only (optional).  |

Example:

```
mkit attest --additional-signer \
  "algorithm=p256,signer=external,path=/usr/local/bin/mkit-sign-se,args=sign|--tag|demo"
```

`|` is used inside `args=` because `,` is the outer separator.
When `args=` is present it overrides `attest.external_signer_args`
for this signer only; absent means "fall through to config."

### 6.3 `keyid` conventions

No hard format — it's free-form UTF-8. But strongly recommended:

- `repo-key` → `blake3:<32-hex-of-pubkey>`.
- Sigstore keyless → `sigstore:<cert-san>` (e.g.
  `sigstore:https://github.com/user/repo/.github/workflows/release.yml@refs/tags/v1`).
- External → whatever the external signer returns; by convention
  scheme-prefixed (`makechain:0x…`, `x509:<spki-hash>`, etc.).

The keyid is purely a dispatch key into the verifier registry. It is
NOT authoritative — the signature itself is the only thing that
proves identity.

### 6.4 Predicate types — conventions, not requirements

mkit knows about zero predicate types and validates none of them.
Ecosystem conventions to encourage (non-normative, for users to opt
into):

- `https://slsa.dev/provenance/v1` — SLSA build provenance.
- `https://in-toto.io/attestation/vuln/v0.1` — vuln-scan results.
- `https://mkit.io/predicate/review/v1` — code review sign-off. *[to
  be defined in `docs/PREDICATE-REVIEW.md` if we actually ship it.]*
- Third-party (e.g. `https://makechain.net/settlement/v1`) — entirely
  opaque to mkit.

---

## 7. Integration with existing mkit primitives

### 7.1 Commits

No change to the commit object format. An attestation is a separate
resource; a commit with zero attestations and a commit with five
attestations are indistinguishable at the commit layer.

### 7.2 Signing code (`SPEC-SIGNING.md`)

The DSSE signer for `repo-key` reuses `std.crypto.sign.Ed25519` and
the same `.mkit/keys/default.key`. It signs the DSSE PAE per §2.1 —
note this is a DIFFERENT signed-bytes domain from commit signing:

```
COMMIT_DOMAIN       = "mkit.commit\x00"      (SPEC-SIGNING §2)
REMIX_DOMAIN        = "mkit.remix\x00"       (SPEC-SIGNING §2)
DSSE signing        = "DSSEv1 ..." (PAE, §2.1)
```

The PAE prefix `"DSSEv1 "` cannot collide with either domain prefix
(no `\x00` byte, different leading bytes). Cross-domain signature
confusion (SPEC-SIGNING §2's R-17) is therefore extended to cover
attestations with no additional work.

### 7.3 Transport

SPEC-TRANSPORT v1 gains **two** new verbs:

```
OP_UPLOAD_ATTESTATION    = 0x08
OP_DOWNLOAD_ATTESTATION  = 0x09
OP_LIST_ATTESTATIONS     = 0x0A
```

(Opcodes chosen to avoid collision with existing verbs up to 0x07,
plus OP_CLOSE at 0xFF.) Semantics mirror the pack ops:

- `UPLOAD_ATTESTATION`: `[32-byte commit hash] [envelope bytes]`.
  Server stores at `.mkit/attestations/<commit>/<blake3(env)>.dsse`.
- `DOWNLOAD_ATTESTATION`: `[32-byte att-id]` → returns envelope bytes.
- `LIST_ATTESTATIONS`: `[32-byte commit hash]` → returns a count +
  sorted list of `<att-id>` hashes.

`mkit push` uploads every attestation under the pushed commits;
`mkit pull` / `mkit fetch` download them. Transport protocols that
predate attestations (e.g. a pre-0.3 server) return
`STATUS_UNSUPPORTED` for the new opcodes; the client degrades to
attestation-less pull with a `warning:` line on stderr.

## 8. CLI surface

```
mkit attest <commit> --predicate-type <uri> --predicate <file.json>
                     [--signer <name>]
                     [--add-signature <att-id>]
    Create a new attestation or add a signature to an existing one.

mkit attest verify <commit> [--require-predicate <uri>] [--require-signer <keyid>]
    Verify at least one attestation on <commit>. Exits 0 iff passed.

mkit attest ls <commit>
    List attestations attached to a commit.

mkit attest show <att-id>
    Pretty-print an envelope (decoded payload + per-signer keyid).

mkit attest rm <att-id>
    Remove an attestation locally. No remote effect.
```

All attestation subcommands are namespaced under `mkit attest` to keep
the top-level help readable. Homebrew/Scoop version-wire format is
unchanged (§`mkit version`).

---

## 9. Config

New keys in `.mkit/config` (validated by `config.validateConfigValue`):

```
attest.signer               = "repo-key" | "sigstore-keyless" | "external"  (default: repo-key)
attest.external_signer_path = /abs/path/to/binary   (required when signer = external)
attest.external_signer_args = a|b|c                 (pipe-separated argv, optional; default empty)
attest.auto_sign_commit     = false                 (default — mkit doesn't auto-attest on commit)
```

`attest.auto_sign_commit = true` attaches a minimal attestation with
`predicateType = https://mkit.io/predicate/commit-signed/v1` (TBD) to
every new commit, so downstream verifiers can require "every commit
has at least a repo-key signature". Opt-in because it doubles the
signing work on every commit.

---

## 10. Security properties (what this does and doesn't protect)

Protects against:
- **Silent substitution of attestation content.** JCS + BLAKE3 content-
  addressing means any byte change produces a new att-id.
- **Cross-domain signature reuse.** DSSE PAE prefix is distinct from
  commit-signing PAE (§7.2).
- **Single-signer compromise.** Multi-sig lets you require N-of-M
  policy at verify time.
- **Predicate-type sprawl.** mkit doesn't parse predicates, so a
  future unsafe predicate-type can't subvert mkit's invariants.

Does NOT protect against:
- **A malicious predicate body.** Interpreting the predicate is the
  consumer's job; mkit just moves the bytes.
- **Revocation timing.** Without a transparency log the
  "when was this signature made" is the signer's claim. Use Rekor
  (Sigstore keyless) for auditable timestamping.
- **A malicious signer impl.** An `external` signer can return
  whatever it wants. The keyid / trust root has to be checked by
  whoever consumes the envelope.

---

## 11. Non-goals

- **Revocation lists.** Out of scope; relies on transparency log or
  signer-level key rotation.
- **Signed predicates as typed structs.** We never parse `predicate`.
- **Automatic SLSA provenance generation.** Separate feature; if
  shipped, it'd be a predicate-type-specific emitter that drives
  `mkit attest` at build time.
- **C2PA / JUMBF support.** Different ecosystem, different shape.
- **Binary-only DSSE variant.** Defeats interop.

---

## 12. Stability

This document is draft through the first implementation PR. Once
shipped in a tagged release, any breaking change to the on-disk
layout or wire envelope requires a version bump and a `SPEC-ATTESTATIONS-v2.md`
(same pattern as `SPEC-OBJECTS`). The DSSE + in-toto bodies are
governed by their upstream specs; mkit tracks those as they evolve.
