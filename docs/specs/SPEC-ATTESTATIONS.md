---
spec: SPEC-ATTESTATIONS
version: 1
status: draft
audience: implementers and integrators producing or verifying native mkit attestations (in-toto v1 + DSSE)
---

# SPEC-ATTESTATIONS &mdash; mkit v1 attestation format

Status: **Draft**. This document defines a native attestation primitive
for mkit: the on-disk layout, the wire envelope, the signing contract,
the CLI, and the transport additions. It supersedes the historical
`docs/NOTARY.md` design note.

Scope: everything about how mkit produces, stores, transports, and
verifies an attestation about a commit. **Not** in scope: what an
attestation *means* &mdash; that's the business of the predicate-type URI,
which is chosen by whoever makes the claim (mkit itself, Makechain,
GitHub, a user's build server, etc.).

This spec is normative for the wire bytes and on-disk layout that the
`mkit-attest` crate produces and the `mkit attest` / `mkit verify-attest`
CLI consume. Items marked **(planned)** are spec'd here for forward
compatibility but are not implemented in the current `mkit-attest`
crate or CLI; consumers MUST NOT rely on them.

---

## 1. Design constraints

1. **Content-addressed, same shape as everything else in mkit.** An
   attestation has a stable hash; the hash is the on-disk name; the
   transport carries bytes by hash.
2. **Standards-compliant envelope.** The signed bytes MUST be consumable
   by any off-the-shelf tool that understands the format &mdash; today that
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
5. **Minimal external dep surface.** JCS, DSSE PAE, BLAKE3 hashing, and
   the on-disk store are hand-rolled in `mkit-attest`. `serde_json` is
   used **only** to (a) parse-and-validate a caller-supplied predicate
   body as a JSON object before pass-through, and (b) extract the
   `subject[].digest.blake3` field on the verify path. The canonical
   encoder never goes through `serde_json::to_string` &mdash; see §4.3. `sha2`
   is an unconditional dependency (not feature-gated): every subject
   carries a `sha256` digest alongside `blake3` (§4.2) regardless of
   which signing-algorithm features are compiled in, so external
   consumers (cosign, `gh attestation verify`, the SLSA verifier) that
   only understand the in-toto/SLSA DigestSet `sha256` key can still
   read mkit's subjects.

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
- **JCS** is [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785).
- **Base64** is standard base64 (RFC 4648 §4), padded.
- **Hash** is BLAKE3, consistent with `SPEC-OBJECTS.md`.
- **Signature algorithms** &mdash; Ed25519 (COSE −19), ECDSA-P-256 (COSE −7,
  ES256), and ECDSA-secp256k1 (COSE −47, ES256K). All three are wired
  through the `Signer` trait (§6) and registered as trust-root
  variants on the verify side. Ed25519 is the built-in repo-key
  default; the others are reached via per-algorithm key paths or the
  keystore signer.

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
directly &mdash; no further hashing wrapper. (Ed25519 internally pre-hashes
with SHA-512 inside `ed25519-dalek`; ECDSA backends pre-hash with
SHA-256. The signer trait always hands the signer the raw PAE; the
signer's algorithm is responsible for any required digest.)

Reference encoding (`mkit-attest::envelope::pae_of`):

```
PAE("hello", "body")  ==  b"DSSEv1 5 hello 4 body"
PAE("t",     "")      ==  b"DSSEv1 1 t 0 "
```

---

## 3. On-disk layout

```
.mkit/
  attestations/
    <commit-hash-hex>/                      ← one directory per subject
      <attestation-id-hex>.dsse              ← one DSSE envelope per file
```

- `<commit-hash-hex>` &mdash; the 64-char lowercase hex of the commit's
  BLAKE3 hash. Directory is created on first attestation.
- `<attestation-id-hex>` &mdash; the 64-char lowercase hex of
  `BLAKE3(envelope-bytes)` where the bytes are the serialized DSSE
  envelope (§4). Makes the filename deterministic from the envelope
  contents, so reposting an identical attestation is idempotent.
- File contents &mdash; UTF-8 JSON bytes of the DSSE envelope (§4). **No
  trailing newline.** The attestation file ID is `BLAKE3(file_bytes)`
  hex, so any trailing whitespace would change the ID and break the
  content-addressing invariant.
- Single-envelope size cap: **1 MiB** (`store::MAX_ENVELOPE_SIZE`).
  Multi-signer envelopes in practice stay in the low kilobytes; the
  cap exists to bound a malformed read.
- Writes are atomic: a temp file in the same directory is `fsync`ed
  and `rename(2)`d into place, and on Unix the parent directory is
  `fsync`ed after the rename to make the dirent update durable.

There is no index file, no central manifest. `ls .mkit/attestations/<commit-hash>/`
lists every attestation attached to that commit. This is the same
discoverability model as `refs/`.

### 3.1 Relationship to objects/

Attestations are NOT objects in the `objects/` tree. They are a
separate resource class. Rationale:

- An attestation is *about* a commit; it doesn't participate in the
  DAG. Putting it under `objects/` would imply Merkle-inclusion which
  would be wrong &mdash; two repos with the same commit hash should be able
  to carry different attestations.
- Attestations arrive asynchronously (a settlement service attests
  hours after a commit is pushed). Fetching an old commit should not
  require fetching every attestation ever added.

---

## 4. Envelope format

### 4.1 DSSE envelope JSON

JCS-canonical key order is **strictly ascending UCS-2 codepoint**, so
the wire bytes have keys in this exact order:

```json
{
  "payload":     "<base64(statement_json)>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures":  [
    { "keyid": "<signer-identifier>", "sig": "<base64(sig_bytes)>" }
  ]
}
```

- `"payload"` < `"payloadType"` < `"signatures"`, and inside each
  signature object `"keyid"` < `"sig"`. JCS sort is mandatory; the
  encoder builds the object members in this order and the strict
  decoder rejects any envelope whose bytes don't match this exact
  shape.
- `payload` is base64-encoded UTF-8 of the in-toto Statement JSON (§4.2).
- `signatures` is a non-empty array. Order is append-only by
  convention (mkit emits primary signer first, then each
  `--additional-signer` in the order they appeared on argv); the
  envelope encoder preserves the caller-supplied vector order.
- `keyid` is an arbitrary string. Conventions in §6.3.

### 4.2 in-toto v1 Statement body

JCS-canonical key order. Note `predicate` precedes `predicateType`
(by codepoint sort), `_type` is first (`_` = 0x5F sorts before `p` =
0x70), and `subject` is last (`s` = 0x73 > `p`):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": { ... arbitrary JSON, predicate-type's own schema ... },
  "predicateType": "<uri-identifying-the-predicate>",
  "subject": [
    {
      "digest": { "blake3": "<commit-hash-hex>", "sha256": "<commit-hash-hex>" },
      "name": "<optional-human-readable-string>"
    }
  ]
}
```

- Inside each subject entry, `"digest"` precedes the optional
  `"name"`; within `"digest"`, `"blake3"` precedes `"sha256"` (JCS
  codepoint sort). The encoder emits `name` only when set.
- `subject[0].digest` is **mandatory** on both keys: every subject
  carries both a `blake3` digest (mkit's own content-addressing hash)
  and a `sha256` digest of the identical underlying bytes &mdash; never a
  second, independent artifact reference, just an additional name for
  the same one. `sha256` exists because it's the digest algorithm the
  in-toto/SLSA `DigestSet` convention &mdash; and every widely-deployed
  consumer (cosign, `gh attestation verify`, the SLSA verifier) &mdash;
  actually looks for; without it those tools cannot read a mkit
  attestation's subjects at all.
- `subject[0].digest.blake3` is the commit hash. Additional subjects
  MAY appear (for example, a file within the commit's tree); implementations
  MUST NOT require them.
- `predicateType` is the URI that tells a consumer how to interpret
  `predicate`. §6.4 lists ecosystem conventions.
- `predicate` is opaque to mkit. The caller hands the encoder
  already-canonical predicate bytes (a JSON **object**, starting `{`
  ending `}`); they are pass-through verbatim into the enclosing
  Statement's bytes. The encoder rejects predicates that don't parse
  as a JSON object.
- The `mkit attest` CLI defaults to a `{}` predicate body when
  `--predicate-file` is omitted.

### 4.3 Canonicalization

Both the outer DSSE envelope and the inner Statement are serialized
via RFC 8785 JCS. This makes `<attestation-id>` (hash of envelope
bytes) a stable function of the logical content. Implementation rules:

- UTF-8 throughout.
- Object members appear in strictly ascending byte-wise order on the
  key. All keys mkit emits are ASCII, so byte order coincides with
  UCS-2 codepoint order.
- Numbers are restricted to non-negative integers (`u64`). JCS's
  float-serialization rules are deliberately not implemented &mdash; mkit
  never emits a non-integer number in either the envelope or the
  Statement frame. Predicate bodies pass through verbatim and inherit
  whatever number serialization the caller produced.
- Strings per JCS §3.2.3 (short-form escapes for `\"`, `\\`, `\b`,
  `\f`, `\n`, `\r`, `\t`; lowercase `\uXXXX` for the remaining
  control chars `< 0x20`; everything else, including all non-ASCII
  Unicode, emitted verbatim as UTF-8; `/` is NOT escaped).
- No trailing whitespace; no trailing newline. The bytes written to
  disk are the bytes hashed for the attestation ID (§3).

The JCS writer lives in `mkit-attest::jcs`. It is restricted to the
JSON subset used by DSSE + in-toto (string, `u64`, bool, null,
object, array). `serde_json::to_string` is never called on the emit
path &mdash; it does NOT honor JCS sort and number-format rules.
`serde_json` IS used for parsing on the verify side (extract
`subject[].digest.blake3`) and for validating caller-supplied
predicate bodies.

The strict envelope decoder in `mkit-attest::envelope::decode` accepts
**only** the exact byte shape `encode` emits &mdash; no whitespace
tolerance, no key-order flexibility. Third-party DSSE envelopes
written by other tools must be re-canonicalized before mkit's decoder
will accept them. (This is intentional: an mkit producer always
writes through `encode`, so the strict decoder gives the strongest
possible "what you wrote is what came back" guarantee.)

---

## 5. Attestation lifecycle

### 5.1 Create

1. User or service constructs a predicate (arbitrary JSON object).
2. mkit builds the in-toto Statement (§4.2) with the commit hash as
   subject and the caller-supplied `predicateType` + `predicate`.
3. Statement is JCS-canonicalized; bytes become the envelope payload.
4. `Signer.sign(PAE(payloadType, payload))` is called once per
   configured signer (primary `--signer` first, then each
   `--additional-signer` in order); signatures are collected into the
   envelope's `signatures[]` array in that same order.
5. Envelope assembled (§4.1), JCS-canonicalized, BLAKE3-hashed for
   the attestation id.
6. Envelope written to `.mkit/attestations/<commit>/<att-id>.dsse`.

Multi-signature envelopes are produced in a single `mkit attest`
invocation by repeating `--additional-signer` (§8). Any signer
failure aborts the attest with no partial envelope on disk.

### 5.2 Adding signatures after the fact **(planned)**

The current CLI does not support attaching a new signature to an
already-on-disk envelope. The wire format does not preclude this &mdash;
a future tool could decode, append to `signatures[]`, re-encode, and
write under the new `<att-id>` derived from the new bytes &mdash; but no
`mkit attest --add-signature <att-id>` flag exists today. Producers
that need multi-party attestations must collect all signatures at
create time via `--additional-signer`.

If implemented, the new envelope MUST be written under the att-id
derived from its new bytes; the previous-att-id file is NOT
overwritten or deleted, so the two envelopes co-exist on disk.

### 5.3 Verify

For each envelope attached to the commit:

1. Decode envelope bytes via the strict decoder; reject if it doesn't
   match the canonical shape, if `payloadType` is not
   `application/vnd.in-toto+json`, or if `signatures[]` is empty.
2. For each signature, look up the `keyid` in the trust-root
   `Registry` (§6.3). On hit, run the algorithm-specific verifier
   over `PAE(payloadType, payload)` + signature bytes:
   - `TrustRoot::Ed25519PubKey([u8; 32])` &mdash; the SPEC-SIGNING §1
     acceptance predicate (rejects malleability: non-canonical R,
     out-of-range S, non-canonical or low-order A/R).
   - `TrustRoot::P256PubKeySec1(Vec<u8>)` &mdash; ECDSA-P-256/SHA-256 over
     a SEC1-encoded pubkey (33-byte compressed or 65-byte
     uncompressed).
   - `TrustRoot::Secp256k1PubKeySec1(Vec<u8>)` &mdash; ECDSA-secp256k1/
     SHA-256 over a SEC1-encoded pubkey.
   - `TrustRoot::SigstoreCa` &mdash; placeholder; any signature dispatched
     to it surfaces `Reason::UnsupportedTrustRoot`. Real Sigstore
     verification (Fulcio cert chain + Rekor inclusion) is not
     implemented.
3. Each signature returns a typed `Reason`: `Ok`, `UnknownKeyid`,
   `UnknownKeyidPrefix` (keyid prefix not recognized by
   `Algorithm::from_keyid`), `SignatureMismatch`,
   `UnsupportedTrustRoot`, or `AlgorithmNotEnabled` (the algorithm's
   crypto backend was compiled out of this build).
4. The envelope verifies if **at least one** signature returns
   `Reason::Ok`. The caller is also responsible for binding the
   envelope to the commit being asked about &mdash; `mkit-attest` exposes
   `verify::extract_primary_commit_hash` to read the first subject's
   blake3 digest out of the Statement payload for that purpose. A
   signature-valid envelope whose subject digest does not match the
   commit actually being queried MUST NOT be treated as an attestation
   *for that commit* &mdash; the attestation directory name
   (`.mkit/attestations/<commit-hex>/`) is not itself proof of what a
   given envelope attests to, since it is ordinary repo-tree state any
   process with write access to the repo can populate.

**Conformance requirement:** every caller-facing verification entry
point MUST perform the binding check in the previous paragraph itself
&mdash; it MUST NOT be an opt-in step callers can forget. `mkit verify-attest`
(the CLI) already does this correctly: it calls
`extract_primary_commit_hash` and rejects any envelope whose subject
hash does not equal the commit hex the directory is keyed under
(`mkit-cli`'s `verify_attest` command), before considering the
envelope's signature at all. **The WASM binding
(`mkit_wasm::attest::attest_verify`) does not** &mdash; it takes no
commit-hash parameter and returns whether *any* signature verifies,
with no subject-binding check, despite being a public, documented API
surface. That is a real, narrow gap in one entry point, not a property
of `mkit-attest`'s verification model in general. Closing it requires
adding a required commit-hash parameter to `attest_verify` and
performing the same check internally; this document stays **Draft**
until that lands.

The `mkit verify-attest` CLI enumerates every envelope under
`.mkit/attestations/<commit>/`, prints a per-signature verdict, and
exits 0 iff every envelope has at least one verifying signature whose
subject binds to that commit.

There is no revocation list. Revocation is: stop trusting the
`keyid`. Transparency-log-backed signatures would solve this
differently by binding signatures to timestamps; that's future work
gated on a real Sigstore backend.

---

## 6. Signers, trust roots, and predicate types

### 6.1 `Signer` trait

The `Signer` trait (`mkit_attest::Signer`) has three methods:

- `algorithm() -> Algorithm` &mdash; the COSE-tagged signing algorithm
  this signer produces (`Ed25519` / `Secp256k1` / `P256`). Callers
  use this to pick the right verifier path on the receive side
  without reparsing the keyid.
- `keyid() -> Result<String, Error>` &mdash; identifies which trust root
  verifies this signer's output. May fail before the first sign call
  for signers that learn their keyid from the signer process (for example,
  `ExternalSigner` returns `KeyIdNotKnownUntilFirstSign`).
- `sign(pae: &[u8]) -> Result<Vec<u8>, Error>` &mdash; signs the DSSE PAE.
  Implementation may prompt, network-call, subprocess, etc. Returns
  raw signature bytes (the envelope encoder base64s on the way out).

Verification is symmetric but NOT attached to the same trait, because
the verifier often has no knowledge of how the signature was produced
(for example, for a future Sigstore-keyless signature the verifier is
Fulcio's cert chain, which no signer owns). Verifiers dispatch on
`keyid` (§6.3) and the resolved `TrustRoot` variant.

### 6.2 Built-in signers

mkit ships three production signer kinds, plus a scaffold for
Sigstore. Each is opt-in; the CLI picks the signer via `--signer`
flag or the `attest.signer` config key.

| Signer name | What it signs with | Where the trust root lives |
|---|---|---|
| `repo-key` (default) | Ed25519/secp256k1/P-256 over a raw 32-byte secret on disk under `.mkit/keys/` | The corresponding public key, registered by `keyid` in the trust-roots file. |
| `keystore` | A user-scoped `mkit-keystore` key reference (the keystore performs the signing) | The keystore backend's canonical key id. |
| `external` | Subprocess wire conversation per [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md) | Whatever the external signer's trust model is. |
| `sigstore` *(scaffold)* | &mdash; | &mdash; &mdash; `Error::SigstoreNotImplemented` is returned. Not selectable from the CLI factory. |

`repo-key` covers all three algorithms:
- Ed25519 reuses the existing commit-signing keypair at
  `.mkit/keys/default.key` (path is configurable via
  `signing_key`).
- secp256k1 and P-256 each read a raw 32-byte secret from
  `attest.secp256k1_key_path` / `attest.p256_key_path` (defaults
  `.mkit/keys/secp256k1.key`, `.mkit/keys/p256.key`). Neither path
  is auto-generated &mdash; `mkit keygen --algorithm <alg>` must run
  first.

`external` is the extension point an HSM, Secure Enclave, browser-
crypto wallet, Makechain, etc. wraps. The full wire contract &mdash;
invocation, request/response shapes, capability discovery, PIN
prompts, error semantics, size caps, timeout, determinism,
versioning &mdash; is specified normatively in
[**`SPEC-EXTERNAL-SIGNER.md`**](./SPEC-EXTERNAL-SIGNER.md), with the
underlying length-prefixed buffa framing defined in
[`SPEC-RPC.md`](./SPEC-RPC.md). Protocol version is **v1**; that
document is the source of truth for any new signer implementation.

In summary, the wire is length-prefixed `SignerFrame` protobuf
messages (NOT one-line JSON) carrying:

```
parent → child:   Hello { protocol = v1, want_capabilities = true, ... }
child  → parent:  HelloResponse { protocol = v1, capabilities, ... }
parent → child:   SignRequest { algorithm, key_form, key_ref, payload }
child  → parent:  SignResponse { signature, public_key, key_id }
                    OR Error { code, message }
```

The binary path comes from user-scoped `attest.external_signer_path`
and MUST be absolute (relative paths are rejected at construction to
close a `$PATH` resolution race). The child receives the PAE inside
`SignRequest.payload` on stdin &mdash; never on argv.

**Bounded execution.** mkit bounds the whole signer conversation with a
single wall-clock deadline (spawn → request-write → response-read →
stderr-drain → child-exit) and concurrently drains the child's stderr so
a stderr-heavy signer cannot deadlock against a blocked stdout read. On
timeout the child is killed and reaped. The deadline defaults to 120s
(generous for hardware touch/PIN/biometric) and is configurable via the
user-scoped `attest.external_signer_timeout_secs`. See
[SPEC-EXTERNAL-SIGNER §2.1](SPEC-EXTERNAL-SIGNER.md#21-timeout-and-liveness).
WebAuthn assertions are additionally validated against a configurable
ceremony policy (RP-ID, origin, UP/UV, crossOrigin, counter) &mdash; see
[SPEC-EXTERNAL-SIGNER §6.1](SPEC-EXTERNAL-SIGNER.md#61-webauthn-verifier-policy).

**Signer argv.** The subprocess is spawned with an optional argv
vector in addition to the protobuf request on stdin. By default the
vector is empty. There are three ways to populate it, each
overriding the previous:

1. User-scoped `attest.external_signer_args` &mdash; a pipe-separated
   list (`sign|--tag|prod`). Pipe instead of comma because the
   multi-sig spec already uses `,` as its key=value separator.
2. `--external-signer-arg <V>` on `mkit attest`, repeatable. When
   any instance appears, the collected values REPLACE (not append
   to) the config value &mdash; per-invocation override for "sign with
   tag X just this once."
3. `args=<a>|<b>|<c>` on `--additional-signer` for the multi-sig
   envelope &mdash; see §6.2.1 below.

Every token is passed verbatim to `Command::args` &mdash; no shell
interpolation, no splitting on whitespace.

#### 6.2.1 Multi-sig spec: `--additional-signer` clause

`mkit attest --additional-signer` takes a comma-separated
`key=value` spec. The recognized keys are:

| Key         | Meaning                                                    |
|-------------|------------------------------------------------------------|
| `algorithm` | `ed25519` / `secp256k1` / `p256`. Required.                |
| `signer`    | `repo-key` / `external`. Required.                         |
| `path`      | Overrides key path (repo-key) or binary path (external).   |
| `args`      | Pipe-separated argv for external signers only (optional).  |

Keystore-backed signing is available as the primary `attest.signer`.
`--additional-signer` is currently limited to `repo-key` and
`external` until the multi-sig grammar grows a key-ref field for
keystore selection.

Example:

```
mkit attest --additional-signer \
  "algorithm=p256,signer=external,path=/usr/local/bin/mkit-sign-se,args=sign|--tag|demo"
```

`|` is used inside `args=` because `,` is the outer separator.
When `args=` is present it overrides `attest.external_signer_args`
for this signer only; absent means "fall through to config." An
explicit `args=` with no value is a valid "zero argv" override.

### 6.3 `keyid` conventions

Free-form UTF-8. Strongly recommended canonical shapes:

- Ed25519 `repo-key` &mdash; `blake3:<hex>` where `<hex>` is the 64-char
  lowercase hex of `BLAKE3(pubkey_bytes)` (32 bytes → 64 hex chars).
  The full keyid string is 71 bytes long (`blake3:` + 64 hex). The
  legacy `blake3:` prefix is preserved for backward compatibility
  with attestations produced before the multi-algorithm split; the
  verifier maps it to Ed25519 via `Algorithm::from_keyid`.
- secp256k1/P-256 `repo-key` &mdash; `secp256k1:<hex>` / `p256:<hex>` of
  the SEC1-encoded compressed pubkey (33 bytes → 66 hex chars).
- Keystore-backed keys &mdash; whatever the keystore backend returns from
  `KeySigner::keyid()`. Conventionally prefixed by its algorithm.
- External &mdash; whatever the external signer returns in
  `SignResponse.key_id`; by convention scheme-prefixed
  (`x509:<spki-hash>`, `makechain:0x…`, etc.).
- Sigstore keyless **(planned)** &mdash; `sigstore:<cert-san>` (for example,
  `sigstore:https://github.com/user/repo/.github/workflows/release.yml@refs/tags/v1`).

The keyid is purely a dispatch key into the verifier registry. It is
NOT authoritative &mdash; the signature itself is the only thing that
proves identity. `Algorithm::from_keyid` recognizes the prefixes
`ed25519:`, `secp256k1:`, `p256:`, and the legacy `blake3:`;
anything else surfaces `Reason::UnknownKeyidPrefix` on the verify
side.

### 6.4 Predicate types &mdash; conventions, not requirements

mkit knows about zero predicate types and validates none of them.
Ecosystem conventions to encourage (non-normative, for users to opt
into):

- `https://slsa.dev/provenance/v1` &mdash; SLSA build provenance.
- `https://in-toto.io/attestation/vuln/v0.1` &mdash; vuln-scan results.
- `https://github.com/officialunofficial/mkit/spec/predicate/review/v1`
  &mdash; code review sign-off **(planned; not yet defined)**.
- Third-party predicates (for example, a Makechain settlement predicate at
  a yet-to-be-provisioned URI such as
  `tag:github.com,2024:officialunofficial/mkit/settlement/v1`) are
  entirely opaque to mkit.

### 6.5 Trust-roots file

The verify path resolves a `keyid` to a `TrustRoot` variant via a
user-scoped trust-roots file. By default this lives at
`$XDG_CONFIG_HOME/mkit/trust-roots.toml` (typically
`~/.config/mkit/trust-roots.toml`). `mkit verify-attest --trust-roots
<path>` overrides the location.

**An in-repo trust-roots file is REJECTED unless `--trust-roots` is
explicitly passed.** A hostile clone could otherwise ship
`.mkit/attest-trust-roots.toml` listing attacker keys and the verify
loop would print "ok" against attacker-controlled signatures.

Schema (a strict subset of TOML &mdash; the parser is hand-rolled and
recognizes only this exact grammar; unknown keys inside a block are
tolerated and ignored):

```toml
# Repeat one block per trusted key.
[[trust_root]]
keyid      = "ed25519:9f2c7e1a4b6d0358f7a12e9c3d5b8064af731c0e29d4b8f651a3c7e0d9b2f4a6"   # exact match against the keyid carried in the DSSE signature
kind       = "ed25519"             # see table below
pubkey_hex = "3a7c9e1f4b2d6058a9c3e7f1b4d6082a5c9e3f7b1d4602a8c5e9f3b7d1042a6c"         # raw public-key bytes, lowercase hex
```

| `kind`                       | Maps to `TrustRoot` variant  | `pubkey_hex` expects                                |
|------------------------------|------------------------------|-----------------------------------------------------|
| `ed25519`                    | `Ed25519PubKey([u8; 32])`    | exactly 32 bytes (64 hex chars)                     |
| `p256-sec1` or `p256`        | `P256PubKeySec1(Vec<u8>)`    | SEC1: 33 bytes compressed (66 hex) or 65 bytes uncompressed (130 hex) |
| `secp256k1` or `secp256k1-sec1` | `Secp256k1PubKeySec1(Vec<u8>)` | SEC1: 33 bytes compressed (66 hex) or 65 bytes uncompressed (130 hex) |
| anything else                | silently skipped             | &mdash;                                                   |

Missing file ⇒ empty registry ⇒ every signature surfaces
`UnknownKeyid` ⇒ no envelope verifies. The CLI prints a
`note: trust-roots file not found at ...` hint in that case.

---

## 7. Integration with existing mkit primitives

### 7.1 Commits

No change to the commit object format. An attestation is a separate
resource; a commit with zero attestations and a commit with five
attestations are indistinguishable at the commit layer.

### 7.2 Signing code (`SPEC-SIGNING.md`)

The Ed25519 DSSE signer for `repo-key` reuses `ed25519-dalek` and the
same `.mkit/keys/default.key` as commit signing. It signs the DSSE
PAE per §2.1 &mdash; note this is a DIFFERENT signed-bytes domain from
commit signing:

```
COMMIT_DOMAIN       = "mkit.commit\x00"      (SPEC-SIGNING §2)
REMIX_DOMAIN        = "mkit.remix\x00"       (SPEC-SIGNING §2)
DSSE signing        = "DSSEv1 ..." (PAE, §2.1)
```

The PAE prefix `"DSSEv1 "` cannot collide with either domain prefix
(no `\x00` byte, different leading bytes). Cross-domain signature
confusion (SPEC-SIGNING §2's R-17) is therefore extended to cover
attestations with no additional work.

### 7.3 Transport **(planned)**

Push/pull of attestations across the wire is not yet implemented in
any of the `mkit-transport-{file,http,s3,ssh,memory}` backends, and
the SPEC-RPC opcode table does not yet carry attestation verbs.
`mkit push` / `mkit pull` / `mkit fetch` move only the object DAG
today; attestations remain repo-local until a future transport
revision adds them.

When that revision lands it MUST:

- Allow uploading an envelope as `(commit-hash, envelope-bytes)`,
  with the server computing `<att-id> = BLAKE3(envelope-bytes)` and
  writing `.mkit/attestations/<commit>/<att-id>.dsse`.
- Allow downloading by `<att-id>` (returning envelope bytes).
- Allow listing every `<att-id>` attached to a given `<commit>`,
  returning the same sorted-by-att-id order `store::list` produces.
- Degrade cleanly: a pre-attestation-aware server returns whatever
  the SPEC-RPC unsupported-verb status is, and the client emits a
  `warning:` line to stderr and continues without attestations.

Opcode numbers and exact frame shapes will be specified in
`SPEC-RPC` once the wire revision is cut.

---

## 8. CLI surface

```
mkit attest [--commit <hash>]
            [--algorithm ed25519|secp256k1|p256]
            [--signer repo-key|external|keystore]
            [--predicate-type <URI>]
            [--predicate-file <path>]
            [--external-signer-arg <V>]...
            [--additional-signer "<spec>"]...
    Produce a signed DSSE attestation for a commit. Prints the
    att-id (64 hex chars) on success.

mkit verify-attest [--commit <hash>]
                   [--trust-roots <path>]
                   [--algorithm <filter>]
    Verify every attestation attached to a commit. Exits 0 iff every
    listed attestation has at least one verifying signature. The
    --algorithm filter narrows the per-signature display to one of
    ed25519 / secp256k1 / p256; the verdict is unchanged.
```

Defaults:
- `--commit` &mdash; HEAD.
- `--algorithm` &mdash; `attest.default_algorithm` from config, else
  `ed25519`.
- `--signer` &mdash; `attest.signer` from config, else `repo-key`.
- `--predicate-type` &mdash;
  `https://github.com/officialunofficial/mkit/spec/predicate/empty/v1`
  (placeholder; real callers pass their own URI).
- `--predicate-file` &mdash; omitted ⇒ predicate body is `{}`.
- `--trust-roots` &mdash; `$XDG_CONFIG_HOME/mkit/trust-roots.toml`.

The following subcommands appear in earlier drafts but are **not
implemented**:

- `mkit attest verify` &mdash; folded into the top-level `mkit verify-attest`.
- `mkit attest ls` / `show` / `rm` &mdash; list/inspect/delete by
  hand against `.mkit/attestations/<commit>/<att-id>.dsse`.
- `mkit attest --add-signature <att-id>` &mdash; see §5.2; multi-signer
  envelopes must currently be produced in a single invocation.
- `--require-predicate` / `--require-signer` filters on
  `mkit verify-attest` &mdash; the verify command currently exits 0 if
  every envelope verifies under at least one trust-rooted signature,
  without further policy filtering.

---

## 9. Config

Keys in the merged config (`.mkit/config` repo-local + user-scoped
`$XDG_CONFIG_HOME/mkit/config`). Security-sensitive keys are
**user-scoped only**: setting them in repo-local config is rejected
with a stderr warning. See `THREAT-MODEL.md` for the motivation.

```
[attest]
default_algorithm    = "ed25519" | "secp256k1" | "p256"   (user-scoped)
signer               = "repo-key" | "external" | "keystore"  (user-scoped)
external_signer_path = /abs/path/to/binary               (user-scoped; required when signer = external)
external_signer_args = a|b|c                             (user-scoped; pipe-separated argv, optional)
external_signer_timeout_secs = 120                       (user-scoped; whole-conversation deadline, default 120)
secp256k1_key_path   = .mkit/keys/secp256k1.key          (user-scoped; default shown)
p256_key_path        = .mkit/keys/p256.key               (user-scoped; default shown)

[key]                                                    # see SPEC-KEYSTORE
ed25519_ref     = "<backend>:<label>"                    (user-scoped)
secp256k1_ref   = "<backend>:<label>"                    (user-scoped)
p256_ref        = "<backend>:<label>"                    (user-scoped)
```

`signer = "keystore"` signs with the keystore reference selected for
the configured algorithm (`key.<alg>_ref`, falling back to
`key.default_ref`). Repo-local config MUST NOT select `keystore` or
populate any `key.*_ref` &mdash; a hostile clone would otherwise pin the
victim's signing identity to an attacker-chosen key alias.

**`attest.auto_sign_commit` (planned).** Earlier drafts proposed an
"auto-attest every commit with a minimal `commit-signed` predicate"
toggle. This is not implemented; `mkit commit` does not invoke the
attest pipeline today. Producers that want commit-level attestations
must run `mkit attest` explicitly after the commit lands.

---

## 10. Security properties (what this does and doesn't protect)

Protects against:
- **Silent substitution of attestation content.** JCS + BLAKE3 content-
  addressing means any byte change produces a new att-id.
- **Cross-domain signature reuse.** DSSE PAE prefix is distinct from
  commit-signing PAE (§7.2).
- **Single-signer compromise.** Multi-sig lets you require N-of-M
  policy at verify time (callers must implement the N-of-M check
  themselves on top of the per-signature `Reason` results &mdash; the
  envelope verifies as long as *any* signature returns `Ok`).
- **Predicate-type sprawl.** mkit doesn't parse predicates, so a
  future unsafe predicate-type can't subvert mkit's invariants.
- **In-repo trust-roots planting.** `mkit verify-attest` refuses to
  read a trust-roots file under the repo's `.mkit/` directory unless
  the user passes `--trust-roots` explicitly.
- **Ed25519 malleability.** Verify uses `verify_strict` (rejects
  non-canonical R/A and s ≥ ℓ), so honest verifiers reach the same
  verdict on the same signature bytes.

Does NOT protect against:
- **A malicious predicate body.** Interpreting the predicate is the
  consumer's job; mkit just moves the bytes.
- **Revocation timing.** Without a transparency log the
  "when was this signature made" is the signer's claim. Real
  Sigstore-style auditable timestamping is future work.
- **A malicious signer impl.** An `external` signer can return
  whatever it wants. The keyid/trust root has to be checked by
  whoever consumes the envelope.

---

## 11. Non-goals

- **Revocation lists.** Out of scope; relies on transparency log or
  signer-level key rotation.
- **Signed predicates as typed structs.** mkit never parses `predicate`
  beyond "is this a JSON object?" on the produce side.
- **Automatic SLSA provenance generation.** Separate feature; if
  shipped, it'd be a predicate-type-specific emitter that drives
  `mkit attest` at build time.
- **C2PA/JUMBF support.** Different ecosystem, different shape.
- **Binary-only DSSE variant.** Defeats interop.
- **Float number support in JCS.** mkit never emits one.

---

## 12. Stability

This document stays draft while the §5.3 WASM-verification gap remains
open. Once that closes, any breaking change to the on-disk layout or
wire envelope requires a version bump and a `SPEC-ATTESTATIONS-v2.md`
(same pattern as `SPEC-OBJECTS`). The DSSE + in-toto bodies are
governed by their upstream specs; mkit tracks those as they evolve.

Items currently marked **(planned)** &mdash; §5.2 (`--add-signature`),
§7.3 (transport verbs), §8 (`mkit attest ls/show/rm`,
`--require-predicate`/`--require-signer`), §9
(`attest.auto_sign_commit`), §6.4 review predicate URI &mdash; are
forward-compatible additions and will not require a version bump
when implemented.

---

## 13. Invariants

§10 is the authoritative statement of what this format does and does
not protect. This table maps each guarantee to its enforcement point.

| Invariant | Enforced by |
|---|---|
| Any byte change to an envelope yields a new att-id | att-id = `BLAKE3(envelope-bytes)`; JCS makes the bytes a stable function of content (§3, §4.3) |
| Reposting an identical attestation is idempotent | filename derived from the envelope hash (§3) |
| An envelope round-trips only if byte-identical to what `encode` emits | strict decoder: exact key order, no whitespace tolerance (§4.3) |
| A DSSE signature can never be replayed as a commit/remix/tag signature | PAE prefix `"DSSEv1 "` is disjoint from every SPEC-SIGNING domain (§7.2) |
| `keyid` alone never authenticates | keyid is a dispatch key only; trust-root lookup + signature verification decide (§6.3, §5.3) |
| A hostile clone cannot plant trust roots | in-repo trust-roots file rejected unless `--trust-roots` is explicit (§6.5, §10) |
| Missing trust roots fail closed | empty registry ⇒ every signature `UnknownKeyid` ⇒ no envelope verifies (§6.5) |
| A hostile repo cannot redirect signing | `attest.*` signer/key/path keys are user-scoped only (§9) |
| Ed25519 verdicts are identical across honest verifiers | `verify_strict` rejects malleable encodings (§5.3, §10) |
| A malicious predicate body cannot subvert mkit | the predicate is never parsed beyond "is a JSON object" (§1, §10) |
| No partial envelope reaches disk | any signer failure aborts before write; writes are tmp + fsync + rename atomic (§5.1, §3) |
| Malformed reads are bounded | 1 MiB envelope size cap (§3) |

What the format does NOT guarantee &mdash; revocation timing, predicate
semantics, honesty of an external signer &mdash; is enumerated in §10 and is
not restated here.
