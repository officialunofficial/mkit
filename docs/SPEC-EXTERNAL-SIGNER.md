# SPEC-EXTERNAL-SIGNER — mkit external signer protocol v1

Status: **Draft** (protocol version `v1`). This document defines the
wire contract between the mkit host process and a user-supplied
external signer binary. Any implementation that follows this spec is
drop-in compatible with the `external` signer selector referenced in
`SPEC-ATTESTATIONS.md` §6.2.

Audience: integrators shipping a signer for a platform mkit does not
ship natively — Apple Secure Enclave, Ledger / Trezor, WebAuthn/CTAP,
MetaMask / EVM wallet bridges, Makechain, HSMs, etc. Reference
implementation: `contrib/signers/mkit-sign-file` (file-based raw key).

---

## 1. Scope

This protocol covers **one thing**: mkit asks an external binary to
produce a DSSE signature over a specific blob (the PAE) under a
specific algorithm, and the binary returns the signature plus a keyid.

In scope:

- Process invocation, I/O framing, lifetimes, and exit-code semantics.
- The request + response JSON shapes.
- Error surface, size limits, timeouts, determinism expectations.
- Protocol versioning.

Out of scope (explicitly):

- Key generation or import. The signer is assumed to already possess
  or have access to the secret.
- User interaction (PIN prompts, biometrics, hardware touch). If a
  signer needs those it handles them itself; mkit only cares about
  the final request/response.
- Transport-level authentication between mkit and the signer. Both
  run under the same user on the same host; OS process isolation is
  the trust boundary.
- Attestation envelope construction. That's §4–§5 of
  `SPEC-ATTESTATIONS.md`; the external signer only handles one signing
  step.

---

## 2. Invocation

mkit spawns the signer as a child process. The binary path comes from
the `attest.external_signer_path` key in `.mkit/config` and **MUST be
absolute** — relative paths are rejected at config-load time to close
a path-search TOCTOU (see `ExternalSigner::new` in
`rust/crates/mkit-attest/src/signer_external.rs`).

Argv and environment:

- **argv[0]**: the binary path as configured.
- **argv[1..]**: empty by default. The host MAY pass additional argv
  tokens verbatim to the child — see SPEC-ATTESTATIONS §6.2 for
  mkit's config + CLI surface (`attest.external_signer_args`,
  `--external-signer-arg`, multi-sig `args=` clause). No shell
  interpolation happens; each host-supplied token is one argv entry.
  Signers SHOULD still accept a zero-argv invocation as a well-defined
  default (e.g. read key from a standard env var or fall back to a
  per-platform default location) so hosts that don't drive argv keep
  working.
- **env**: inherited from mkit unmodified. Signers are free to read
  their own env vars (`MKIT_SIGN_FILE_KEY`, `LEDGER_PATH`, etc.).
- **cwd**: inherited from mkit.
- **stdio**: mkit pipes stdin, stdout, and stderr. No tty.

Lifecycle:

- One request per process. mkit spawns a fresh child for every sign
  call. The signer MUST NOT expect a multi-request session. This
  trades a handful of milliseconds per sign for a dramatically
  simpler state model and lets signers that prompt the user (Ledger,
  Secure Enclave) always start from a clean slate.
- mkit writes the request line, closes the child's stdin, and reads
  stdout until EOF.

Exit codes:

- **0** — success. stdout contains exactly one JSON line (§4).
- **non-zero** — any failure. stderr is captured by mkit and surfaced
  to the user via `Error::ExternalSignerFailed`. stdout SHOULD be
  empty; mkit does not parse it on error paths.

---

## 3. Request format

One line of UTF-8 JSON, terminated by a single `\n`, written to the
child's stdin. mkit closes stdin immediately after the request so the
child sees EOF.

```json
{"pae_base64":"<base64>","algorithm":"ed25519"}
```

Fields (all required in v1):

| Field          | Type   | Meaning                                                          |
|----------------|--------|------------------------------------------------------------------|
| `pae_base64`   | string | RFC 4648 §4 standard base64 (padded) of the DSSE PAE bytes.      |
| `algorithm`    | string | One of `"ed25519"`, `"secp256k1"`, `"p256"`.                     |

Field semantics:

- `pae_base64` decodes to the exact bytes the signer signs. The
  signer MUST NOT re-wrap, re-hash (beyond what the algorithm itself
  requires), or otherwise transform the decoded PAE. Ed25519 signs
  the PAE directly; ECDSA algorithms (`secp256k1`, `p256`) hash the
  PAE with SHA-256 per the algorithm contract.
- `algorithm` is an explicit agreement point. If the signer holds a
  key that cannot produce the requested algorithm, it MUST exit
  non-zero — it MUST NOT silently sign under a different algorithm.

Additional fields MAY appear in future protocol versions and MUST be
ignored by v1 signers.

---

## 4. Response format

One line of UTF-8 JSON, written to the child's stdout, followed by
EOF (trailing `\n` is tolerated but not required).

```json
{"keyid":"p256:04a1b2...","sig_base64":"<base64>"}
```

Fields (all required in v1):

| Field         | Type   | Meaning                                                                  |
|---------------|--------|--------------------------------------------------------------------------|
| `keyid`       | string | Identifier for the key that produced the signature (see §4.1).           |
| `sig_base64`  | string | RFC 4648 §4 base64 of the raw signature bytes (see §4.2).                |

### 4.1 `keyid` conventions

The canonical shape is `<prefix>:<hex-pubkey>` where `<prefix>` is one
of:

- `ed25519` — 32-byte raw Ed25519 public key, lowercase hex (64 chars).
- `secp256k1` — 33-byte SEC1-compressed pubkey, lowercase hex (66 chars).
- `p256` — 33-byte SEC1-compressed pubkey, lowercase hex (66 chars).
- `blake3` — legacy; accepted by the verifier and maps to `ed25519`
  for backward compatibility with pre-multi-algorithm attestations.

Platform-specific prefixes are also permitted:

- `makechain:0x…`
- `webauthn:<credential-id>`
- `sigstore:<subject-alternative-name>`
- `x509:<spki-hash>`

When using a platform-specific prefix, the verifier-side trust-root
registry (SPEC-ATTESTATIONS §6.3) decides how the keyid maps to a
public key. mkit itself does not enforce a shape on the `keyid`
string — it is an opaque dispatch key.

### 4.2 `sig_base64` encoding

The decoded bytes MUST be the raw signature in the shape each
algorithm specifies:

- **ed25519**: 64 bytes. Canonical signature form
  (`verify_strict`-compatible; reject non-canonical R or s ≥ L).
- **secp256k1**: 64 bytes, compact `r ‖ s` big-endian, **low-S
  normalised** (per BIP-146). DER-encoded ASN.1 signatures are NOT
  accepted.
- **p256**: 64 bytes, compact `r ‖ s` big-endian, **low-S normalised**.
  DER is not accepted.

Signers MUST normalise `s` to the low half of the curve order for
ECDSA algorithms; mkit's verifier rejects high-S signatures.

---

## 5. Error handling

A signer reports failure by exiting non-zero. mkit captures both
stdout and stderr up to a 1 MiB cap (§6) and surfaces stderr to the
user as the error message payload in `Error::ExternalSignerFailed`.

Recommended:

- Write a one-line human-readable reason to stderr.
- Leave stdout empty.
- Use distinct non-zero exit codes if the signer wants to distinguish
  user-cancel vs. hardware-locked vs. wrong-algorithm; mkit currently
  treats all non-zero exits uniformly, but follow-on protocol
  versions may surface exit codes separately.

Examples of failure conditions a signer MUST handle:

- Requested `algorithm` doesn't match the key the signer can reach.
- Key file has wrong permissions / is missing / wrong length.
- User declined a biometric or hardware-button prompt.
- Request JSON is malformed or carries unknown fields in a future
  protocol version the signer doesn't speak.

---

## 6. Size limits

- **Request (stdin)**: ≤ 1 MiB. mkit's real requests are a few hundred
  bytes; the cap exists purely as DoS protection.
- **Response (stdout)**: ≤ 1 MiB. Again — real responses are ~200
  bytes; the cap protects against a runaway child.
- **stderr**: ≤ 1 MiB captured by mkit; more is truncated.

Exceeding the stdout cap surfaces as
`Error::ExternalSignerOutputTooLarge`.

---

## 7. Timeout

mkit waits up to **30 seconds** for the child to produce a complete
response and exit. Configurable via
`attest.external_signer_timeout_secs` in `.mkit/config`. Signers that
need longer (hardware signers prompting for user touch, remote HSMs)
MUST either fit within this budget or document the required override.

On timeout mkit kills the child process with SIGKILL-equivalent and
surfaces the failure as `Error::ExternalSignerFailed`.

---

## 8. Determinism

Signers SHOULD be deterministic on `(algorithm, pae)`:

- **Ed25519** is inherently deterministic (RFC 8032).
- **ECDSA** (secp256k1, p256) SHOULD use RFC 6979 deterministic `k`.

Non-deterministic signers (randomised-`k` ECDSA, HSMs that mix fresh
randomness) are **permitted**. Callers of mkit MUST NOT rely on
byte-identical signatures across invocations; the only invariants
they may rely on are (a) the signature verifies and (b) the keyid is
stable.

Golden-vector tests in `rust/crates/mkit-attest/tests/golden_*.rs`
cover the deterministic case. A signer that wants to be re-signable
by an auditor against those vectors MUST implement RFC 6979 for
ECDSA.

---

## 9. Versioning

The protocol version is **v1**. Absent any version marker, v1 is
assumed.

Future protocol versions will add a top-level `"v": 2` (or higher)
field in the request. v1 signers MUST ignore unknown top-level fields
and MUST NOT fail because a future mkit sent extra keys — this is the
forward-compat escape hatch.

If mkit wants to talk a newer protocol, it will:

1. Try the new version first (`"v": 2, …` request).
2. If the signer exits with a documented "unsupported version"
   status, retry with a v1 request.

This negotiation is entirely within mkit; signers only need to look
at `"v"` if they care.

---

## 10. Worked examples

All three examples use the same DSSE PAE for illustration:

```
PAE bytes     : DSSEv1 28 application/vnd.in-toto+json 2 {}
pae_base64    : RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ==
```

### 10.1 Ed25519

Request (stdin):

```json
{"algorithm":"ed25519","pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ=="}
```

Response (stdout):

```json
{"keyid":"ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","sig_base64":"<86 base64 chars>"}
```

- `sig_base64` decodes to 64 bytes.
- `keyid` is `ed25519:` + 64 hex chars = 72-char string.

### 10.2 secp256k1

Request:

```json
{"algorithm":"secp256k1","pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ=="}
```

Response:

```json
{"keyid":"secp256k1:0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","sig_base64":"<86 base64 chars>"}
```

- `sig_base64` decodes to 64 bytes: compact `r ‖ s`, low-S normalised.
- `keyid` is `secp256k1:` + 66 hex chars (SEC1 compressed pubkey).

### 10.3 P-256

Request:

```json
{"algorithm":"p256","pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ=="}
```

Response:

```json
{"keyid":"p256:036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296","sig_base64":"<86 base64 chars>"}
```

- `sig_base64` decodes to 64 bytes: compact `r ‖ s`, low-S normalised.
- `keyid` is `p256:` + 66 hex chars (SEC1 compressed pubkey).

Platform-specific keyid example (Makechain):

```json
{"keyid":"makechain:0xabcdef0123456789...","sig_base64":"<...>"}
```

The verifier side registers the `makechain:...` keyid against its
own trust-root variant; mkit does not need to know the mapping.

---

## 11. Test vectors

The in-tree golden vectors cover every algorithm:

- `rust/crates/mkit-attest/tests/golden_phase8.rs` — Ed25519 over a
  fixed seed + fixed PAE. Third parties can re-sign the same PAE with
  the same seed and compare byte-for-byte.
- `rust/crates/mkit-attest/tests/golden_secp256k1.rs` — secp256k1,
  RFC 6979 deterministic.
- `rust/crates/mkit-attest/tests/golden_p256.rs` — P-256, RFC 6979
  deterministic.

Each file has a fixed 32-byte secret and a fixed PAE literal. A
signer implementation that wants to prove byte-identical compatibility
feeds those into its own signing path and compares against the hex
signature pinned at the top of the file.

---

## 12. Security model

The external signer is **fully trusted** to hold the secret key. mkit
performs no validation beyond:

1. The response parses as the v1 JSON shape.
2. The `sig_base64` has the length the advertised algorithm requires.
3. On the verify side later, the signature verifies against whatever
   public key the caller-side trust-root registry maps `keyid` to.

mkit cannot defend against:

- A signer that refuses to sign (denial of service).
- A signer that signs with an unrelated key and returns a keyid that
  resolves to a trust root the attacker has also poisoned.
- A signer that leaks the secret via a side channel.
- A signer that exfiltrates the PAE contents to a network server.

Operational consequence: users MUST vet the external signer binary
they configure. `attest.external_signer_path` is a code-execution
configuration — treat it with the same care as
`git config core.editor` or a shell-profile hook. The install path
SHOULD be root-owned and on a non-user-writable filesystem where the
threat model warrants it.

Relation to the DSSE / in-toto / verify layers:

- The signature is meaningful only insofar as the verifier trusts the
  keyid. Adding a `keyid` to the trust-root registry is the act that
  grants trust.
- Multi-signature envelopes (SPEC-ATTESTATIONS §5.2) let a policy
  layer require N-of-M signatures, which limits the blast radius of a
  single compromised signer.

---

## 13. Compatibility

- This spec does not change the DSSE envelope format. External
  signers produce one `(keyid, sig)` pair; the envelope builder
  writes it into `signatures[]` per `SPEC-ATTESTATIONS.md` §4.1.
- The v1 wire is the one implemented today by
  `mkit-attest::ExternalSigner`. Prior mkit pre-releases accepted a
  request without an `algorithm` field and defaulted to Ed25519;
  that shape is deprecated and v1 signers SHOULD require the
  `algorithm` key to avoid accidentally signing under the wrong
  algorithm when paired with a future mkit.

---

## 14. Protocol v1.1 — WebAuthn extension

Status: **Draft extension** to v1. Strictly backward-compatible:
a v1 signer that does not emit the new field is a conforming v1.1
signer too; a v1 verifier that does not understand the extension
will (correctly) reject a wrapped signature as a crypto mismatch —
see §14.5.

### 14.1 Motivation

FIDO2 / WebAuthn roaming authenticators (YubiKey, Nitrokey, SoloKey,
platform authenticators behind `navigator.credentials.get`) do NOT
sign arbitrary byte strings. The authenticator firmware always signs:

```text
signature = ECDSA(privkey, authenticatorData || SHA256(clientDataJSON))
```

where `clientDataJSON` is a UTF-8 JSON object containing the caller's
`challenge` as a base64url-no-pad string. Because the authenticator
cannot be reprogrammed, any signer that drives a WebAuthn credential
MUST feed the PAE through the WebAuthn wrapping and then return the
wrapping material to the verifier so the verifier can reconstruct what
was actually signed. This section defines that wrapping.

### 14.2 Response shape

A v1.1 signer MAY include an optional top-level `webauthn` object in
its response. When present, the response has this shape:

```json
{
  "keyid": "p256:<hex>",
  "sig_base64": "<base64(compact r||s)>",
  "webauthn": {
    "authenticator_data": "<base64url, no pad>",
    "client_data_json":   "<base64url, no pad>"
  }
}
```

Semantics when `webauthn` is present:

- `algorithm` (from the request, §3) MUST be `"p256"`. All shipping
  WebAuthn authenticators use ECDSA over NIST P-256; other curves
  are out of scope for v1.1.
- `sig_base64` decodes to a 64-byte compact `r || s`, low-S
  normalised (same as v1 P-256).
- `webauthn.authenticator_data` is the raw `authenticatorData` as
  returned by the authenticator, encoded base64url-no-pad per WebAuthn
  spec convention.
- `webauthn.client_data_json` is the raw UTF-8 bytes of the
  `clientDataJSON` the authenticator signed, encoded base64url-no-pad.
- The signature was produced as:
  `ECDSA(privkey, authenticator_data_raw || SHA256(client_data_json_raw))`.

Semantics when `webauthn` is absent: pure v1 behaviour — the signer
signed `SHA256(pae)` directly and no wrapping is in play.

### 14.3 `clientDataJSON` body

The signer constructs the body itself before handing it to the
authenticator. The body MUST be a UTF-8 JSON object containing at
least:

| Key         | Value                                                               |
|-------------|---------------------------------------------------------------------|
| `type`      | Literal string `"webauthn.get"` (assertions; `webauthn.create` is for enrollment and is NOT accepted on the verify path). |
| `challenge` | `base64url_nopad(pae_bytes)` — this BINDS the WebAuthn ceremony to the DSSE PAE. |
| `origin`    | String identifying the RP — e.g. `"https://mkit.local"`. Not load-bearing for the verify step. |

Additional fields MAY appear (browsers emit `crossOrigin`, some emit
`tokenBinding`, some emit `topOrigin`) and MUST be passed through
unmodified — they contribute to the hash under the signature.

### 14.4 Verifier contract

A v1.1-aware verifier, given a decoded `webauthn` object and the PAE
bytes, MUST:

1. base64url-no-pad decode `authenticator_data` and `client_data_json`.
2. Parse `client_data_json` as UTF-8 JSON; assert it is an object.
3. Assert `type == "webauthn.get"`. The `create` type is a different
   ceremony and MUST NOT be accepted for signature verification.
4. Assert `challenge == base64url_nopad(pae_bytes)` — this is the
   per-payload binding.
5. Reconstruct signed bytes: `signed = authenticator_data ||
   SHA256(client_data_json)`.
6. Verify the 64-byte compact ECDSA signature against the advertised
   P-256 pubkey over `signed`.

Step 4 is the critical security property: without it a replayed
signature from any unrelated WebAuthn ceremony would satisfy the crypto
check. The helper in `mkit-attest` is
`verify_webauthn_wrapping(pae, wrapping, pubkey_sec1, sig_compact)`;
see `rust/crates/mkit-attest/src/webauthn.rs` for the reference
implementation.

### 14.5 Absence semantics and interop

- A v1.0 verifier does not understand the `webauthn` object and
  verifies the signature directly against `SHA256(pae)`. That verify
  MUST fail (the signature was over `auth_data || SHA256(cdj)`, not
  `SHA256(pae)`), surfacing as `Reason::SignatureMismatch`. The
  failure is loud and safe: no wrapping means no verdict.
- A v1.0 signer never emits a `webauthn` object; a v1.1 verifier
  seeing no `webauthn` field behaves exactly as v1.0. This keeps the
  upgrade fully one-sided — deploy new signers first, then new
  verifiers, with no flag day.
- The `webauthn` field travels OUTSIDE the DSSE envelope proper. For
  mkit attestations the signer places it inside the in-toto
  Statement's `predicate` under a reserved `_webauthn_wrapping` key
  so the DSSE signature is over a PAE that already includes the
  wrapping bytes — i.e. the binding is attested by the DSSE layer.

### 14.6 Reference signer

`contrib/signers/mkit-sign-ctap/` drives a plugged-in roaming
authenticator via CTAP-HID and emits v1.1 responses. See its
`README.md` for the argv surface; its end-to-end test exercises the
wire format against any physical authenticator on the host and skips
with a clear message when none is attached.

### 14.7 Worked example (mock, no hardware)

Request (stdin) — identical to a v1 P-256 request:

```json
{"algorithm":"p256","pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ=="}
```

Response (stdout, one line, whitespace added here only for display):

```json
{
  "keyid": "p256:036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  "sig_base64": "<88 base64 chars>",
  "webauthn": {
    "authenticator_data": "<base64url of 37+ bytes>",
    "client_data_json":   "<base64url of {\"type\":\"webauthn.get\",\"challenge\":\"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ\",\"origin\":\"https://mkit.local\",\"crossOrigin\":false}>"
  }
}
```

(Note the `challenge` is base64url-no-pad of the PAE, which differs
from the standard-base64 `pae_base64` in the request only by padding
and alphabet for the `+`/`/` vs `-`/`_` positions.)

---

## Table of contents

1. Scope
2. Invocation
3. Request format
4. Response format — 4.1 keyid; 4.2 sig_base64
5. Error handling
6. Size limits
7. Timeout
8. Determinism
9. Versioning
10. Worked examples — 10.1 Ed25519; 10.2 secp256k1; 10.3 P-256
11. Test vectors
12. Security model
13. Compatibility
14. Protocol v1.1 — WebAuthn extension — 14.1 Motivation; 14.2 Response shape; 14.3 clientDataJSON; 14.4 Verifier contract; 14.5 Absence semantics; 14.6 Reference signer; 14.7 Worked example
