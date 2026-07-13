---
spec: SPEC-RELEASE-THRESHOLD
version: 1
status: draft-normative
audience: implementers and integrators producing or verifying mkit release-party threshold signatures
---

# SPEC-RELEASE-THRESHOLD &mdash; BLS12-381 threshold signatures for mkit releases

Status: **Draft**. The signer/verifier pair and the keystore-backed share
storage (issue #160) are implemented in `mkit-attest`/`mkit-keystore`
behind the `bls-threshold` Cargo feature &mdash; see §6. The release-party
ceremony CLI (`contrib/release-party/`) that drives the dealer/aggregator
flow in §5 does not exist yet; this document stays draft until it does.

This spec is normative for the wire bytes a threshold-signed release
ships and the verifier path that consumes them. It is **not** a
replacement for `SPEC-ATTESTATIONS.md` &mdash; DSSE envelope shape, in-toto
v1 Statement shape, JCS canonicalization, and `attestation_id`
construction are all inherited unchanged. This document only describes
the signer/verifier pair that produces a single signature standing in
for M maintainers.

---

## 1. Motivation &mdash; "release party"

mkit's release process today (`docs/RELEASE.md`) is cut by one human
running `git tag -s vX.Y.Z`. The cosign keyless signatures come from
GitHub Actions OIDC; the release-tag signature is one person.

For a project that wants N maintainers to co-sign a release without
each one having to publish a separate signature, BLS12-381 threshold
signatures over the [`commonware-cryptography`](https://docs.rs/commonware-cryptography)
crate provide:

- N shares dealt by a trusted dealer (implemented) or DKG-generated (not
  yet implemented &mdash; §2.2). M-of-N partial signatures recover a single
  signature.
- Verifiers check **one** signature against **one** aggregated public
  key &mdash; no per-maintainer dispatch on the consumer side.
- Adding or rotating maintainers happens through key resharing without
  changing the verifier-side public key (resharing tooling not yet
  implemented &mdash; §2.2, §5.3).

The "release party" framing: a release is cut by M-of-N maintainers
each posting their partial signature to a coordination channel; an
aggregator combines them; the resulting BLS signature lands on the
GitHub Release alongside the existing cosign keyless signature. No
single maintainer can produce a valid release signature alone.

This spec defines the signer/verifier pair (§3-§4) and the keystore
backend for share storage (§6; `SPEC-KEYSTORE.md`). The
dealer/aggregator CLI and CI integration that make the ceremony usable
end-to-end (§5) are the one piece not yet built.

### 1.1 Non-goals

- BLS does **not** replace cosign keyless signing. Cosign attests
  "GitHub Actions built this from commit X"; the BLS aggregate attests
  "M maintainers approved this release." Both ride in the same SLSA
  bundle.
- BLS is **not** for commit signing. Ed25519 stays canonical at the
  commit layer (`docs/specs/SPEC-SIGNING.md`). The threshold scheme exists
  for release-cadence artifacts only.

---

## 2. Trust model

### 2.1 Trusted dealer

A single party (the project lead, in practice) runs
`mkit_attest::bls_threshold_trusted_dealer(rng, n)` and hands each
maintainer their `Share`, plus the cohort's public `Sharing<MinSig>`
(which every holder also keeps a copy of for partial-verification).

Trust assumptions in this phase:

1. The dealer is honest at the moment of dealing &mdash; they do not retain
   the unsplit secret after distribution and do not collude with any
   M-1 maintainers.
2. Share distribution to maintainers happens over a confidential
   channel (HSM-backed envelope, encrypted handoff over Signal, etc.).
3. The fault model is `N3f1` (commonware's `Faults` trait): quorum =
   ceil(2n/3). At n=4 this gives 3-of-4; at n=7, 5-of-7.

The dealer assumption is **explicitly time-bounded**: it holds for the
window between key generation and the first DKG resharing.
Public commitment to the cohort public key (for example published in the
project README and pinned in trust-roots TOML) closes the window: any
future deal that doesn't match the published key is rejected.

### 2.2 DKG

`commonware-cryptography::bls12381::dkg` provides the
distributed-key-generation protocol. No single party ever sees the
unsplit secret. The DKG ceremony reuses every piece of the
signer/verifier machinery (`ThresholdSigner`, `aggregate`, `verify`)
because the only thing that changes is how shares are produced.

The DKG plan is the subject of a separate spec; this document only
guarantees that the on-disk share format the keystore backend defines
is compatible with both ceremonies.

---

## 3. Wire shape

### 3.1 Partial signature (in-flight, holder → aggregator)

A `PartialSignature<MinSig>` per `commonware-cryptography`:

```text
+---------------------+------------------------------+
| index: Participant  | value: V::Signature (G1)     |
| (4 bytes, u32 BE)   | (48 bytes, G1 compressed)    |
+---------------------+------------------------------+
```

Total: 52 bytes on the wire. `mkit_attest::bls_threshold` ships this
via the `commonware_codec::Encode` impl on `PartialSignature`; the
release-party ceremony CLI wraps it in a thin JSON envelope for
human-friendly coordination-channel transport.

### 3.2 Aggregated signature (on-disk, in DSSE envelope)

A `V::Signature` per `commonware-cryptography`, with the MinSig
variant:

```text
+----------------------------------+
| signature: G1 compressed         |
| (48 bytes — SIGNATURE_SIZE)      |
+----------------------------------+
```

48 bytes total. This is what lands in the DSSE envelope's
`signatures[i].sig` field, base64-encoded per DSSE §3.

### 3.3 Aggregated public key

A `V::Public` per `commonware-cryptography`:

```text
+----------------------------------+
| public_key: G2 compressed        |
| (96 bytes — PUBLIC_KEY_SIZE)     |
+----------------------------------+
```

96 bytes. The DSSE `keyid` carries this as
`bls12381-thr:<192 hex chars>` (205 chars total: 13-char prefix + 192
hex). The verifier registry maps this keyid to the public key bytes
for the BLS verify step.

### 3.4 Algorithm wire identifier

The mkit-rpc `Algorithm` proto enum has a fixed integer for this
algorithm:

```proto
ALGORITHM_BLS12381_THRESHOLD = 5;
```

The integer is load-bearing: the buffa codegen pins it. The variant
appears in `SignerFrame.SignResponse.algorithm` when a future external
signer produces a partial; today the adapter is in-process and does not
emit a `SignerFrame`, but the integer is already reserved so an external
BLS signer subprocess can use it.

### 3.5 Variant choice

`MinSig` (signature in G1, public key in G2) over `MinPk` (the
reverse). Rationale: each release ships one aggregated signature in
the SLSA bundle; the public key is registered once in the verifier
trust root and amortized across every release. This minimizes the
signature side (48 bytes vs. 96).

### 3.6 Ciphersuite

The signature scheme is the IETF BLS-signature construction over
BLS12-381 with a proof-of-possession scheme, using the `MinSig`
variant selected in §3.5:

```text
BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_
```

This identifies, per
[draft-irtf-cfrg-bls-signature](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/):
the curve (BLS12-381), the signature group (G1, that is, `MinSig`), the
hash-to-curve suite (`XMD:SHA-256_SSWU_RO_`, an
[RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) expand-message-XMD
construction with SHA-256 and the Simplified Shallue–van de Woestijne–
Ulas map), and the proof-of-possession scheme (`POP_`, which requires
each participating key to have a separately-verified proof of
possession before it may contribute to an aggregate &mdash; closing the
rogue-key attack that plain BLS aggregation is vulnerable to without
one). This is a real, standard IETF ciphersuite; it is not an mkit- or
commonware-specific construction, and any BLS12-381 implementation
conforming to that draft and RFC 9380 can be checked against it.

### 3.7 Namespace

Layered *on top of* the ciphersuite in §3.6 (not a replacement for its
hash-to-curve step) is an mkit-specific application namespace, fixed
at:

```text
NAMESPACE = b"mkit-attest/dsse/v1"
```

`mkit_attest::BLS_THRESHOLD_NAMESPACE` exposes the constant. Signing
and verification combine the namespace and the message (the DSSE PAE,
§4) via a unique, unambiguous encoding &mdash; not bare concatenation &mdash; before
that combined value is hash-to-curve'd per §3.6. The namespace separates
the maintainer-set BLS key from any other context that might share the
same shares &mdash; a release signature cannot be replayed as a vote, a
commit endorsement, or any other BLS message under a different
namespace.

The `dsse/v1` suffix names the current, and so far only, application
namespace this key is used under &mdash; it is not a compatibility-era label
(see SPEC-CONVENTIONS §4). If a distinct application use of this key
is ever introduced, it gets its own distinctly-named namespace
constant; there is no plan to migrate this namespace's bytes to a
different value while today's usage continues.

---

## 4. Verifier algorithm

Given:

- `pae`: the DSSE PAE of the envelope being verified
  (`SPEC-ATTESTATIONS.md` §4).
- `aggregate_pubkey`: 96 bytes, the cohort's G2 compressed public key,
  resolved from the DSSE `keyid` via the trust-root registry.
- `signature`: 48 bytes, the G1 compressed aggregated signature from
  the DSSE envelope's `signatures[i].sig`.

The verifier:

1. Reject if `aggregate_pubkey.len() != 96`.
2. Decode `aggregate_pubkey` as a G2 point (commonware
   `V::Public::decode`); reject on decode failure.
3. Reject if `signature.len() != 48`.
4. Decode `signature` as a G1 point; reject on decode failure.
5. Run `ops::verify_message::<MinSig>(&pk, NAMESPACE, pae, &sig)` &mdash;
   the single BLS verify against the namespaced hash-to-curve. The
   internal computation is one optimal-ate pairing check.

Failure of any step is fatal: the verifier MUST NOT accept the
signature. Pass/fail is binary; there is no per-share verdict at the
aggregated layer (that's a feature, not a bug &mdash; the aggregate is the
unit of consensus).

`mkit_attest::bls_threshold_verify` exposes this as a single function.
`TrustRoot::Bls12381ThresholdPubKey` is wired into `verify_envelope`'s
registry dispatch (`mkit-attest/src/verify.rs`, feature-gated behind
`bls-threshold`), so callers verifying a full DSSE envelope get this
check automatically without calling `bls_threshold_verify` directly.

---

## 5. Ceremony walkthrough

The CLI (`contrib/release-party/`) does not exist yet; this section
describes the flow it will implement, giving downstream work a
concrete shape to target.

### 5.1 Genesis (one-time)

```text
release-party deal --maintainers alice,bob,carol,dave \
                   --threshold-mode N3f1 \
                   --out cohort.json
```

Output:

- `cohort.json` &mdash; the cohort `Sharing<MinSig>` (public polynomial,
  mode, total) and the keyid (`bls12381-thr:<hex>`). Public; committed
  to the repo and pinned in trust-roots TOML.
- Four encrypted share files, one per maintainer, transported out of
  band via Signal / age / SSH-wrapped. The keystore backend defines
  the at-rest format (§6; `SPEC-KEYSTORE.md`).

### 5.2 Per-release (every `vX.Y.Z`)

1. The release coordinator (could be any maintainer) builds the
   release artifacts and computes the DSSE PAE for the in-toto v1
   Statement claiming the release tag as subject.
2. Coordinator posts the PAE bytes to a coordination channel (Signal
   group, GitHub Actions issue comment, OpenBao audit-log channel &mdash;
   pick one, document it).
3. Each maintainer pulls the PAE, runs
   `release-party sign --share ~/.mkit/release-share.json
                       --pae <bytes>`,
   which:
   - Loads the share via the keystore backend.
   - Computes the partial signature via
     `ThresholdSigner::sign(pae)`.
   - Emits the 52-byte partial as a base64-wrapped JSON object the
     maintainer posts back to the channel.
4. Coordinator collects M partials (M = `bls_threshold_for(n)`), runs
   `release-party aggregate --partials partial-*.json --cohort
   cohort.json`, which calls `bls_threshold_aggregate` and emits a
   48-byte signature.
5. Coordinator wraps the signature in a DSSE envelope with `keyid =
   bls12381-thr:<hex>` and pushes the envelope to the GitHub Release
   alongside the cosign keyless signature.

### 5.3 Rotation

Not yet implemented (§2.2). The high-level shape: a quorum of current
holders runs the keysharing protocol to mint a new share set; the
public key **does not change**, so existing trust-roots TOML pins keep
working. Maintainer set churn is invisible at the verifier layer &mdash; by
design.

---

## 6. Implementation status

The signer/verifier pair is implemented in `mkit-attest` behind the
`bls-threshold` Cargo feature: the algorithm identifier
(`Algorithm::ALGORITHM_BLS12381_THRESHOLD = 5` in `common.proto`),
`mkit-attest::signer_bls_threshold`, the `ThresholdSigner` holder-side
adapter, `bls_threshold_aggregate`, `bls_threshold_verify`, and
`bls_threshold_trusted_dealer` all exist.

The keystore backend is implemented in `mkit-keystore`: the
`Bls12381Threshold` algorithm variant, `SoftwareKeystore::store_bls_share`/
`load_bls_share`/`delete_bls_share`/`list_bls_shares`, the
`BlsShareRecord` AEAD wire format (magic `MKITKSB1`), the
`TrustRoot::Bls12381ThresholdPubKey` registry dispatch in
`verify_envelope`, the trust-roots TOML schema for `bls12381-thr:`
keyids, and `mkit key generate --algorithm bls12381-thr` all exist.

Not yet implemented: DKG in place of the trusted dealer (§2.2); the
`contrib/release-party/` CLI itself (`sign`/`aggregate`/`deal`, §5); its
`.github/workflows/release.yml` integration; maintainer
rotation/resharing tooling (§5.3); and multi-host distribution to
replace the single-host trusted dealer.

---

## 7. Open questions

- **Share serialization at rest.** The
  software backend stores each share as a
  `commonware_codec::Encode`-encoded `Share` wrapped in a
  `BlsShareRecord` (magic `MKITKSB1`, `XChaCha20-Poly1305`,
  protector-managed DEK). The record's AAD binds the share to the
  cohort public key, holder index, M-of-N threshold, and total &mdash; so
  a swapped 1-of-N share cannot be passed off as 3-of-N. Round-trip
  through age/OpenBao is unblocked: those tools wrap arbitrary
  bytes, and the wire format is opaque to them. See `SPEC-KEYSTORE.md`
  §"BLS12-381 threshold share storage".
- **Coordination channel.** Signal vs. GitHub issue comment vs.
  OpenBao audit log &mdash; each has different trust-root assumptions. The
  CLI implementation will pick one; the spec stays neutral.
- **Rotation cadence.** Annual? Triggered by maintainer churn? An
  operational question with implications that don't affect wire bytes.
- **Bridge to sigstore.** Could a Fulcio cert ever certify a BLS
  public key? Out of scope for now; would be a separate spec.

---

## 8. Invariants

| Invariant | Enforced by |
|---|---|
| No single maintainer can produce a valid release signature | M-of-N threshold with quorum = ceil(2n/3) under the `N3f1` fault model (§1, §2.1) |
| Verifiers check exactly one signature against exactly one public key, with a binary verdict | single `verify_message::<MinSig>` pairing check; any step failure is fatal, no per-share verdict at the aggregated layer (§4) |
| Malformed key or signature bytes never reach the pairing | fixed sizes (96-byte G2 key, 48-byte G1 signature) and point-decode rejection, verifier steps 1–4 (§3.2, §3.3, §4) |
| A release signature cannot be replayed as any other BLS message | the pinned hash-to-curve namespace `mkit-attest/dsse/v1` (§3.7) |
| The DSSE `keyid` resolves to the intended cohort key, not an attacker-supplied one | trust-root registry maps `bls12381-thr:<hex>` to pinned public-key bytes (§3.3, §4) |
| A re-deal that doesn't match the published cohort key is rejected | public commitment to the cohort key (README and trust-roots TOML pin), bounding the trusted-dealer window (§2.1) |
| Maintainer rotation never invalidates existing verifier pins | resharing keeps the aggregated public key unchanged (§1, §5.3) |
| A stored 1-of-N share cannot be passed off as M-of-N (or swapped across cohorts) | `BlsShareRecord` AAD binds the share to cohort key, holder index, threshold, and total (§7) |
| Envelope shape, Statement shape, and `attestation_id` never diverge from ordinary attestations | inherited unchanged from SPEC-ATTESTATIONS; this spec defines only the signer/verifier pair (scope statement, preamble) |
| The BLS aggregate never stands in for build provenance or commit signatures | cosign keyless and Ed25519 commit signing remain separate, co-shipped surfaces (§1.1) |

Dealer honesty at the moment of dealing (§2.1 item 1) is a **trust
assumption**, not an enforced invariant; it becomes structural only
with DKG (§2.2), which is specified separately.
