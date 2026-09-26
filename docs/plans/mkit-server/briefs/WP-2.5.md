# WP-2.5: mkit-attest `secp256k1-eip191` and `webauthn-p256` owner schemes

- **Milestone/track:** M2 / crypto (pure mkit-attest; may land during M0/M1)
- **Base:** `feat/mkit-server` at `8bcf4d2b` or later; **branch:** `mkit-server/wp-2-5-ecdsa-owner-schemes`
- **Depends on:** 2.3 (#1110, `mkit_attest::eth`), 2.4a (#1114, grant codec and header), 2.4b (#1119, the stateless
  verifier and the `ed25519` scheme). SPEC-WRITE-GRANTS §4, §4.1, §4.3, §4.4 and §7 are normative.
- **Unblocks:** 2.6/2.7/2.9 (server grant enforcement for `0x` namespaces), 2.12/2.13 (grant registry and CLI; the
  CLI signs with wallets and passkeys through the client helpers below), 2.2 (`grant_schemes` in `GetServerInfo`
  advertises `webauthn-p256` only when a relying party is configured)
- **Parallel with:** nothing in `mkit-attest/src/grant/`. Shared files: `rust/tests/golden/grants/MANIFEST.txt`,
  SPEC-WRITE-GRANTS §13.1, `scripts/golden/grants_ref.py`, `rust/fuzz/src/lib.rs`.
- **Size:** M (~700–900 non-test changed lines; tests, goldens and the Python cross-check extra)
- **Area gates (registry):** `rust`, `wasm`, `golden` (+ `docs`: SPEC-WRITE-GRANTS Status paragraph and §13.1)

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-2-5-ecdsa-owner-schemes origin/feat/mkit-server`.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp/2-5"; mkdir -p "$TMPDIR"` before any test (the macOS `/tmp` symlink
  breaks the mkit-attest sign tests). Per-worktree target dir; `CARGO_PROFILE_{DEV,TEST}_DEBUG=0`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body.
- Pre-production policy (replace unshipped APIs directly); `CHANGELOG.md` `[Unreleased]`; workspace lints; no
  `unsafe`; no proto change; no new dependency; stop and propose a split above ~1500 non-test changed lines.
- Carry-forward notes:
  - wasm32 clippy needs `--no-deps`. Baseline: **mkit-attest has 2 pre-existing wasm32 lints**
    (`signer_external.rs`, `store.rs`); new code adds none.
  - The machine is shared: keep nextest runs targeted (`-p mkit-attest -E 'test(/grant|secp256k1|webauthn|p256/)'`
    while iterating), and re-run a timeout alone before calling it a regression.
  - From the 2.3 review: a successful secp256k1 recovery is **not** authorization. Go through
    `eth::eip191_recover_address` (never `recover_secp256k1` on another prehash) and compare the address with the
    namespace.
  - From 2.4b: replace the `SchemeNotImplemented` arms and the `ecdsa_owner_schemes_are_not_implemented_yet` stub
    test; add the relying-party setting to `VerifierConfig` (today it refuses `webauthn-p256` with
    `NoRelyingParty`); keep `VerifiedGrant`, `OwnerVerified`, `VerifiedEpoch` and `VerifiedVisibility`
    unforgeable (no public fields or constructors, `compile_fail` doctests stay green).

## Goal

Implement the two ECDSA owner schemes of SPEC-WRITE-GRANTS §4 in the existing dispatch
(`grant::owner::verify_owner_signature`), so grants, epoch statements and visibility statements for `0x`
namespaces verify:

- **`secp256k1-eip191`**: a 65-byte `r ‖ s ‖ v` blob over the EIP-191 personal message of the statement; strict
  low-S recovery (`v ∈ {27, 28}`, no normalization); the recovered key's §4.1 address MUST equal the namespace's 20
  bytes exactly.
- **`webauthn-p256`**: a four-field length-prefixed blob (public key, `authenticatorData`, `clientDataJSON`, raw
  low-S `r ‖ s`); every §4.3 rule, with strict `clientDataJSON` parsing (duplicate member names rejected at any
  depth); the relying-party binding against the deployment's configured relying parties; the §4.1 address of the
  public key MUST equal the namespace.

Plus the deployment configuration for §4.3 (relying parties and their origins in `VerifierConfig`), client-side
helpers to build a `webauthn-p256` blob and challenge, signed golden vectors and verify-reject vectors for each
scheme cross-checked by independent Python libraries, proptests, and fuzz coverage of the new parsers.

## PRD and spec refs

- PRD §6.4 (self-certifying `0x` namespaces; "P-256 signatures are normalized to low-S on the client"; "the grant
  verifier lives in mkit-attest").
- **SPEC-WRITE-GRANTS**
  - §2: a `0x` namespace is owned by any secp256k1 **or** P-256 key whose §4.1 address equals its 40 lowercase hex
    digits.
  - §4 table:
    - `secp256k1-eip191`: message `"\x19Ethereum Signed Message:\n"` ‖ decimal byte length ‖ statement; Keccak-256
      digest; blob `r(32) ‖ s(32) ‖ v`, `v ∈ {27, 28}`, recovery id `v − 27`; owner = address of the recovered key;
      valid only for `0x`.
    - `webauthn-p256`: ECDSA P-256/SHA-256 over `authenticatorData ‖ SHA-256(clientDataJSON)`; blob = four
      `[u32 LE length][bytes]` fields (public key exactly 64 bytes `x ‖ y`; `authenticatorData`; `clientDataJSON`;
      signature exactly 64 bytes `r ‖ s`), **nothing after the fourth**; owner = address of the public key; valid
      only for `0x`.
    - A statement signed under a scheme the deployment does not advertise fails.
  - §4.1: address = last 20 bytes of Keccak-256(`x ‖ y`); reject off-curve keys and the point at infinity.
  - §4.3 (all MUST):
    1. public key and signature fields exactly 64 bytes; `authenticatorData` ≥ 37 bytes; flags byte (offset 32)
       has UP (`0x01`). **UV and the signature counter are not checked** (the verifier is stateless).
    2. `clientDataJSON` is an RFC 8259 JSON object with **no duplicate member names at any depth**; `type` is the
       string `webauthn.get`; `challenge` is exactly the 43-character unpadded base64url of BLAKE3(statement);
       `crossOrigin`, if present, is `false`; a `topOrigin` member is rejected.
    3. the signature is verified over the exact received `clientDataJSON` bytes, never a reserialization.
    4. `authenticatorData[0..32]` = SHA-256 of a configured relying-party id, and `origin` equals, byte for byte, an
       origin configured **for that relying party**.
    - A deployment with no relying party MUST NOT accept or advertise `webauthn-p256`.
  - §4.4: secp256k1 `r, s ∈ [1, n−1]`, `s ≤ n/2`, reject high-`s`, never normalize (client flips `s` and `v`, and
    adds 27 to `v ∈ {0, 1}`). P-256: the client decodes DER and normalizes; the verifier rejects out-of-range or
    high-`s`, never normalizes.
  - §7 steps 3 and 4 (scheme advertised and valid for the namespace form; signature verifies incl. low-S and WebAuthn
    rules; recovered or derived owner equals the namespace). Steps 1, 3, 4 are cacheable by exact header bytes.
  - §11 (every failure is one Connect code; the server maps it), §12 (relying-party pinning, low-S uniqueness),
    §13.1 (planned fixtures: a signature for each ECDSA scheme; a WebAuthn assertion; a high-`s` signature for each
    ECDSA scheme; a cleared user-present flag; an ECDSA scheme on the wrong namespace form).
- SPEC-CONVENTIONS §3 (`[u32 LE length][bytes]`), §5 (goldens).

## Existing code (tip `8bcf4d2b`)

| Symbol | Location | Use |
|---|---|---|
| `verify_owner_signature` | `rust/crates/mkit-attest/src/grant/owner.rs:36` | Replace the `SchemeNotImplemented` arm; keep the advertised → form → signature order |
| `ecdsa_owner_schemes_are_not_implemented_yet` | `grant/owner.rs` tests | Delete; replaced by the scheme tests |
| `VerifierConfig`, `is_loopback_origin` | `grant/config.rs` | Add relying parties; `NoRelyingParty` stays for "accepts `webauthn-p256` without one" |
| `OwnerVerified` (macro `verified_statement!`), `OwnerVerified::check` | `grant/verify.rs` | Record the relying party a `webauthn-p256` owner signature used; `check` re-tests it so a stale cached value fails closed (as it already re-tests the scheme) |
| `GrantError` (`#[non_exhaustive]`, `reason()`) | `grant/error.rs` | New variants below; drop `SchemeNotImplemented` |
| `eth::eip191_recover_address`, `eth::address_p256`, `eth::p256_check_raw_low_s`, `eth::p256_der_to_low_s_raw`, `eth::normalize_eip191_signature` | `rust/crates/mkit-attest/src/eth.rs` | Verifier primitives (strict) and client normalizers. `recover_secp256k1` stays `pub(crate)` and unused here. |
| `webauthn::verify_webauthn_wrapping_with_policy` | `rust/crates/mkit-attest/src/webauthn.rs` | **Not reused** (see "Spec vs breakdown" 2) |
| `serde_json` (already a normal dependency) | `mkit-attest/Cargo.toml` | Strict `clientDataJSON` walk through a custom `DeserializeSeed` (no `Value`, which keeps the last duplicate) |
| golden writer | `rust/crates/mkit-attest/tests/golden_grants.rs` + `golden_grants/signed.rs` | Add `golden_grants/ecdsa.rs`; `write_all` keeps writing the one `MANIFEST.txt` |
| cross-check | `scripts/golden/grants_ref.py` | Extend: Python-side EIP-191 recovery and WebAuthn verification |
| fuzz | `rust/fuzz/src/lib.rs` `epoch_visibility_parse_one_iteration` | Extend (no new target, no `fuzz.yml` change) |

## Scope

**IN**
- `secp256k1-eip191` and `webauthn-p256` in `verify_owner_signature`, hence in `verify_grant_owner`,
  `verify_for_registration`, `verify_epoch_statement` and `verify_visibility_statement`.
- `grant/webauthn.rs` (new): the blob codec (`WebAuthnAssertion`), the strict `clientDataJSON` check, the §4.3
  verification, `RelyingParty`, and the client helper `webauthn_challenge`.
- `VerifierConfig` relying parties; `OwnerVerified` relying-party record.
- `GrantError` variants; removal of `SchemeNotImplemented` (pre-production).
- Goldens, verify-reject vectors, Python cross-check, proptests, fuzz extension, SPEC-WRITE-GRANTS Status + §13.1,
  CHANGELOG.

**OUT**
- Server enforcement, `grant_schemes` advertisement and relying-party deployment config (2.2, 2.6+).
- Wallet or passkey signing UX, keystore (2.13). The client helpers here only encode what a client already has.
- `mkit-wasm` exports.
- Changes to the pre-existing `webauthn.rs` DSSE wrapping helper (SPEC-EXTERNAL-SIGNER §14).

## Design

### Configuration (`grant/config.rs`, `grant/webauthn.rs`)

```rust
/// A WebAuthn relying party a deployment accepts `webauthn-p256` assertions for (§4.3 rule 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty { id: String, id_hash: [u8; 32], origins: Vec<String> }
impl RelyingParty {
    /// `id`: a lowercase DNS name (labels of `[a-z0-9-]`, 1–63 bytes, no leading or trailing `-`; ≤ 253 bytes).
    /// `origins`: at least one; each non-empty printable ASCII (0x21..=0x7E), compared byte for byte with
    /// `clientDataJSON.origin`. No duplicates. Errors: `GrantError::RelyingParty`.
    pub fn new<'a>(id: &str, origins: impl IntoIterator<Item = &'a str>) -> Result<Self, GrantError>;
    pub fn id(&self) -> &str; pub fn origins(&self) -> &[String];
}

impl VerifierConfig {
    // Both constructors gain the relying parties (pre-production: replace, don't add a third constructor).
    pub fn new(audience: &str, schemes: AcceptedSchemes, relying_parties: Vec<RelyingParty>) -> Result<Self, GrantError>;
    pub fn new_allowing_loopback(audience: &str, schemes: AcceptedSchemes, relying_parties: Vec<RelyingParty>)
        -> Result<Self, GrantError>;
    pub fn relying_parties(&self) -> &[RelyingParty];
}
```

- `webauthn-p256` in `schemes` with an empty `relying_parties` → `NoRelyingParty` (§4.3 last paragraph).
- Two relying parties with the same id → `RelyingParty`.
- `new` (production) also refuses a loopback relying party (`LoopbackRelyingParty`): id `localhost` or
  `*.localhost`, or an origin for which `is_loopback_origin` holds. This is defense in depth beyond the spec (any
  local process can ask a passkey to sign for `localhost`), mirroring the §3.2/§10 loopback-audience ban;
  `new_allowing_loopback` allows it.
- Relying parties configured while `webauthn-p256` is not accepted are allowed and unused (fail closed).

### Owner dispatch (`grant/owner.rs`)

`verify_owner_signature(cfg, scheme, statement, blob, namespace) -> Result<(), GrantError>` keeps its signature and
order: advertised (`SchemeNotAdvertised`) → form (`SchemeNamespaceMismatch`; both ECDSA schemes need
`Namespace::Address`) → scheme. A crate-private `verify_owner` returns the relying party a `webauthn-p256`
assertion used, which `verify_grant_owner` stores in `OwnerVerified` (private field, read-only accessor
`relying_party() -> Option<(&str, &str)>` giving id and origin); `OwnerVerified::check` re-tests that the current
`cfg` still has that relying party and origin (`RelyingPartyMismatch` / `OriginNotAllowed`), so an entry cached
across a config change fails closed.

**`secp256k1-eip191`, in order:**
1. `blob.len() == 65`, else `SignatureLength`.
2. `eth::eip191_recover_address(statement, blob)`: `RecoveryIdInvalid` → `SignatureRecoveryId`;
   `ScalarOutOfRange` → `SignatureScalar`; `HighS` → `HighS`; `RecoveryFailed` / `InvalidPoint` → `BadSignature`.
3. The address equals the namespace's 20 bytes, else `OwnerMismatch` (§7 step 4).

**`webauthn-p256`, in order** (the Python reference returns the same first failure):
1. Blob framing (`WebAuthnAssertion::parse`): four `[u32 LE len][bytes]` fields, nothing after the fourth, a length
   past the end rejected, public key and signature exactly 64 bytes → else `WebAuthnBlob`.
2. Signature scalars (`eth::p256_check_raw_low_s`): `SignatureScalar` (r or s ∉ [1, n−1]), `HighS`.
3. Public key on P-256 (`eth::address_p256`), else `InvalidOwnerKey`; its address equals the namespace, else
   `OwnerMismatch`.
4. `authenticatorData` ≥ 37 bytes, else `AuthenticatorData`; UP bit set, else `UserNotPresent`.
5. `authenticatorData[0..32]` equals the SHA-256 id hash of a configured relying party, else
   `RelyingPartyMismatch`.
6. `clientDataJSON`, strictly (below): syntax, UTF-8, top level not an object, or a duplicate member name at any
   depth → `ClientData`; `type` missing, not a string or not `webauthn.get` → `ClientDataType`; `challenge` missing,
   not a string or not exactly `webauthn_challenge(statement)` → `Challenge`; `crossOrigin` present and not the
   literal `false` → `CrossOrigin`; `topOrigin` present (any value) → `TopOrigin`; `origin` missing, not a string, or
   not one of **that** relying party's origins → `OriginNotAllowed`.
7. ECDSA P-256 / SHA-256 verification over `authenticatorData ‖ SHA-256(clientDataJSON as received)`, else
   `BadSignature`.

UV, the backup flags, the attested-data and extension flags and the counter are ignored; bytes after the first 37 of
`authenticatorData` are covered by the signature only.

### Strict `clientDataJSON`

A `serde_json::Deserializer::from_slice` driven by a recursive `DeserializeSeed` (then `Deserializer::end`, so
trailing non-whitespace fails): every object collects its **decoded** member names and rejects a repeat (so
`"type"` and `"type"` are duplicates); arrays and nested objects recurse; the top level must be an object and
reports the decoded values of `type`, `challenge`, `origin`, `crossOrigin` and `topOrigin` as
`{ string | false | other }`. Member values are compared after JSON unescaping (RFC 8259 semantics: the member *is*
the decoded string). serde_json already rejects invalid UTF-8, unpaired surrogate escapes, raw control characters,
`NaN`/`Infinity`, comments, trailing commas and a BOM. Two limits are normative (added to §4.3 rule 2 in review):
nesting at most `MAX_CLIENT_DATA_DEPTH` = 64 (top-level object = 1), enforced by the walk's own counter, below
serde_json's internal cap (which allows only 127 levels, so "128" could not be the rule); and every number finite as a
correctly rounded binary64 (`1e400` rejected). The Python reference applies the same rules with `json.loads`
(`object_pairs_hook` for duplicates, `parse_constant` refusing `NaN`/`Infinity`, `parse_float`/`parse_int` refusing
non-finite values, a depth count, strict UTF-8 decoding, and a lone-surrogate check), and decides curve membership
from the curve equations itself (pycryptodome accepts `(0, 0)`, its point at infinity, as a P-256 key).

### Client helpers (`grant/webauthn.rs`)

```rust
/// The four §4 `webauthn-p256` blob fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnAssertion { pub public_key: [u8; 64], pub authenticator_data: Vec<u8>,
                               pub client_data_json: Vec<u8>, pub signature: [u8; 64] }
impl WebAuthnAssertion {
    pub fn parse(blob: &[u8]) -> Result<Self, GrantError>;   // framing only (WebAuthnBlob); verification is separate
    pub fn encode(&self) -> Vec<u8>;                          // parse(encode(a)) == a
}
/// The `challenge` a client puts in `clientDataJSON`: unpadded base64url of BLAKE3(statement), 43 characters.
#[must_use] pub fn webauthn_challenge(statement: &[u8]) -> String;
```

Client normalization stays in `eth` (`p256_der_to_low_s_raw`, `normalize_eip191_signature`); docs point there.

### New `GrantError` variants (reasons are fixture text)

`SignatureRecoveryId` "signature recovery id", `SignatureScalar` "signature scalar", `HighS` "high s",
`OwnerMismatch` "owner mismatch", `InvalidOwnerKey` "invalid owner key", `WebAuthnBlob` "webauthn blob",
`AuthenticatorData` "authenticator data", `UserNotPresent` "user not present", `RelyingPartyMismatch`
"relying party mismatch", `ClientData` "client data", `ClientDataType` "client data type", `Challenge`
"challenge", `CrossOrigin` "cross origin", `TopOrigin` "top origin", `OriginNotAllowed` "origin not allowed",
`RelyingParty` "relying party", `LoopbackRelyingParty` "loopback relying party". `SchemeNotImplemented` is removed.

## Tests to write first

Names match `test(/grant|secp256k1|webauthn|p256/)`.

- **secp256k1** (`owner.rs` unit + `tests/grant_owner_ecdsa.rs`):
  - `secp256k1_grant_epoch_and_visibility_verify` (via the public verifiers) and
    `secp256k1_eip191_owner_signature_verifies` (unit).
  - `secp256k1_owner_signature_rejects`: 64/66-byte blob; `v` ∈ {0, 1, 26, 29, 255}; r = 0, s = 0, r = n, s = n;
    the high-`s` twin (and `normalize_eip191_signature` maps it back to a verifying blob); another key's signature
    (`OwnerMismatch`); another statement's signature (`OwnerMismatch`, recovery gives a different address); an `r`
    that is no x-coordinate (`BadSignature`); the scheme on an `ed25519-` namespace; not advertised.
  - Proptest `secp256k1_owner_roundtrip_and_tamper`: random key and statement bytes; the normalized signature
    verifies against its own address; flipping any blob or statement byte never verifies against that namespace.
- **webauthn-p256**:
  - `webauthn_blob_framing` (roundtrip, every truncation, trailing byte, a length past the end) and the framing
    cases of `webauthn_owner_signature_rejects` (63-byte key field, empty blob).
  - `webauthn_grant_epoch_and_visibility_verify` and `webauthn_client_data_shapes_that_verify`: grant, epoch and
    visibility; with and without `crossOrigin: false`; with extra members (`"other_keys_can_be_added_here"`); with
    escaped member names and values; with UV set; with `authenticatorData` longer than 37 bytes.
  - `webauthn_client_data_strict_json` (unit) and `webauthn_owner_signature_rejects`, one case per step-list item
    above, each re-signed so that only that rule fails: UP cleared (UV set);
    36-byte `authenticatorData`; rpIdHash of an unconfigured id; origin of another configured relying party; type
    `webauthn.create`; challenge of another statement, padded challenge, challenge as raw bytes; `crossOrigin: true`
    and `"false"`; `topOrigin`; duplicate member at top level, via escape, and nested; invalid UTF-8; lone
    surrogate; trailing garbage; top-level array; high-`s`; s = 0; off-curve key; `x ≥ p`; another key's assertion
    (`OwnerMismatch`); signature by another key under the owner's public key (`BadSignature`); signature over a
    reserialized `clientDataJSON` (`BadSignature`).
  - Proptests: `webauthn_owner_roundtrip_and_tamper` (random key, statement, flags with UP, extra authData bytes;
    verifies; any single-byte mutation of the blob never verifies) and `webauthn_client_data_matches_serde_json`
    (differential: every JSON text serde_json produces from a duplicate-free value is accepted structurally; any
    bytes the strict walk accepts, `serde_json::from_slice::<Value>` accepts).
- **config**: `verifier_config_webauthn_needs_relying_party` (also: duplicate relying-party id),
  `webauthn_relying_party_rules` (uppercase id, empty label, `-` edge, 254 bytes, IP literal, no origins, empty or
  non-ASCII origin, duplicate origin), `verifier_config_rejects_loopback_relying_party` (production only).
- `webauthn_owner_verified_rechecks_relying_party`: a cached `OwnerVerified` fails `check` after the relying party
  or its origin is removed from the config, or the scheme is dropped.
- `webauthn_client_normalizes_der_signatures`: a high-`s` DER signature normalized by
  `eth::p256_der_to_low_s_raw` verifies; its raw high-`s` form is `HighS`.
- The unforgeability doctests (`compile_fail,E0451`) still compile-fail.

## Golden-vector plan (mandatory)

**Fixtures** (`rust/tests/golden/grants/`, written by `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest --features
grants --test golden_grants`, pinned in the one `MANIFEST.txt`):

1. `secp256k1-eip191.json`: owner private key (fixed), its `x`, `y`, address and namespace; a grant, an epoch
   statement and a visibility statement signed with RFC 6979 + low-S, each with fields, statement, id, EIP-191
   digest, 65-byte blob, header, and accept/reject contexts (scheme-specific ones plus `NamespaceMismatch`, `Expired`,
   `AudienceNotListed`, `RepositoryMismatch`).
2. `webauthn-p256.json`: owner P-256 key, `x`, `y`, address; the relying parties config (two, each with origins);
   signed grant/epoch/visibility vectors with `authenticatorData`, `clientDataJSON`, raw signature (RFC 6979,
   normalized low-S), blob, header and contexts; plus client-data shape variants (no `crossOrigin`, extra member,
   escaped names and values, UV set, long `authenticatorData`, second relying party).
3. `reject/verify-secp256k1-*.json` and `reject/verify-webauthn-*.json`: each fails with one stated rule
   (high-`s` for each scheme; UP cleared; ECDSA scheme on an `ed25519-` namespace for each scheme; `v` 0 and 29;
   scalars; other owner; wrong relying party; wrong origin; origin of the other relying party; type; challenge;
   `crossOrigin`; `topOrigin`; duplicate members; short `authenticatorData`; off-curve key; bad signature;
   reserialized client data; blob framing). The verify-reject JSON gains an optional `relying_parties` field.

**Independent cross-check** (`python3 scripts/golden/grants_ref.py rust/tests/golden/grants`): no code shared with
the Rust crates.
- EIP-191: message and Keccak-256 with pycryptodome `Crypto.Hash.keccak`; public-key recovery written from SEC 1
  §4.1.6 over python-`ecdsa` 0.19 curve arithmetic (`ecdsa.SECP256k1`), cross-checked against
  `VerifyingKey.from_public_key_recovery_with_digest` and `verify_digest`; re-signing with
  `SigningKey.sign_digest_deterministic` (RFC 6979, HMAC-SHA-256) then low-S normalization gives byte-equal
  signatures.
- WebAuthn: pycryptodome `ECC.construct(curve='P-256', …)` (validates the point), `DSS` (`fips-186-3`, binary) over
  `SHA256(authData ‖ SHA256(clientDataJSON))`, deterministic RFC 6979 re-signing (`deterministic-rfc6979`) with
  low-S normalization gives byte-equal signatures; the §4.3 checks rewritten from the spec with Python `json`.
- Every accept and reject context, and every `reject/verify-*` vector, re-runs through the Python verifier and must
  give the same first reason.
- PR body: at least one EIP-191 grant signature re-derived with Foundry `cast wallet sign` / `cast wallet verify`
  (`cast` 1.x), tool versions listed.

**Spec:** the Status paragraph says both ECDSA schemes are implemented; §13.1 moves "a signature for each ECDSA
scheme; a WebAuthn assertion; a high-`s` signature for each ECDSA scheme; a cleared user-present flag; an ECDSA
scheme on the wrong namespace form" from "Planned" to the landed table.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp/2-5"; mkdir -p "$TMPDIR"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
( cd rust && cargo fmt --all --check )
( cd rust && cargo clippy --locked --workspace --all-targets --all-features -- -D warnings )
( cd rust && cargo nextest run --locked -p mkit-attest --all-features -p mkit-fuzz )   # reverse deps below
( cd rust && cargo nextest run --locked -p mkit-keystore -p mkit-cli -p mkit-wasm -E 'test(/attest|sign|grant/)' )
( cd rust && cargo test --locked --doc -p mkit-attest --all-features )
( cd rust && RUSTDOCFLAGS=-D\ warnings cargo doc --no-deps -p mkit-attest --all-features )
( cd rust && cargo check -p mkit-attest --features grants --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-attest --features grants --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # only the 2 baseline sites
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
bash scripts/check-wasm-dep-graph.sh
python3 scripts/golden/grants_ref.py rust/tests/golden/grants
just ci-security
just ci-scripts                        # spec status (SPEC-WRITE-GRANTS edited)
```

## Acceptance checklist

- [ ] Both ECDSA schemes verify through `verify_owner_signature` and every public verifier; `SchemeNotImplemented`
      and its stub test are gone.
- [ ] Owner binding is exact: recovered or derived address == the namespace's 20 bytes; `ed25519` ↔ `ed25519-`,
      ECDSA ↔ `0x`.
- [ ] Low-S on both curves, scalars in `[1, n−1]`, `v ∈ {27, 28}`; the verifier never normalizes.
- [ ] Every §4.3 rule, with strict client data (duplicates at any depth, decoded names), exact received bytes, UP
      required, UV not required, relying-party hash **and** that relying party's origin.
- [ ] `VerifierConfig` holds relying parties; `webauthn-p256` without one is refused; a stale cached `OwnerVerified`
      fails `check` when its relying party or origin is gone.
- [ ] Goldens and verify-reject vectors for each scheme, cross-checked by `grants_ref.py` with python-`ecdsa` and
      pycryptodome; §13.1 updated; proptests; fuzz covers the blob and client-data parsers.
- [ ] Result types remain unforgeable; wasm32 check passes; wasm clippy shows only baseline sites.

## Risks

- **JSON leniency.** `serde_json::Value` keeps the last duplicate member, which lets a crafted client data carry two
  `challenge` or `origin` members that different parsers read differently. The strict walk rejects any repeat,
  compared after unescaping.
- **Recovery is not authorization.** Any well-formed EIP-191 signature recovers *some* address. The address
  comparison is the authorization; a test signs with a second key and expects `OwnerMismatch`.
- **Relying-party confusion.** A passkey of relying party A must not be accepted with an origin configured for
  relying party B. The origin is checked against the relying party whose id hash matched, not against the union.
- **Stale caches.** `OwnerVerified` is cacheable by header bytes, but a `webauthn-p256` result also depends on the
  relying-party config; `check` re-tests it.
- **Golden determinism.** P-256 signatures come from RFC 6979 then explicit low-S normalization (the `p256` crate
  does not normalize); secp256k1 from `k256` `sign_prehash_recoverable` (normalizes). The Python side reproduces
  both byte for byte.

## Spec vs breakdown (specs win)

1. **Raw signature, not DER.** The breakdown's blob carries a "DER signature" converted on the verify path. §4 and
   §4.4 put a raw 64-byte low-S `r ‖ s` in the blob; the client decodes DER (`eth::p256_der_to_low_s_raw`), and the
   verifier never parses DER (as the 2.3 brief already recorded).
2. **No reuse of `verify_webauthn_wrapping_with_policy`.** That helper (SPEC-EXTERNAL-SIGNER §14) parses
   `clientDataJSON` into a `serde_json::Value` (last duplicate wins), does not reject `topOrigin`, treats
   `crossOrigin` as a boolean only when it is one, pins at most one relying party with an origin list not tied to it,
   compares the challenge as decoded bytes against a PAE, and returns `crate::Error`. §4.3 needs all of those the
   other way, so the grant scheme gets its own strict module; the DSSE helper is unchanged.
3. **Relying-party pinning is mandatory**, not "when pinned": §4.3 rule 4 and its last paragraph. The breakdown's
   test "RP mismatch rejected when pinned" becomes "`webauthn-p256` is refused without a relying party" plus the
   mismatch tests.
4. **UV is not required.** The breakdown's policy sets only `require_user_presence`, which matches; §4.3 rule 1 makes
   UV and the counter explicitly unchecked.
5. **File layout.** The breakdown names `grant/schemes.rs` and fixtures `grant-eip191.json`, `grant-webauthn.json`
   and `epoch-eip191.json`. This brief keeps the ECDSA dispatch in `owner.rs`, puts WebAuthn in
   `grant/webauthn.rs`, and names one fixture per scheme token (`secp256k1-eip191.json`, `webauthn-p256.json`)
   covering all three statement kinds, as §4 says the schemes sign them all.
6. **Owner binding for `webauthn-p256`.** The breakdown says "address from x‖y"; §4.1 also requires the key to be a
   valid curve point, so an off-curve or `x ≥ p` key is `InvalidOwnerKey` before the address comparison.
