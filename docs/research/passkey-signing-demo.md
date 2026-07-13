# Research: Passkeys for the full signing lifecycle in the demo pages

Status: research note (not a spec). Branch `research/passkey-signing-lifecycle`.
Question: can a visitor on the demo pages enroll a **passkey** (Touch ID /
Face ID/Android biometric/security key) and use it to drive mkit's full
*sign → verify* lifecycle, in-browser?

Answer: **yes, and almost all of it already exists.** The cryptographic core is
compiled into the demo's WASM module and covered by 30+ Rust tests. The only
gaps are (1) two `#[wasm_bindgen]` exports, (2) the browser ceremony wiring, and
(3) demo UI. There is one genuine design fork (challenge sizing) to decide.

---

## 1. The structural constraint that shapes everything

Platform passkeys produce **ES256/P-256 (ECDSA)** signatures *only*. EdDSA
exists on a small subset of roaming security keys (YubiKey 5+) and **never** on
the synced platform passkeys an Apple/Google account provides.

mkit's **core commit/remix/tag signing is Ed25519-only** (`SPEC-SIGNING` §1,
§10). Therefore:

> **A passkey cannot sign a core mkit commit object.** It can only sign the
> P-256-capable surface: DSSE **attestations** (`SPEC-ATTESTATIONS`).

This is not a limitation to fight &mdash; it's the correct framing for the demo. The
passkey story mkit can honestly tell is **"sign an attestation over a commit with
your passkey"** (a Review/approval/provenance claim), which is exactly what the
existing `attest-demo` models with its P-256 option ("what hardware keys,
passkeys, and Secure Enclave use").

Signing *commits themselves* with a passkey would need a spec change
(a P-256 commit-signature variant or a webauthn commit domain) &mdash; out of scope
for the demo, noted here as the boundary.

---

## 2. What already exists (compiled into the demo's WASM)

The Rust backend behind `apps/web/vendor/mkit-wasm` already implements the entire
verification path. Key files:

| File | What's there |
|---|---|
| `rust/crates/mkit-attest/src/webauthn.rs` | `verify_webauthn_wrapping_with_policy(pae, wrapping, pubkey_sec1, sig_compact, policy)` + permissive `verify_webauthn_wrapping`; `WebAuthnWrapping{authenticator_data, client_data_json}`; `WebAuthnPolicy`; `build_client_data_json`; `from_b64url_fields`. **30+ tests.** |
| `rust/crates/mkit-attest/src/signer_p256.rs` | `verify_p256(pubkey_sec1, msg, sig_compact)` &mdash; low-S enforced, SEC1 33/65-byte keys. |
| `rust/crates/mkit-attest/src/envelope.rs` | `pae_of(payload_type, payload)` &mdash; DSSE PAE. |
| `rust/crates/mkit-attest/tests/golden_p256.rs` | `webauthn_shape_self_consistency_compressed_and_uncompressed()` shape test (self-signed, no published browser vector) &mdash; signs `authenticatorData ‖ SHA-256(clientDataJSON)` and verifies. |

The verifier already does the full WebAuthn two-layer check (SPEC-EXTERNAL-SIGNER
§6.1): `type == "webauthn.get"`, `challenge == base64url-nopad(PAE)`,
`authenticatorData ≥ 37 bytes`, P-256 signature over
`authenticatorData ‖ SHA-256(clientDataJSON)`, plus configurable RP-ID/origin/
UP/UV/counter policy (all defaulting permissive).

**Already exposed to JS** (`mkit-wasm/src/lib.rs` → `mkit_wasm.d.ts`):
`attest_keypair`, `attest_build`, `attest_verify` (all support `"p256"`),
`keypair_*`, `sign_bytes_commit_domain`, `verify_bytes_commit_domain`.

**NOT exposed to JS:** every `verify_webauthn_*` function. That is the whole gap.

---

## 3. What's missing (the entire delta)

> **Status (this branch):** step 3a is **done** &mdash; `attest_pae`,
> `verify_webauthn_wrapping`, and `verify_webauthn_wrapping_with_policy` are
> implemented in `rust/crates/mkit-wasm/src/lib.rs`, covered by
> `rust/crates/mkit-wasm/tests/webauthn.rs` (5 tests, forges a passkey-shaped
> assertion and verifies it through the exports), pass clippy clean, and build
> via `wasm-pack` into the generated `pkg/`. Because `MkitApi = typeof Wasm`,
> they are already reachable from the demo as `api.attest_pae(...)` /
> `api.verify_webauthn_wrapping[_with_policy](...)` with no extra plumbing.
> Remaining: 3b (browser ceremony) and 3c (demo UI).

### 3a. Two WASM exports (`rust/crates/mkit-wasm/src/lib.rs`) &mdash; DONE
Implemented as **three** exports (the PAE helper is required for the demo to
derive the challenge):
- `attest_pae(commit_hash_hex, predicate_type, predicate_jcs) -> Uint8Array`
- `verify_webauthn_wrapping(pae, authenticator_data, client_data_json, pubkey_hex, signature) -> void` (throws with a typed reason on failure)
- `verify_webauthn_wrapping_with_policy(..., policy_json) -> void` (empty string = permissive; recognizes `expected_rp_id`, `allowed_origins`, `require_user_presence`, `require_user_verification`, `allow_cross_origin`, `previous_sign_count`)

Original sketch of the surface, for reference:
```rust
#[wasm_bindgen]
pub fn verify_webauthn_wrapping(
    pae_hex: &str,
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
    pubkey_hex: &str,        // SEC1 P-256, 33 or 65 bytes
    signature_hex: &str,     // 64-byte compact r||s
) -> Result<bool, JsValue>;

// stricter variant taking a JSON policy {expected_rp_id, allowed_origins, ...}
#[wasm_bindgen]
pub fn verify_webauthn_wrapping_with_policy(/* + policy_json: &str */) -> Result<bool, JsValue>;
```
Optionally export `build_client_data_json(pae, origin, cross_origin)` so the demo
can show the exact bytes the authenticator signs. These are thin pass-throughs;
no new crypto. Rebuild + re-vendor `mkit-wasm/pkg`.

### 3b. Browser ceremony (client)
- **Enroll:** `navigator.credentials.create({ publicKey: { pubKeyCredParams:[{alg:-7,type:"public-key"}], rp:{id:"mkit.sh"}, ... }})` → extract the P-256 public key (COSE → SEC1).
- **Sign:** `navigator.credentials.get({ publicKey: { challenge: PAE, ... }})` → returns `signature`, `authenticatorData`, `clientDataJSON`.
- **Verify:** feed those four+pae into the new WASM export → green check.

Recommended library: **`ox`'s `WebAuthnP256` module** (the low-level primitive under
`wevm/webauthx`) &mdash; it already does COSE→SEC1 key extraction, the `create`/`get`
ceremonies, and DER→compact `r,s` with low-S normalization, which is exactly
mkit's `verify_p256` contract. `webauthx` itself is the higher-level ceremony
orchestrator (client `Registration.create`/`Authentication.sign`); the demo likely
only needs its client half since **mkit's WASM is the verifier** &mdash; its server half is
redundant. `@simplewebauthn/browser` is the heavier, more conventional alternative.

### 3c. Demo UI
Extend `attest-demo.tsx` (or a new `passkey-demo.tsx`) with a "Sign with a passkey"
path alongside the seed path: Enroll button → Sign button (biometric prompt) →
Verifies ✓, showing the live `authenticatorData`/`clientDataJSON` so the
ceremony is legible. The existing seed-based P-256 path stays as the
"no-hardware" fallback.

---

## 4. The one real design fork: challenge sizing

mkit's verifier requires `clientDataJSON.challenge == base64url-nopad(PAE)` &mdash; that is,
**the entire PAE is the WebAuthn challenge.** For a DSSE attestation the PAE is
`"DSSEv1 <len> application/vnd.in-toto+json <len> <JCS statement>"`, which can run
to hundreds of bytes–1 KB for a realistic predicate.

WebAuthn challenges are arbitrary `BufferSource`, but **platform authenticators
(Apple/Android) impose practical caps** (roughly hundreds of bytes; not formally
specified, varies by platform). A large in-toto statement could exceed it.

Two options:
- **A &mdash; keep demo payloads small** (tiny claim JSON). Zero code change; works with
  the current verifier as-is. Cleanest for a *demo*. **Recommended starting point.**
- **B &mdash; add a hashed-challenge verifier variant** (`challenge == base64url(SHA-256(PAE))`)
  for production robustness. This is a SPEC-EXTERNAL-SIGNER/verifier change, not
  a demo concern &mdash; flag it, don't block on it.

Decide A for the demo; track B as a follow-up if/when this graduates to a real
signing path.

---

## 5. Whether an existing Apple/Google org is required

For **web** passkeys this is not required: a web passkey is bound to the site's
origin/RP ID (`mkit.sh`), and only needs the page served over HTTPS with a
matching RP ID. The Apple Developer/Google Play org matters only if the project
later extends to **native iOS/Android apps** sharing the same passkeys via
Apple App Site Association/Android Digital Asset Links &mdash; a separate, larger
effort. The browser demo can ship without touching either org.

RP-ID note: the demo's WASM verify should pass `expected_rp_id: "mkit.sh"` (and an
origin allow-list) via the policy variant so the green check actually proves
origin binding rather than accepting any assertion.

---

## 6. Effort estimate

| Piece | Size |
|---|---|
| 2 wasm-bindgen exports + rebuild/re-vendor | small (pass-through; crypto done) |
| Client ceremony via `ox`/`webauthx` | small–medium |
| Demo UI (enroll → sign → verify) | medium |
| Tests (golden browser-assertion vector) | small (one interop test exists; add a pinned real-browser vector) |

No new cryptography, no spec change for option A. The risky/expensive part &mdash;
a correct, low-S, policy-checked WebAuthn verifier &mdash; is already written and tested.

---

## 7. Open questions to confirm before building

1. Demo scope: passkey-signs-an-**attestation** (recommended, matches reality) vs.
   a mocked "passkey-signs-a-commit" (would misrepresent mkit's Ed25519 core).
2. Challenge sizing: option A (small payloads) for v1? (recommended)
3. Library: `ox` (lean) vs `webauthx` (full ceremony) vs `@simplewebauthn/browser`.
4. Should the WASM verify default to strict policy (`rp_id=mkit.sh`, origin
   allow-list) so the demo demonstrates origin binding, not just a raw signature?
