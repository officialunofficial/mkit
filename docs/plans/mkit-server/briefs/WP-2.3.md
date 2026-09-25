# WP-2.3: mkit-attest Keccak-256, EIP-191, secp256k1 recovery, address derivation

- **Milestone/track:** M2 / crypto (pure mkit-attest; may land during M0/M1)
- **Base:** `feat/mkit-server` at `392072d3` or later; **branch:** `mkit-server/wp-2-3-eth-primitives`
- **Depends on:** S2 (merged, `09a38456`; SPEC-WRITE-GRANTS §4, §4.1 and §4.4 are normative)
- **Unblocks:** 2.5 (the `secp256k1-eip191` and `webauthn-p256` owner schemes)
- **Parallel with:** 2.4a/2.4b (shared file: `rust/crates/mkit-attest/{Cargo.toml,src/lib.rs}`; see "Feature
  coordination"), 1.3, 4.1–4.3
- **Size:** M (~600–750 changed lines incl. tests; goldens excluded)
- **Area gates (registry):** `rust`, `wasm`, `sec`, `golden` (+ `docs`: this WP starts SPEC-WRITE-GRANTS §13.1's
  fixture list)

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-2-3-eth-primitives origin/feat/mkit-server`.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` before any test. The macOS `/tmp` symlink breaks
  exactly the mkit-attest sign tests.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body.
- Pre-production policy; `CHANGELOG.md` `[Unreleased]` entry; workspace lints; no `unsafe`; no proto change; stop
  and propose a split above ~1500 changed lines.
- Carry-forward notes:
  - `connectrpc` is 0.9.1. Adding `sha3` rewrites `rust/Cargo.lock`, so check the diff moves nothing else
    (`git diff rust/Cargo.lock` should add only `sha3`, and `keccak` if it isn't already a normal dependency).
  - wasm32 clippy needs `--no-deps`. `mkit-attest` has **2 pre-existing wasm32 lints**
    (`src/signer_external.rs:329`, `src/store.rs:235`), and `mkit-core` has 6. New code adds none.
  - Test timeouts under load also happen on the base branch. Re-run alone, and compare with base before calling it a
    regression.

## Goal

Add the Ethereum-compatible primitives the grant schemes need, in a new `mkit-attest/src/eth.rs` behind a new
`grants` feature, all wasm-safe:

- Keccak-256 (the original Keccak with `0x01` padding, **not** FIPS 202 SHA3-256).
- The EIP-191 version `0x45` personal-message digest.
- Strict low-S secp256k1 public-key recovery from `r‖s‖v`.
- Curve-validated address derivation for secp256k1 and P-256 keys (the last 20 bytes of Keccak-256 of `x‖y`).
- The **client-side** normalizers the spec mandates: EIP-191 `v`/high-`s` normalization, and P-256 DER to raw low-S
  `r‖s`.
- The **verifier-side** strict checks: no normalization, and rejection of high-`s` or out-of-range scalars.

Golden vectors come from public, independently verifiable references.

## PRD and spec refs

- PRD §6.4 (self-certifying `0x` namespaces; "P-256 signatures are normalized to low-S on the client"; "the grant
  verifier lives in mkit-attest (adding Keccak-256 and secp256k1 recovery)").
- **SPEC-WRITE-GRANTS §2** (the `0x` namespace = 40 lowercase hex, no checksum case).
- **§4** scheme table:
  - `secp256k1-eip191`: the message is `"\x19Ethereum Signed Message:\n"` + the statement's byte length in decimal
    ASCII + the statement. The digest is Keccak-256. The blob is `r(32) ‖ s(32) ‖ v`, with `v ∈ {27, 28}` and
    recovery id `v − 27`.
  - `webauthn-p256`: the blob's signature field is **raw 64-byte `r‖s`**, not DER.
- **§4.1:** the address is the last 20 bytes of Keccak-256 of the 64 coordinate bytes, and a verifier MUST reject a
  key that is not a valid curve point, including the point at infinity. Keccak-256, not SHA3-256.
- **§4.4:**
  - secp256k1: `r, s ∈ [1, n−1]`, `s ≤ n/2`; the verifier MUST reject high-`s` and MUST NOT normalize. A client MUST
    replace high `s` with `n − s` and flip `v`, and add 27 to `v ∈ {0, 1}`.
  - P-256: the client decodes DER and normalizes to low-S. The verifier rejects out-of-range or high-S and never
    normalizes.
- **§13.1** (planned fixtures under `rust/tests/golden/grants/`: an EIP-191 message and recovery; address derivation
  for a secp256k1 key and a P-256 key; a high-`s` signature for each ECDSA scheme).

## Scope

**IN**
- `sha3` dependency and `grants` feature.
- `eth.rs` with the API below.
- `EthError`.
- Goldens with cross-checks.
- SPEC-WRITE-GRANTS §13.1: list this WP's fixtures, and change the Status paragraph from "lists none until then" to
  "lists them in §13.1".
- CHANGELOG.

**OUT**
- Scheme binding to namespaces, grant parsing, and WebAuthn assertion checks: 2.4a/2.4b/2.5.
- Any server or CLI code.
- Signing with wallets or keystore (2.13).
- `mkit-wasm` exports.

## Files and symbols (tip `392072d3`)

| File | What exists | Change |
|---|---|---|
| `rust/crates/mkit-attest/Cargo.toml` | features `default`/`algo-*` :26–29; `mkit-core` (no default features) :64; `blake3` :68; `base64 = "0.23"` :69; `k256 0.14` (`ecdsa`,`std`,`pkcs8`) :90; `p256 0.14` :94; `sha2 0.11` (no default features) :100 | Add `sha3 = { version = "0.11", default-features = false, optional = true }` and the `grants` feature. |
| `rust/crates/mkit-attest/src/lib.rs` | module list :45–67; `pub enum Error` :102 (flat, published) | `#[cfg(feature = "grants")] pub mod eth;`. **Don't** add variants to `Error`: use a module-local `EthError`. |
| `rust/crates/mkit-attest/src/eth.rs` | — | New |
| `rust/crates/mkit-attest/src/signer_k256.rs` | `verify_secp256k1` :175 (low-S check via `sig.normalize_s() != sig`) | Reference only: reuse the same low-S idiom |
| `rust/crates/mkit-attest/src/signer_p256.rs` | `verify_p256` :186 (compact, low-S enforced) | Reference only |
| `rust/tests/golden/grants/{eth-primitives.json,MANIFEST.txt}` | — | New |
| `docs/specs/SPEC-WRITE-GRANTS.md` | Status paragraph (lines 10–14), §13.1 | List fixtures |
| `CHANGELOG.md` | | `### Added` |

Resolved versions (`rust/Cargo.lock`): `ecdsa 0.17.0`, `k256 0.14.0`, `p256 0.14.0`, `elliptic-curve 0.14.1`,
`digest 0.10.7` and `0.11.3`, `sha2 0.11.0`, `keccak 0.2.2`. `sha3 0.11.0` depends on `digest 0.11` and `keccak 0.2`
(so no new digest major). `sha3 0.12.0` exists but adds `sponge-cursor`; stay on 0.11.

### Feature coordination (2.3 vs 2.4a/2.4b)

Both WPs gate on one feature. Use this exact line so the second PR's rebase is trivial:

```toml
grants = ["algo-ed25519", "algo-secp256k1", "algo-p256", "dep:sha3"]
```

If 2.4a merges first, it lands `grants = ["algo-ed25519"]` without `sha3`, and this WP widens the line on rebase.
`grants` is **not** default. `mkit-wasm` (`rust/crates/mkit-wasm/Cargo.toml:46`, default features) is unaffected.

## Design

```rust
//! Ethereum-compatible primitives for SPEC-WRITE-GRANTS §4 owner schemes.
//! Keccak-256 here is the ORIGINAL Keccak (0x01 padding) as Ethereum uses it — never `sha3::Sha3_256`.

pub type Address = [u8; 20];
pub const EIP191_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

#[must_use] pub fn keccak256(data: &[u8]) -> [u8; 32];                 // sha3::Keccak256
#[must_use] pub fn eip191_message(statement: &[u8]) -> Vec<u8>;        // prefix || decimal len || statement
#[must_use] pub fn eip191_hash(statement: &[u8]) -> [u8; 32];          // keccak256(eip191_message(..))

/// Verifier: strict recovery. Rejects v ∉ {27,28}, r or s ∉ [1, n−1], s > n/2 (`HighS`, never normalized).
/// `prehash` MUST be a Keccak-256 digest (see `eip191_hash`); passing any other digest recovers a meaningless key.
pub fn recover_secp256k1(prehash: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 64], EthError>;  // returns x||y
/// `eip191_hash` + `recover_secp256k1` + `address_secp256k1`.
pub fn eip191_recover_address(statement: &[u8], sig: &[u8; 65]) -> Result<Address, EthError>;

/// Curve-validated derivation (§4.1): parse 0x04||x||y with the curve crate first (rejects off-curve points;
/// the identity has no 65-byte encoding), then keccak256(x||y)[12..].
pub fn address_secp256k1(xy: &[u8; 64]) -> Result<Address, EthError>;
pub fn address_p256(xy: &[u8; 64]) -> Result<Address, EthError>;
#[must_use] pub fn address_hex(a: &Address) -> String;                 // 40 lowercase hex, no "0x", no checksum case

/// Client-side (§4.4): v ∈ {0,1} → +27; high s → n − s and flip v 27↔28. Rejects r/s out of range, v ∉ {0,1,27,28}.
pub fn normalize_eip191_signature(sig: [u8; 65]) -> Result<[u8; 65], EthError>;
/// Client-side (§4.4): decode a DER ECDSA-P256 signature (strict DER) into raw r||s with s normalized to <= n/2.
pub fn p256_der_to_low_s_raw(der: &[u8]) -> Result<[u8; 64], EthError>;
/// Verifier-side (§4.4): r, s ∈ [1, n−1] and s <= n/2; never normalizes.
pub fn p256_check_raw_low_s(raw: &[u8; 64]) -> Result<(), EthError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EthError { RecoveryIdInvalid, ScalarOutOfRange, HighS, RecoveryFailed, InvalidPoint, InvalidDer }
```

Implementation notes. The ecdsa 0.17 / elliptic-curve 0.14 API moved between minors, so check the pinned sources in
`~/.cargo/registry` and don't rely on memory.
- `k256::ecdsa::Signature::from_scalars` rejects zero and scalars ≥ n.
- Low-S uses the repo idiom `sig.normalize_s() != sig` (`signer_k256.rs:185`).
- `RecoveryId::new(is_y_odd = v == 28, is_x_reduced = false)`.
- `VerifyingKey::recover_from_prehash(prehash, &sig, recid)`.
- For the uncompressed point use the crate's SEC1 encoding; its name may be `to_encoded_point(false)` or `to_sec1_*`.
- Recovery ids 2 and 3 (x-reduced) are never produced from `v ∈ {27, 28}`.

## Tests to write first

- `keccak256_empty_is_ethereum_keccak`: `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, and a
  negative check that it differs from SHA3-256("")
  `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.
- `eip191_hash_matches_public_vector`: `"Some data"` →
  `1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655`.
- `recover_public_vector`: key `0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318` signs
  `"Some data"`, giving sig
  `b91467e5…f5fd` ‖ `6007e74c…a029` ‖ `1c`
  (full value
  `0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c`),
  and recovers address `2c7536e3605d9c16a7a3d7b1898e529396a65c23`. This is the web3.js-documented vector,
  re-confirmed with Foundry `cast`.
- `address_of_secp256k1_key_one`: the generator point's address is `7e5f4552091a69125d5dfcb7b8c2659029395bdf`.
- `address_of_p256_key_one`: the P-256 generator (d = 1) gives `d3a9f047ad43d7e2e4e7e491f1fe2e657a2651b6` (from
  pycryptodome + Keccak).
- `recover_rejects_high_s` (build it from the public vector: `s' = n − s`, `v` flipped). The verifier returns
  `HighS`, and `normalize_eip191_signature` maps it back to the original bytes.
- `recover_rejects_bad_v` for 0, 1, 26, 29, 35 and 255.
- `recover_rejects_scalar_range` for r = 0, s = 0, r = n and s = n.
- `recover_other_message_gives_other_address` (not an error).
- `address_rejects_off_curve` (all-zero `x‖y`, and a flipped `y` coordinate) for both curves.
- `p256_der_high_s_is_normalized_by_client_and_rejected_raw_by_verifier`. Also: DER with a leading-zero
  non-minimal integer is rejected (`InvalidDer`), and trailing bytes after the DER sequence are rejected.
- `eip191_message_length_is_decimal_ascii` for statement lengths 0, 9, 10, 4096 and 4097.
- Golden-driven: `eth_primitives_golden_vectors` reads `eth-primitives.json` and asserts every entry.

## Golden-vector plan (SPEC-CONVENTIONS §5; mandatory)

**Fixture:** `rust/tests/golden/grants/eth-primitives.json`, plus a `MANIFEST.txt` with its BLAKE3. Sections:

1. `keccak256`: `""`, `"abc"`, and a 4096-byte statement-shaped input (lines built from the SPEC-WRITE-GRANTS §3.4
   example, repeated to 4096 bytes), each with its Keccak-256. Plus one `sha3_256_negative` entry.
2. `eip191`: the public "Some data" vector (message, digest, private key, 65-byte sig, address). Plus one grant-shaped
   statement: the §3.4 example grant text byte for byte (≈ 400 bytes, multi-line), signed by a fixed test key with
   the message, digest, sig and recovered address recorded.
3. `high_s`: the high-`s` twin of each `eip191` signature, with `expected: "HighS"` and `normalized` = the original.
4. `address`: secp256k1 key 1, and one fixed random secp256k1 key; P-256 key 1, and one fixed random P-256 key (each
   `{ curve, private_key, x, y, address }`).
5. `p256_der`: one DER signature whose `s` is high, with its expected normalized raw `r‖s`; and one malformed DER with
   `expected: "InvalidDer"`.

**Generation.** A `MKIT_WRITE_GOLDEN=1` test in `rust/crates/mkit-attest/tests/golden_eth.rs` writes the file.
Expected values then come **from the references below, not from the code under test**: the generator may compute
them, but the PR must show that each one equals the independent value.

**Independent cross-check** (commands, tool versions and outputs go in the PR body):

| Value | Reference | Command |
|---|---|---|
| Keccak-256 | Foundry `cast` (1.6.x) | `cast keccak ""`, `cast keccak 0x<hex>` |
| EIP-191 digest | `cast hash-message "<msg>"` and viem `hashMessage` | `bun x`/node in a temp dir: `import { hashMessage } from 'viem'` |
| EIP-191 signature | `cast wallet sign --private-key <k> "<msg>"` (RFC 6979, low-S) | compare r, s and v byte for byte |
| Recovered address | viem `recoverMessageAddress({ message, signature })` and `cast wallet verify` | lowercase the result |
| secp256k1 address | `cast wallet address --private-key <k>` | |
| P-256 address | Python pycryptodome: `ECC.construct(curve='P-256', d=k)`, then `Crypto.Hash.keccak.new(digest_bits=256)` of `x‖y` | |
| P-256 DER normalization | pycryptodome `DSS` (DER), then flip `s ↦ n − s` in Python | |

Verified while writing this brief with `cast 1.6.0-nightly` and pycryptodome 3.23:
- `keccak("")` = `c5d24601…a470`
- `hash-message("Some data")` = `1da44b58…1655`
- `sign` = `b91467e5…0291c`
- key-1 address = `0x7E5F…5Bdf`
- P-256 key-1 address = `d3a9f047…51b6`

**Spec update:** SPEC-WRITE-GRANTS Status paragraph and §13.1: list `grants/eth-primitives.json` and what it pins.
The file overlaps with 2.4a/2.4b/2.5, which append their fixtures; merge in registry order and rebase.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p mkit-attest --all-features -p mkit-keystore -p mkit-cli -p mkit-wasm )
( cd rust && cargo test --doc -p mkit-attest --all-features )
# wasm
( cd rust && cargo check -p mkit-attest --features grants --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-attest --features grants --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # ONLY the 2 baseline sites: signer_external.rs:329, store.rs:235
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
bash scripts/check-wasm-dep-graph.sh
# crypto stack + security (new dependency)
bash scripts/check-crypto-stack-version.sh     # sha2 / ed25519-dalek pins must be unchanged
just ci-security                               # cargo audit + cargo deny (licenses: sha3/keccak are MIT OR Apache-2.0)
just ci-geiger
just ci-scripts                                # spec status (SPEC-WRITE-GRANTS edited)
just ci                                        # rust/Cargo.lock changed
```

## Acceptance checklist

- [ ] `eth.rs` behind `grants`, with the API above. Keccak is `sha3::Keccak256`; a test proves it is not SHA3-256.
- [ ] The verifier functions never normalize: they reject high-S, out-of-range scalars and bad `v`. The client
      normalizers are separate functions, named for that role.
- [ ] Address derivation validates the curve point for both curves.
- [ ] Goldens committed. Every value is cross-checked against `cast`/viem/pycryptodome, with evidence in the PR body.
- [ ] `check-crypto-stack-version.sh`, `just ci-security` and `just ci-geiger` pass. The `Cargo.lock` diff adds only
      `sha3` (and `keccak` if needed).
- [ ] wasm32 check with `--features grants` passes; wasm clippy shows only the 2 baseline mkit-attest sites.
- [ ] SPEC-WRITE-GRANTS §13.1 lists the new fixture.
- [ ] `mkit-attest`'s public `Error` enum is unchanged.

## Risks

- **SHA3 vs Keccak.** `sha3::Sha3_256` silently gives valid-looking wrong addresses. The empty-input test pins the
  distinction.
- **Recovery misuse.** Recovery from a non-Keccak prehash "succeeds" with a random key. The public API funnels through
  `eip191_recover_address`; document the prehash contract on `recover_secp256k1`.
- **Malleability.** k256 `verify_prehash` rejects high-S, but recovery may not. Always check low-S explicitly before
  recovering.
- **DER strictness.** The P-256 DER parser is client-side, but a lenient one could accept BER. Use
  `p256::ecdsa::Signature::from_der` (strict; it needs ecdsa's `der` feature, which the existing `pkcs8` feature
  should already pull in, so confirm with `cargo tree -e features -p mkit-attest`) and test the non-minimal-integer
  case.
- **Crate API drift** (`ecdsa 0.17`). Read the pinned sources for `RecoveryId` and the SEC1 encoding methods.

## Spec vs breakdown (specs win)

1. The breakdown's `p256_der_to_compact_low_s_required` ("reject high-S; the client side normalizes") and grounding
   fact G16 ("the grant blob carries a **DER** signature, so the verifier must parse DER") contradict SPEC-WRITE-GRANTS
   §4 and §4.4. There the `webauthn-p256` blob carries a **raw 64-byte `r‖s`**, the **client** decodes DER and
   normalizes to low-S, and the verifier rejects high-S raw signatures without normalizing. This brief splits the
   helper into `p256_der_to_low_s_raw` (client) and `p256_check_raw_low_s` (verifier). 2.5 must not parse DER on the
   verify path.
2. The breakdown's single `address_from_uncompressed(x||y)` "for both" curves can't satisfy §4.1's "MUST reject a
   public key that is not a valid point on its curve", because validation is curve-specific. This brief uses
   `address_secp256k1` and `address_p256`.
3. §4.4 also mandates client normalization of EIP-191 signatures (`v ∈ {0, 1}` → +27; high-`s` flip). The breakdown
   omits it; it is added here as `normalize_eip191_signature`.
4. §4.4 requires `r, s ∈ [1, n−1]` explicitly. The breakdown only mentions low-S.
