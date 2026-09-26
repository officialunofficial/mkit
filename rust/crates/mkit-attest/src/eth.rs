//! Ethereum-compatible primitives for the SPEC-WRITE-GRANTS §4 owner
//! schemes (`secp256k1-eip191`, and address derivation for
//! `webauthn-p256`).
//!
//! Keccak-256 here is the ORIGINAL Keccak submission (`0x01` padding) as
//! Ethereum uses it — never FIPS 202 SHA3-256 (`sha3::Sha3_256`), which
//! silently yields valid-looking but wrong addresses.
//!
//! The module keeps two roles apart (SPEC-WRITE-GRANTS §4.4):
//!
//! * **Verifier** functions ([`eip191_recover_address`],
//!   [`p256_check_raw_low_s`],
//!   [`address_secp256k1`], [`address_p256`]) are strict: they reject
//!   `v ∉ {27, 28}`, scalars outside `[1, n − 1]`, high-`s` signatures and
//!   off-curve keys, and never normalize anything.
//! * **Client** normalizers ([`normalize_eip191_signature`],
//!   [`p256_der_to_low_s_raw`]) turn what wallets and authenticators emit
//!   into the single canonical form a verifier accepts.
//!
//! Golden vectors: `rust/tests/golden/grants/eth-primitives.json`.

use k256::ecdsa::{
    RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey,
    signature::hazmat::PrehashVerifier,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha3::{Digest, Keccak256};

/// A 20-byte Ethereum-style address (SPEC-WRITE-GRANTS §4.1).
pub type Address = [u8; 20];

/// The EIP-191 version `0x45` ("personal message") prefix.
pub const EIP191_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n";

/// Failures of the Ethereum-compatible primitives.
///
/// Module-local on purpose: the crate's flat, published
/// [`crate::Error`] is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EthError {
    /// `v` is not 27 or 28 (verifier), or not in {0, 1, 27, 28} (client).
    #[error("EIP-191 recovery byte v is invalid")]
    RecoveryIdInvalid,
    /// `r` or `s` is zero or not below the curve order `n`.
    #[error("ECDSA scalar r or s is outside [1, n - 1]")]
    ScalarOutOfRange,
    /// `s` exceeds `n / 2`; a verifier rejects it and never normalizes.
    #[error("ECDSA signature is not low-S")]
    HighS,
    /// No public key could be recovered from the signature.
    #[error("secp256k1 public-key recovery failed")]
    RecoveryFailed,
    /// The coordinates are not a valid point on the curve.
    #[error("public key is not a valid curve point")]
    InvalidPoint,
    /// The input is not a strict-DER ECDSA P-256 signature.
    #[error("malformed DER ECDSA signature")]
    InvalidDer,
}

/// Keccak-256 (original Keccak, `0x01` padding) of `data`.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The EIP-191 version `0x45` message: [`EIP191_PREFIX`], the byte length
/// of `statement` in decimal ASCII, then `statement` (SPEC-WRITE-GRANTS §4).
#[must_use]
pub fn eip191_message(statement: &[u8]) -> Vec<u8> {
    let len = statement.len().to_string();
    let mut msg = Vec::with_capacity(EIP191_PREFIX.len() + len.len() + statement.len());
    msg.extend_from_slice(EIP191_PREFIX);
    msg.extend_from_slice(len.as_bytes());
    msg.extend_from_slice(statement);
    msg
}

/// Keccak-256 of [`eip191_message`]`(statement)`: the digest a
/// `secp256k1-eip191` owner signs.
#[must_use]
pub fn eip191_hash(statement: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(EIP191_PREFIX);
    h.update(statement.len().to_string().as_bytes());
    h.update(statement);
    h.finalize().into()
}

/// Verifier: strictly recover the secp256k1 public key (`x ‖ y`, 64 bytes)
/// from a 65-byte `r ‖ s ‖ v` signature over `prehash`.
///
/// `prehash` MUST be a Keccak-256 digest (see [`eip191_hash`]). Recovery
/// from any other value "succeeds" with a meaningless key, so this stays
/// crate-private and callers go through [`eip191_recover_address`].
///
/// # Errors
/// * [`EthError::RecoveryIdInvalid`] — `v ∉ {27, 28}`.
/// * [`EthError::ScalarOutOfRange`] — `r` or `s` outside `[1, n − 1]`.
/// * [`EthError::HighS`] — `s > n / 2` (never normalized).
/// * [`EthError::RecoveryFailed`] — no key recovers, or it does not verify.
pub(crate) fn recover_secp256k1(prehash: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 64], EthError> {
    let is_y_odd = match sig[64] {
        27 => false,
        28 => true,
        _ => return Err(EthError::RecoveryIdInvalid),
    };
    let signature =
        K256Signature::from_slice(&sig[..64]).map_err(|_| EthError::ScalarOutOfRange)?;
    // Low-S: `normalize_s` is a no-op iff `s <= n / 2`.
    if signature.normalize_s() != signature {
        return Err(EthError::HighS);
    }
    // `v ∈ {27, 28}` only ever names recovery ids 0 and 1: `x` is never
    // reduced.
    let recid = RecoveryId::new(is_y_odd, false);
    let key = K256VerifyingKey::recover_from_prehash(prehash, &signature, recid)
        .map_err(|_| EthError::RecoveryFailed)?;
    // A correctly recovered key always verifies (by construction), so this
    // never fires today. It guards against a future regression in the
    // ecdsa/k256 recovery code, which does not re-verify in 0.17; it is not
    // a defense against any known attack.
    key.verify_prehash(prehash, &signature)
        .map_err(|_| EthError::RecoveryFailed)?;
    let point = key.to_sec1_point(false);
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&point.as_bytes()[1..]);
    Ok(xy)
}

/// Verifier: the address (§4.1) of the secp256k1 key that produced the
/// 65-byte `r ‖ s ‖ v` signature over [`eip191_hash`]`(statement)`.
///
/// A successful recovery is never authorization: any well-formed
/// signature recovers *some* address. The caller MUST compare the returned
/// address with the `0x` namespace it is authorizing (SPEC-WRITE-GRANTS
/// §2) and reject on mismatch.
///
/// # Errors
/// * [`EthError::RecoveryIdInvalid`] — `v ∉ {27, 28}`.
/// * [`EthError::ScalarOutOfRange`] — `r` or `s` outside `[1, n − 1]`.
/// * [`EthError::HighS`] — `s > n / 2` (never normalized).
/// * [`EthError::RecoveryFailed`] — no key recovers, or it does not verify.
/// * [`EthError::InvalidPoint`] — the recovered key is not a curve point
///   (unreachable in practice).
pub fn eip191_recover_address(statement: &[u8], sig: &[u8; 65]) -> Result<Address, EthError> {
    let xy = recover_secp256k1(&eip191_hash(statement), sig)?;
    address_secp256k1(&xy)
}

/// Curve-validated secp256k1 address (SPEC-WRITE-GRANTS §4.1): the last
/// 20 bytes of Keccak-256 of `x ‖ y`.
///
/// # Errors
/// [`EthError::InvalidPoint`] — `x ‖ y` is not on secp256k1. The point at
/// infinity has no 64-byte encoding, so it can never pass.
pub fn address_secp256k1(xy: &[u8; 64]) -> Result<Address, EthError> {
    K256VerifyingKey::from_sec1_bytes(&uncompressed(xy)).map_err(|_| EthError::InvalidPoint)?;
    Ok(address_of_xy(xy))
}

/// Curve-validated P-256 address (SPEC-WRITE-GRANTS §4.1): the last 20
/// bytes of Keccak-256 of `x ‖ y`.
///
/// # Errors
/// [`EthError::InvalidPoint`] — `x ‖ y` is not on P-256.
pub fn address_p256(xy: &[u8; 64]) -> Result<Address, EthError> {
    P256VerifyingKey::from_sec1_bytes(&uncompressed(xy)).map_err(|_| EthError::InvalidPoint)?;
    Ok(address_of_xy(xy))
}

/// The namespace digits of an address: 40 lowercase hexadecimal digits,
/// no `0x` prefix, no mixed-case checksum (SPEC-WRITE-GRANTS §2).
#[must_use]
pub fn address_hex(a: &Address) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(40);
    for b in a {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Client (SPEC-WRITE-GRANTS §4.4): bring a wallet's EIP-191 signature into
/// the canonical form. `v ∈ {0, 1}` gains 27; a high `s` becomes `n − s`
/// and `v` flips between 27 and 28.
///
/// # Errors
/// * [`EthError::RecoveryIdInvalid`] — `v ∉ {0, 1, 27, 28}`.
/// * [`EthError::ScalarOutOfRange`] — `r` or `s` outside `[1, n − 1]`.
pub fn normalize_eip191_signature(sig: [u8; 65]) -> Result<[u8; 65], EthError> {
    let mut v = match sig[64] {
        v @ (0 | 1) => v + 27,
        v @ (27 | 28) => v,
        _ => return Err(EthError::RecoveryIdInvalid),
    };
    let signature =
        K256Signature::from_slice(&sig[..64]).map_err(|_| EthError::ScalarOutOfRange)?;
    let low = signature.normalize_s();
    if low != signature {
        v = if v == 27 { 28 } else { 27 };
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&low.to_bytes());
    out[64] = v;
    Ok(out)
}

/// Client (SPEC-WRITE-GRANTS §4.4): decode a strict-DER ECDSA P-256
/// signature into raw `r ‖ s` with `s` normalized to at most `n / 2`.
/// Never call this on the verify path; use [`p256_check_raw_low_s`].
///
/// # Errors
/// [`EthError::InvalidDer`] — not strict DER (BER forms, non-minimal
/// integers, trailing bytes), or `r`/`s` outside `[1, n − 1]`.
pub fn p256_der_to_low_s_raw(der: &[u8]) -> Result<[u8; 64], EthError> {
    let signature = P256Signature::from_der(der).map_err(|_| EthError::InvalidDer)?;
    Ok(signature.normalize_s().to_bytes().into())
}

/// Verifier (SPEC-WRITE-GRANTS §4.4): a raw P-256 `r ‖ s` has both scalars
/// in `[1, n − 1]` and `s <= n / 2`. Never normalizes.
///
/// # Errors
/// * [`EthError::ScalarOutOfRange`] — `r` or `s` outside `[1, n − 1]`.
/// * [`EthError::HighS`] — `s > n / 2`.
pub fn p256_check_raw_low_s(raw: &[u8; 64]) -> Result<(), EthError> {
    let signature = P256Signature::from_slice(raw).map_err(|_| EthError::ScalarOutOfRange)?;
    if signature.normalize_s() != signature {
        return Err(EthError::HighS);
    }
    Ok(())
}

// -- Internals -------------------------------------------------------

fn uncompressed(xy: &[u8; 64]) -> [u8; 65] {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(xy);
    sec1
}

fn address_of_xy(xy: &[u8; 64]) -> Address {
    let digest = keccak256(xy);
    let mut a = [0u8; 20];
    a.copy_from_slice(&digest[12..]);
    a
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap is the assertion in tests
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// web3.js `accounts.sign('Some data', key)` documented vector,
    /// re-confirmed with Foundry `cast wallet sign`.
    const PUB_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    const PUB_SIG: &str = "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd\
                           6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c";
    const PUB_ADDR: &str = "2c7536e3605d9c16a7a3d7b1898e529396a65c23";
    /// `PUB_SIG` with `s' = n − s` and `v` flipped (computed in Python).
    const PUB_SIG_HIGH_S: &str = "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd\
                                  9ff818b327d1fc847ffe79bdd03d25e83e3a5df66962ceb160751b8bd754a1181b";
    const SECP256K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// secp256k1 generator `G` (SEC 2 §2.4.1), i.e. the key of `d = 1`.
    const K1_G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                        483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    /// P-256 generator `G` (SEC 2 §2.4.2 / FIPS 186-4 D.1.2.3).
    const P256_G: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                          4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    /// secp256k1 `x = p + 1`, `y = sqrt(1 + 7) mod p`.
    const K1_X_P_PLUS_1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30\
                                 4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee";
    /// P-256 `x = p`, `y = sqrt(b) mod p`.
    const P256_X_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
                            66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";

    /// pycryptodome `DSS(deterministic-rfc6979, der)` P-256 signature,
    /// re-encoded with `s' = n − s` (high) via `DerSequence`.
    const P256_DER_HIGH_S: &str = "3046022100907b70536a3d9eb8726087f33ea2f8ffb76bc9ed5caa4aec4f60a857687f6ab8\
                                   022100a7ce9054d0b2be95d8c96be889576d81de875aac7cb648ffb197cd7e68a813a4";
    /// The same signature as low-S DER, straight from pycryptodome.
    const P256_DER_LOW_S: &str = "3045022100907b70536a3d9eb8726087f33ea2f8ffb76bc9ed5caa4aec4f60a857687f6ab8\
                                  022058316faa2f4d416b2736941776a8927dde5fa0012a6155854221fd4493bb11ad";
    const P256_RAW_LOW_S: &str = "907b70536a3d9eb8726087f33ea2f8ffb76bc9ed5caa4aec4f60a857687f6ab8\
                                  58316faa2f4d416b2736941776a8927dde5fa0012a6155854221fd4493bb11ad";

    fn strip(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn keccak256_empty_is_ethereum_keccak() {
        let k = keccak256(b"");
        assert_eq!(
            hex::encode(k),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // FIPS 202 SHA3-256("") — the value a `Sha3_256` mix-up would give.
        assert_ne!(
            hex::encode(k),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn eip191_hash_matches_public_vector() {
        assert_eq!(
            hex::encode(eip191_hash(b"Some data")),
            "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
        );
        assert_eq!(
            eip191_hash(b"Some data"),
            keccak256(&eip191_message(b"Some data"))
        );
    }

    #[test]
    fn eip191_message_length_is_decimal_ascii() {
        for (len, digits) in [
            (0usize, "0"),
            (9, "9"),
            (10, "10"),
            (4096, "4096"),
            (4097, "4097"),
        ] {
            let statement = vec![b'a'; len];
            let msg = eip191_message(&statement);
            let mut expected = EIP191_PREFIX.to_vec();
            expected.extend_from_slice(digits.as_bytes());
            expected.extend_from_slice(&statement);
            assert_eq!(msg, expected, "length {len}");
            assert_eq!(
                eip191_hash(&statement),
                keccak256(&expected),
                "length {len}"
            );
        }
    }

    #[test]
    fn recover_public_vector() {
        let sig: [u8; 65] = h(&strip(PUB_SIG));
        let addr = eip191_recover_address(b"Some data", &sig).unwrap();
        assert_eq!(address_hex(&addr), PUB_ADDR);

        // The recovered key is the key of the documented private key.
        let xy = recover_secp256k1(&eip191_hash(b"Some data"), &sig).unwrap();
        let sk = k256::ecdsa::SigningKey::from_slice(&h::<32>(PUB_KEY)).unwrap();
        let expected = sk.verifying_key().to_sec1_point(false);
        assert_eq!(&xy[..], &expected.as_bytes()[1..]);
        assert_eq!(address_hex(&address_secp256k1(&xy).unwrap()), PUB_ADDR);
    }

    #[test]
    fn recover_other_message_gives_other_address() {
        let sig: [u8; 65] = h(&strip(PUB_SIG));
        let addr = eip191_recover_address(b"Some datb", &sig).unwrap();
        assert_ne!(address_hex(&addr), PUB_ADDR);
    }

    #[test]
    fn recover_rejects_high_s() {
        let high: [u8; 65] = h(&strip(PUB_SIG_HIGH_S));
        assert_eq!(
            eip191_recover_address(b"Some data", &high),
            Err(EthError::HighS)
        );
        assert_eq!(
            recover_secp256k1(&eip191_hash(b"Some data"), &high),
            Err(EthError::HighS)
        );
        // The client normalizer maps the high-s twin back to the original.
        let original: [u8; 65] = h(&strip(PUB_SIG));
        assert_eq!(normalize_eip191_signature(high).unwrap(), original);
        // ... and leaves a canonical signature untouched.
        assert_eq!(normalize_eip191_signature(original).unwrap(), original);
    }

    #[test]
    fn recover_rejects_bad_v() {
        let mut sig: [u8; 65] = h(&strip(PUB_SIG));
        for v in [0u8, 1, 26, 29, 35, 255] {
            sig[64] = v;
            assert_eq!(
                eip191_recover_address(b"Some data", &sig),
                Err(EthError::RecoveryIdInvalid),
                "v = {v}"
            );
        }
    }

    #[test]
    fn recover_rejects_scalar_range() {
        let sig: [u8; 65] = h(&strip(PUB_SIG));
        let n: [u8; 32] = h(SECP256K1_N);
        let mut cases = Vec::new();
        for (field, value) in [(0usize, [0u8; 32]), (32, [0u8; 32]), (0, n), (32, n)] {
            let mut bad = sig;
            bad[field..field + 32].copy_from_slice(&value);
            cases.push(bad);
        }
        for bad in cases {
            assert_eq!(
                eip191_recover_address(b"Some data", &bad),
                Err(EthError::ScalarOutOfRange)
            );
            assert_eq!(
                normalize_eip191_signature(bad),
                Err(EthError::ScalarOutOfRange)
            );
        }
    }

    #[test]
    fn normalize_adds_27_to_v_zero_and_one() {
        let original: [u8; 65] = h(&strip(PUB_SIG)); // v = 28
        let mut raw = original;
        raw[64] = 1;
        assert_eq!(normalize_eip191_signature(raw).unwrap(), original);
        raw[64] = 0;
        let mut expected = original;
        expected[64] = 27;
        assert_eq!(normalize_eip191_signature(raw).unwrap(), expected);
        // v = 0 with a high s: +27, then flip.
        let mut high: [u8; 65] = h(&strip(PUB_SIG_HIGH_S)); // v = 27
        high[64] = 0;
        assert_eq!(normalize_eip191_signature(high).unwrap(), original);
        for v in [2u8, 26, 29, 35, 255] {
            raw[64] = v;
            assert_eq!(
                normalize_eip191_signature(raw),
                Err(EthError::RecoveryIdInvalid),
                "v = {v}"
            );
        }
    }

    #[test]
    fn address_of_secp256k1_key_one() {
        let a = address_secp256k1(&h(&strip(K1_G))).unwrap();
        assert_eq!(address_hex(&a), "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn address_of_p256_key_one() {
        let a = address_p256(&h(&strip(P256_G))).unwrap();
        assert_eq!(address_hex(&a), "d3a9f047ad43d7e2e4e7e491f1fe2e657a2651b6");
    }

    #[test]
    fn address_rejects_off_curve() {
        let zero = [0u8; 64];
        assert_eq!(address_secp256k1(&zero), Err(EthError::InvalidPoint));
        assert_eq!(address_p256(&zero), Err(EthError::InvalidPoint));

        let mut k1: [u8; 64] = h(&strip(K1_G));
        k1[63] ^= 0x01;
        assert_eq!(address_secp256k1(&k1), Err(EthError::InvalidPoint));
        let mut p: [u8; 64] = h(&strip(P256_G));
        p[63] ^= 0x01;
        assert_eq!(address_p256(&p), Err(EthError::InvalidPoint));

        // Non-canonical coordinates: `x ≥ p` whose reduction mod p IS on
        // the curve (secp256k1 x = p + 1 ≡ 1, P-256 x = p ≡ 0, with the
        // matching y computed in Python), so only the range check rejects.
        assert_eq!(
            address_secp256k1(&h(K1_X_P_PLUS_1)),
            Err(EthError::InvalidPoint)
        );
        assert_eq!(address_p256(&h(P256_X_P)), Err(EthError::InvalidPoint));

        // Each curve's generator is not a point on the other curve.
        assert_eq!(address_p256(&h(&strip(K1_G))), Err(EthError::InvalidPoint));
        assert_eq!(
            address_secp256k1(&h(&strip(P256_G))),
            Err(EthError::InvalidPoint)
        );
    }

    #[test]
    fn address_hex_is_lowercase_without_prefix() {
        let a: Address = [0xAB; 20];
        assert_eq!(address_hex(&a), "ab".repeat(20));
    }

    #[test]
    fn p256_der_high_s_is_normalized_by_client_and_rejected_raw_by_verifier() {
        let high_der = hex::decode(strip(P256_DER_HIGH_S)).unwrap();
        let low_raw: [u8; 64] = h(&strip(P256_RAW_LOW_S));
        // Client: DER high-S -> raw low-S.
        assert_eq!(p256_der_to_low_s_raw(&high_der).unwrap(), low_raw);
        let low_der = hex::decode(strip(P256_DER_LOW_S)).unwrap();
        assert_eq!(p256_der_to_low_s_raw(&low_der).unwrap(), low_raw);
        // Verifier: the raw low-S form passes, the raw high-S form fails.
        assert_eq!(p256_check_raw_low_s(&low_raw), Ok(()));
        let mut high_raw = low_raw;
        high_raw[32..].copy_from_slice(&high_der[high_der.len() - 32..]);
        assert_eq!(p256_check_raw_low_s(&high_raw), Err(EthError::HighS));
    }

    #[test]
    fn p256_der_rejects_non_minimal_and_trailing_bytes() {
        let low_der = hex::decode(strip(P256_DER_LOW_S)).unwrap();
        // `s` starts 0x58 (high bit clear): a 0x00 pad is non-minimal.
        let mut non_minimal = vec![0x30, 0x46];
        non_minimal.extend_from_slice(&low_der[2..37]); // r TLV, unchanged
        non_minimal.extend_from_slice(&[0x02, 0x21, 0x00]);
        non_minimal.extend_from_slice(&low_der[39..]);
        assert_eq!(
            p256_der_to_low_s_raw(&non_minimal),
            Err(EthError::InvalidDer)
        );
        let mut trailing = low_der.clone();
        trailing.push(0x00);
        assert_eq!(p256_der_to_low_s_raw(&trailing), Err(EthError::InvalidDer));
        assert_eq!(p256_der_to_low_s_raw(&[]), Err(EthError::InvalidDer));
        assert_eq!(
            p256_der_to_low_s_raw(&low_raw_bytes()),
            Err(EthError::InvalidDer)
        );
    }

    /// `SEQUENCE { r_tlv, s_tlv }` with a short-form length.
    fn der_seq(r_tlv: &[u8], s_tlv: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30, u8::try_from(r_tlv.len() + s_tlv.len()).unwrap()];
        out.extend_from_slice(r_tlv);
        out.extend_from_slice(s_tlv);
        out
    }

    #[test]
    fn p256_der_rejects_malformed_integers_and_lengths() {
        let low_der = hex::decode(strip(P256_DER_LOW_S)).unwrap();
        let (r_tlv, s_tlv) = (&low_der[2..37], &low_der[37..]);
        let r_body = &r_tlv[3..]; // 32 bytes, after `02 21 00`
        let n: [u8; 32] = h(P256_N);

        let negative = der_seq(&[0x02, 0x01, 0x80], s_tlv);
        let mut wide = vec![0x02, 0x21, 0x01];
        wide.extend_from_slice(r_body);
        let too_wide = der_seq(&wide, s_tlv);
        let r_zero = der_seq(&[0x02, 0x01, 0x00], s_tlv);
        let mut r_n = vec![0x02, 0x21, 0x00];
        r_n.extend_from_slice(&n);
        let r_is_n = der_seq(&r_n, s_tlv);
        let mut long_form = vec![0x30, 0x81, low_der[1]];
        long_form.extend_from_slice(&low_der[2..]);

        for (name, der) in [
            ("negative integer", negative),
            ("33-byte integer", too_wide),
            ("r = 0", r_zero),
            ("r = n", r_is_n),
            ("long-form length", long_form),
        ] {
            assert_eq!(
                p256_der_to_low_s_raw(&der),
                Err(EthError::InvalidDer),
                "{name}"
            );
        }
    }

    fn low_raw_bytes() -> Vec<u8> {
        hex::decode(strip(P256_RAW_LOW_S)).unwrap()
    }

    #[test]
    fn p256_check_raw_rejects_scalar_range() {
        let low_raw: [u8; 64] = h(&strip(P256_RAW_LOW_S));
        let n: [u8; 32] = h(P256_N);
        for (field, value) in [(0usize, [0u8; 32]), (32, [0u8; 32]), (0, n), (32, n)] {
            let mut bad = low_raw;
            bad[field..field + 32].copy_from_slice(&value);
            assert_eq!(p256_check_raw_low_s(&bad), Err(EthError::ScalarOutOfRange));
        }
    }
}
