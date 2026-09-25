//! Golden vectors for the `grants` feature's Ethereum-compatible
//! primitives (SPEC-WRITE-GRANTS §4, §4.1, §4.4; fixture list in §13.1).
//!
//! Two independent halves, as in `mkit-core/tests/golden_proofs.rs`:
//!
//! * [`write_all`] (run via `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest
//!   --features grants --test golden_eth`) regenerates
//!   `rust/tests/golden/grants/eth-primitives.json` and `MANIFEST.txt`
//!   from the pinned inputs below. Do not hand-edit the fixture.
//! * [`eth_primitives_golden_vectors`] reads ONLY the committed files and
//!   replays every entry against the public API.
//!
//! The expected values are not trusted because this crate computed them:
//! every value was cross-checked against independent implementations
//! (Foundry `cast`, viem, pycryptodome); the `cross_check` member of the
//! fixture records the reference for each section.

#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use k256::ecdsa::SigningKey as K256SigningKey;
use mkit_attest::eth::{
    EthError, address_hex, address_p256, address_secp256k1, eip191_hash, eip191_message,
    eip191_recover_address, keccak256, normalize_eip191_signature, p256_check_raw_low_s,
    p256_der_to_low_s_raw, recover_secp256k1,
};
use mkit_attest::signer_p256::verify_p256;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

/// SPEC-WRITE-GRANTS §3.4's example grant, byte for byte (no final LF).
const SPEC_EXAMPLE_GRANT: &str = "mkit-write-grant:v1
0x8ba1f109551bd432803012645ac136ddd64dba72
0x8ba1f109551bd432803012645ac136ddd64dba72/website
3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
read,write
https://git.example.com,https://git.example.org
refs/heads/main=cu;refs/heads/wip/*=cufd
0
1790000000000
1792592000000
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// web3.js `accounts.sign` documented key (signs `"Some data"`).
const WEB3JS_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
/// Fixed random secp256k1 test key (`openssl rand -hex 32`).
const K1_RANDOM_KEY: &str = "ff7cee05af83d7455a2d595a3f4209070800a7f4e8ce75ee887ff2e65f80ed2e";
/// Fixed random P-256 test key (`openssl rand -hex 32`).
const P256_RANDOM_KEY: &str = "288b5057f98ab3cb8576707c39b2706379a1ad45bf7739df9f828c65d483df14";
/// The message of the P-256 DER vector.
const P256_DER_MESSAGE: &str = "mkit eth-primitives p256 der vector";

const SECP256K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn grants_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is rust/crates/mkit-attest; goldens live in rust/tests/golden.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/grants")
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

fn key_one() -> String {
    format!("{:064x}", 1)
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{key}` in {v}"));
    hex::decode(s).unwrap_or_else(|e| panic!("field `{key}` is not hex: {e}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field `{key}` in {v}"))
}

/// `n − s` for 32-byte big-endian values (`s < n`).
fn sub_from_order(n_hex: &str, s: &[u8]) -> [u8; 32] {
    let n = h32(n_hex);
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(n[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[i] = u8::try_from(d).unwrap();
    }
    assert_eq!(borrow, 0, "s must be below n");
    out
}

/// 4096 bytes of statement-shaped input: the §3.4 example, each copy
/// followed by LF, repeated and truncated to 4096 bytes.
fn statement_shaped_4096() -> Vec<u8> {
    let line = format!("{SPEC_EXAMPLE_GRANT}\n");
    line.as_bytes().iter().copied().cycle().take(4096).collect()
}

// -- Generator ---------------------------------------------------------

fn eip191_entry(name: &str, key_hex: &str, statement: &[u8]) -> (Value, Value) {
    let sk = K256SigningKey::from_slice(&h32(key_hex)).unwrap();
    let digest = eip191_hash(statement);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest);
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(&sig.to_bytes());
    sig65[64] = 27 + recid.to_byte();
    let address = eip191_recover_address(statement, &sig65).unwrap();

    let mut high = sig65;
    high[32..64].copy_from_slice(&sub_from_order(SECP256K1_N, &sig65[32..64]));
    high[64] = if sig65[64] == 27 { 28 } else { 27 };

    let entry = json!({
        "name": name,
        "statement": String::from_utf8(statement.to_vec()).unwrap(),
        "message_hex": hex::encode(eip191_message(statement)),
        "digest": hex::encode(digest),
        "private_key": key_hex,
        "signature": hex::encode(sig65),
        "address": address_hex(&address),
    });
    let high_entry = json!({
        "name": format!("{name}/high-s"),
        "statement": String::from_utf8(statement.to_vec()).unwrap(),
        "signature": hex::encode(high),
        "expected": "HighS",
        "normalized": hex::encode(sig65),
    });
    (entry, high_entry)
}

/// Uncompressed public-key coordinates `x ‖ y` of `key` on `curve`.
fn public_xy(curve: &str, key: &[u8; 32]) -> [u8; 64] {
    let point = match curve {
        "secp256k1" => K256SigningKey::from_slice(key)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        "p256" => P256SigningKey::from_slice(key)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        other => panic!("unknown curve {other}"),
    };
    point[1..].try_into().unwrap()
}

fn address_entry(curve: &str, key_hex: &str) -> Value {
    let xy = public_xy(curve, &h32(key_hex));
    let address = match curve {
        "secp256k1" => address_secp256k1(&xy).unwrap(),
        _ => address_p256(&xy).unwrap(),
    };
    json!({
        "curve": curve,
        "private_key": key_hex,
        "x": hex::encode(&xy[..32]),
        "y": hex::encode(&xy[32..]),
        "address": address_hex(&address),
    })
}

fn p256_der_entries() -> Vec<Value> {
    use p256::ecdsa::signature::Signer as _;
    let sk = P256SigningKey::from_slice(&h32(P256_RANDOM_KEY)).unwrap();
    let sig: P256Signature = sk.sign(P256_DER_MESSAGE.as_bytes());
    let low = sig.normalize_s();
    let (r, s) = low.split_bytes();
    let high = P256Signature::from_scalars(r, sub_from_order(P256_N, &s)).unwrap();
    let high_der = high.to_der();
    let low_der = low.to_der();
    let raw = p256_der_to_low_s_raw(high_der.as_bytes()).unwrap();
    let pubkey = sk.verifying_key().to_sec1_point(false).as_bytes().to_vec();

    // `s` of this vector starts below 0x80, so a 0x00 pad is non-minimal.
    let low_der = low_der.as_bytes();
    assert!(
        low_der[39] < 0x80 && low_der[38] == 0x20,
        "vector shape changed"
    );
    let mut non_minimal = vec![0x30, low_der[1] + 1];
    non_minimal.extend_from_slice(&low_der[2..37]);
    non_minimal.extend_from_slice(&[0x02, 0x21, 0x00]);
    non_minimal.extend_from_slice(&low_der[39..]);
    let mut trailing = low_der.to_vec();
    trailing.push(0x00);

    vec![
        json!({
            "name": "high-s",
            "message": P256_DER_MESSAGE,
            "public_key": hex::encode(pubkey),
            "der": hex::encode(high_der.as_bytes()),
            "raw_low_s": hex::encode(raw),
            "raw_high_s": hex::encode(high.to_bytes()),
        }),
        json!({
            "name": "non-minimal-integer",
            "der": hex::encode(non_minimal),
            "expected": "InvalidDer",
        }),
        json!({
            "name": "trailing-byte",
            "der": hex::encode(trailing),
            "expected": "InvalidDer",
        }),
    ]
}

fn build() -> Value {
    let (some_data, some_data_high) = eip191_entry("web3js-some-data", WEB3JS_KEY, b"Some data");
    let (grant, grant_high) = eip191_entry(
        "spec-3.4-example-grant",
        K1_RANDOM_KEY,
        SPEC_EXAMPLE_GRANT.as_bytes(),
    );
    let big = statement_shaped_4096();
    json!({
        "spec": "SPEC-WRITE-GRANTS §4, §4.1, §4.4 (fixtures listed in §13.1)",
        "generator": "MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest --features grants --test golden_eth",
        "cross_check": {
            "keccak256": "Foundry cast 1.6.0-nightly `cast keccak 0x<input_hex>`; pycryptodome 3.23 keccak(digest_bits=256); sha3_256_negative via Python hashlib.sha3_256",
            "eip191": "digest: `cast hash-message` and viem hashMessage({raw}); signature: `cast wallet sign --private-key` (RFC 6979, low-S); address: viem recoverMessageAddress and `cast wallet verify`",
            "high_s": "Python n - s over the eip191 signatures; viem recoverMessageAddress on `normalized`",
            "address": "secp256k1: `cast wallet public-key` and `cast wallet address`; p256: pycryptodome ECC.construct(curve='P-256', d) then keccak(digest_bits=256) of x||y",
            "p256_der": "pycryptodome DSS(deterministic-rfc6979, encoding='der'), then s -> n - s re-encoded with DerSequence"
        },
        "keccak256": [
            { "name": "empty", "input_hex": "", "digest": hex::encode(keccak256(b"")) },
            { "name": "abc", "input_hex": hex::encode(b"abc"), "digest": hex::encode(keccak256(b"abc")) },
            {
                "name": "statement-shaped-4096",
                "input_hex": hex::encode(&big),
                "digest": hex::encode(keccak256(&big)),
            },
        ],
        "sha3_256_negative": {
            "input_hex": "",
            "sha3_256": hex::encode(Sha3_256::digest(b"")),
            "note": "FIPS 202 SHA3-256; keccak256 of the same input MUST differ",
        },
        "eip191": [some_data, grant],
        "high_s": [some_data_high, grant_high],
        "address": [
            address_entry("secp256k1", &key_one()),
            address_entry("secp256k1", K1_RANDOM_KEY),
            address_entry("p256", &key_one()),
            address_entry("p256", P256_RANDOM_KEY),
        ],
        "p256_der": p256_der_entries(),
    })
}

fn write_all() {
    let dir = grants_dir();
    fs::create_dir_all(&dir).unwrap();
    let mut body = serde_json::to_string_pretty(&build()).unwrap();
    body.push('\n');
    fs::write(dir.join("eth-primitives.json"), &body).unwrap();
    let manifest = format!(
        "# SPEC-WRITE-GRANTS golden vectors (deterministic)\n\
         # Produced by `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest --features grants --test golden_eth`\n\
         # Every value is cross-checked against cast / viem / pycryptodome; see `cross_check` in each file.\n\
         # Format: <name> <blake3-hex-of-file-bytes>\n\
         eth-primitives {}\n",
        blake3::hash(body.as_bytes()).to_hex()
    );
    fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
}

// -- Reader ------------------------------------------------------------

fn load() -> (Value, Vec<u8>) {
    let bytes = fs::read(grants_dir().join("eth-primitives.json")).unwrap();
    (serde_json::from_slice(&bytes).unwrap(), bytes)
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("missing array `{key}`"))
}

#[test]
fn eth_primitives_golden_vectors() {
    if writing() {
        write_all();
    }
    let (g, bytes) = load();

    // MANIFEST pins the fixture bytes.
    let manifest = fs::read_to_string(grants_dir().join("MANIFEST.txt")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.starts_with("eth-primitives "))
        .expect("eth-primitives line in MANIFEST.txt");
    assert_eq!(
        line.split_whitespace().nth(1).unwrap(),
        blake3::hash(&bytes).to_hex().as_str(),
        "eth-primitives.json does not match its MANIFEST.txt digest"
    );

    check_keccak(&g);
    check_eip191(&g);
    check_high_s(&g);
    check_address(&g);
    check_p256_der(&g);
}

fn check_keccak(g: &Value) {
    for e in arr(g, "keccak256") {
        let input = hex_field(e, "input_hex");
        assert_eq!(hex_field(e, "digest"), keccak256(&input), "keccak256 {e}");
    }
    let neg = &g["sha3_256_negative"];
    let input = hex_field(neg, "input_hex");
    assert_eq!(
        hex_field(neg, "sha3_256"),
        Sha3_256::digest(&input).to_vec()
    );
    assert_ne!(hex_field(neg, "sha3_256"), keccak256(&input));
}

fn check_eip191(g: &Value) {
    assert_eq!(arr(g, "eip191").len(), 2);
    for e in arr(g, "eip191") {
        let statement = str_field(e, "statement").as_bytes();
        assert_eq!(hex_field(e, "message_hex"), eip191_message(statement));
        let digest = eip191_hash(statement);
        assert_eq!(hex_field(e, "digest"), digest);
        let sig: [u8; 65] = hex_field(e, "signature").try_into().unwrap();
        // RFC 6979 determinism: the recorded (cast-produced) signature is
        // what the private key yields.
        let sk = K256SigningKey::from_slice(&hex_field(e, "private_key")).unwrap();
        let (fresh, recid) = sk.sign_prehash_recoverable(&digest);
        assert_eq!(&sig[..64], &fresh.to_bytes()[..]);
        assert_eq!(sig[64], 27 + recid.to_byte());
        let address = eip191_recover_address(statement, &sig).unwrap();
        assert_eq!(address_hex(&address), str_field(e, "address"));
        let xy = recover_secp256k1(&digest, &sig).unwrap();
        assert_eq!(
            &xy[..],
            &sk.verifying_key().to_sec1_point(false).as_bytes()[1..]
        );
    }
}

fn check_high_s(g: &Value) {
    assert_eq!(arr(g, "high_s").len(), 2);
    for e in arr(g, "high_s") {
        assert_eq!(str_field(e, "expected"), "HighS");
        let statement = str_field(e, "statement").as_bytes();
        let sig: [u8; 65] = hex_field(e, "signature").try_into().unwrap();
        assert_eq!(
            eip191_recover_address(statement, &sig),
            Err(EthError::HighS)
        );
        let normalized = normalize_eip191_signature(sig).unwrap();
        assert_eq!(normalized.to_vec(), hex_field(e, "normalized"));
        assert!(eip191_recover_address(statement, &normalized).is_ok());
    }
}

fn check_address(g: &Value) {
    assert_eq!(arr(g, "address").len(), 4);
    for e in arr(g, "address") {
        let mut xy = [0u8; 64];
        xy[..32].copy_from_slice(&hex_field(e, "x"));
        xy[32..].copy_from_slice(&hex_field(e, "y"));
        let curve = str_field(e, "curve");
        let key: [u8; 32] = hex_field(e, "private_key").try_into().unwrap();
        assert_eq!(public_xy(curve, &key), xy, "x||y of {e}");
        let address = match curve {
            "secp256k1" => address_secp256k1(&xy).unwrap(),
            _ => address_p256(&xy).unwrap(),
        };
        assert_eq!(address_hex(&address), str_field(e, "address"));
    }
}

fn check_p256_der(g: &Value) {
    let der = arr(g, "p256_der");
    assert_eq!(der.len(), 3);
    for e in der {
        let bytes = hex_field(e, "der");
        if let Some(expected) = e["expected"].as_str() {
            assert_eq!(expected, "InvalidDer");
            assert_eq!(p256_der_to_low_s_raw(&bytes), Err(EthError::InvalidDer));
            continue;
        }
        let raw: [u8; 64] = hex_field(e, "raw_low_s").try_into().unwrap();
        assert_eq!(p256_der_to_low_s_raw(&bytes).unwrap(), raw);
        assert_eq!(p256_check_raw_low_s(&raw), Ok(()));
        let high: [u8; 64] = hex_field(e, "raw_high_s").try_into().unwrap();
        assert_eq!(p256_check_raw_low_s(&high), Err(EthError::HighS));
        verify_p256(
            &hex_field(e, "public_key"),
            str_field(e, "message").as_bytes(),
            &raw,
        )
        .unwrap();
    }
}
