use mkit_keystore::{
    Algorithm, BackendKind, ImportOptions, KeyAttrs, KeyLabel, Keystore, SecretKey,
    SoftwareRawKeystore,
};

mod common;

use common::vectors::{PAE, VECTORS};

#[test]
fn software_raw_backend_matches_golden_vectors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = SoftwareRawKeystore::with_root(dir.path().join("raw"));
    assert_store_vectors(&raw, BackendKind::SoftwareRaw);
}

fn assert_store_vectors(store: &dyn Keystore, backend: BackendKind) {
    for vector in VECTORS {
        let algorithm: Algorithm = vector.algorithm.parse().expect("algorithm parses");
        let seed = fixed_32(vector.seed_hex);
        let importer = store.importer().expect("backend imports vectors");
        let mut signer = importer
            .import(
                &KeyLabel::new(vector.label).expect("vector label is valid"),
                SecretKey::new(algorithm, seed),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import vector");
        let metadata = signer.metadata().expect("metadata");
        assert_eq!(metadata.backend(), backend);
        assert_eq!(metadata.algorithm(), algorithm);
        assert_eq!(hex_lower(metadata.public_key()), vector.public_hex);
        assert_eq!(
            metadata.keyid(),
            format!("{}:{}", vector.algorithm, vector.public_hex)
        );

        let signature = signer.sign(golden_message(algorithm)).expect("sign");
        assert_eq!(hex_lower(&signature), vector.signature_hex);
        let signature_again = signer.sign(golden_message(algorithm)).expect("sign again");
        assert_eq!(
            signature, signature_again,
            "software vector must be deterministic"
        );
    }
}

fn golden_message(algorithm: Algorithm) -> &'static [u8] {
    match algorithm {
        Algorithm::Ed25519 => b"",
        Algorithm::Secp256k1 | Algorithm::P256 => PAE,
    }
}

fn fixed_32(hex: &str) -> [u8; 32] {
    let bytes = hex_decode(hex);
    bytes.try_into().expect("32-byte seed")
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2), "hex length");
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        out.push((hex_value(chunk[0]) << 4) | hex_value(chunk[1]));
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
