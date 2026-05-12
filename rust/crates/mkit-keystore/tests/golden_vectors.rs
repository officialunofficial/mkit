use mkit_keystore::{
    Algorithm, BackendKind, ImportOptions, KeyAttrs, Keystore, SecretKey, SoftwareKeystore,
    SoftwareRawKeystore,
};

const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

struct Vector {
    label: &'static str,
    algorithm: Algorithm,
    seed_hex: &'static str,
    public_hex: &'static str,
    signature_hex: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        label: "ed25519-rfc8032-empty",
        algorithm: Algorithm::Ed25519,
        seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        signature_hex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Vector {
        label: "secp256k1-generator",
        algorithm: Algorithm::Secp256k1,
        seed_hex: "0000000000000000000000000000000000000000000000000000000000000001",
        public_hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        signature_hex: "834cd126c1bcadb2998d6881e3dd35f6c10b87905b3dd5ba4714f59fcb018d79085c75876fd776083affcf1fc5c982b1e2bea4f0cfc14876ca4305de964521c9",
    },
    Vector {
        label: "p256-readable-seed",
        algorithm: Algorithm::P256,
        seed_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        public_hex: "02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f",
        signature_hex: "a0075344345ada8f8dd1182e51d0aafcaab7e6c44bc378705cb4b78705faed5c42849f10ff7bf91ea3ac1eda3eb663c289d3dd68c27403acad830a6bde4306c5",
    },
];

#[test]
fn software_backends_match_golden_vectors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let software = SoftwareKeystore::with_root(dir.path().join("software"));
    assert_store_vectors(&software, &BackendKind::Software);

    let raw = SoftwareRawKeystore::with_root(dir.path().join("raw"));
    assert_store_vectors(&raw, &BackendKind::SoftwareRaw);
}

fn assert_store_vectors(store: &dyn Keystore, backend: &BackendKind) {
    for vector in VECTORS {
        let seed = fixed_32(vector.seed_hex);
        let mut signer = store
            .import(
                vector.label,
                SecretKey::new(vector.algorithm, seed),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import vector");
        let metadata = signer.metadata().expect("metadata");
        assert_eq!(&metadata.backend, backend);
        assert_eq!(metadata.algorithm, vector.algorithm);
        assert_eq!(hex_lower(&metadata.public_key), vector.public_hex);
        assert_eq!(
            metadata.keyid,
            format!("{}:{}", vector.algorithm, vector.public_hex)
        );

        let signature = signer.sign(golden_message(vector.algorithm)).expect("sign");
        assert_eq!(hex_lower(&signature), vector.signature_hex);
        let signature_again = signer
            .sign(golden_message(vector.algorithm))
            .expect("sign again");
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
