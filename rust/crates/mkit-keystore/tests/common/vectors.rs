pub(crate) const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

pub(crate) struct Vector {
    pub label: &'static str,
    pub algorithm: &'static str,
    pub seed_hex: &'static str,
    pub public_hex: &'static str,
    pub signature_hex: &'static str,
}

pub(crate) const VECTORS: &[Vector] = &[
    Vector {
        label: "ed25519-rfc8032-empty",
        algorithm: "ed25519",
        seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        signature_hex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Vector {
        label: "secp256k1-generator",
        algorithm: "secp256k1",
        seed_hex: "0000000000000000000000000000000000000000000000000000000000000001",
        public_hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        signature_hex: "834cd126c1bcadb2998d6881e3dd35f6c10b87905b3dd5ba4714f59fcb018d79085c75876fd776083affcf1fc5c982b1e2bea4f0cfc14876ca4305de964521c9",
    },
    Vector {
        label: "p256-readable-seed",
        algorithm: "p256",
        seed_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        public_hex: "02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f",
        signature_hex: "a0075344345ada8f8dd1182e51d0aafcaab7e6c44bc378705cb4b78705faed5c42849f10ff7bf91ea3ac1eda3eb663c289d3dd68c27403acad830a6bde4306c5",
    },
];
