#![cfg(feature = "managed-access")]
use mkit_vcs_worker::access_policy::{
    GetRequest, Identity, InitializeRequest, Policy, ReplaceRequest, decode,
};

const ROOT: &str = "../../rust/tests/golden/server-access/";

#[test]
fn committed_management_vectors_are_pinned_and_parse_as_specified() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ROOT);
    let manifest = std::fs::read_to_string(root.join("MANIFEST.txt")).unwrap();
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let (expected, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        assert_eq!(blake3_hex(&bytes), expected, "{name}");
        if name.ends_with("-response.json") {
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let expected_body = match name {
                "initialize-response.json" | "replace-response.json" => {
                    let identity = Identity::parse(
                        "http://localhost:8791",
                        "managed-test",
                        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
                    )
                    .unwrap();
                    let generation = if name.starts_with("initialize") { 1 } else { 2 };
                    serde_json::to_string(&Policy::new(&identity, generation, vec![])).unwrap()
                }
                "invalid-response.json" => r#"{"code":"invalid_argument"}"#.into(),
                "unavailable-response.json" => r#"{"code":"unavailable"}"#.into(),
                "conflict-response.json" => r#"{"code":"conflict"}"#.into(),
                _ => panic!("unregistered response: {name}"),
            };
            assert_eq!(bytes, format!("{expected_body}\n").as_bytes(), "{name}");
            assert!(parsed.is_object());
            continue;
        }
        let metadata: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(name.replace(".json", ".meta.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["method"], "POST");
        assert!(root.join(metadata["response"].as_str().unwrap()).is_file());
        match name {
            "initialize.json" => {
                assert_eq!(decode::<InitializeRequest>(&bytes).unwrap().version, 1)
            }
            "get.json" => assert_eq!(decode::<GetRequest>(&bytes).unwrap().version, 1),
            "replace.json" => assert_eq!(
                decode::<ReplaceRequest>(&bytes)
                    .unwrap()
                    .expected_generation,
                "1"
            ),
            "invalid-duplicate.json" => assert!(decode::<GetRequest>(&bytes).is_err()),
            _ => panic!("unregistered vector: {name}"),
        }
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    mkit_vcs_worker::hashing::blake3_hex(bytes)
}
