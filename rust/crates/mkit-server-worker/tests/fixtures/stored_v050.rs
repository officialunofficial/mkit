//! Stored encodings written by v0.5.0, including nested row variants.
//! Fixed JSON bodies are prefixed by their literal row version in decoder tests;
//! hexadecimal fixtures contain complete binary rows. Keep these bytes unchanged.
//! Added stored fields require serde defaults so later 0.5.x keeps decoding them.
//!
//! All fixture data and decoder tests for this crate live here. Test macros expand
//! in their owning modules to access private codecs without widening visibility.
//! Existing upload goldens additionally pin receipts, tokens and marker blobs.
#![allow(clippy::unwrap_used)]

pub(crate) fn json<T: serde::Serialize + serde::de::DeserializeOwned>(
    name: &str,
    bytes: &[u8],
) -> T {
    let row: T = serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(serde_json::to_vec(&row).unwrap(), bytes, "{name}");
    row
}

pub(crate) fn value(body: &[u8], prefix: &[u8]) -> mkit_server::Value {
    mkit_server::Value::new([prefix, body].concat())
}

pub(crate) fn hex(bytes: &str) -> mkit_server::Value {
    let bytes = bytes.trim();
    assert!(bytes.len().is_multiple_of(2));
    mkit_server::Value::new(
        (0..bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>(),
    )
}
macro_rules! hex_fixture {
    ($name:literal) => {
        crate::stored_golden::hex(
            std::str::from_utf8(crate::stored_golden::fixture(concat!($name, ".hex"))).unwrap(),
        )
    };
}
pub(crate) use hex_fixture;

macro_rules! json_fixture {
    ($ty:ty, $name:literal) => {
        crate::stored_golden::json::<$ty>(
            $name,
            crate::stored_golden::fixture(concat!($name, ".json")),
        )
    };
}
pub(crate) use json_fixture;
macro_rules! row_fixture {
    ($name:literal, $prefix:expr) => {
        crate::stored_golden::value(
            crate::stored_golden::fixture(concat!($name, ".json")),
            $prefix,
        )
    };
}
pub(crate) use row_fixture;

// Exact original fixture bytes; tests must never regenerate this table.
// Different row types can have identical canonical bytes.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub(crate) fn fixture(name: &str) -> &'static [u8] {
    match name {
        "addressing-multi.hex" => br"6d756c7469
",
        "addressing-single.hex" => br"73696e676c65
",
        "object-root-binding.hex" => br"0101010101010101010101010101010101010101010101010101010101010101010000000000000008
",
        "purge-NamespacePosition-empty.json" => br#"{"paths":false,"done":false,"after":null,"repository":null,"cursor":0}"#,
        "purge-NamespacePosition-populated.json" => br#"{"paths":true,"done":false,"after":[114,114,0,114,101,112,111],"repository":"repo","cursor":3}"#,
        "r2-object_multipart-Definition.json" => br#"{"object":"object","root":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"len":8,"part_size":8388608,"cvs":[[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]],"operation":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]}"#,
        "r2-object_multipart-Session.json" => br#"{"definition":{"object":"object","root":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"len":8,"part_size":8388608,"cvs":[[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]],"operation":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]},"upload":"upload"}"#,
        "r2-object_multipart-VerifiedObjectPartRef.json" => br#"{"index":0,"len":8,"tag":[1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,101,116,97,103]}"#,
        "sharding-d34.hex" => br"643334
",
        "sharding-single.hex" => br"73696e676c65
",
        _ => panic!("unknown stored fixture: {name}"),
    }
}

macro_rules! tests {
    (purge) => {
        use super::*;
        #[derive(Default)]
        struct Cache;
        impl CacheDelete for Cache {
            fn delete<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
                Box::pin(async {
                    panic!("zero allowance must retain the checkpoint without deleting")
                })
            }
        }
        #[test]
        fn v050_stored_encodings() {
            futures::executor::block_on(async {
                let local = LocalCache { cache: Cache };
                let request = Request {
                    purge_id: "golden".into(),
                    audience: "https://server.example".into(),
                    repository: String::new(),
                    namespace: "root".into(),
                    trigger: mkit_server::purge::Trigger::Suspension,
                    url_paths: Vec::new(),
                    object_ids: Vec::new(),
                    refs: Vec::new(),
                };
                for expected in [
                    crate::stored_golden::row_fixture!("purge-NamespacePosition-empty", b""),
                    crate::stored_golden::row_fixture!("purge-NamespacePosition-populated", b""),
                ] {
                    let row: NamespacePosition =
                        serde_json::from_slice(expected.as_bytes()).unwrap();
                    assert_eq!(serde_json::to_vec(&row).unwrap(), expected.as_bytes());
                    // The catalog walk is gone, so a restored v0.5.0 position
                    // is complete once its (here empty) path deletion is.
                    assert!(
                        local
                            .invalidate_checkpoint(
                                &request,
                                expected.as_bytes(),
                                &SliceBudget::new(0)
                            )
                            .await
                            .unwrap()
                            .is_none()
                    );
                }
            });
        }
    };
    (r2_object_multipart) => {
        use super::*;
        #[test]
        fn v050_stored_encodings() {
            let _ =
                crate::stored_golden::json_fixture!(Definition, "r2-object_multipart-Definition");
            let expected =
                crate::stored_golden::row_fixture!("r2-object_multipart-Definition", b"\x01");
            let row: Definition = decode(expected.as_bytes()).unwrap();
            assert_eq!(encode(&row).unwrap(), expected.as_bytes());
            let _ = crate::stored_golden::json_fixture!(Session, "r2-object_multipart-Session");
            let expected =
                crate::stored_golden::row_fixture!("r2-object_multipart-Session", b"\x01");
            let row: Session = decode(expected.as_bytes()).unwrap();
            assert_eq!(encode(&row).unwrap(), expected.as_bytes());
            let _ = crate::stored_golden::json_fixture!(
                VerifiedObjectPartRef,
                "r2-object_multipart-VerifiedObjectPartRef"
            );
            let expected = crate::stored_golden::row_fixture!(
                "r2-object_multipart-VerifiedObjectPartRef",
                b"\x01"
            );
            let row: VerifiedObjectPartRef = decode(expected.as_bytes()).unwrap();
            assert_eq!(encode(&row).unwrap(), expected.as_bytes());
        }

        #[derive(Clone)]
        struct PinnedRoot;
        impl ObjectBucket for PinnedRoot {
            fn spawn_put(
                &self,
                _: String,
                _: u64,
                _: crate::r2::PutBody,
            ) -> futures::channel::oneshot::Receiver<crate::r2::PutResult> {
                panic!("stored root must be reused")
            }
            async fn head(&self, _: &str) -> Result<Option<u64>, String> {
                panic!("unexpected HEAD")
            }
            async fn get(
                &self,
                _: &str,
                _: Option<std::ops::Range<u64>>,
            ) -> Result<Option<(u64, crate::r2::ObjectStream)>, String> {
                let expected = crate::stored_golden::hex_fixture!("object-root-binding");
                let bytes = Bytes::copy_from_slice(expected.as_bytes());
                Ok(Some((
                    bytes.len() as u64,
                    Box::pin(futures::stream::iter([Ok(bytes)])),
                )))
            }
            async fn delete(&self, _: &str) -> Result<(), String> {
                panic!("unexpected delete")
            }
            async fn list(
                &self,
                _: &str,
                _: Option<&str>,
            ) -> Result<crate::r2::ObjectPage, String> {
                panic!("unexpected list")
            }
            async fn delete_many(&self, _: Vec<String>) -> Result<(), String> {
                panic!("unexpected delete")
            }
            async fn probe(&self) -> Result<(), String> {
                panic!("unexpected probe")
            }
        }
        #[test]
        fn v050_object_root_binding_is_reused() {
            let store = R2BlobStore::new(PinnedRoot, "packs");
            futures::executor::block_on(store.pin_object_root("object", [1; 32], 8)).unwrap();
        }
    };
    (sharding_guard) => {
        use super::*;
        #[test]
        fn v050_binary_rows() {
            use crate::stored_golden::hex_fixture;
            for (mode, expected) in [
                (Sharding::Single, hex_fixture!("sharding-single")),
                (Sharding::D34, hex_fixture!("sharding-d34")),
            ] {
                assert_eq!(mode_name(mode).as_bytes(), expected.as_bytes());
                assert_eq!(compare(&expected, mode), Outcome::Ok);
            }
            for (mode, expected) in [
                (AddressingMode::Single, hex_fixture!("addressing-single")),
                (AddressingMode::Multi, hex_fixture!("addressing-multi")),
            ] {
                assert_eq!(mode.name().as_bytes(), expected.as_bytes());
                assert_eq!(compare_addressing(&expected, mode), Outcome::Ok);
            }
        }
    };
}
pub(crate) use tests;
