#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Definition, "r2-object_multipart-Definition");
    let expected = crate::stored_golden::row_fixture!("r2-object_multipart-Definition", b"\x01");
    let row: Definition = decode(expected.as_bytes()).unwrap();
    assert_eq!(encode(&row).unwrap(), expected.as_bytes());
    let _ = crate::stored_golden::json_fixture!(Session, "r2-object_multipart-Session");
    let expected = crate::stored_golden::row_fixture!("r2-object_multipart-Session", b"\x01");
    let row: Session = decode(expected.as_bytes()).unwrap();
    assert_eq!(encode(&row).unwrap(), expected.as_bytes());
    let _ = crate::stored_golden::json_fixture!(
        VerifiedObjectPartRef,
        "r2-object_multipart-VerifiedObjectPartRef"
    );
    let expected =
        crate::stored_golden::row_fixture!("r2-object_multipart-VerifiedObjectPartRef", b"\x01");
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
    async fn list(&self, _: &str, _: Option<&str>) -> Result<crate::r2::ObjectPage, String> {
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
