#![allow(clippy::unwrap_used)]
use super::*;
#[derive(Default)]
struct Cache;
impl CacheDelete for Cache {
    fn delete<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { panic!("zero allowance must retain the checkpoint without deleting") })
    }
}
#[test]
fn v050_stored_encodings() {
    futures::executor::block_on(async {
        let source = mkit_server::MemoryKv::default();
        let partition =
            mkit_server::Partition::Coordinator(mkit_server::NamespaceKey::deployment_default());
        let local = LocalCache {
            cache: Cache,
            snapshot_deployment: Some("fixture".into()),
        };
        let invalidator = NamespaceCache {
            local: &local,
            source: &source,
            remote: &source,
            partition: &partition,
            sharding: mkit_server::pipeline::Sharding::D34,
            single: None,
        };
        let request = Request {
            purge_id: "golden".into(),
            audience: "https://server.example".into(),
            repository: String::new(),
            namespace: "root".into(),
            trigger: mkit_server::purge::Trigger::Suspension,
            url_paths: vec!["/object".into()],
            object_ids: Vec::new(),
            refs: Vec::new(),
        };
        for expected in [
            crate::stored_golden::row_fixture!("purge-NamespacePosition-empty", b""),
            crate::stored_golden::row_fixture!("purge-NamespacePosition-populated", b""),
        ] {
            let row: NamespacePosition = serde_json::from_slice(expected.as_bytes()).unwrap();
            assert_eq!(serde_json::to_vec(&row).unwrap(), expected.as_bytes());
            let restored = invalidator
                .invalidate_checkpoint(&request, expected.as_bytes(), &SliceBudget::new(0))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(restored, expected.as_bytes());
        }
    });
}
