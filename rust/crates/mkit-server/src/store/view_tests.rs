use super::view::ViewStore;
use super::{Batch, BlobKey, NamespaceStore, Value, Write, codec, keys};
use crate::pipeline::{D34Shards, ShardMap, SinglePartition};
use crate::{MemoryKv, NamespaceKey, RepoId, RepoName};
use futures_executor::block_on;

fn legacy_visibility(shards: &dyn ShardMap) {
    block_on(async {
        let store = MemoryKv::default();
        let repository = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("legacy").unwrap(),
        };
        let name = "refs/heads/main";
        let hash = [7; 32];
        let source = shards.ref_shard(&repository, name);
        let index = shards.ref_index(&repository, name);
        let member = shards.membership(&repository, &BlobKey::pack(hash));
        for (partition, key, value) in [
            (
                source.clone(),
                keys::ref_key(&repository.name, name),
                codec::encode_ref_id(&hash),
            ),
            (
                index.clone(),
                keys::ref_index_key(&repository.name, name),
                codec::encode_ref_id(&hash),
            ),
            (
                member.clone(),
                keys::membership(&repository.name, &hash),
                Value::default(),
            ),
        ] {
            let mut batch = Batch::new();
            batch.writes.push(Write::Put(key, value));
            store.apply(&partition, batch).await.unwrap();
        }
        let reader = ViewStore {
            store: &store,
            repo: &repository,
            writer: false,
            policy: None,
        };
        assert_eq!(
            reader
                .get(&source, &keys::ref_key(&repository.name, name))
                .await
                .unwrap(),
            Some(codec::encode_ref_id(&hash))
        );
        assert_eq!(
            reader
                .get(&index, &keys::ref_index_key(&repository.name, name))
                .await
                .unwrap(),
            Some(codec::encode_ref_id(&hash))
        );
        assert_eq!(
            reader
                .get(&member, &keys::membership(&repository.name, &hash))
                .await
                .unwrap(),
            Some(Value::default())
        );
    });
}

#[test]
fn persisted_legacy_single_live_rows_remain_visible_without_inspector() {
    legacy_visibility(&SinglePartition);
}

#[test]
fn persisted_legacy_d34_live_rows_remain_visible_without_inspector() {
    legacy_visibility(&D34Shards);
}
