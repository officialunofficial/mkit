//! Object-index membership and repository isolation on every KV backend.

use mkit_server::pipeline::{D34Shards, ShardMap, SinglePartition};
use mkit_server::store::index::{self, IndexValue, LocatedObject};
use mkit_server::store::{BlobKey, codec, keys};
use mkit_server::{
    Batch, KeyClasses, NamespaceKey, NamespaceStore, RepoId, RepoName, StoreError, Value,
};

use super::CaseResult::Pass;
use super::{KvHarness, Outcome, commit};

async fn run<H: KvHarness>(h: H, shards: &dyn ShardMap) -> Outcome {
    let s = h.store();
    let a = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: ok!(RepoName::new("idx-a")),
    };
    let b = RepoId {
        namespace: a.namespace.clone(),
        name: ok!(RepoName::new("idx-b")),
    };
    let id = [0x12; 32];
    let pack = [0x34; 32];
    let location = IndexValue {
        frame_offset: 7,
        frame_length: 19,
        wire_type: 0,
        decoded_size: 24,
        chain_depth: 0,
        delta_base: None,
    };
    let index_key = keys::object_index(&a.name, &id, &pack);
    let index_part = shards.object_index(&a, &id);
    let index_value = ok!(codec::encode_object_index(&location));
    if s.capabilities().key_classes != KeyClasses::All {
        ensure_err!(
            s.apply(&index_part, Batch::new().put(index_key, index_value))
                .await,
            StoreError::Unsupported(_)
        );
        return Ok(Pass);
    }
    commit(&s, &index_part, Batch::new().put(index_key, index_value)).await?;
    commit(
        &s,
        &shards.object_index(&b, &id),
        Batch::new().put(
            keys::object_index(&b.name, &id, &pack),
            ok!(codec::encode_object_index(&location)),
        ),
    )
    .await?;
    ensure_eq!(
        ok!(index::contains_many(&s, shards, &a, &[id]).await),
        [false]
    );
    ensure_eq!(
        ok!(index::contains_many(&s, shards, &b, &[id]).await),
        [false]
    );
    let member_part = shards.membership(&a, &BlobKey::pack(pack));
    commit(
        &s,
        &member_part,
        Batch::new().put(keys::membership(&a.name, &pack), Value::default()),
    )
    .await?;
    ensure_eq!(
        ok!(index::locate_many(&s, shards, &a, &[id]).await),
        [Some(LocatedObject {
            pack,
            value: location
        })]
    );
    ensure!(
        ok!(index::holds_any(&s, shards, &a, &[id]).await),
        "member absent"
    );
    ensure!(
        !ok!(index::holds_any(&s, shards, &b, &[id]).await),
        "cross-repo member"
    );
    Ok(Pass)
}

/// Single partition: the key itself isolates repositories.
pub async fn idx_object_membership_gate_single<H: KvHarness>(h: H) -> Outcome {
    run(h, &SinglePartition).await
}

/// D34: both the key and the index partition isolate repositories.
pub async fn idx_object_membership_gate_d34<H: KvHarness>(h: H) -> Outcome {
    run(h, &D34Shards).await
}
