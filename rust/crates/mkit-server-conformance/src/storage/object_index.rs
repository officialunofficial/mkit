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
    let index_value = ok!(codec::encode_object_index(&id, &location));
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
            ok!(codec::encode_object_index(&id, &location)),
        ),
    )
    .await?;
    ensure_eq!(
        ok!(index::contains_many(&s, shards, &a, &[id]).await),
        [Ok(false)]
    );
    ensure_eq!(
        ok!(index::contains_many(&s, shards, &b, &[id]).await),
        [Ok(false)]
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
        [Ok(Some(LocatedObject {
            pack,
            value: location
        }))]
    );
    ensure!(
        ok!(ok!(index::holds_any(&s, shards, &a, &[id]).await)),
        "member absent"
    );
    ensure!(
        !ok!(ok!(index::holds_any(&s, shards, &b, &[id]).await)),
        "cross-repo member"
    );
    commit(
        &s,
        &member_part,
        Batch::new().delete(keys::membership(&a.name, &pack)),
    )
    .await?;
    ensure_eq!(
        ok!(index::contains_many(&s, shards, &a, &[id]).await),
        [Ok(false)]
    );
    Ok(Pass)
}

/// More than one scan page of orphaned rows precedes a valid member. Removing
/// the membership row hides that index row again on every KV backend.
pub async fn idx_object_paging_and_membership_delete<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    if s.capabilities().key_classes != KeyClasses::All {
        return Ok(Pass);
    }
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: ok!(RepoName::new("idx-page")),
    };
    let id = [0x56; 32];
    let location = IndexValue {
        frame_offset: 7,
        frame_length: 19,
        wire_type: 0,
        decoded_size: 24,
        chain_depth: 0,
        delta_base: None,
    };
    let part = D34Shards.object_index(&repo, &id);
    let value = ok!(codec::encode_object_index(&id, &location));
    for chunk in (0..130_u16).collect::<Vec<_>>().chunks(96) {
        let mut batch = Batch::new();
        for i in chunk {
            let mut pack = [0; 32];
            pack[30..].copy_from_slice(&i.to_be_bytes());
            batch = batch.put(keys::object_index(&repo.name, &id, &pack), value.clone());
        }
        commit(&s, &part, batch).await?;
    }
    let mut member_pack = [0; 32];
    member_pack[30..].copy_from_slice(&129_u16.to_be_bytes());
    let membership_key = keys::membership(&repo.name, &member_pack);
    let member_part = D34Shards.membership(&repo, &BlobKey::pack(member_pack));
    ensure_eq!(
        ok!(index::contains_many(&s, &D34Shards, &repo, &[id]).await),
        [Ok(false)]
    );
    commit(
        &s,
        &member_part,
        Batch::new().put(membership_key.clone(), Value::default()),
    )
    .await?;
    ensure_eq!(
        ok!(index::locate_many(&s, &D34Shards, &repo, &[id]).await),
        [Ok(Some(LocatedObject {
            pack: member_pack,
            value: location,
        }))]
    );
    commit(&s, &member_part, Batch::new().delete(membership_key)).await?;
    ensure_eq!(
        ok!(index::contains_many(&s, &D34Shards, &repo, &[id]).await),
        [Ok(false)]
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
