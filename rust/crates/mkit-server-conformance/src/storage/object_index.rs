//! Object-index membership and repository isolation on every KV backend.

use mkit_server::pipeline::{D34Shards, ShardMap, SinglePartition};
use mkit_server::store::index::{self, IndexValue, LocatedObject};
use mkit_server::store::{BlobKey, codec, keys};
use mkit_server::{
    Batch, KeyClasses, NamespaceKey, NamespaceStore, RangeScan, RepoId, RepoName, StoreError, Value,
};

use super::CaseResult::Pass;
use super::{KvHarness, Outcome, commit, k, part};

fn range(start: &[u8], end: &[u8], after: Option<mkit_server::Cursor>, limit: u32) -> RangeScan {
    RangeScan::new(k(start), k(end), after, limit)
}

/// All backends serve a nonempty prefix in request order; the default
/// implementation serves the entire request.
pub async fn idx_scan_many_default_and_prefix<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("idx_scan_many_default_and_prefix"));
    for name in [b"a1", b"b1", b"c1"] {
        commit(&s, &p, Batch::new().put(k(name), Value::default())).await?;
    }
    let ranges = [
        range(b"a", b"b", None, 2),
        range(b"b", b"c", None, 2),
        range(b"c", b"d", None, 2),
    ];
    let pages = ok!(s.scan_many(&p, &ranges).await);
    ensure!(
        !pages.is_empty() && pages.len() <= ranges.len(),
        "invalid served prefix"
    );
    for (range, page) in ranges.iter().zip(&pages) {
        ensure_eq!(page.entries.len(), 1);
        ensure!(
            page.entries[0].0.as_bytes() >= range.start.as_bytes()
                && page.entries[0].0.as_bytes() < range.end.as_bytes(),
            "wrong range"
        );
    }
    Ok(Pass)
}

/// Empty ranges and a continuation page retain scan semantics.
pub async fn idx_scan_many_empty_and_continuation<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("idx_scan_many_empty_and_continuation"));
    ensure_eq!(ok!(s.scan_many(&p, &[]).await), vec![]);
    for name in [b"a1", b"a2"] {
        commit(&s, &p, Batch::new().put(k(name), Value::default())).await?;
    }
    let ranges = [range(b"x", b"y", None, 1), range(b"a", b"b", None, 1)];
    let first = ok!(s.scan_many(&p, &ranges).await);
    ensure!(!first.is_empty(), "missing first page");
    ensure!(
        first[0].entries.is_empty() && first[0].next.is_none(),
        "empty range changed"
    );
    let second = if first.len() == 2 {
        first[1].clone()
    } else {
        ok!(s.scan_many(&p, &ranges[1..]).await).remove(0)
    };
    ensure_eq!(second.entries.len(), 1);
    let next = second.next;
    ensure!(next.is_some(), "missing continuation");
    let resumed = ok!(s.scan_many(&p, &[range(b"a", b"b", next, 1)]).await);
    ensure_eq!(resumed[0].entries.len(), 1);
    ensure_eq!(resumed[0].entries[0].0, k(b"a2"));
    Ok(Pass)
}

/// A cursor from another range fails the batched call closed.
pub async fn idx_scan_many_forged_cursor<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("idx_scan_many_forged_cursor"));
    commit(&s, &p, Batch::new().put(k(b"a1"), Value::default())).await?;
    let first = ok!(s.scan_many(&p, &[range(b"a", b"b", None, 1)]).await);
    let cursor = first[0]
        .next
        .clone()
        .unwrap_or_else(|| mkit_server::Cursor::new(k(b"a1").as_bytes().to_vec()));
    ensure_err!(
        s.scan_many(&p, &[range(b"b", b"c", Some(cursor), 1)]).await,
        StoreError::Invalid(_)
    );
    Ok(Pass)
}

/// Each returned page respects its requested row limit; too many ranges
/// are rejected before any backend-specific work.
pub async fn idx_scan_many_range_limit<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("idx_scan_many_range_limit"));
    for name in [b"a1", b"a2"] {
        commit(&s, &p, Batch::new().put(k(name), Value::default())).await?;
    }
    let ranges = [range(b"a", b"b", None, 1)];
    let pages = ok!(s.scan_many(&p, &ranges).await);
    ensure_eq!(pages[0].entries.len(), 1);
    let too_many = vec![ranges[0].clone(); mkit_server::MAX_SCAN_RANGES + 1];
    ensure_err!(s.scan_many(&p, &too_many).await, StoreError::Invalid(_));
    Ok(Pass)
}

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
