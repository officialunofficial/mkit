//! [`ContentIndex`] cases over any [`KvHarness`] store (M0-02b): holders,
//! GC holds, grace, the blocklist and the GC-ordering races (R-64). Each
//! case uses its own objects, so its own content shards.

use mkit_core::hash::Hash;
use mkit_server::store::{
    BlockEntry, HoldOutcome, Holder, MAX_BLOCK_REASON_BYTES, MAX_HOLD_TTL_MS, ObjectState, codec,
    content_shard, keys,
};
use mkit_server::{ContentIndex, KeyClasses, NamespaceKey, NamespaceStore, RepoName, StoreError};

use super::CaseResult::{Pass, Skip};
use super::{CaseResult, KvHarness, Outcome};

const GRACE: u64 = 1_000;

/// A holder repo in the default namespace.
fn holder(repo: &str) -> Result<Holder, String> {
    Ok(Holder::new(
        NamespaceKey::deployment_default(),
        ok!(RepoName::new(repo)),
    ))
}

/// A `ContentIndex` over a fresh store, or the skip for a store that lacks
/// every key class or atomic batches, after checking that a mutation is
/// `Unsupported` there.
async fn index<H: KvHarness>(
    h: &H,
    object: &Hash,
) -> Result<Result<ContentIndex<H::Store>, CaseResult>, String> {
    let idx = ContentIndex::new(h.store());
    let caps = idx.store().capabilities();
    if caps.key_classes == KeyClasses::All && caps.atomic_multi_key {
        return Ok(Ok(idx));
    }
    let added = idx.add_holder(object, &holder("gate")?, None, 1).await;
    ensure_err!(added, StoreError::Unsupported(_));
    Ok(Err(Skip(
        "ContentIndex needs every key class and atomic_multi_key",
    )))
}

/// `let idx = index!(h, object);`: the index, or return the skip.
macro_rules! index {
    ($h:expr, $object:expr) => {
        match index(&$h, &$object).await? {
            Ok(idx) => idx,
            Err(skip) => return Ok(skip),
        }
    };
}

async fn state<S: NamespaceStore>(
    idx: &ContentIndex<S>,
    object: &Hash,
) -> Result<ObjectState, String> {
    ok!(idx.state(object).await).ok_or_else(|| "object state missing".into())
}

async fn collectable<S: NamespaceStore>(
    idx: &ContentIndex<S>,
    object: &Hash,
    now: u64,
) -> Result<bool, String> {
    Ok(ok!(idx.collectable(object, now, GRACE).await).is_some())
}

async fn hold_row<S: NamespaceStore>(
    idx: &ContentIndex<S>,
    object: &Hash,
    id: &Hash,
) -> Result<Option<u64>, String> {
    let key = keys::hold(object, id);
    match ok!(idx.store().get(&content_shard(object), &key).await) {
        Some(val) => Ok(Some(ok!(codec::decode_hold(&val)))),
        None => Ok(None),
    }
}

/// Adding a holder is idempotent: one row, counted once.
pub async fn idx_holder_add_idempotent<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x21; 32];
    let idx = index!(h, obj);
    for i in 0..3 {
        let added = ok!(idx.add_holder(&obj, &holder("a")?, None, 1).await);
        ensure_eq!(added.newly_added, i == 0);
    }
    ensure_eq!(state(&idx, &obj).await?.holders, 1);
    ensure_eq!(
        ok!(idx.holders(&obj, None, 10).await).holders,
        vec![holder("a")?]
    );
    Ok(Pass)
}

/// Removing a holder is idempotent; removing an absent one is no error.
pub async fn idx_holder_remove<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x22; 32];
    let idx = index!(h, obj);
    for repo in ["a", "b"] {
        ok!(idx.add_holder(&obj, &holder(repo)?, None, 1).await);
    }
    for repo in ["a", "a", "never"] {
        ok!(idx.remove_holder(&obj, &holder(repo)?, 2).await);
    }
    ensure_eq!(state(&idx, &obj).await?.holders, 1);
    ensure_eq!(
        ok!(idx.holders(&obj, None, 10).await).holders,
        vec![holder("b")?]
    );
    Ok(Pass)
}

/// Holder pages follow `next` to every holder, in order, once each.
pub async fn idx_holders_pagination<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x23; 32];
    let idx = index!(h, obj);
    let all = (0..5)
        .map(|i| holder(&format!("h{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    for holder in all.iter().rev() {
        ok!(idx.add_holder(&obj, holder, None, 1).await);
    }
    let (mut seen, mut after) = (vec![], None);
    for page_no in 0.. {
        ensure!(page_no <= 2 * all.len(), "the holder pages did not end");
        let page = ok!(idx.holders(&obj, after.as_ref(), 2).await);
        ensure!(page.holders.len() <= 2, "page over limit");
        seen.extend(page.holders);
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    ensure_eq!(seen, all);
    Ok(Pass)
}

/// A live hold blocks collection until its expiry.
pub async fn idx_hold_blocks_collection<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x24; 32];
    let idx = index!(h, obj);
    ensure_eq!(
        ok!(idx.add_hold(&obj, &[1; 32], 5_000, 30).await),
        HoldOutcome::Held
    );
    ensure!(
        !collectable(&idx, &obj, 30 + GRACE).await?,
        "held object collectable"
    );
    ensure!(
        !collectable(&idx, &obj, 4_999).await?,
        "held object collectable"
    );
    Ok(Pass)
}

/// An expired hold allows collection; the GC plan prunes it and marks the
/// object `deleting`.
pub async fn idx_expired_hold_allows_collection<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x25; 32];
    let idx = index!(h, obj);
    ensure_eq!(
        ok!(idx.add_hold(&obj, &[1; 32], 5_000, 30).await),
        HoldOutcome::Held
    );
    let plan = ok!(idx.collectable(&obj, 5_000, GRACE).await).ok_or("a hold ends at expiry")?;
    ensure!(
        ok!(idx.commit_collect(plan).await),
        "the plan did not commit"
    );
    ensure!(state(&idx, &obj).await?.deleting, "not marked deleting");
    ensure_eq!(hold_row(&idx, &obj, &[1; 32]).await?, None);
    ensure!(
        !collectable(&idx, &obj, u64::MAX).await?,
        "collectable while deleting"
    );
    Ok(Pass)
}

/// No collection within the grace period after the last change, or while
/// a holder remains.
pub async fn idx_grace_period<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x26; 32];
    let idx = index!(h, obj);
    ok!(idx.add_holder(&obj, &holder("a")?, None, 10).await);
    ensure!(
        !collectable(&idx, &obj, 10 + GRACE * 10).await?,
        "held object collectable"
    );
    ok!(idx.remove_holder(&obj, &holder("a")?, 20).await);
    ensure!(
        !collectable(&idx, &obj, 20 + GRACE - 1).await?,
        "collectable within grace"
    );
    ensure!(
        collectable(&idx, &obj, 20 + GRACE).await?,
        "not collectable after grace"
    );
    Ok(Pass)
}

/// Block and unblock; an over-long reason is `Invalid` and writes nothing.
pub async fn idx_block_unblock<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x27; 32];
    let idx = index!(h, obj);
    let entry = BlockEntry::new("dmca", 9);
    ok!(idx.block(&obj, &entry, 1).await);
    ensure_eq!(ok!(idx.blocked(&obj).await), Some(entry.clone()));
    let before = state(&idx, &obj).await?;
    let long = BlockEntry::new("x".repeat(MAX_BLOCK_REASON_BYTES + 1), 0);
    ensure_err!(idx.block(&obj, &long, 2).await, StoreError::Invalid(_));
    ensure_eq!(state(&idx, &obj).await?, before);
    ok!(idx.unblock(&obj, 3).await);
    ensure_eq!(ok!(idx.blocked(&obj).await), None);
    Ok(Pass)
}

/// Objects never see each other's rows, across shards or within one.
pub async fn idx_objects_in_different_shards_isolated<H: KvHarness>(h: H) -> Outcome {
    let (a, b, mut c) = ([0x28; 32], [0x38; 32], [0x28; 32]);
    c[31] = 0;
    let idx = index!(h, a);
    ensure!(content_shard(&a) != content_shard(&b), "same shard");
    ok!(idx.add_holder(&a, &holder("x")?, None, 1).await);
    ensure_eq!(
        ok!(idx.add_hold(&a, &[1; 32], 99, 1).await),
        HoldOutcome::Held
    );
    ok!(idx.block(&a, &BlockEntry::new("r", 1), 1).await);
    for other in [b, c] {
        ensure_eq!(ok!(idx.state(&other).await), None);
        ensure_eq!(ok!(idx.blocked(&other).await), None);
        ensure!(
            ok!(idx.holders(&other, None, 10).await).holders.is_empty(),
            "foreign holders"
        );
        ensure!(
            collectable(&idx, &other, GRACE).await?,
            "foreign hold or holder"
        );
    }
    Ok(Pass)
}

/// GC ordering (R-64): once a GC plan commits, new holds and holders are a
/// retryable `Unavailable` until GC finishes; a hold taken before the plan
/// commits makes it fail.
pub async fn idx_gc_commit_then_add_hold_unavailable<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x29; 32];
    let idx = index!(h, obj);
    ok!(idx.release_hold(&obj, &[0; 32], 1).await);
    let plan = ok!(idx.collectable(&obj, 1 + GRACE, GRACE).await).ok_or("not collectable")?;
    ensure!(
        ok!(idx.commit_collect(plan).await),
        "the plan did not commit"
    );
    let now = 2 + GRACE;
    let hold = idx.add_hold(&obj, &[1; 32], now + 100, now).await;
    ensure_err!(hold, StoreError::Unavailable(_));
    let added = idx.add_holder(&obj, &holder("a")?, None, now).await;
    ensure_err!(added, StoreError::Unavailable(_));
    ensure_eq!(hold_row(&idx, &obj, &[1; 32]).await?, None);
    ok!(idx.finish_collect(&obj, now).await);
    ensure_eq!(
        ok!(idx.add_hold(&obj, &[1; 32], now + 100, now).await),
        HoldOutcome::Held
    );
    let later = now + 100 + GRACE;
    let plan = ok!(idx.collectable(&obj, later, GRACE).await).ok_or("not collectable")?;
    let hold = idx.add_hold(&obj, &[2; 32], later + 100, later).await;
    ensure_eq!(ok!(hold), HoldOutcome::Held);
    ensure!(
        !ok!(idx.commit_collect(plan).await),
        "a stale plan committed"
    );
    ensure!(!state(&idx, &obj).await?.deleting, "marked deleting");
    Ok(Pass)
}

/// A blocked object refuses new holds, writing nothing; a holder is still
/// recorded, reporting the block so the relay can take it down (R-75).
pub async fn idx_blocked_on_add<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x2a; 32];
    let idx = index!(h, obj);
    let entry = BlockEntry::new("csam", 1);
    ok!(idx.block(&obj, &entry, 1).await);
    let before = state(&idx, &obj).await?;
    let hold = ok!(idx.add_hold(&obj, &[1; 32], 100, 2).await);
    ensure_eq!(hold, HoldOutcome::Blocked(entry.clone()));
    ensure_eq!(state(&idx, &obj).await?, before);
    ensure_eq!(hold_row(&idx, &obj, &[1; 32]).await?, None);
    let added = ok!(idx.add_holder(&obj, &holder("a")?, None, 3).await);
    ensure_eq!((added.newly_added, added.blocked), (true, Some(entry)));
    Ok(Pass)
}

/// Re-adding a hold keeps the later expiry (`max`); an expired or over-long
/// hold is `Invalid`.
pub async fn idx_hold_extension_keeps_max<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x2b; 32];
    let idx = index!(h, obj);
    for (expiry, now, kept) in [(500, 1, 500), (300, 2, 500), (700, 3, 700)] {
        ensure_eq!(
            ok!(idx.add_hold(&obj, &[1; 32], expiry, now).await),
            HoldOutcome::Held
        );
        ensure_eq!(hold_row(&idx, &obj, &[1; 32]).await?, Some(kept));
    }
    ensure_err!(
        idx.add_hold(&obj, &[2; 32], 5, 5).await,
        StoreError::Invalid(_)
    );
    let long = idx.add_hold(&obj, &[2; 32], 11 + MAX_HOLD_TTL_MS, 10).await;
    ensure_err!(long, StoreError::Invalid(_));
    let max = ok!(idx.add_hold(&obj, &[2; 32], 10 + MAX_HOLD_TTL_MS, 10).await);
    ensure_eq!(max, HoldOutcome::Held);
    Ok(Pass)
}

/// Ordinary mutations delete the expired holds they read, not only the
/// GC plan; a live hold stays. (One hold at a time, so the case holds
/// whatever page size the backend's scans return.)
pub async fn idx_expired_holds_pruned_on_mutation<H: KvHarness>(h: H) -> Outcome {
    let obj = [0x2c; 32];
    let idx = index!(h, obj);
    ensure_eq!(
        ok!(idx.add_hold(&obj, &[1; 32], 50, 1).await),
        HoldOutcome::Held
    );
    ok!(idx.add_holder(&obj, &holder("a")?, None, 600).await);
    ensure_eq!(hold_row(&idx, &obj, &[1; 32]).await?, None);
    ensure_eq!(
        ok!(idx.add_hold(&obj, &[2; 32], 900, 600).await),
        HoldOutcome::Held
    );
    ok!(idx.block(&obj, &BlockEntry::new("r", 1), 700).await);
    ensure_eq!(hold_row(&idx, &obj, &[2; 32]).await?, Some(900));
    ok!(idx.remove_holder(&obj, &holder("a")?, 901).await);
    ensure_eq!(hold_row(&idx, &obj, &[2; 32]).await?, None);
    Ok(Pass)
}
