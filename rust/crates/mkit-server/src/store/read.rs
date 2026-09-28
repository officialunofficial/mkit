//! Typed readers over any [`NamespaceStore`]: the `store::keys` layouts and
//! `store::codec` values in one place, so no backend reimplements them.

use mkit_core::hash::Hash;

use super::codec;
use super::error::StoreError;
use super::keys::{self, ParsedKey};
use super::kv::{Cursor, Key, NamespaceStore};
use super::partition::Partition;
use crate::pipeline::ShardMap;
use crate::quota::{QuotaScope, QuotaState};
use crate::replay::{ReplayKey, ReplayRecord};
use crate::repo::{RepoId, RepoName};

/// One page of [`list_refs`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefPage {
    /// Full ref names and ids, in name order.
    pub refs: Vec<(String, Hash)>,
    /// Resume point, if more refs may follow.
    pub next: Option<Cursor>,
}

/// A ref's id, if it exists.
pub async fn read_ref<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    repo: &RepoName,
    name: &str,
) -> Result<Option<Hash>, StoreError> {
    let value = store.get(p, &keys::ref_key(repo, name)).await?;
    value.as_ref().map(codec::decode_ref_id).transpose()
}

/// Up to `limit` refs of `repo` whose names start with `prefix` as raw
/// bytes, after `after`. Names are returned in full. `ListRefs` passes
/// [`crate::refs::list_scan_prefix`] so it matches at a component boundary
/// (SPEC-REFS §4), then strips it.
pub async fn list_refs<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    repo: &RepoName,
    prefix: &str,
    after: Option<&Cursor>,
    limit: u32,
) -> Result<RefPage, StoreError> {
    let (start, end) = keys::ref_prefix_range(repo, prefix);
    let page = store.scan(p, &start, &end, after, limit).await?;
    let refs = page
        .entries
        .iter()
        .map(|(key, value)| match keys::parse(key) {
            Some(ParsedKey::Ref { name, .. }) => Ok((name, codec::decode_ref_id(value)?)),
            _ => Err(StoreError::Corrupt("malformed ref key".into())),
        })
        .collect::<Result<_, _>>()?;
    Ok(RefPage {
        refs,
        next: page.next,
    })
}

/// Repository-scoped pack membership, with an optional read-your-writes ref.
/// Unknown or malformed hints are ignored (STC §7.9). Membership is checked
/// in this repository's index first, then in its strongly consistent ref shard.
pub async fn is_member<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
    hint: Option<&str>,
) -> Result<bool, StoreError> {
    let key = keys::membership(&repo.name, pack);
    let index = shards.membership(repo, &crate::store::BlobKey::pack(*pack));
    if store.get(&index, &key).await?.is_some() {
        return Ok(true);
    }
    if let Some(name) = hint
        && crate::refs::validate_ref_name(name)
        && crate::refs::is_served_ref_name(name)
    {
        return Ok(store
            .get(&shards.ref_shard(repo, name), &key)
            .await?
            .is_some());
    }
    Ok(false)
}

/// The replay record for `scope`, if any (PRD §5.4 stage 0).
pub async fn replay_lookup<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    scope: &ReplayKey,
) -> Result<Option<ReplayRecord>, StoreError> {
    let value = store.get(p, &keys::replay(&scope.0)).await?;
    value.as_ref().map(codec::decode_replay_record).transpose()
}

/// The current quota window of `scope`, if any.
pub async fn quota_state<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    scope: &QuotaScope,
) -> Result<Option<QuotaState>, StoreError> {
    let value = store.get(p, &keys::quota(scope)).await?;
    value.as_ref().map(codec::decode_quota_state).transpose()
}

/// The grant epoch; an absent key is epoch 0.
pub async fn grant_epoch<S: NamespaceStore>(store: &S, p: &Partition) -> Result<u64, StoreError> {
    let value = store.get(p, &keys::grant_epoch()).await?;
    value.as_ref().map_or(Ok(0), codec::decode_u64)
}

/// How long past its envelope's expiry a replay record is kept. An envelope
/// verifies while the verifier's clock is at most its expiry, so a record
/// pruned on a clock that runs ahead could let a replay through on a clock
/// that runs behind. The grace exceeds any tolerated skew: the commit-
/// deadline margin (SPEC-WRITE-GRANTS §5.5, 5 s) and the auth v2 clock
/// lead (`mkit_core::write_auth::MAX_CLOCK_LEAD_MS`, 30 s).
pub const REPLAY_PRUNE_GRACE_MS: u64 = 60_000;

// The grace covers the largest skew the auth v2 verifier tolerates.
const _: () =
    assert!(REPLAY_PRUNE_GRACE_MS >= mkit_core::write_auth::MAX_CLOCK_LEAD_MS.unsigned_abs());

/// Up to `limit` replay records whose envelopes expired before
/// `now_ms - REPLAY_PRUNE_GRACE_MS`, as `(index key, record key)` pairs to
/// delete. A record is written once per scope and never revived after its
/// envelope expired, so the deletes need no precondition.
pub async fn expired_replay_keys<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    now_ms: u64,
    limit: u32,
) -> Result<Vec<(Key, Key)>, StoreError> {
    let (start, end) = keys::replay_expiry_before(now_ms.saturating_sub(REPLAY_PRUNE_GRACE_MS));
    let page = store.scan(p, &start, &end, None, limit).await?;
    page.entries
        .into_iter()
        .map(|(index, _)| match keys::parse(&index) {
            Some(ParsedKey::ReplayExpiry { scope, .. }) => Ok((index, keys::replay(&scope))),
            _ => Err(StoreError::Corrupt("malformed replay expiry key".into())),
        })
        .collect()
}

/// Up to `limit` quota windows of length `window_ms` that ended by
/// `now_ms`, as `(index key, quota key)` pairs. A quota key is rewritten
/// when its scope opens a new window, so the caller guards each quota-key
/// delete with `Equals` on the value it read.
pub async fn stale_quota_keys<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    now_ms: u64,
    window_ms: u64,
    limit: u32,
) -> Result<Vec<(Key, Key)>, StoreError> {
    let Some(last_stale_start) = now_ms.checked_sub(window_ms) else {
        return Ok(Vec::new());
    };
    let (start, end) = keys::quota_window_before(last_stale_start.saturating_add(1));
    let page = store.scan(p, &start, &end, None, limit).await?;
    page.entries
        .into_iter()
        .map(|(index, _)| {
            let quota = keys::quota_for_window(&index)
                .ok_or_else(|| StoreError::Corrupt("malformed quota window key".into()))?;
            Ok((index, quota))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;
    use crate::memory::MemoryKv;
    use crate::repo::NamespaceKey;
    use crate::store::{Batch, Value};

    fn ns() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    #[test]
    fn typed_readers_decode_their_layouts() {
        let kv = MemoryKv::default();
        let repo = RepoName::new("r").unwrap();
        let scope = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[1; 32]);
        let old = ReplayKey([1; 32]);
        let batch = Batch::new()
            .put(
                keys::ref_key(&repo, "refs/heads/a"),
                codec::encode_ref_id(&[1; 32]),
            )
            .put(
                keys::ref_key(&repo, "refs/heads/b"),
                codec::encode_ref_id(&[2; 32]),
            )
            .put(
                keys::ref_key(&repo, "refs/tags/t"),
                codec::encode_ref_id(&[3; 32]),
            )
            .put(keys::grant_epoch(), codec::encode_u64(4))
            .put(keys::replay_expiry(100, &old.0), Value::default())
            .put(keys::replay_expiry(200, &[2; 32]), Value::default())
            .put(keys::quota_window(0, &scope), Value::default());
        block_on(async {
            assert_eq!(grant_epoch(&kv, &ns()).await.unwrap(), 0);
            kv.apply(&ns(), batch).await.unwrap();
            assert_eq!(
                read_ref(&kv, &ns(), &repo, "refs/heads/b").await.unwrap(),
                Some([2; 32])
            );
            assert_eq!(
                read_ref(&kv, &ns(), &repo, "refs/heads/c").await.unwrap(),
                None
            );
            let page = list_refs(&kv, &ns(), &repo, "refs/heads/", None, 1)
                .await
                .unwrap();
            assert_eq!(page.refs, vec![("refs/heads/a".into(), [1; 32])]);
            let rest = list_refs(&kv, &ns(), &repo, "refs/heads/", page.next.as_ref(), 10)
                .await
                .unwrap();
            assert_eq!((rest.refs.len(), rest.next), (1, None));
            assert_eq!(grant_epoch(&kv, &ns()).await.unwrap(), 4);
            assert_eq!(replay_lookup(&kv, &ns(), &old).await.unwrap(), None);
            assert_eq!(quota_state(&kv, &ns(), &scope).await.unwrap(), None);
            assert_eq!(
                expired_replay_keys(&kv, &ns(), 200 + REPLAY_PRUNE_GRACE_MS, 10)
                    .await
                    .unwrap(),
                vec![(keys::replay_expiry(100, &old.0), keys::replay(&old.0))]
            );
            // Within the grace window nothing is pruned, even long past expiry.
            let within = expired_replay_keys(&kv, &ns(), 100 + REPLAY_PRUNE_GRACE_MS, 10).await;
            assert!(within.unwrap().is_empty());
            assert!(
                stale_quota_keys(&kv, &ns(), 99, 100, 10)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                stale_quota_keys(&kv, &ns(), 100, 100, 10).await.unwrap(),
                vec![(keys::quota_window(0, &scope), keys::quota(&scope))]
            );
        });
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use crate::pipeline::D34Shards;
    use crate::store::{Batch, BatchOutcome, PartitionStats, ScanPage, StoreCapabilities, Value};
    use crate::{MemoryKv, NamespaceKey};
    use futures_executor::block_on;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Observed {
        inner: MemoryKv,
        gets: Mutex<Vec<(Partition, Key)>>,
    }
    impl NamespaceStore for Observed {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
            self.gets.lock().unwrap().push((p.clone(), k.clone()));
            self.inner.get(p, k).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }
    fn repo(name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).unwrap(),
        }
    }
    const PACK: Hash = [7; 32];
    const REF: &str = "refs/heads/main";
    fn plant(kv: &Observed, p: &Partition, repo: &RepoId) {
        assert_eq!(
            block_on(kv.inner.apply(
                p,
                Batch::new().put(keys::membership(&repo.name, &PACK), Value::default())
            ))
            .unwrap(),
            BatchOutcome::Committed
        );
    }
    #[test]
    fn index_hit_needs_only_one_get() {
        let kv = Observed::default();
        let r = repo("a");
        let shards = D34Shards;
        plant(
            &kv,
            &shards.membership(&r, &crate::store::BlobKey::pack(PACK)),
            &r,
        );
        assert!(block_on(is_member(&kv, &shards, &r, &PACK, Some(REF))).unwrap());
        assert_eq!(kv.gets.lock().unwrap().len(), 1);
    }
    #[test]
    fn ref_hint_sees_unrelayed_membership() {
        let kv = Observed::default();
        let r = repo("a");
        let shards = D34Shards;
        plant(&kv, &shards.ref_shard(&r, REF), &r);
        assert!(!block_on(is_member(&kv, &shards, &r, &PACK, None)).unwrap());
        kv.gets.lock().unwrap().clear();
        assert!(block_on(is_member(&kv, &shards, &r, &PACK, Some(REF))).unwrap());
        assert_eq!(kv.gets.lock().unwrap()[1].0, shards.ref_shard(&r, REF));
    }
    #[test]
    fn missing_membership_and_unknown_hint_are_false() {
        let kv = Observed::default();
        let r = repo("a");
        assert!(!block_on(is_member(&kv, &D34Shards, &r, &PACK, None)).unwrap());
        assert!(!block_on(is_member(&kv, &D34Shards, &r, &PACK, Some(REF))).unwrap());
    }
    #[test]
    fn invalid_and_unserved_hints_do_not_read_a_ref_shard() {
        for hint in [
            "bad ref",
            "refs/heads/../main",
            "main",
            "refsx/heads/main",
            "",
        ] {
            let kv = Observed::default();
            let r = repo("a");
            assert!(!block_on(is_member(&kv, &D34Shards, &r, &PACK, Some(hint))).unwrap());
            // The mandatory index lookup still happens; the hint adds no call.
            assert_eq!(kv.gets.lock().unwrap().len(), 1, "{hint}");
        }
    }
    #[test]
    fn index_and_ref_hint_never_cross_repository_or_namespace() {
        let kv = Observed::default();
        let a = repo("a");
        let b = repo("b");
        let shards = D34Shards;
        plant(
            &kv,
            &shards.membership(&a, &crate::store::BlobKey::pack(PACK)),
            &a,
        );
        plant(&kv, &shards.ref_shard(&a, REF), &a);
        assert!(!block_on(is_member(&kv, &shards, &b, &PACK, Some(REF))).unwrap());
        let other = RepoId {
            namespace: NamespaceKey::from_stored(format!("ed25519-{}", "b".repeat(64))),
            name: a.name.clone(),
        };
        assert!(!block_on(is_member(&kv, &shards, &other, &PACK, Some(REF))).unwrap());
    }
}
