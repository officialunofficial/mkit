//! Typed readers over any [`NamespaceStore`]: the `store::keys` layouts and
//! `store::codec` values in one place, so no backend reimplements them.

use mkit_core::hash::Hash;

use super::codec;
use super::error::StoreError;
use super::keys::{self, ParsedKey};
use super::kv::{Cursor, Key, NamespaceStore};
use super::partition::Partition;
use crate::quota::{QuotaScope, QuotaState};
use crate::replay::{ReplayKey, ReplayRecord};
use crate::repo::RepoName;

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

/// Up to `limit` refs of `repo` whose names start with `prefix`, after
/// `after`. Names are returned in full; the binding strips the prefix.
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
