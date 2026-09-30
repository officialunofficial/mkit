//! Content-addressed opaque `ETags` keep exact job guards bounded. These are
//! provisional vc sub-4 facts; normal job cleanup removes them with the pack.
use crate::repo::RepoName;
use crate::store::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, StoreError, Value, keys,
};
use mkit_core::hash::{Hash, Hasher, from_hex, to_hex};

#[cfg(all(test, feature = "memory"))]
#[path = "etag_tests.rs"]
mod tests;

fn identity(tag: &str) -> Hash {
    let mut hash = Hasher::new();
    hash.update(b"mkit-verify-opaque-etag:v1");
    hash.update(tag.as_bytes());
    hash.finalize()
}

fn bad() -> StoreError {
    StoreError::Corrupt("verification ETag binding mismatch".into())
}

/// Resolve a job's bounded binding before passing the original opaque string
/// to the unchanged source interface. Missing or changed auxiliary facts close.
pub(super) async fn resolve<N: NamespaceStore>(
    store: &N,
    partition: &Partition,
    repo: &RepoName,
    pack: &Hash,
    token: Option<&str>,
) -> Result<Option<String>, StoreError> {
    let Some(token) = token else { return Ok(None) };
    let id = from_hex(token).map_err(|_| bad())?;
    if to_hex(&id) != token {
        return Err(bad());
    }
    let key = keys::verify_row(repo, pack, keys::VC_CANDIDATE, Some(&id));
    let raw = store.get(partition, &key).await?.ok_or_else(bad)?;
    let tag = std::str::from_utf8(raw.as_bytes()).map_err(|_| bad())?;
    if identity(tag) != id {
        return Err(bad());
    }
    Ok(Some(tag.to_owned()))
}

/// A lost checkpoint can leave an unused fact, never change another binding.
/// Writes are pure functions of the token and are safe to replay after a crash.
pub(super) async fn capture<N: NamespaceStore>(
    store: &N,
    partition: &Partition,
    repo: &RepoName,
    pack: &Hash,
    tag: &str,
    deadline: u64,
) -> Result<String, StoreError> {
    let id = identity(tag);
    let key = keys::verify_row(repo, pack, keys::VC_CANDIDATE, Some(&id));
    let value = Value::new(tag.as_bytes().to_vec());
    let batch = Batch::new()
        .require(Precondition::NotAfter(deadline))
        .require(Precondition::Absent(key.clone()))
        .put(key.clone(), value.clone());
    match store.apply(partition, batch).await? {
        BatchOutcome::Committed => {}
        BatchOutcome::PreconditionFailed { .. }
            if store.get(partition, &key).await? == Some(value) => {}
        _ => {
            return Err(StoreError::Unavailable(
                "verification ETag write contended".into(),
            ));
        }
    }
    Ok(to_hex(&id))
}
