//! Explicit published-value source. Inspection must never fall back to live rows.
use super::list::{BucketSource, IndexBucket, Scan};
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::{NamespaceStore, Partition, RepoId, StoreError};
use mkit_core::hash::Hash;

/// Sorted full ref names and raw ids.
pub type PublishedRows = Vec<(String, Hash)>;
/// A validated snapshot, a live fallback, or a fail-closed storage error.
pub type PublishedBucket = Result<Option<PublishedRows>, StoreError>;

/// Ref data only: the pipeline authorizes each request before invoking this seam.
pub trait PublishedSource: MaybeSend + MaybeSync {
    /// Whether the deployment configures inspection.
    fn inspection_configured(&self) -> bool;
    /// Whether inputs contain exclusively published values, using the current snapshot format.
    fn uses_published_values(&self) -> bool {
        false
    }
    /// Optional unsigned `ReadRef` acceleration; false by default.
    fn read_ref_enabled(&self) -> bool {
        false
    }
    /// A validated bucket, or `None` to use the live published-equivalent index.
    fn bucket<'a>(
        &'a self,
        repo: &'a RepoId,
        partition: &'a Partition,
        now_ms: u64,
    ) -> BoxFuture<'a, PublishedBucket>;
}

pub(super) struct ReaderBucket<'a, N> {
    pub store: &'a N,
    pub partition: &'a Partition,
    pub source: Option<&'a dyn PublishedSource>,
    pub now_ms: u64,
}
impl<N: NamespaceStore> BucketSource for ReaderBucket<'_, N> {
    async fn scan(
        &self,
        repo: &RepoId,
        prefix: &str,
        last: Option<&str>,
        limit: u32,
    ) -> Result<Scan, StoreError> {
        if let Some(source) = self.source {
            if source.inspection_configured() && !source.uses_published_values() {
                return Err(StoreError::unavailable("published view unavailable"));
            }
            if let Some(rows) = source.bucket(repo, self.partition, self.now_ms).await? {
                let mut selected = rows
                    .into_iter()
                    .filter(|(name, _)| {
                        name.starts_with(prefix) && last.is_none_or(|last| name.as_str() > last)
                    })
                    .take(limit as usize + 1)
                    .collect::<Vec<_>>();
                let more = selected.len() > limit as usize;
                selected.truncate(limit as usize);
                return Ok(Scan {
                    rows: selected,
                    more,
                });
            }
        }
        IndexBucket {
            store: self.store,
            partition: self.partition,
        }
        .scan(repo, prefix, last, limit)
        .await
    }
}
