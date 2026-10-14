//! Borrow the pipeline's routing configuration for trusted typed reads.
use super::{HookSet, Pipeline};
use crate::reads::ReadAccess;
use crate::store::{MultipartBlobStore, NamespaceStore};

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Borrow typed reads with this pipeline's routing and visibility defaults.
    /// The caller must authorize each repository before using this trusted facade.
    #[must_use]
    pub fn read_access(&self) -> ReadAccess<'_, N> {
        ReadAccess::new(
            &self.meta,
            self.shards.as_ref(),
            self.cfg.default_repo_visibility,
            self.cfg.takedown_denial,
        )
    }
}
