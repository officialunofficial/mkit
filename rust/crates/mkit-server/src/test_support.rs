//! Typed fixtures for embedder tests, available only with `test-support`.
//!
//! These helpers use the server's key routing and production value codecs.
//! They deliberately bypass authorization and lifecycle transitions; use them
//! only to prepare isolated test stores. Storage adapters still use
//! `store::adapter_spi` for their storage contracts.

use mkit_core::hash::{Hash, to_hex};

use crate::pipeline::{RepoVisibility, ShardMap};
use crate::reads::VisibilityWitness;
use crate::store::{codec, keys, publication};
use crate::{Batch, BatchOutcome, BlobKey, NamespaceStore, Partition, RepoId, StoreError};

/// Visibility fixture metadata, independent of the stored representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilitySeed {
    /// Public or private repository policy.
    pub visibility: RepoVisibility,
    /// Last accepted statement creation or envelope write time.
    pub last_created_ms: u64,
    /// Last accepted statement id, if any.
    pub last_statement_id: Option<Hash>,
    /// Time at which visibility last changed.
    pub changed_ms: u64,
}

/// Writes typed fixtures to a test store using its normal shard map.
pub struct TestSeeder<'a, N> {
    store: &'a N,
    shards: &'a dyn ShardMap,
}

impl<N> core::fmt::Debug for TestSeeder<'_, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestSeeder").finish_non_exhaustive()
    }
}

impl<'a, N: NamespaceStore> TestSeeder<'a, N> {
    /// Borrow an isolated test store and the shard map used by its readers.
    #[must_use]
    pub fn new(store: &'a N, shards: &'a dyn ShardMap) -> Self {
        Self { store, shards }
    }

    /// Seed the repository record; other rows are left as they are.
    ///
    /// # Errors
    /// Returns storage failures or a refused fixture batch.
    pub async fn seed_repository(
        &self,
        repo: &RepoId,
        created_at_ms: u64,
    ) -> Result<(), StoreError> {
        self.apply(
            &self.shards.coordinator(&repo.namespace),
            Batch::new().put(
                keys::repo_record(&repo.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms }),
            ),
        )
        .await
    }

    /// Seed visibility, which may precede creation of the repository record.
    ///
    /// # Errors
    /// Returns storage failures or a refused fixture batch.
    pub async fn seed_visibility(
        &self,
        repo: &RepoId,
        seed: VisibilitySeed,
    ) -> Result<(), StoreError> {
        let row = codec::RepoVisibilityV1 {
            visibility: match seed.visibility {
                RepoVisibility::Public => codec::StoredVisibility::Public,
                RepoVisibility::Private => codec::StoredVisibility::Private,
            },
            last_created_ms: seed.last_created_ms,
            last_statement_id: seed.last_statement_id.as_ref().map(to_hex),
            changed_ms: seed.changed_ms,
        };
        self.apply(
            &self.shards.coordinator(&repo.namespace),
            Batch::new().put(
                keys::repo_visibility(&repo.name),
                codec::encode_repo_visibility(&row),
            ),
        )
        .await
    }

    /// Replace the membership and published-member rows in one fixture batch.
    /// `None` removes that row. This does not create content or ref state.
    ///
    /// # Errors
    /// Returns storage failures or a refused fixture batch.
    pub async fn seed_pack_witness(
        &self,
        repo: &RepoId,
        pack: &Hash,
        member: Option<VisibilityWitness>,
        published: Option<VisibilityWitness>,
    ) -> Result<(), StoreError> {
        let mut batch = Batch::new();
        for (key, witness) in [
            (keys::membership(&repo.name, pack), member),
            (keys::published_member(&repo.name, pack), published),
        ] {
            batch = match witness {
                Some(witness) => batch.put(
                    key,
                    publication::Witness {
                        generation: witness.generation,
                        sequence: witness.sequence,
                        published: witness.published,
                        held: witness.held,
                        boundary: witness.boundary,
                    }
                    .encode(),
                ),
                None => batch.delete(key),
            };
        }
        self.apply(&self.shards.membership(repo, &BlobKey::pack(*pack)), batch)
            .await
    }

    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<(), StoreError> {
        match self.store.apply(partition, batch).await? {
            BatchOutcome::Committed => Ok(()),
            _ => Err(StoreError::Invalid("fixture batch did not commit".into())),
        }
    }
}
