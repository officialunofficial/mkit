//! Internal safety reads for GC and takedown consumers.

use crate::error::ServerError;
use crate::repo::NamespaceKey;
use crate::store::watermark::{self, ActiveShardsPage, WatermarkError};
use crate::store::{BlobStore, Cursor, KeyClasses, NamespaceStore, Partition};

use super::{HookSet, Pipeline, Sharding, meta_error, ms};

fn map_watermark(error: WatermarkError) -> ServerError {
    match error {
        WatermarkError::Recovering => {
            ServerError::unavailable("coordinator lease table is recovering")
        }
        WatermarkError::Store(error) => meta_error(error),
    }
}

impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Namespace relay lower bound for GC and takedown. Consumers add the
    /// lease clock margin to their threshold. Recovery may lower this value;
    /// it is unavailable until the recovered lease table is reconciled.
    ///
    /// # Errors
    /// Unavailable during lease-table recovery or on an unreadable store.
    pub async fn namespace_relay_watermark(&self, ns: &NamespaceKey) -> Result<u64, ServerError> {
        let now = ms(self.clock.now_ms());
        if self.cfg.sharding == Sharding::Single {
            if self.meta.capabilities().key_classes == KeyClasses::RefsOnly {
                return Ok(now);
            }
            let partition = Partition::Namespace(ns.clone());
            if self.meta.capabilities().key_classes == KeyClasses::All {
                watermark::check_recovery(&self.meta, &partition)
                    .await
                    .map_err(map_watermark)?;
            }
            return crate::relay::relay_watermark(&self.meta, &partition, now)
                .await
                .map_err(meta_error);
        }
        watermark::namespace_relay_watermark(&self.meta, &self.shards.coordinator(ns), now)
            .await
            .map_err(map_watermark)
    }

    /// Enumerate coordinator ref-shard rows for a safety re-check. Expired
    /// rows retained for relay backlog are included.
    ///
    /// # Errors
    /// Unavailable during lease-table recovery or on an unreadable store.
    pub async fn active_shards(
        &self,
        ns: &NamespaceKey,
        cursor: Option<&Cursor>,
        limit: u32,
    ) -> Result<ActiveShardsPage, ServerError> {
        if self.cfg.sharding == Sharding::Single {
            if self.meta.capabilities().key_classes == KeyClasses::All {
                watermark::check_recovery(&self.meta, &Partition::Namespace(ns.clone()))
                    .await
                    .map_err(map_watermark)?;
            }
            return Ok(ActiveShardsPage {
                shards: if cursor.is_none() && limit > 0 {
                    vec![Partition::Namespace(ns.clone())]
                } else {
                    Vec::new()
                },
                next: None,
            });
        }
        watermark::active_shards(&self.meta, &self.shards.coordinator(ns), cursor, limit)
            .await
            .map_err(map_watermark)
    }
}
