//! Source publication orchestration over the final guarded storage boundary.
//! Callers must provide an already initialized external recovery identity and
//! route source operations to the raw local store, avoiding wrapper recursion.
use crate::sql::{SqlConn, SqlError, SqlKvStore};
use mkit_server::store::adapter_spi::publication_fence::{
    Generation, Intent, PublicationFence, SourceReceipt, SourceStatus,
};
use mkit_server::store::adapter_spi::publication_fence_plan::publication_batch;
use mkit_server::{Batch, BatchOutcome, NamespaceStore, Partition, RepoId, StoreError};
use mkit_server::{
    BoxFuture, Cursor, Key, MaybeSend, MaybeSync, PartitionStats, ScanPage, StoreCapabilities,
    Value,
};

/// Installed at the durable source store, shared by fetch and alarm writes.
/// The local argument is deliberately the raw SQL store to avoid recursion.
pub(crate) trait SourcePublication<C>: MaybeSend + MaybeSync {
    fn apply<'a>(
        &'a self,
        local: &'a SqlKvStore<C>,
        source: &'a Partition,
        batch: Batch,
        recovery_due_ms: u64,
    ) -> BoxFuture<'a, Result<BatchOutcome, StoreError>>;
}

/// A remote authority/projection store with local source transactions.
#[derive(Debug)]
pub(crate) struct RemotePublication<R> {
    pub remote: R,
    pub generation: Generation,
}
impl<C: SqlConn, R: NamespaceStore> SourcePublication<C> for RemotePublication<R> {
    fn apply<'a>(
        &'a self,
        local: &'a SqlKvStore<C>,
        source: &'a Partition,
        batch: Batch,
        recovery_due_ms: u64,
    ) -> BoxFuture<'a, Result<BatchOutcome, StoreError>> {
        Box::pin(async move {
            let Partition::Ref { ns, repo, .. } = source else {
                return Err(StoreError::Invalid(
                    "publication source is not a ref partition".into(),
                ));
            };
            let writer = PublicationWriter::new(
                &RepoId {
                    namespace: ns.clone(),
                    name: repo.clone(),
                },
                self.generation,
            );
            let local = AuditedStore(local);
            let routed = RoutedStore {
                local: &local,
                remote: &self.remote,
                partition: source,
            };
            writer.apply(&routed, source, batch, recovery_due_ms).await
        })
    }
}

/// Use the same audit extension as ordinary `PressureStore` writes. Ref shards
/// cannot host audit events; malformed events still fail instead of bypassing
/// the extension merely because publication orchestration is enabled.
struct AuditedStore<'a, C>(&'a SqlKvStore<C>);
impl<C: SqlConn> NamespaceStore for AuditedStore<'_, C> {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let partition = p.clone();
        self.0.apply_extended(p, batch, move |get, batch, _| {
            mkit_server::admin::extend_audit_batch(&partition, batch, |key| {
                get(key).map_err(StoreError::from)
            })
            .map_err(|_| SqlError::Corrupt("automatic audit extension"))?;
            Ok(())
        })
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

/// Route only the hosting partition locally. Other authorities must use the
/// remote namespace store; sending them to this object's SQL would split state.
struct RoutedStore<'a, L, R> {
    local: &'a L,
    remote: &'a R,
    partition: &'a Partition,
}
impl<L: NamespaceStore, R: NamespaceStore> NamespaceStore for RoutedStore<'_, L, R> {
    fn capabilities(&self) -> StoreCapabilities {
        self.local.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        if p == self.partition {
            self.local.get(p, key).await
        } else {
            self.remote.get(p, key).await
        }
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if p == self.partition {
            self.local.scan(p, start, end, after, limit).await
        } else {
            self.remote.scan(p, start, end, after, limit).await
        }
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        if p == self.partition {
            self.local.apply(p, batch).await
        } else {
            self.remote.apply(p, batch).await
        }
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        if p == self.partition {
            self.local.stats(p).await
        } else {
            self.remote.stats(p).await
        }
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.remote.probe().await
    }
}

/// A writer bound to one repository and externally allocated incarnation.
#[derive(Debug)]
pub struct PublicationWriter {
    fence: PublicationFence,
    generation: Generation,
}
impl PublicationWriter {
    /// Initialization and legacy reconciliation belong to the embedding.
    #[must_use]
    pub fn new(repo: &RepoId, generation: Generation) -> Self {
        Self {
            fence: PublicationFence::new(repo),
            generation,
        }
    }
    /// Apply through invalidation and a guarded local terminal marker.
    pub async fn apply<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
        mut batch: Batch,
        recovery_due_ms: u64,
    ) -> Result<BatchOutcome, StoreError> {
        let Some(plan) = publication_batch(source, &batch)? else {
            let cleans_relay = batch.writes.iter().any(|write| matches!(write,
                mkit_server::Write::Delete(key) if matches!(mkit_server::store::adapter_spi::keys::parse(key),Some(mkit_server::store::adapter_spi::keys::ParsedKey::Relay(_)))));
            let outcome = store.apply(source, batch).await?;
            if cleans_relay && outcome == BatchOutcome::Committed {
                // Only actual committed markers can complete after delivery.
                // Unrelated relay cleanup must never abort a live write.
                if let Ok(Some(marker)) = self.fence.source_marker(store, source).await
                    && marker.status() == SourceStatus::Committed
                    && marker.intent().generation() == self.generation
                {
                    let _completion = self.fence.reconcile_delivered(store, marker.intent()).await;
                }
            }
            return Ok(outcome);
        };
        let mut caps = store.capabilities();
        caps.reserved_batch_ops = caps
            .reserved_batch_ops
            .checked_add(2)
            .ok_or_else(|| StoreError::Invalid("publication batch reservation overflow".into()))?;
        batch.validate(&caps)?;
        self.check_generation(store).await?;
        // This is only an early rejection. The final transaction checks the
        // original guards again, ahead of the appended publication guard.
        let preflight = store
            .apply(
                source,
                Batch {
                    preconditions: batch.preconditions.clone(),
                    writes: Vec::new(),
                },
            )
            .await?;
        if preflight != BatchOutcome::Committed {
            return Ok(preflight);
        }
        self.recover(store, source).await?;
        let previous = self.fence.latest_intent(store, source).await?;
        let attempt = previous
            .as_ref()
            .map_or(Some(1), |row| row.intent().attempt().checked_add(1))
            .ok_or_else(|| StoreError::Invalid("publication attempt overflow".into()))?;
        let targets = plan.fence_targets()?;
        let intent = self
            .fence
            .begin_with_recovery(
                store,
                source,
                attempt,
                plan.digest,
                targets,
                recovery_due_ms,
            )
            .await?;
        if intent.generation() != self.generation {
            return Err(pending());
        }
        self.fence.arm(store, &intent).await?;
        let original_guards = batch.preconditions.len();
        PublicationFence::source_commit_fragment(&intent, &mut batch)?;
        if let Err(error) = batch.validate(&store.capabilities()) {
            self.abort(store, &intent).await?;
            return Err(error);
        }
        let outcome = store.apply(source, batch).await;
        match outcome {
            Ok(BatchOutcome::Committed) => {
                // Record only a receipt read from the durable terminal marker.
                self.record_source(store, &intent).await?;
                Ok(BatchOutcome::Committed)
            }
            Ok(ref refusal) => {
                let status = self.abort(store, &intent).await?;
                if status == SourceStatus::Committed {
                    return Ok(BatchOutcome::Committed);
                }
                match refusal {
                    BatchOutcome::PreconditionFailed { index, .. } if *index >= original_guards => {
                        Err(pending())
                    }
                    _ => outcome,
                }
            }
            Err(error) => {
                // A lost reply is not an abort. Resolve the local CAS race;
                // committed wins even if the transport reported an error.
                match self.abort(store, &intent).await? {
                    SourceStatus::Committed => Ok(BatchOutcome::Committed),
                    SourceStatus::Aborted => Err(error),
                    SourceStatus::Armed => Err(pending()),
                }
            }
        }
    }
    async fn check_generation<S: NamespaceStore>(&self, store: &S) -> Result<(), StoreError> {
        if self.fence.generation(store).await? != self.generation {
            return Err(pending());
        }
        Ok(())
    }
    async fn record_source<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<SourceStatus, StoreError> {
        let source = intent.source()?;
        let marker = self
            .fence
            .source_marker(store, &source)
            .await?
            .ok_or_else(pending)?;
        if marker.intent() != intent {
            return Err(pending());
        }
        let receipt = SourceReceipt::verify(store, intent).await?;
        self.fence.source_receipt(store, &receipt).await?;
        Ok(marker.status())
    }
    async fn abort<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<SourceStatus, StoreError> {
        let source = intent.source()?;
        let mut batch = Batch::new();
        PublicationFence::source_abort_fragment(intent, &mut batch)?;
        // Even a failed/lost abort reply requires inspecting actual state.
        // This never clears uncertainty using a clock or missing marker.
        let _outcome = store.apply(&source, batch).await;
        self.record_source(store, intent).await
    }
    /// Reconcile one durable attempt, including a crash before local arming.
    /// A committed attempt remains pending until real relay cleanup proves all
    /// projections committed. Invoke this from durable recovery alarms too.
    pub async fn recover<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
    ) -> Result<(), StoreError> {
        self.check_generation(store).await?;
        let Some(row) = self.fence.latest_intent(store, source).await? else {
            return Ok(());
        };
        if row.complete() {
            return Ok(());
        }
        let intent = row.intent();
        if intent.generation() != self.generation {
            return Err(pending());
        }
        self.recover_intent(store, intent).await
    }
    /// Recover only the attempt bound to a durable wake. A superseded wake
    /// completes harmlessly without following or canceling its successor.
    pub async fn recover_exact<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<(), StoreError> {
        self.check_generation(store).await?;
        if intent.generation() != self.generation {
            return Ok(());
        }
        let source = intent.source()?;
        let row = self
            .fence
            .latest_intent(store, &source)
            .await?
            .ok_or_else(pending)?;
        if row.intent() != intent || row.complete() {
            return Ok(());
        }
        self.recover_intent(store, intent).await
    }
    async fn recover_intent<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<(), StoreError> {
        let source = intent.source()?;
        let marker = self.fence.source_marker(store, &source).await?;
        if marker
            .as_ref()
            .is_none_or(|marker| marker.intent() != intent)
        {
            // Arm the exact pending intent, then irreversibly cancel it. A
            // delayed original caller cannot publish after this abort wins.
            self.fence.arm(store, intent).await?;
        }
        let marker = self
            .fence
            .source_marker(store, &source)
            .await?
            .ok_or_else(pending)?;
        if marker.intent() != intent {
            return Err(pending());
        }
        if marker.status() == SourceStatus::Armed {
            self.abort(store, intent).await?;
        }
        self.fence.reconcile_delivered(store, intent).await
    }
}

fn pending() -> StoreError {
    StoreError::unavailable("publication recovery pending; retry")
}

/// Durable coordinator recovery, scheduled atomically with invalidation.
#[derive(Debug)]
pub struct RecoveryHandler<R> {
    /// Routes source partitions to their authoritative durable objects.
    pub remote: R,
    /// Externally allocated identity shared by every source writer.
    pub generation: Generation,
}
impl<S: NamespaceStore, R: NamespaceStore> mkit_server::timers::TimerHandler<S>
    for RecoveryHandler<R>
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::PUBLICATION_FENCE_RECOVERY
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> BoxFuture<'a, Result<mkit_server::timers::Fired, StoreError>> {
        Box::pin(async move {
            let intent = PublicationFence::decode_recovery_intent(&timer.value)?;
            let source = intent.source()?;
            let Partition::Ref { ns, repo, .. } = &source else {
                return Err(StoreError::Invalid(
                    "invalid publication recovery source".into(),
                ));
            };
            if ctx.partition != &Partition::Coordinator(ns.clone()) {
                return Err(StoreError::Invalid(
                    "publication recovery outside authority".into(),
                ));
            }
            let repo = RepoId {
                namespace: ns.clone(),
                name: repo.clone(),
            };
            let fence = PublicationFence::new(&repo);
            let intent = fence.recovery_intent(&timer.value)?;
            let source = fence.recovery_source(&timer.value)?;
            if timer.reference.as_ref() != fence.recovery_reference(&source)? {
                return Err(StoreError::Invalid(
                    "publication recovery identity rebound".into(),
                ));
            }
            let routed = RoutedStore {
                local: ctx.store,
                remote: &self.remote,
                partition: ctx.partition,
            };
            let writer = PublicationWriter::new(&repo, self.generation);
            match writer.recover_exact(&routed, &intent).await {
                Ok(()) => Ok(mkit_server::timers::Fired::Done(Batch::new())),
                Err(StoreError::Unavailable(_)) => Ok(mkit_server::timers::Fired::Retry),
                Err(error) => Err(error),
            }
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
