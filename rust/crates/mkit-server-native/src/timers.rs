//! Native timer scheduling, rebuilt from `SQLite` and notified by committed puts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mkit_server::sql::SqlKvStore;
use mkit_server::timers::{
    RETRY_BACKOFF_MS, TickBudget, TimerRegistry, earliest_timer_put, run_due,
};
use mkit_server::{
    Batch, BatchOutcome, BoxFuture, Clock, Cursor, Key, NamespaceStore, Partition, PartitionStats,
    ScanPage, Sleep, StoreCapabilities, StoreError, Value,
};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::{Blocking, RusqliteConn, Shutdown};

#[derive(Debug, Default)]
struct Heads {
    partitions: BTreeMap<Partition, u64>,
    ordered: BTreeSet<(u64, Partition)>,
}

impl Heads {
    fn lower(&mut self, partition: &Partition, due: u64) {
        if let Some(current) = self.partitions.get(partition).copied() {
            if current <= due {
                return;
            }
            self.ordered.remove(&(current, partition.clone()));
        }
        self.partitions.insert(partition.clone(), due);
        self.ordered.insert((due, partition.clone()));
    }

    fn take_due(&mut self, now: u64) -> Vec<Partition> {
        let mut due_partitions = Vec::new();
        while let Some((due, partition)) = self.ordered.first() {
            if *due > now {
                break;
            }
            let partition = partition.clone();
            self.ordered.pop_first();
            self.partitions.remove(&partition);
            due_partitions.push(partition);
        }
        due_partitions
    }
}

#[derive(Debug, Default)]
struct Directory {
    heads: Mutex<Heads>,
    changed: Notify,
}

impl Directory {
    fn lower(&self, partition: &Partition, due: u64) {
        self.heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lower(partition, due);
        self.changed.notify_one();
    }
}

/// Delegates metadata operations and wakes a driver after committed timer puts.
///
/// For synchronous stores, put this wrapper **inside** [`Blocking`]: the
/// notification then survives cancellation of the awaiting request, just as
/// the committed batch does.
#[derive(Debug)]
pub struct TimerNotifying<N> {
    inner: N,
    directory: Arc<Directory>,
}

impl<N> TimerNotifying<N> {
    /// Wrap a store with a new, initially empty timer directory.
    #[must_use]
    pub fn new(inner: N) -> Self {
        Self {
            inner,
            directory: Arc::default(),
        }
    }

    /// The underlying store, for backend-specific startup queries.
    #[must_use]
    pub fn inner(&self) -> &N {
        &self.inner
    }
}

impl<N: NamespaceStore> NamespaceStore for TimerNotifying<N> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.inner.has(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(p, keys).await
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
        let earliest = earliest_timer_put(&batch);
        let outcome = self.inner.apply(p, batch).await?;
        if outcome == BatchOutcome::Committed
            && let Some(due) = earliest
        {
            self.directory.lower(p, due);
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// `SQLite` metadata shared by the native pipeline and its timer driver.
pub type TimerStore = Blocking<TimerNotifying<SqlKvStore<RusqliteConn>>>;

/// A prepared `SQLite` driver. Construction needs no runtime; [`Self::start`]
/// rebuilds its directory on the blocking pool and starts the loop.
pub struct TimerDriver {
    store: TimerStore,
    registry: TimerRegistry<'static, TimerStore>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for TimerDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimerDriver")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl TimerDriver {
    /// Prepare a driver over the same notifying store as the pipeline.
    #[must_use]
    pub fn new(
        store: TimerStore,
        registry: TimerRegistry<'static, TimerStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            registry,
            clock,
        }
    }

    /// The notifying store this driver runs over: a write committed through it
    /// wakes the driver, as a request's commit does.
    #[must_use]
    pub fn store(&self) -> &TimerStore {
        &self.store
    }

    /// Rebuild timer heads and spawn on the current runtime.
    ///
    /// The returned task finishes its current tick on shutdown. Await it
    /// after the listeners drain, before releasing the server's root locks.
    ///
    /// # Errors
    /// A failed startup query, including a corrupt partition or timer key.
    pub async fn start(self, shutdown: Shutdown) -> Result<JoinHandle<()>, StoreError> {
        self.start_with_drain(shutdown, Duration::ZERO).await
    }

    /// [`Self::start`], but after `stop` triggers the driver first runs every
    /// partition due at or before now (repeatedly, until nothing is due) for
    /// at most `drain` before it exits; zero skips the drain. `stop` is
    /// separate from the listeners' switch so that work committed while they
    /// drain is still delivered.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub async fn start_with_drain(
        self,
        stop: Shutdown,
        drain: Duration,
    ) -> Result<JoinHandle<()>, StoreError> {
        let store = Arc::clone(self.store.inner());
        let heads = crate::blocking::on_pool(move || store.inner().timer_heads()).await?;
        let directory = &self.store.inner().directory;
        for (partition, due) in heads {
            directory.lower(&partition, due);
        }
        Ok(tokio::spawn(self.drive(stop, drain)))
    }

    fn now(&self) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(0)
    }

    /// Run every head due now. `Idle` when none was; `Stopped` when `stop`
    /// triggered before every claimed head ran (a restart rebuilds them from
    /// `SQLite`).
    async fn run_due_heads(&self, stop: Option<&Shutdown>) -> Pass {
        let directory = &self.store.inner().directory;
        let now = self.now();
        let partitions = directory
            .heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_due(now);
        if partitions.is_empty() {
            return Pass::Idle;
        }
        // Claim every head due at this wake before running any tick.
        // Immediate puts cannot take a second turn before the other heads.
        let mut claimed = partitions.into_iter();
        while let Some(partition) = claimed.next() {
            if stop.is_some_and(Shutdown::is_triggered) {
                // Give the unrun claims back, due now, so the shutdown drain
                // (or a restart, from `SQLite`) still runs them.
                directory.lower(&partition, now);
                for rest in claimed {
                    directory.lower(&rest, now);
                }
                return Pass::Stopped;
            }
            // Concurrent puts create fresh entries; reports only lower them.
            let next = match run_due(
                &self.store,
                &partition,
                &self.registry,
                self.clock.as_ref(),
                now,
                &TickBudget::default(),
            )
            .await
            {
                Ok(report) => report.next_wake_ms,
                Err(error) => {
                    tracing::warn!(%error, ?partition, "timer tick failed");
                    Some(self.now().saturating_add(RETRY_BACKOFF_MS))
                }
            };
            if let Some(due) = next {
                directory.lower(&partition, due);
            }
        }
        Pass::Ran
    }

    async fn drive(self, stop: Shutdown, drain: Duration) {
        let directory = &self.store.inner().directory;
        // Set once, when `stop` is first seen: the deadline covers the
        // in-flight pass and the drain together.
        let mut deadline: Option<tokio::time::Instant> = None;
        loop {
            if stop.is_triggered() {
                break;
            }
            let pass = if drain.is_zero() {
                self.run_due_heads(Some(&stop)).await
            } else {
                let running = self.run_due_heads(Some(&stop));
                tokio::pin!(running);
                tokio::select! {
                    pass = &mut running => pass,
                    () = stop.wait() => {
                        let limit = tokio::time::Instant::now() + drain;
                        deadline = Some(limit);
                        if let Ok(pass) = tokio::time::timeout_at(limit, running).await {
                            pass
                        } else {
                            tracing::warn!(
                                ?drain,
                                "shutdown drain deadline reached during the in-flight timer pass"
                            );
                            return;
                        }
                    }
                }
            };
            match pass {
                Pass::Ran => continue,
                Pass::Stopped => break,
                Pass::Idle => {}
            }
            let earliest = directory
                .heads
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .ordered
                .first()
                .map(|(due, _)| *due);
            let delay = earliest.map_or(60_000, |due| due.saturating_sub(self.now()).min(60_000));
            tokio::select! {
                () = stop.wait() => break,
                () = directory.changed.notified() => {},
                () = tokio::time::sleep(Duration::from_millis(delay)) => {},
            }
        }
        if drain.is_zero() {
            return;
        }
        let limit = deadline.unwrap_or_else(|| tokio::time::Instant::now() + drain);
        let drained = tokio::time::timeout_at(limit, async {
            while self.run_due_heads(None).await != Pass::Idle {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                ?drain,
                "shutdown drain deadline reached with timers still due"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    Idle,
    Ran,
    Stopped,
}

/// The native [`Sleep`]: `tokio::time::sleep`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleep;

impl Sleep for TokioSleep {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}
