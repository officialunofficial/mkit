//! The Durable Object side of the key-level contract: decode one
//! [`NsRequest`], run it on the object's `SqlKvStore`, answer one
//! [`NsReply`].
//!
//! The object evaluates batch preconditions (with `NotAfter` against its
//! own clock) and runs partition-local timer handlers on its alarm. No
//! pipeline logic (CAS, quota, replay) runs in it, so any other backend can
//! replace it. [`serve`] is the whole key-value protocol and is generic
//! over the store, so host tests run it over a simulated Durable Object connection;
//! `NsObject` is the wasm32 shell around it.

use core::future::Future;
use mkit_server::sql::SqlError;
use mkit_server::sql::{SqlConn, SqlKvStore};
use mkit_server::storage_error::StorageOp;
use mkit_server::store::export_page;
use mkit_server::telemetry::{
    Metrics,
    pressure::{self, PressureState},
};
use std::sync::{Arc, Mutex, PoisonError};

use mkit_server::{
    Batch, BatchOutcome, Clock, Cursor, Key, NamespaceStore, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value,
};

use crate::classes::ShardClass;
use crate::wire::{Blob, NsCall, NsErrKind, NsReply, NsRequest, WireOutcome};

/// Answer one request body with a reply body. Never fails: a malformed
/// request is an `Invalid` reply, a failed store an error reply whose
/// backend detail goes to the log only.
pub async fn serve<S: NamespaceStore>(store: &S, body: &str, class: ShardClass) -> String {
    encode(&serve_reply(store, body, class).await.0)
}

/// Keep the committed timer Put alongside its typed reply for alarm wiring.
async fn serve_reply<S: NamespaceStore>(
    store: &S,
    body: &str,
    class: ShardClass,
) -> (NsReply, Option<u64>) {
    match decode_request(body, class) {
        Ok((partition, call)) => dispatch(store, &partition, call)
            .await
            .unwrap_or_else(|error| (failure(&error), None)),
        Err(reply) => (reply, None),
    }
}

/// The SQL store of one Durable Object. Every committed put batch,
/// including timer effects, observes physical pressure before returning.
pub struct PressureStore<C> {
    inner: SqlKvStore<C>,
    state: Mutex<PressureState>,
    class: ShardClass,
    clock: Arc<dyn Clock>,
    metrics: Arc<dyn Metrics>,
    backup_interval_ms: Option<u64>,
    seeded_due: Mutex<Option<u64>>,
}

impl<C> core::fmt::Debug for PressureStore<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PressureStore")
            .field("inner", &self.inner)
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

impl<C: SqlConn> PressureStore<C> {
    /// Attach per-instance alerts and metrics to a SQL store.
    #[must_use]
    pub fn new(
        inner: SqlKvStore<C>,
        class: ShardClass,
        clock: Arc<dyn Clock>,
        metrics: Arc<dyn Metrics>,
    ) -> Self {
        Self {
            inner,
            state: Mutex::default(),
            class,
            clock,
            metrics,
            backup_interval_ms: None,
            seeded_due: Mutex::default(),
        }
    }

    /// Seed a backup after the first committed Put in each partition.
    #[must_use]
    pub fn with_backup_interval(mut self, interval_ms: u64) -> Self {
        self.backup_interval_ms = Some(interval_ms);
        self
    }

    /// The earliest timer seeded by a committed batch since the last check.
    pub fn take_seeded_due(&self) -> Option<u64> {
        self.seeded_due
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The underlying SQL connection.
    #[must_use]
    pub fn conn(&self) -> &C {
        self.inner.conn()
    }

    /// Earliest timer per partition for the Durable Object alarm driver.
    ///
    /// # Errors
    /// Failed queries or corrupt timer rows.
    pub fn timer_heads(&self) -> Result<Vec<(Partition, u64)>, StoreError> {
        self.inner.timer_heads()
    }

    /// Forget logical stats cached by the underlying store.
    pub fn clear_stats_cache(&self) {
        self.inner.clear_stats_cache();
    }

    fn observe_pressure(&self) {
        // The SQL apply future finishes on its first poll. This local,
        // synchronous size read follows commit without opening the input gate.
        match self.conn().size_bytes() {
            Ok(bytes) => {
                #[allow(clippy::cast_precision_loss)]
                self.metrics.gauge(
                    pressure::METRIC_PARTITION_BYTES,
                    &[("kind", self.class.label())],
                    bytes as f64,
                );
                if let Some(capacity) = self.inner.capacity() {
                    let limit = capacity.soft_limit();
                    let now_ms = u64::try_from(self.clock.now_ms()).unwrap_or(0);
                    let levels = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        let (next, levels) = pressure::observe(*state, bytes, limit, now_ms);
                        *state = next;
                        levels
                    };
                    for level in levels {
                        pressure::emit(level, self.class.label(), bytes, limit);
                    }
                }
            }
            Err(error) => tracing::warn!(error = %error, "storage pressure size read failed"),
        }
    }

    async fn seed_backup_if_needed(&self, partition: &Partition) {
        let Some(interval_ms) = self.backup_interval_ms else {
            return;
        };
        match self
            .inner
            .get(partition, &mkit_server::store::keys::backup_state())
            .await
        {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                crate::log_failure(&format!("backup seed state read failed: {error}"));
                return;
            }
        }
        let now_ms = u64::try_from(self.clock.now_ms()).unwrap_or(0);
        let due = crate::backup::seeded_due(now_ms, interval_ms);
        // Call the inner store directly: this batch itself holds Puts and
        // must not recurse through the post-commit hook.
        match self
            .inner
            .apply(partition, crate::backup::seed_batch(now_ms, interval_ms))
            .await
        {
            Ok(BatchOutcome::Committed) => {
                let mut pending = self
                    .seeded_due
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *pending = Some(pending.map_or(due, |old| old.min(due)));
            }
            Ok(BatchOutcome::PreconditionFailed { .. }) => {}
            Ok(BatchOutcome::DeadlinePassed { .. }) => unreachable!("seed batch has no deadline"),
            Err(error) => crate::log_failure(&format!("backup seed failed: {error}")),
        }
    }
}

impl<C: SqlConn> NamespaceStore for PressureStore<C> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, partition: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(partition, key).await
    }

    async fn get_many(
        &self,
        partition: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(partition, keys).await
    }

    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(partition, start, end, after, limit).await
    }

    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let has_put = batch.has_put();
        let outcome = self.inner.apply(partition, batch).await?;
        if has_put && outcome == BatchOutcome::Committed {
            self.observe_pressure();
            self.seed_backup_if_needed(partition).await;
        }
        Ok(outcome)
    }

    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(partition).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

fn decode_request(body: &str, class: ShardClass) -> Result<(Partition, NsCall), NsReply> {
    let invalid = |message: &str| NsReply::Err {
        kind: NsErrKind::Invalid,
        message: message.into(),
    };
    let request: NsRequest =
        serde_json::from_str(body).map_err(|_| invalid("malformed request"))?;
    let partition =
        Partition::decode(&request.part.0).map_err(|_| invalid("malformed partition"))?;
    if !class.accepts(&partition) {
        return Err(invalid("partition kind not served by this class"));
    }
    Ok((partition, request.call))
}

/// A reply body.
pub(crate) fn encode(reply: &NsReply) -> String {
    serde_json::to_string(reply).unwrap_or_else(|_| {
        // Serializing these types cannot fail; stay total anyway.
        r#"{"reply":"err","kind":"unavailable","message":"reply encoding failed"}"#.to_owned()
    })
}

/// The reply for a store failure, logging an `Unavailable`'s detail.
pub(crate) fn failure(e: &StoreError) -> NsReply {
    if let StoreError::Unavailable(source) = e {
        // A SQL failure keeps its engine text redacted: expose it here, for
        // the log only.
        let detail = match source.downcast_ref::<SqlError>() {
            Some(SqlError::Backend(text)) => text.expose().to_owned(),
            _ => source.to_string(),
        };
        let (line, _) = mkit_server::storage_error::describe_and_map(StorageOp::SqlExec, detail);
        crate::log_failure(&line);
    }
    NsReply::error(e)
}

async fn dispatch<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    call: NsCall,
) -> Result<(NsReply, Option<u64>), StoreError> {
    let key = |b: Blob| Key::new(b.0);
    let reply = match call {
        NsCall::Get { key: k } => NsReply::Value {
            value: store
                .get(p, &key(k))
                .await?
                .map(|v| Blob(v.into_bytes().into())),
        },
        NsCall::GetMany { keys } => {
            let keys: Vec<Key> = keys.into_iter().map(key).collect();
            NsReply::Values {
                values: store
                    .get_many(p, &keys)
                    .await?
                    .into_iter()
                    .map(|v| v.map(|v| Blob(v.into_bytes().into())))
                    .collect(),
            }
        }
        NsCall::Scan {
            start,
            end,
            after,
            limit,
        } => {
            let (start, end) = (key(start), key(end));
            let (start, end) = (&start, &end);
            let page = bounded_page(
                limit,
                after.map(|c| Cursor::new(c.0)),
                |after, n| async move { store.scan(p, start, end, after.as_ref(), n).await },
            )
            .await?;
            NsReply::page(page)
        }
        NsCall::Apply { batch } => {
            let batch = batch.into();
            let earliest = crate::alarm::earliest_timer_put(&batch);
            let outcome = WireOutcome::from(store.apply(p, batch).await?);
            let earliest = if outcome == WireOutcome::Committed {
                earliest
            } else {
                None
            };
            return Ok((NsReply::Outcome { outcome }, earliest));
        }
        NsCall::Stats => {
            let stats = store.stats(p).await?;
            NsReply::Stats {
                bytes: stats.bytes,
                keys: stats.keys,
            }
        }
        NsCall::Probe => {
            store.probe().await?;
            NsReply::Ok
        }
        NsCall::Export { after, limit } => {
            let page = bounded_page(
                limit,
                after.map(|c| Cursor::new(c.0)),
                |after, n| async move {
                    let page = export_page(store, p, after.as_ref(), n).await?;
                    Ok(ScanPage {
                        entries: page.records.into_iter().map(|r| (r.key, r.value)).collect(),
                        next: page.next,
                    })
                },
            )
            .await?;
            NsReply::page(page)
        }
        #[cfg(feature = "test-faults")]
        NsCall::TestSnapshot => NsReply::Snapshot {
            bytes: Blob(crate::backup::test_snapshot(store, p).await?),
        },
        #[cfg(feature = "test-faults")]
        NsCall::TestImport { bytes } => {
            use mkit_server::store::{ExportReader, ImportMode, Importer};
            let (header, records) = ExportReader::new(&bytes.0)?;
            let mut importer = Importer::new(store, &header, ImportMode::Fresh)?;
            for record in records {
                let record = record?;
                if record.partition != *p {
                    return Err(StoreError::Invalid("test import partition mismatch".into()));
                }
                importer.push(record).await?;
            }
            NsReply::Imported {
                records: importer.finish().await?,
            }
        }
    };
    Ok((reply, None))
}

/// Most entries one scan or export page returns, whatever the caller asks.
pub const MAX_PAGE_ENTRIES: u32 = 1000;

/// Key and value bytes after which a scan or export page ends early and
/// returns `next`: a page of 512 KiB values stays a few MiB of JSON in a
/// 128 MB isolate, not hundreds.
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// Entries read from the store per step: one step overshoots the byte
/// budget by at most this many maximum-size values.
const PAGE_STEP: u32 = 16;

/// A page of at most `limit` (clamped to [`MAX_PAGE_ENTRIES`]) entries and
/// about [`MAX_PAGE_BYTES`], read in steps of [`PAGE_STEP`] through `step`
/// (`after`, `limit`) → page. A short page with `next` is allowed by the
/// contract: callers page until `next` is `None`.
async fn bounded_page<F, Fut>(
    limit: u32,
    after: Option<Cursor>,
    mut step: F,
) -> Result<ScanPage, StoreError>
where
    F: FnMut(Option<Cursor>, u32) -> Fut,
    Fut: Future<Output = Result<ScanPage, StoreError>>,
{
    if limit == 0 {
        // The store's own `Invalid`.
        return step(after, 0).await;
    }
    let limit = limit.min(MAX_PAGE_ENTRIES);
    let (mut page, mut bytes, mut cursor) = (ScanPage::default(), 0, after);
    loop {
        let have = u32::try_from(page.entries.len()).unwrap_or(limit);
        let got = step(cursor.take(), (limit - have).min(PAGE_STEP)).await?;
        bytes += got
            .entries
            .iter()
            .map(|(k, v)| k.as_bytes().len() + v.as_bytes().len())
            .sum::<usize>();
        page.entries.extend(got.entries);
        match got.next {
            Some(next) if page.entries.len() < limit as usize && bytes < MAX_PAGE_BYTES => {
                cursor = Some(next);
            }
            next => {
                page.next = next;
                return Ok(page);
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use object::{DoConn, NsObject};

#[cfg(target_arch = "wasm32")]
mod object {
    use std::cell::{Cell, OnceCell};
    use std::sync::Arc;

    use mkit_server::Clock;
    use mkit_server::sql::{Capacity, SqlKvStore};
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    use worker::{Method, Request, Response, ScheduledTime, State, Storage};

    use super::{PressureStore, decode_request, dispatch, encode, failure};
    use crate::alarm::{AlarmAction, alarm_after_put, alarm_after_tick_with_current};
    use crate::classes::ShardClass;
    use crate::clock::WorkerClock;
    use crate::do_sql::{DO_CAPACITY, DoSqlConn};

    /// The connection a partition's Durable Object runs its store on: the
    /// fail-once fault wraps it under `test-faults`.
    #[cfg(feature = "test-faults")]
    pub type DoConn = crate::faults::FaultConn<DoSqlConn>;
    /// The connection a partition's Durable Object runs its store on: the
    /// fail-once fault wraps it under `test-faults`.
    #[cfg(not(feature = "test-faults"))]
    pub type DoConn = DoSqlConn;

    /// One partition's Durable Object: its store, opened (and migrated) on
    /// the first request and kept for the object's lifetime. The
    /// `#[durable_object]` class itself stays in the deployment's cdylib
    /// (M0-17) and holds one of these.
    pub struct NsObject {
        class: ShardClass,
        conn: DoConn,
        capacity: Capacity,
        store: OnceCell<PressureStore<DoConn>>,
        storage: Storage,
        clock: WorkerClock,
        registry: TimerRegistry<PressureStore<DoConn>>,
        backup_interval_ms: Option<u64>,
        /// A request committed a timer Put while an alarm handler awaited R2.
        alarm_dirty: Cell<bool>,
    }

    impl core::fmt::Debug for NsObject {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("NsObject")
                .field("conn", &self.conn)
                .field("capacity", &self.capacity)
                .field("store", &self.store)
                .field("storage", &self.storage)
                .field("clock", &self.clock)
                .finish_non_exhaustive()
        }
    }

    impl NsObject {
        /// The object for `state`, capped at [`DO_CAPACITY`]; gives the
        /// state back.
        #[must_use]
        pub fn new(state: State, class: ShardClass) -> (Self, State) {
            let (conn, state) = DoSqlConn::from_state(state);
            #[cfg(feature = "test-faults")]
            let conn = crate::faults::FaultConn::new(conn);
            let object = Self {
                class,
                conn,
                capacity: DO_CAPACITY,
                store: OnceCell::new(),
                storage: state.storage(),
                clock: WorkerClock,
                registry: TimerRegistry::new(),
                backup_interval_ms: None,
                alarm_dirty: Cell::new(false),
            };
            (object, state)
        }

        /// Cap the store at `capacity` instead (e.g. Workers Free's 1 GB,
        /// [`crate::do_sql::DO_FREE_MAX_BYTES`]).
        #[must_use]
        pub fn with_capacity(mut self, capacity: Capacity) -> Self {
            self.capacity = capacity;
            self
        }

        /// Install the handlers built by the deployment adapter at startup.
        #[must_use]
        pub fn with_registry(mut self, registry: TimerRegistry<PressureStore<DoConn>>) -> Self {
            self.registry = registry;
            self
        }

        /// Enable post-commit backup seeding for this object.
        #[must_use]
        pub fn with_backup_interval(mut self, interval_ms: u64) -> Self {
            self.backup_interval_ms = Some(interval_ms);
            self
        }

        /// The store, opened on first use: migration runs once per
        /// instance.
        fn store(&self) -> Result<&PressureStore<DoConn>, mkit_server::StoreError> {
            if let Some(store) = self.store.get() {
                return Ok(store);
            }
            let inner = SqlKvStore::open_with_capacity(self.conn.clone(), self.capacity)?;
            let mut store = PressureStore::new(
                inner,
                self.class,
                Arc::new(WorkerClock),
                Arc::new(crate::telemetry::ConsoleMetrics::default()),
            );
            if let Some(interval_ms) = self.backup_interval_ms {
                store = store.with_backup_interval(interval_ms);
            }
            Ok(self.store.get_or_init(|| store))
        }

        /// Answer one `POST` from [`crate::ns_client`].
        pub async fn handle(&self, mut req: Request) -> worker::Result<Response> {
            if req.method() != Method::Post {
                return Response::error("method not allowed", 405);
            }
            let body = req.text().await?;
            let decoded = decode_request(&body, self.class);
            let reply = match decoded.and_then(|request| {
                self.store()
                    .map(|store| (store, request))
                    .map_err(|error| failure(&error))
            }) {
                Ok((store, (partition, call))) => {
                    // `SqlKvStore` caches stats for a minute; the wire
                    // suite's stats hook (`test-faults`) measures growth
                    // write by write, so it reads the table every time.
                    #[cfg(feature = "test-faults")]
                    if req.path() == "/stats" {
                        store.clear_stats_cache();
                    }
                    let (reply, earliest) = dispatch(store, &partition, call)
                        .await
                        .unwrap_or_else(|error| (failure(&error), None));
                    let seeded = store.take_seeded_due();
                    let earliest = match (earliest, seeded) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                    if earliest.is_some() {
                        self.alarm_dirty.set(true);
                    }
                    if let Some(earliest) = earliest
                        && let Err(error) = self.lower_alarm(earliest).await
                    {
                        crate::log_failure(&format!("timer alarm update failed: {error}"));
                    }
                    encode(&reply)
                }
                Err(reply) => encode(&reply),
            };
            let mut response = Response::ok(reply)?;
            response
                .headers_mut()
                .set("Content-Type", "application/json")?;
            Ok(response)
        }

        fn now_ms(&self) -> u64 {
            // A pre-epoch reading counts as 0, as natively: never fire everything.
            u64::try_from(self.clock.now_ms()).unwrap_or(0)
        }

        async fn set_alarm(&self, timestamp: i64) -> worker::Result<()> {
            // workers-rs interprets an i64 as a relative offset. A Date
            // explicitly supplies the absolute timestamp chosen by the core.
            #[allow(clippy::cast_precision_loss)]
            let date = worker::js_sys::Date::new(&worker::wasm_bindgen::JsValue::from_f64(
                timestamp as f64,
            ));
            self.storage.set_alarm(ScheduledTime::new(date)).await
        }

        async fn lower_alarm(&self, earliest: u64) -> worker::Result<()> {
            let current = self.storage.get_alarm().await?;
            if let Some(next) = alarm_after_put(current, earliest, self.now_ms()) {
                self.set_alarm(next).await?;
            }
            Ok(())
        }

        /// Fire due timers and multiplex all partition heads onto one alarm.
        pub async fn alarm(&self) -> worker::Result<Response> {
            self.alarm_dirty.set(false);
            let store = self.store().map_err(|error| alarm_error(&error))?;
            let heads = store.timer_heads().map_err(|error| alarm_error(&error))?;
            let now = self.now_ms();
            let mut next_wake = None;
            for (partition, _) in heads {
                let report = run_due(
                    store,
                    &partition,
                    &self.registry,
                    &self.clock,
                    now,
                    &TickBudget::default(),
                )
                .await
                .map_err(|error| alarm_error(&error))?;
                if let Some(next) = report.next_wake_ms {
                    next_wake = Some(next_wake.map_or(next, |current: u64| current.min(next)));
                }
            }
            let current = self.storage.get_alarm().await?;
            // A request can interleave while a backup awaits R2. Its timer
            // Put must survive this handler's final set/delete decision.
            let action = if self.alarm_dirty.get() {
                AlarmAction::Set(i64::try_from(now).unwrap_or(i64::MAX))
            } else {
                alarm_after_tick_with_current(current, next_wake, now)
            };
            let result = match action {
                AlarmAction::Set(next) => self.set_alarm(next).await,
                AlarmAction::Delete => self.storage.delete_alarm().await,
            };
            if let Err(error) = result {
                crate::log_failure(&format!("timer alarm update failed: {error}"));
            }
            if self.alarm_dirty.replace(false)
                && let Err(error) = self.set_alarm(i64::try_from(now).unwrap_or(i64::MAX)).await
            {
                crate::log_failure(&format!("timer alarm update failed: {error}"));
            }
            Response::ok("timers processed")
        }
    }

    fn alarm_error(error: &mkit_server::StoreError) -> worker::Error {
        let _ = failure(error);
        worker::Error::RustError(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use mkit_server::{Batch, MemoryKv, Precondition, Value};

    use super::*;
    use crate::wire::WireBatch;

    fn request(call: NsCall) -> String {
        let p = Partition::decode(b"nroot\0").unwrap();
        serde_json::to_string(&NsRequest::new(&p, call).unwrap()).unwrap()
    }

    fn reply(store: &MemoryKv, call: NsCall) -> NsReply {
        serde_json::from_str(&block_on(serve(
            store,
            &request(call),
            ShardClass::RefStore,
        )))
        .unwrap()
    }

    #[test]
    fn alarm_hint_is_returned_only_for_committed_timer_puts() {
        let store = MemoryKv::default();
        let timer = mkit_server::store::keys::timer(500, 1, b"timer");
        let apply = |batch| {
            block_on(serve_reply(
                &store,
                &request(NsCall::Apply {
                    batch: WireBatch::from(batch),
                }),
                ShardClass::RefStore,
            ))
        };
        let batch = Batch::new()
            .require(Precondition::Absent(timer.clone()))
            .put(timer.clone(), Value::new(Vec::new()));
        let (reply, earliest) = apply(batch.clone());
        assert_eq!(
            reply,
            NsReply::Outcome {
                outcome: WireOutcome::Committed
            }
        );
        assert_eq!(earliest, Some(500));
        let (reply, earliest) = apply(batch);
        assert!(matches!(
            reply,
            NsReply::Outcome {
                outcome: WireOutcome::PreconditionFailed { .. }
            }
        ));
        assert_eq!(earliest, None);
        let (_, earliest) = apply(Batch::new().delete(timer));
        assert_eq!(earliest, None);
    }

    #[test]
    fn serve_dispatches_and_reports_typed_errors() {
        let store = MemoryKv::default();
        let k = Key::new(b"r\0x".to_vec());
        let batch = Batch::new()
            .require(Precondition::Absent(k.clone()))
            .put(k.clone(), Value::new(b"1".to_vec()));
        let apply = || NsCall::Apply {
            batch: WireBatch::from(batch.clone()),
        };
        assert_eq!(
            reply(&store, apply()),
            NsReply::Outcome {
                outcome: WireOutcome::Committed
            }
        );
        assert!(matches!(
            reply(&store, apply()),
            NsReply::Outcome {
                outcome: WireOutcome::PreconditionFailed { index: 0, .. }
            }
        ));
        assert_eq!(
            reply(
                &store,
                NsCall::Get {
                    key: Blob(b"r\0x".to_vec())
                }
            ),
            NsReply::Value {
                value: Some(Blob(b"1".to_vec()))
            }
        );
        assert_eq!(reply(&store, NsCall::Probe), NsReply::Ok);
        let NsReply::Page { entries, next } = reply(
            &store,
            NsCall::Export {
                after: None,
                limit: 10,
            },
        ) else {
            panic!("not a page");
        };
        assert_eq!(entries, vec![(Blob(b"r\0x".to_vec()), Blob(b"1".to_vec()))]);
        assert_eq!(next, None);
        // A zero scan limit is the store's `Invalid`, typed on the wire.
        assert!(matches!(
            reply(
                &store,
                NsCall::Scan {
                    start: Blob::default(),
                    end: Blob(vec![0xff]),
                    after: None,
                    limit: 0
                }
            ),
            NsReply::Err {
                kind: NsErrKind::Invalid,
                ..
            }
        ));
        for body in ["", "{}", r#"{"part":"!!","call":{"op":"probe"}}"#] {
            let r: NsReply =
                serde_json::from_str(&block_on(serve(&store, body, ShardClass::RefStore))).unwrap();
            assert!(
                matches!(
                    r,
                    NsReply::Err {
                        kind: NsErrKind::Invalid,
                        ..
                    }
                ),
                "{body}: {r:?}"
            );
        }
        let bad_part = r#"{"part":"cQ==","call":{"op":"probe"}}"#;
        let r: NsReply =
            serde_json::from_str(&block_on(serve(&store, bad_part, ShardClass::RefStore))).unwrap();
        assert!(matches!(
            r,
            NsReply::Err {
                kind: NsErrKind::Invalid,
                ..
            }
        ));
    }

    fn put(store: &MemoryKv, k: Vec<u8>, v: Vec<u8>) {
        let p = Partition::decode(b"nroot\0").unwrap();
        block_on(store.apply(&p, Batch::new().put(Key::new(k), Value::new(v)))).unwrap();
    }

    /// Page through `call(after)` to the end; each page's raw byte size.
    fn pages(
        store: &MemoryKv,
        call: impl Fn(Option<Blob>) -> NsCall,
    ) -> (Vec<Vec<u8>>, Vec<usize>) {
        let (mut keys, mut sizes, mut after) = (Vec::new(), Vec::new(), None);
        loop {
            let NsReply::Page { entries, next } = reply(store, call(after.take())) else {
                panic!("not a page");
            };
            assert!(entries.len() <= MAX_PAGE_ENTRIES as usize);
            sizes.push(entries.iter().map(|(k, v)| k.0.len() + v.0.len()).sum());
            keys.extend(entries.into_iter().map(|(k, _)| k.0));
            match next {
                Some(n) => after = Some(n),
                None => return (keys, sizes),
            }
        }
    }

    #[test]
    fn scan_and_export_pages_are_clamped_and_byte_bounded() {
        // 40 maximum-size values: 20 MiB, over the page byte budget.
        let big = MemoryKv::default();
        let key = |i: u16| [b"r\0big\0".as_slice(), &i.to_be_bytes()].concat();
        for i in 0..40 {
            put(&big, key(i), vec![7; mkit_server::MAX_VALUE_BYTES]);
        }
        let scan = |after| NsCall::Scan {
            start: Blob::default(),
            end: Blob(vec![0xff]),
            after,
            limit: u32::MAX,
        };
        let export = |after| NsCall::Export {
            after,
            limit: u32::MAX,
        };
        let step = PAGE_STEP as usize * (mkit_server::MAX_VALUE_BYTES + 1024);
        for call in [&scan as &dyn Fn(Option<Blob>) -> NsCall, &export] {
            let (keys, sizes) = pages(&big, call);
            assert_eq!(keys, (0..40).map(key).collect::<Vec<_>>());
            assert!(sizes.len() > 1, "{sizes:?}");
            assert!(
                sizes.iter().all(|&s| s <= MAX_PAGE_BYTES + step),
                "{sizes:?}"
            );
        }
        // 1,100 small rows: a limit of u32::MAX returns at most 1,000.
        let small = MemoryKv::default();
        for i in 0..1100_u16 {
            put(&small, key(i), vec![1]);
        }
        for call in [&scan as &dyn Fn(Option<Blob>) -> NsCall, &export] {
            let NsReply::Page { entries, next } = reply(&small, call(None)) else {
                panic!("not a page");
            };
            assert_eq!(entries.len(), MAX_PAGE_ENTRIES as usize);
            assert!(next.is_some());
            assert_eq!(pages(&small, call).0.len(), 1100);
        }
    }
}
