//! Host simulations of the two Workers backends, for the conformance suite
//! and the fault tests.
//!
//! - [`SimBucket`]: R2 with the semantics [`R2BlobStore`] relies on: a put
//!   runs on its own thread (spawned) and fails, writing nothing, when its
//!   body is short, long or aborted; a failed `If-None-Match: *` condition
//!   is `Ok(false)`; bodies come back in 256 KiB pieces, below the store's
//!   piece limit (re-chunking of larger pieces is unit-tested in `r2.rs`).
//! - [`SimDoConn`]: Durable Object SQL over rusqlite: it refuses what a
//!   Durable Object refuses (transaction control, pragmas, `vacuum`, more
//!   than 100 bound parameters, statements over 100 KB), has a fixed hard
//!   size limit whose `SQLITE_FULL` is fatal (a real object resets), and
//!   measures `databaseSize` as workerd does
//!   (`(page_count − freelist_count) × page_size`) and keeps the default
//!   `backup_to` (`Unsupported`).
//! - [`Loopback`]: the Worker → Durable Object hop, in process: one
//!   database per Durable Object name, reached through the real JSON wire
//!   and `ns_object::serve`.
//!
//! [`R2BlobStore`]: mkit_server_worker::r2::R2BlobStore
#![allow(dead_code, unreachable_pub)]

use mkit_server_worker::sql;

pub mod multipart_allocator;

/// Check retained retry identity, capped delays and payloads through cold ticks.
pub async fn retained_timer_backoff<S: mkit_server::NamespaceStore>(
    store: &S,
    partition: &mkit_server::Partition,
    registry: &mkit_server::timers::TimerRegistry<'_, S>,
    original: &mkit_server::Key,
    payload: &mkit_server::Value,
    unknown: bool,
) -> u64 {
    use mkit_server::store::adapter_spi::keys;
    use mkit_server::timers::{MAX_RETRY_BACKOFF_MS, RETRY_BACKOFF_MS, TickBudget, run_due};
    let Some(keys::ParsedKey::Timer {
        kind,
        reference,
        due_at_ms,
    }) = keys::parse(original)
    else {
        panic!("expected timer");
    };
    let mut now = 100;
    let mut wake = now + RETRY_BACKOFF_MS;
    for attempt in 1_u8..=10 {
        if attempt > 1 {
            now = wake;
            let report = run_due(
                store,
                partition,
                registry,
                &mkit_server::ManualClock::new(i64::try_from(now).expect("test clock fits i64")),
                now,
                &TickBudget::default(),
            )
            .await
            .expect("retry tick succeeds");
            assert_eq!(
                (report.fired, report.unknown, report.failed),
                (0, u32::from(unknown), u32::from(!unknown))
            );
            wake = report.next_wake_ms.expect("retained timer has a wake");
        }
        let delay = (RETRY_BACKOFF_MS * (1_u64 << (attempt.min(8) - 1))).min(MAX_RETRY_BACKOFF_MS);
        assert_eq!(wake, now + delay);
        let retry = keys::timer_retry(wake, kind, &reference, due_at_ms, attempt.min(8));
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let rows = store
            .scan(partition, &start, &end, None, 2)
            .await
            .expect("timer scan succeeds");
        assert!(rows.next.is_none());
        assert_eq!(rows.entries, vec![(retry, payload.clone())]);
        assert_eq!(
            store
                .get(partition, original)
                .await
                .expect("original timer lookup succeeds"),
            None
        );
    }
    wake
}

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use futures::StreamExt as _;
use futures::channel::oneshot;
use futures::executor::block_on;
use mkit_server::{Clock, StoreError};
use mkit_server_worker::sql::{
    Capacity, DEFAULT_PAGE_SIZE, Row, SqlConn, SqlError, SqlKvStore, SqlValue, TxFn, reserve_floor,
};
pub use sqlite::RusqliteConn;
mod sqlite;
use mkit_server_worker::do_sql::classify_error;
use mkit_server_worker::naming::DoTarget;
use mkit_server_worker::ns_client::{DoNamespaceStore, NsTransport};
use mkit_server_worker::ns_object::serve;
use mkit_server_worker::r2::{ObjectBucket, ObjectPage, ObjectStream, PutBody, PutResult};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

type BackendParts = BTreeMap<u16, (String, Bytes)>;
type BackendUploads = BTreeMap<String, (String, BackendParts)>;

/// Simulated R2 (see the module docs).
#[derive(Debug, Clone, Default)]
pub struct SimBucket {
    objects: Arc<Mutex<BTreeMap<String, Bytes>>>,
    uploads: Arc<Mutex<BackendUploads>>,
    next_upload: Arc<AtomicUsize>,
    pub metadata_reads: Arc<AtomicUsize>,
    pub backend_completions: Arc<AtomicUsize>,
    pub operations: Arc<AtomicUsize>,
    pub lose_completion_reply: Arc<AtomicBool>,
    /// Fail this many next puts after their body arrived, as R2 does for a
    /// second write of one key within a second (HTTP 429).
    fail_puts: Arc<AtomicUsize>,
    /// Decide the condition and the 429 before reading the body, and answer
    /// without reading it (R2 may).
    early: Arc<AtomicBool>,
}

/// The piece size simulated bodies arrive in: below the store's limit.
// Model the bounded chunks of an R2 response while charging each copied
// chunk to the reading thread's heap meter.
const SIM_PIECE: usize = 256 * 1024;

impl SimBucket {
    pub fn fail_next_puts(&self, n: usize) {
        self.fail_puts.store(n, Ordering::SeqCst);
    }

    /// Answer a failed condition or a 429 before reading the body.
    pub fn answer_early(self) -> Self {
        self.early.store(true, Ordering::SeqCst);
        self
    }

    pub fn objects(&self) -> usize {
        lock(&self.objects).len()
    }

    pub fn replace_object(&self, key: &str, bytes: Bytes) {
        lock(&self.objects).insert(key.to_owned(), bytes);
    }

    /// A put's answer before it writes, if it does not write: a pending
    /// 429, or the key already present.
    fn refuse(&self, key: &str) -> Option<PutResult> {
        let fail = self
            .fail_puts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        if fail.is_ok() {
            return Some(Err("429: too many writes to one key".to_owned()));
        }
        lock(&self.objects).contains_key(key).then_some(Ok(false))
    }
}

impl ObjectBucket for SimBucket {
    fn spawn_put(&self, key: String, len: u64, mut body: PutBody) -> oneshot::Receiver<PutResult> {
        self.operations.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        let this = self.clone();
        std::thread::spawn(move || {
            multipart_allocator::exclude_current_thread();
            let result = block_on(async {
                if this.early.load(Ordering::SeqCst)
                    && let Some(answer) = this.refuse(&key)
                {
                    // The body is dropped unread.
                    return answer;
                }
                let mut bytes = Vec::new();
                while let Some(item) = body.next().await {
                    let chunk = item.map_err(|_| "body aborted".to_owned())?;
                    bytes.extend_from_slice(&chunk);
                    if bytes.len() as u64 > len {
                        return Err("fixed length stream: too long".to_owned());
                    }
                }
                if bytes.len() as u64 != len {
                    return Err("fixed length stream: too short".to_owned());
                }
                if let Some(answer) = this.refuse(&key) {
                    return answer;
                }
                let mut objects = lock(&this.objects);
                if objects.contains_key(&key) {
                    return Ok(false);
                }
                objects.insert(key, Bytes::from(bytes));
                Ok(true)
            });
            let _ = tx.send(result);
        });
        rx
    }

    async fn create_object_upload(&self, key: &str) -> Result<String, String> {
        self.operations.fetch_add(1, Ordering::SeqCst);
        let id = self.next_upload.fetch_add(1, Ordering::SeqCst).to_string();
        lock(&self.uploads).insert(id.clone(), (key.to_owned(), BTreeMap::new()));
        Ok(id)
    }

    fn spawn_object_part(
        &self,
        key: String,
        upload: String,
        number: u16,
        len: u64,
        mut body: PutBody,
    ) -> oneshot::Receiver<Result<String, String>> {
        self.operations.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        let this = self.clone();
        std::thread::spawn(move || {
            multipart_allocator::exclude_current_thread();
            let result = block_on(async {
                let mut bytes = Vec::new();
                while let Some(piece) = body.next().await {
                    bytes.extend_from_slice(&piece.map_err(|_| "body aborted".to_owned())?);
                    if bytes.len() as u64 > len {
                        return Err("overrun".into());
                    }
                }
                if bytes.len() as u64 != len {
                    return Err("underrun".into());
                }
                let mut uploads = lock(&this.uploads);
                let (object, parts) = uploads.get_mut(&upload).ok_or("SessionGone")?;
                if *object != key {
                    return Err("wrong key".into());
                }
                let etag = format!(
                    "part-{number}-{}",
                    this.next_upload.fetch_add(1, Ordering::SeqCst)
                );
                parts.insert(number, (etag.clone(), Bytes::from(bytes)));
                Ok(etag)
            });
            let _ = tx.send(result);
        });
        rx
    }

    async fn complete_object_upload(
        &self,
        key: &str,
        upload: &str,
        selected: Vec<(u16, String)>,
    ) -> Result<(), String> {
        self.backend_completions.fetch_add(1, Ordering::SeqCst);
        self.operations.fetch_add(1, Ordering::SeqCst);
        let this = self.clone();
        let key = key.to_owned();
        let upload = upload.to_owned();
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            // Remote backend storage is outside the Worker's resident heap.
            multipart_allocator::exclude_current_thread();
            let result = (|| {
                let mut uploads = lock(&this.uploads);
                let (object, parts) = uploads.get(&upload).ok_or("SessionGone")?;
                if object != &key {
                    return Err("wrong key".into());
                }
                let mut result = Vec::new();
                for (number, etag) in selected {
                    let (actual, bytes) = parts.get(&number).ok_or("missing part")?;
                    if *actual != etag {
                        return Err("part replaced".into());
                    }
                    result.extend_from_slice(bytes);
                }
                lock(&this.objects).insert(key.clone(), Bytes::from(result));
                uploads.remove(&upload);
                if this.lose_completion_reply.swap(false, Ordering::SeqCst) {
                    return Err("lost completion reply".into());
                }
                Ok(())
            })();
            let _ = tx.send(result);
        });
        rx.await.map_err(|_| "backend task dropped".to_owned())?
    }

    async fn abort_object_upload(&self, key: &str, upload: &str) -> Result<(), String> {
        self.operations.fetch_add(1, Ordering::SeqCst);
        let mut uploads = lock(&self.uploads);
        if uploads.get(upload).is_some_and(|(object, _)| object != key) {
            return Err("wrong key".into());
        }
        uploads.remove(upload);
        Ok(())
    }

    async fn head(&self, key: &str) -> Result<Option<u64>, String> {
        self.operations.fetch_add(1, Ordering::SeqCst);
        Ok(lock(&self.objects).get(key).map(|b| b.len() as u64))
    }

    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
        self.metadata_reads.fetch_add(1, Ordering::SeqCst);
        self.operations.fetch_add(1, Ordering::SeqCst);
        let Some(object) = lock(&self.objects).get(key).cloned() else {
            return Ok(None);
        };
        let size = object.len() as u64;
        let body = match range {
            Some(r) => object.slice(
                usize::try_from(r.start).expect("range")..usize::try_from(r.end).expect("range"),
            ),
            None => object,
        };
        let stream = futures::stream::unfold(body, |mut rest| async move {
            if rest.is_empty() {
                None
            } else {
                let n = rest.len().min(SIM_PIECE);
                let piece = Bytes::copy_from_slice(&rest[..n]);
                let _ = rest.split_to(n);
                Some((Ok(piece), rest))
            }
        });
        Ok(Some((size, Box::pin(stream))))
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        lock(&self.objects).remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str, cursor: Option<&str>) -> Result<ObjectPage, String> {
        let objects = lock(&self.objects);
        let keys: Vec<_> = objects
            .keys()
            .filter(|key| key.starts_with(prefix) && cursor.is_none_or(|c| key.as_str() > c))
            .take(1001)
            .cloned()
            .collect();
        let next = (keys.len() > 1000).then(|| keys[999].clone());
        Ok(ObjectPage {
            keys: keys.into_iter().take(1000).collect(),
            cursor: next,
        })
    }

    async fn delete_many(&self, keys: Vec<String>) -> Result<(), String> {
        let mut objects = lock(&self.objects);
        for key in keys {
            objects.remove(&key);
        }
        Ok(())
    }

    async fn probe(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Simulated Durable Object SQL (see the module docs).
#[derive(Debug, Clone)]
pub struct SimDoConn(pub RusqliteConn);

/// What a Durable Object's authorizer refuses, as workerd reports it.
fn authorize(sql: &str, params: &[SqlValue]) -> Result<(), SqlError> {
    let upper = sql.to_uppercase();
    let refused = [
        "PRAGMA",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "VACUUM",
        "ATTACH",
    ];
    if let Some(word) = refused.iter().find(|w| upper.contains(*w)) {
        return Err(classify_error(&format!(
            "not authorized ({word}): SQLITE_AUTH"
        )));
    }
    if params.len() > 100 {
        return Err(classify_error("too many SQL variables: SQLITE_RANGE"));
    }
    if sql.len() > 100 * 1024 {
        return Err(classify_error("statement too long: SQLITE_TOOBIG"));
    }
    Ok(())
}

impl SimDoConn {
    /// A Durable Object database on `conn`, with a fixed hard limit of
    /// `hard_limit` bytes (10 GB on Workers Paid).
    pub fn open(conn: RusqliteConn, hard_limit: u64) -> Self {
        conn.set_size_limit(hard_limit).expect("hard limit");
        Self(conn)
    }
}

/// The engine reached the hard limit. A Durable Object treats `SQLITE_FULL`
/// inside a transaction as a critical error and resets the object, so the
/// simulation refuses to go on: the store's reserve must keep every batch,
/// deletes included, below the hard limit.
fn engine_full<T>(result: Result<T, SqlError>) -> Result<T, SqlError> {
    assert!(
        !matches!(result, Err(SqlError::Full)),
        "hard SQLITE_FULL: a real Durable Object would reset here"
    );
    result
}

impl SqlConn for SimDoConn {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        authorize(sql, params)?;
        engine_full(self.0.exec(sql, params))
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        authorize(sql, params)?;
        engine_full(self.0.query(sql, params))
    }

    /// `transactionSync`: the body's statements run inside it. A `Full`
    /// the body returns itself is the store's soft cap; any other `Full`
    /// (the commit) is the engine's.
    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        let soft = Arc::new(AtomicBool::new(false));
        let flag = soft.clone();
        let result = self.0.transaction(Box::new(move |c| {
            let out = f(SimDoConn(c));
            flag.store(matches!(out, Err(SqlError::Full)), Ordering::SeqCst);
            out
        }));
        if soft.load(Ordering::SeqCst) {
            result
        } else {
            engine_full(result)
        }
    }

    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }

    /// workerd's `databaseSize`: `(page_count − freelist_count) ×
    /// page_size`, which is also what `RusqliteConn` measures.
    fn size_bytes(&self) -> Result<u64, SqlError> {
        self.0.size_bytes()
    }
}

/// How the loopback builds each Durable Object's store.
#[derive(Clone)]
pub struct DoConfig {
    pub clock: Option<Arc<dyn Clock>>,
    pub capacity: Capacity,
    pub hard_limit: u64,
}

impl Default for DoConfig {
    fn default() -> Self {
        let capacity = mkit_server_worker::do_sql::DO_CAPACITY;
        Self {
            clock: None,
            capacity,
            hard_limit: capacity.cap_bytes(),
        }
    }
}

type DoStore = Arc<SqlKvStore<SimDoConn>>;

/// The in-process Worker → Durable Object hop (see the module docs).
#[derive(Clone)]
pub struct Loopback {
    dir: PathBuf,
    config: DoConfig,
    objects: Arc<Mutex<HashMap<DoTarget, DoStore>>>,
    calls: Arc<AtomicUsize>,
}

impl Loopback {
    /// Durable Objects with their databases under `dir`.
    pub fn new(dir: PathBuf, config: DoConfig) -> Self {
        Self {
            dir,
            config,
            objects: Arc::default(),
            calls: Arc::default(),
        }
    }

    pub fn store(dir: PathBuf, config: DoConfig) -> DoNamespaceStore<Self> {
        DoNamespaceStore::new(
            Self::new(dir, config),
            mkit_server::Partition::Namespace(mkit_server::NamespaceKey::deployment_default()),
        )
    }

    fn object(&self, target: &DoTarget) -> DoStore {
        let mut objects = lock(&self.objects);
        if let Some(store) = objects.get(target) {
            return store.clone();
        }
        let mut file = format!("{}-", target.binding);
        for b in target.name.bytes() {
            let _ = write!(file, "{b:02x}");
        }
        let conn = RusqliteConn::open(self.dir.join(format!("{file}.sqlite3"))).expect("open");
        let conn = match &self.config.clock {
            Some(clock) => conn.with_clock(clock.clone()),
            None => conn,
        };
        let conn = SimDoConn::open(conn, self.config.hard_limit);
        let store =
            Arc::new(SqlKvStore::open_with_capacity(conn, self.config.capacity).expect("open"));
        objects.insert(target.clone(), store.clone());
        store
    }

    /// Apply directly to model a concurrent isolate without adding a transport hop.
    pub async fn raw_apply(
        &self,
        target: &DoTarget,
        partition: &mkit_server::Partition,
        batch: mkit_server::Batch,
    ) {
        use mkit_server::NamespaceStore;
        assert_eq!(
            self.object(target)
                .apply(partition, batch)
                .await
                .expect("apply"),
            mkit_server::BatchOutcome::Committed
        );
    }

    /// Inspect a partition directly, bypassing the class guard for regression tests.
    pub async fn raw_value(
        &self,
        target: &DoTarget,
        partition: &mkit_server::Partition,
        key: &mkit_server::Key,
    ) -> Option<mkit_server::Value> {
        use mkit_server::NamespaceStore;
        self.object(target).get(partition, key).await.expect("read")
    }

    /// Forget every object's cached stats.
    pub fn clear_stats(&self) {
        for store in lock(&self.objects).values() {
            store.clear_stats_cache();
        }
    }

    /// The Durable Objects opened so far.
    pub fn targets(&self) -> Vec<DoTarget> {
        lock(&self.objects).keys().cloned().collect()
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NsTransport for Loopback {
    async fn call(
        &self,
        target: &DoTarget,
        _op: &'static str,
        body: String,
    ) -> Result<String, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let store = self.object(target);
        let class = [
            mkit_server_worker::classes::ShardClass::RefStore,
            mkit_server_worker::classes::ShardClass::NsCoordinator,
            mkit_server_worker::classes::ShardClass::RefShard,
            mkit_server_worker::classes::ShardClass::RepoIndexShard,
            mkit_server_worker::classes::ShardClass::ContentIndexShard,
        ]
        .into_iter()
        .find(|class| class.binding() == target.binding)
        .expect("class binding");
        Ok(serve(&*store, &body, class).await)
    }
}

/// A soft limit `bytes` above an empty, migrated Durable Object, with the
/// smallest safe reserve between it and the fixed hard limit.
pub fn capacity_above_empty(bytes: u64) -> DoConfig {
    let scratch = RusqliteConn::open_in_memory().expect("a database");
    SqlKvStore::open(SimDoConn(scratch.clone())).expect("migrate");
    let empty = scratch.size_bytes().expect("size");
    let reserve = reserve_floor(DEFAULT_PAGE_SIZE);
    let capacity = Capacity::new(empty + bytes + reserve).with_reserve(reserve);
    DoConfig {
        clock: None,
        capacity,
        hard_limit: capacity.cap_bytes(),
    }
}
