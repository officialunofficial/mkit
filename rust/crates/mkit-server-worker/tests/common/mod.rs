//! Host simulations of the two Workers backends, for the conformance suite
//! and the fault tests.
//!
//! - [`SimBucket`]: R2 with the semantics [`R2BlobStore`] relies on: a put
//!   runs on its own thread (spawned) and fails, writing nothing, when its
//!   body is short, long or aborted; a failed `If-None-Match: *` condition
//!   is `Ok(false)`; bodies come back in 1.5 MiB pieces, so the store must
//!   re-chunk them.
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
use mkit_server::sql::{
    Capacity, DEFAULT_PAGE_SIZE, Row, SqlConn, SqlError, SqlKvStore, SqlValue, TxFn, reserve_floor,
};
use mkit_server::{Clock, StoreError};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::do_sql::classify_error;
use mkit_server_worker::naming::DoTarget;
use mkit_server_worker::ns_client::{DoNamespaceStore, NsTransport};
use mkit_server_worker::ns_object::serve;
use mkit_server_worker::r2::{ObjectBucket, ObjectStream, PutBody, PutResult};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Simulated R2 (see the module docs).
#[derive(Debug, Clone, Default)]
pub struct SimBucket {
    objects: Arc<Mutex<BTreeMap<String, Bytes>>>,
    /// Fail this many next puts after their body arrived, as R2 does for a
    /// second write of one key within a second (HTTP 429).
    fail_puts: Arc<AtomicUsize>,
    /// Decide the condition and the 429 before reading the body, and answer
    /// without reading it (R2 may).
    early: Arc<AtomicBool>,
}

/// The piece size simulated bodies arrive in: above the store's limit.
const SIM_PIECE: usize = 1536 * 1024;

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
        let (tx, rx) = oneshot::channel();
        let this = self.clone();
        std::thread::spawn(move || {
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

    async fn head(&self, key: &str) -> Result<Option<u64>, String> {
        Ok(lock(&self.objects).get(key).map(|b| b.len() as u64))
    }

    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
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
        let pieces: Vec<Result<Bytes, String>> = body
            .chunks(SIM_PIECE)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Ok(Some((size, Box::pin(futures::stream::iter(pieces)))))
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        lock(&self.objects).remove(key);
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
        DoNamespaceStore::new(Self::new(dir, config))
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
        Ok(serve(&*store, &body).await)
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
