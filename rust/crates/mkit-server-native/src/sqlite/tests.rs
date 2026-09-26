//! Engine-backed tests of `SqlKvStore<RusqliteConn>`: migrations, atomicity
//! under injected faults, the rule-8 clock, `SQLITE_FULL`, concurrency,
//! durability and backup/restore. The black-box contract runs in
//! `mkit-server-conformance/tests/sqlite_backends.rs`.

use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, PoisonError};

use futures::StreamExt as _;
use futures::executor::block_on;
use mkit_server::sql::{
    Capacity, DEFAULT_PAGE_SIZE, MAX_BOUND_PARAMS, SqlConn, SqlError, SqlKvStore, SqlValue,
    TIMER_HEADS, TxFn, batch_growth_bytes, reserve_floor, schema,
};
use mkit_server::store::{
    EXPORT_END, ExportReader, ImportMode, codec, encode_export_header, encode_export_record,
    export_partition, import_stream, keys,
};
use mkit_server::{
    Batch, BatchOutcome, Key, MAX_BATCH_OPS, MAX_KEY_BYTES, NamespaceStore, Partition,
    Precondition, Redacted, StoreError, StoreMaintenance, Value,
};

use super::RusqliteConn;

fn ns(name: &str) -> Partition {
    Partition::decode(format!("n{name}\0").as_bytes()).unwrap()
}

fn k(s: &str) -> Key {
    Key::new(format!("r\0{s}").into_bytes())
}

fn v(s: &str) -> Value {
    Value::new(s.as_bytes().to_vec())
}

fn file(dir: &Path) -> RusqliteConn {
    RusqliteConn::open(dir.join("meta.sqlite3")).unwrap()
}

#[test]
fn timer_index_migrates_v1_and_reopening_is_idempotent() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    conn.exec(schema::BOOTSTRAP, &[]).unwrap();
    for statement in schema::MIGRATIONS[0].statements {
        conn.exec(statement, &[]).unwrap();
    }
    conn.exec("INSERT INTO mkit_schema (id, version) VALUES (1, 1)", &[])
        .unwrap();
    assert!(
        conn.query(
            "SELECT name FROM sqlite_master WHERE name = 'kv_timers'",
            &[]
        )
        .unwrap()
        .is_empty()
    );
    let store = SqlKvStore::open(conn.clone()).unwrap();
    assert_eq!(store.layout_version(), 2);
    assert_eq!(
        conn.query(
            "SELECT name FROM sqlite_master WHERE name = 'kv_timers'",
            &[]
        )
        .unwrap(),
        vec![vec![SqlValue::Text("kv_timers".to_owned())]]
    );
    let reopened = SqlKvStore::open(conn.clone()).unwrap();
    assert_eq!(reopened.layout_version(), 2);
    assert_eq!(
        conn.query("SELECT version FROM mkit_schema WHERE id = 1", &[])
            .unwrap(),
        vec![vec![SqlValue::Integer(2)]]
    );
}

#[test]
fn timer_heads_returns_minimum_per_partition() {
    let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
    assert!(store.timer_heads().unwrap().is_empty());
    for (partition, due) in [(ns("a"), 90), (ns("b"), 20), (ns("a"), 10)] {
        apply(
            &store,
            &partition,
            Batch::new().put(keys::timer(due, 1, b"ref"), v("timer")),
        )
        .unwrap();
    }
    apply(
        &store,
        &ns("c"),
        Batch::new().put(k("not-a-timer"), v("ref")),
    )
    .unwrap();
    let mut heads = store.timer_heads().unwrap();
    heads.sort();
    assert_eq!(heads, vec![(ns("a"), 10), (ns("b"), 20)]);
}

#[test]
fn timer_heads_query_plan_uses_partial_index() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let store = SqlKvStore::open(conn.clone()).unwrap();
    apply(
        &store,
        &ns("a"),
        Batch::new().put(keys::timer(10, 1, b"ref"), v("timer")),
    )
    .unwrap();
    let plan = conn
        .query(&format!("EXPLAIN QUERY PLAN {TIMER_HEADS}"), &[])
        .unwrap();
    assert!(
        plan.iter()
            .flatten()
            .any(|value| matches!(value, SqlValue::Text(detail) if detail.contains("kv_timers"))),
        "timer heads index unused: {plan:?}"
    );
}

fn apply<C: SqlConn>(
    s: &SqlKvStore<C>,
    p: &Partition,
    b: Batch,
) -> Result<BatchOutcome, StoreError> {
    block_on(s.apply(p, b))
}

fn all<S: NamespaceStore>(s: &S, p: &Partition) -> Vec<(Key, Value)> {
    let page = block_on(s.scan(p, &Key::default(), &Key::new(vec![0xff]), None, 10_000)).unwrap();
    assert!(page.next.is_none());
    page.entries
}

/// Knobs and records shared by every clone of a [`TestConn`].
#[derive(Default)]
struct Knobs {
    now: AtomicU64,
    /// Clock readings taken while a transaction was open, and outside one.
    reads_in_tx: AtomicUsize,
    reads_outside_tx: AtomicUsize,
    /// Fail the exec with this 0-based index inside the next transactions.
    fail_exec_at: Mutex<Option<usize>>,
    execs_in_tx: AtomicUsize,
    /// Answer `SQLITE_FULL` to every exec starting with this text.
    full_on: Mutex<Option<&'static str>>,
    /// Every statement issued, and the most parameters bound to one.
    statements: Mutex<Vec<String>>,
    max_params: AtomicUsize,
}

/// A [`SqlConn`] wrapper around a [`RusqliteConn`] that injects faults and
/// records what the store does.
#[derive(Clone)]
struct TestConn {
    inner: RusqliteConn,
    knobs: Arc<Knobs>,
}

impl TestConn {
    fn memory() -> Self {
        Self {
            inner: RusqliteConn::open_in_memory().unwrap(),
            knobs: Arc::default(),
        }
    }

    fn record(&self, sql: &str, params: &[SqlValue]) {
        let knobs = &self.knobs;
        knobs.max_params.fetch_max(params.len(), Ordering::SeqCst);
        knobs
            .statements
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(sql.to_owned());
    }
}

impl SqlConn for TestConn {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        self.record(sql, params);
        if self.inner.in_transaction() {
            let n = self.knobs.execs_in_tx.fetch_add(1, Ordering::SeqCst);
            let fail_at = *self.knobs.fail_exec_at.lock().unwrap();
            if fail_at == Some(n) {
                return Err(SqlError::Backend(Redacted::new("injected")));
            }
        }
        if self
            .knobs
            .full_on
            .lock()
            .unwrap()
            .is_some_and(|p| sql.starts_with(p))
        {
            return Err(SqlError::Full);
        }
        self.inner.exec(sql, params)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, SqlError> {
        self.record(sql, params);
        self.inner.query(sql, params)
    }

    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        let knobs = Arc::clone(&self.knobs);
        knobs.execs_in_tx.store(0, Ordering::SeqCst);
        self.inner
            .transaction(Box::new(move |inner| f(Self { inner, knobs })))
    }

    fn now_ms(&self) -> u64 {
        let counter = if self.inner.in_transaction() {
            &self.knobs.reads_in_tx
        } else {
            &self.knobs.reads_outside_tx
        };
        counter.fetch_add(1, Ordering::SeqCst);
        self.knobs.now.load(Ordering::SeqCst)
    }

    fn size_bytes(&self) -> Result<u64, SqlError> {
        self.inner.size_bytes()
    }
}

#[test]
fn migrate_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let s = SqlKvStore::open(file(dir.path())).unwrap();
    assert_eq!(s.layout_version(), schema::SCHEMA_VERSION);
    let p = ns("m");
    apply(&s, &p, Batch::new().put(k("a"), v("1"))).unwrap();
    assert_eq!(block_on(s.migrate()).unwrap(), schema::SCHEMA_VERSION);
    assert_eq!(schema::migrate(s.conn()).unwrap(), schema::SCHEMA_VERSION);
    drop(s);
    let s = SqlKvStore::open(file(dir.path())).unwrap();
    assert_eq!(all(&s, &p), vec![(k("a"), v("1"))]);
    let version = s
        .conn()
        .query("SELECT version FROM mkit_schema", &[])
        .unwrap();
    assert_eq!(
        version,
        vec![vec![SqlValue::Integer(schema::SCHEMA_VERSION.into())]]
    );
}

#[test]
fn newer_schema_version_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let s = SqlKvStore::open(file(dir.path())).unwrap();
    apply(&s, &ns("n"), Batch::new().put(k("a"), v("1"))).unwrap();
    let newer = i64::from(schema::SCHEMA_VERSION) + 1;
    s.conn()
        .exec(
            "UPDATE mkit_schema SET version = ?1",
            &[SqlValue::Integer(newer)],
        )
        .unwrap();
    drop(s);
    let err = SqlKvStore::open(file(dir.path())).unwrap_err();
    assert!(matches!(err, StoreError::Unsupported(_)), "{err:?}");
    // Refused without touching anything.
    let conn = file(dir.path());
    let version = conn.query("SELECT version FROM mkit_schema", &[]).unwrap();
    assert_eq!(version, vec![vec![SqlValue::Integer(newer)]]);
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM kv", &[]).unwrap()[0][0],
        SqlValue::Integer(1)
    );
}

#[test]
fn apply_is_atomic_under_injected_failure() {
    let conn = TestConn::memory();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let p = ns("atomic");
    apply(&s, &p, Batch::new().put(k("a"), v("0"))).unwrap();
    let batch = Batch::new()
        .require(Precondition::Equals(k("a"), v("0")))
        .put(k("a"), v("1"))
        .put(k("b"), v("1"))
        .delete(k("a"))
        .put(k("c"), v("1"));
    for n in 0..4 {
        *conn.knobs.fail_exec_at.lock().unwrap() = Some(n);
        let err = apply(&s, &p, batch.clone()).unwrap_err();
        assert!(
            matches!(err, StoreError::Unavailable(_)),
            "exec {n}: {err:?}"
        );
        assert_eq!(all(&s, &p), vec![(k("a"), v("0"))], "exec {n} left rows");
    }
    *conn.knobs.fail_exec_at.lock().unwrap() = None;
    assert_eq!(apply(&s, &p, batch).unwrap(), BatchOutcome::Committed);
    assert_eq!(all(&s, &p), vec![(k("b"), v("1")), (k("c"), v("1"))]);
}

#[test]
fn panicking_transaction_body_rolls_back_and_releases_the_connection() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let body: TxFn<RusqliteConn, ()> = Box::new(|c| {
        let params = [
            SqlValue::Blob(b"nx\0".to_vec()),
            SqlValue::Blob(vec![1]),
            SqlValue::Blob(vec![]),
        ];
        c.exec(
            "INSERT INTO kv (part, key, value) VALUES (?1, ?2, ?3)",
            &params,
        )?;
        panic!("injected");
    });
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| conn.transaction(body)));
    assert!(unwound.is_err());
    assert!(!conn.in_transaction());
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM kv", &[]).unwrap()[0][0],
        SqlValue::Integer(0)
    );
    apply(&s, &ns("x"), Batch::new().put(k("a"), v("1"))).unwrap();
}

#[test]
fn not_after_uses_conn_clock_inside_transaction() {
    let conn = TestConn::memory();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let p = ns("clock");
    conn.knobs.now.store(1_000, Ordering::SeqCst);
    let late = Batch::new()
        .require(Precondition::NotAfter(999))
        .put(k("a"), v("1"));
    assert_eq!(
        apply(&s, &p, late).unwrap(),
        BatchOutcome::DeadlinePassed { backend_now: 1_000 }
    );
    let on_time = Batch::new()
        .require(Precondition::NotAfter(1_000))
        .put(k("a"), v("1"));
    assert_eq!(apply(&s, &p, on_time).unwrap(), BatchOutcome::Committed);
    // Exactly one reading per apply, each taken with the transaction open.
    assert_eq!(conn.knobs.reads_in_tx.load(Ordering::SeqCst), 2);
    assert_eq!(conn.knobs.reads_outside_tx.load(Ordering::SeqCst), 0);
    assert_eq!(all(&s, &p), vec![(k("a"), v("1"))]);
}

#[test]
fn sqlite_full_maps_to_store_full() {
    let conn = TestConn::memory();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let p = ns("full");
    apply(&s, &p, Batch::new().put(k("a"), v("1")).put(k("b"), v("2"))).unwrap();
    *conn.knobs.full_on.lock().unwrap() = Some("INSERT INTO kv");
    let err = apply(&s, &p, Batch::new().delete(k("a")).put(k("c"), v("3"))).unwrap_err();
    assert!(matches!(err, StoreError::Full), "{err:?}");
    assert_eq!(block_on(s.get(&p, &k("a"))).unwrap(), Some(v("1")));
    let prune = Batch::new()
        .require(Precondition::Present(k("a")))
        .delete(k("a"));
    assert_eq!(apply(&s, &p, prune).unwrap(), BatchOutcome::Committed);
    assert_eq!(all(&s, &p), vec![(k("b"), v("2"))]);
    // Rule 7: an engine `Full` on a delete-only batch is never `Full`.
    *conn.knobs.full_on.lock().unwrap() = Some("DELETE FROM kv");
    let err = apply(&s, &p, Batch::new().delete(k("b"))).unwrap_err();
    assert!(matches!(err, StoreError::Unavailable(_)), "{err:?}");
    assert_eq!(all(&s, &p), vec![(k("b"), v("2"))]);
}

#[test]
fn engine_page_limit_is_full_and_other_sqlite_full_is_not() {
    // At the page limit (no soft cap): the engine's own SQLITE_FULL.
    let conn = RusqliteConn::open_in_memory().unwrap();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    conn.set_size_limit(conn.size_bytes().unwrap() + 64 * 1024)
        .unwrap();
    let p = ns("engine");
    let big = Value::new(vec![7; 2048]);
    let full = (0..200).find_map(|i| {
        apply(
            &s,
            &p,
            Batch::new().put(k(&format!("big{i:03}")), big.clone()),
        )
        .err()
    });
    assert!(matches!(full, Some(StoreError::Full)), "{full:?}");
    // Far from the page limit, SQLITE_FULL is the host disk: not `Full`.
    assert!(super::at_page_limit(100, 100, 4096));
    assert!(super::at_page_limit(100, 100 + 2_612, 4096));
    assert!(!super::at_page_limit(100, 100 + 2_613, 4096));
    assert!(
        !super::at_page_limit(3, 4_294_967_294, 4096),
        "no limit set"
    );
}

/// Rule 7 at the engine (the review's reproduction): fill a capped store
/// with keys of 1 to `MAX_KEY_BYTES` bytes until the soft limit refuses
/// puts, then delete every row (shuffled single deletes, then maximal
/// delete batches). No delete may fail, and the file never grows past one
/// batch's growth. With `max_record`, no row overflows its b-tree page, so
/// deletes free no overflow pages and splits must take new ones: the case
/// where deletes grow the file.
fn deletes_never_hit_the_cap(seed: u64, fill_bytes: u64, max_record: Option<usize>) {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let reserve = reserve_floor(DEFAULT_PAGE_SIZE);
    let capacity = Capacity::new(conn.size_bytes().unwrap() + fill_bytes + reserve);
    assert_eq!(capacity.reserve_bytes(), reserve);
    let s = SqlKvStore::open_with_capacity(conn.clone(), capacity).unwrap();
    let p = ns("rule7");
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = move |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % n as u64).unwrap()
    };
    let mut keys: Vec<Key> = Vec::new();
    loop {
        let mut batch = Batch::new();
        let mut added = Vec::new();
        for _ in 0..20 {
            let len = 1 + next(MAX_KEY_BYTES);
            let mut key: Vec<u8> = (0..len).map(|_| next(256).to_le_bytes()[0]).collect();
            let mut value = vec![0; [0, 10, 100, 600][next(4)]];
            if let Some(max) = max_record
                && key.len() + value.len() > max
            {
                key.truncate(max);
                value.clear();
            }
            added.push(Key::new(key.clone()));
            batch = batch.put(Key::new(key), Value::new(value));
        }
        match apply(&s, &p, batch) {
            Ok(BatchOutcome::Committed) => keys.extend(added),
            Err(StoreError::Full) => break,
            other => panic!("seed {seed}: fill: {other:?}"),
        }
    }
    assert!(
        conn.size_bytes().unwrap() >= capacity.soft_limit(),
        "seed {seed}"
    );
    keys.sort();
    keys.dedup();
    for i in (1..keys.len()).rev() {
        keys.swap(i, next(i + 1));
    }
    let filled = conn.page_count();
    let free = filled - conn.size_bytes().unwrap() / DEFAULT_PAGE_SIZE;
    assert_eq!(
        free, 0,
        "seed {seed}: deletes start with an empty free list"
    );
    let mut peak = filled;
    let (one_by_one, in_batches) = keys.split_at(keys.len() / 2);
    let singles = one_by_one
        .iter()
        .map(|key| Batch::new().delete(key.clone()));
    let batches = in_batches.chunks(MAX_BATCH_OPS).map(|chunk| {
        chunk
            .iter()
            .fold(Batch::new(), |b, key| b.delete(key.clone()))
    });
    for batch in singles.chain(batches) {
        let outcome = apply(&s, &p, batch);
        assert_eq!(outcome.unwrap(), BatchOutcome::Committed, "seed {seed}");
        peak = peak.max(conn.page_count());
    }
    assert!(all(&s, &p).is_empty());
    let growth = (peak - filled) * DEFAULT_PAGE_SIZE;
    let bound = batch_growth_bytes(DEFAULT_PAGE_SIZE);
    assert!(growth <= bound, "seed {seed}: grew {growth}");
}

#[test]
fn delete_only_batches_never_full_at_the_soft_limit() {
    for seed in 0..6 {
        deletes_never_hit_the_cap(seed, 2 << 20, None);
        deletes_never_hit_the_cap(seed, 2 << 20, Some(900));
    }
}

#[test]
#[ignore = "heavy: 32 seeds of 16 MiB; run with --ignored"]
fn delete_only_batches_never_full_at_the_soft_limit_heavy() {
    for seed in 0..32 {
        deletes_never_hit_the_cap(seed, 16 << 20, None);
        deletes_never_hit_the_cap(seed, 16 << 20, Some(900));
    }
}

#[test]
fn soft_limit_refuses_puts_below_the_hard_cap() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let base = conn.size_bytes().unwrap();
    let capacity = Capacity::new(base + (64 << 10) + (1 << 20)).with_reserve(1 << 20);
    let s = SqlKvStore::open_with_capacity(conn.clone(), capacity).unwrap();
    let p = ns("soft");
    let row = Value::new(vec![1; 1000]);
    let mut n = 0;
    while apply(&s, &p, Batch::new().put(k(&format!("{n:04}")), row.clone())).is_ok() {
        n += 1;
    }
    let full = apply(&s, &p, Batch::new().put(k("x"), v("1"))).unwrap_err();
    assert!(matches!(full, StoreError::Full), "{full:?}");
    let used = conn.size_bytes().unwrap();
    assert!(
        used >= capacity.soft_limit() && used < capacity.cap_bytes(),
        "{used}"
    );
    // Guarded delete-only batches, and reads, still work.
    let guard = Batch::new().require(Precondition::Present(k("0000")));
    let prune = (0..n / 2).fold(guard, |b, i| b.delete(k(&format!("{i:04}"))));
    assert_eq!(apply(&s, &p, prune).unwrap(), BatchOutcome::Committed);
    assert_eq!(all(&s, &p).len(), n - n / 2);
    // Freed pages bring the store back under the soft limit.
    apply(&s, &p, Batch::new().put(k("x"), v("1"))).unwrap();
}

#[test]
fn stale_transaction_is_rolled_back_and_nested_is_refused() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let p = ns("stale");
    // A transaction left open behind the store's back, holding a write.
    conn.exec(&["BEG", "IN"].concat(), &[]).unwrap();
    let insert = "INSERT INTO kv (part, key, value) VALUES (?1, ?2, ?3)";
    let row = [
        SqlValue::Blob(p.encode().unwrap().to_vec()),
        SqlValue::Blob(k("ghost").as_bytes().to_vec()),
        SqlValue::Blob(vec![]),
    ];
    conn.exec(insert, &row).unwrap();
    assert!(conn.in_transaction());
    apply(&s, &p, Batch::new().put(k("a"), v("1"))).unwrap();
    assert!(!conn.in_transaction());
    assert_eq!(
        all(&s, &p),
        vec![(k("a"), v("1"))],
        "the stale write is gone"
    );
    // A nested transaction is an error, and the outer one still commits.
    let body: TxFn<RusqliteConn, bool> = Box::new(|c: RusqliteConn| {
        let inner: TxFn<RusqliteConn, ()> = Box::new(|_| Ok(()));
        Ok(c.transaction(inner).is_err())
    });
    assert!(conn.transaction(body).unwrap());
    assert!(!conn.in_transaction());
}

#[test]
fn backup_is_a_connection_hook() {
    // The shared store has no engine-specific backup: the default hook.
    let s = SqlKvStore::open(TestConn::memory()).unwrap();
    let err = block_on(s.backup_to("/nowhere")).unwrap_err();
    assert!(matches!(err, StoreError::Unsupported(_)), "{err:?}");
}

#[test]
fn transaction_closure_is_static_fnonce() {
    // Compile-level: the body owns what it moves in (a non-Clone value
    // consumed once) and borrows nothing of the caller.
    fn run<C: SqlConn>(conn: &C, owned: Batch) -> Result<usize, SqlError> {
        let body: TxFn<C, usize> = Box::new(move |_conn: C| {
            let consumed: Vec<_> = owned.writes.into_iter().collect();
            Ok(consumed.len())
        });
        conn.transaction(body)
    }
    let conn = RusqliteConn::open_in_memory().unwrap();
    let batch = Batch::new().put(k("a"), v("1")).delete(k("b"));
    assert_eq!(run(&conn, batch).unwrap(), 2);
}

#[test]
fn concurrent_apply_from_threads_serializes() {
    let dir = tempfile::tempdir().unwrap();
    let shared = Arc::new(SqlKvStore::open(file(dir.path())).unwrap());
    for own_connection in [false, true] {
        let p = ns(if own_connection {
            "race-own"
        } else {
            "race-shared"
        });
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let (barrier, shared, p) = (barrier.clone(), shared.clone(), p.clone());
                let path = dir.path().to_owned();
                std::thread::spawn(move || {
                    let store = if own_connection {
                        Arc::new(SqlKvStore::open(file(&path)).unwrap())
                    } else {
                        shared
                    };
                    barrier.wait();
                    let batch = Batch::new()
                        .require(Precondition::Absent(k("x")))
                        .put(k("x"), v(&i.to_string()));
                    apply(&store, &p, batch).unwrap()
                })
            })
            .collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let won = outcomes
            .iter()
            .filter(|o| **o == BatchOutcome::Committed)
            .count();
        assert_eq!(won, 1, "{outcomes:?}");
        assert_eq!(all(&*shared, &p).len(), 1);
    }
}

#[test]
fn durable_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let p = ns("durable");
    {
        let s = SqlKvStore::open(file(dir.path())).unwrap();
        apply(
            &s,
            &p,
            Batch::new()
                .put(k("a"), v("1"))
                .put(k("b"), Value::default()),
        )
        .unwrap();
        apply(&s, &p, Batch::new().delete(k("a")).put(k("c"), v("3"))).unwrap();
    }
    let s = SqlKvStore::open(file(dir.path())).unwrap();
    assert_eq!(
        all(&s, &p),
        vec![(k("b"), Value::default()), (k("c"), v("3"))]
    );
}

/// A store holding two versioned partitions of rows.
fn populated(dir: &Path) -> SqlKvStore<RusqliteConn> {
    let s = SqlKvStore::open(file(dir)).unwrap();
    for (name, n) in [("one", 120_usize), ("two", 3)] {
        let version = codec::encode_u32(keys::LAYOUT_VERSION);
        apply(
            &s,
            &ns(name),
            Batch::new().put(keys::layout_version(), version),
        )
        .unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(50) {
            let batch = chunk.iter().fold(Batch::new(), |b, i| {
                b.put(
                    k(&format!("{name}{i:03}")),
                    Value::new(vec![u8::try_from(*i).unwrap(); *i]),
                )
            });
            apply(&s, &ns(name), batch).unwrap();
        }
    }
    s
}

#[test]
fn backup_via_vacuum_into_restores() {
    let dir = tempfile::tempdir().unwrap();
    let s = populated(dir.path());
    let dest = dir.path().join("backup.sqlite3");
    block_on(s.backup_to(dest.to_str().unwrap())).unwrap();
    // Writes after the backup are not in it.
    apply(&s, &ns("one"), Batch::new().put(k("late"), v("1"))).unwrap();
    let restored = SqlKvStore::open(RusqliteConn::open(&dest).unwrap()).unwrap();
    assert_eq!(restored.layout_version(), schema::SCHEMA_VERSION);
    for name in ["one", "two"] {
        let mut want = all(&s, &ns(name));
        want.retain(|(key, _)| *key != k("late"));
        assert_eq!(all(&restored, &ns(name)), want);
    }
    // The destination must not exist.
    assert!(block_on(s.backup_to(dest.to_str().unwrap())).is_err());
}

#[test]
fn logical_export_import_matches_physical_backup() {
    let dir = tempfile::tempdir().unwrap();
    let s = populated(dir.path());
    let dest = dir.path().join("physical.sqlite3");
    block_on(s.backup_to(dest.to_str().unwrap())).unwrap();
    let physical = SqlKvStore::open(RusqliteConn::open(&dest).unwrap()).unwrap();
    let logical = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
    for name in ["one", "two"] {
        let p = ns(name);
        let bytes = block_on(async {
            let (header, stream) = export_partition(&s, &p, 7).await.unwrap();
            let mut bytes = encode_export_header(&header).to_vec();
            let records: Vec<_> = stream.collect().await;
            for record in records {
                bytes.extend_from_slice(&encode_export_record(&record.unwrap()).unwrap());
            }
            bytes.extend_from_slice(&EXPORT_END);
            bytes
        });
        let (header, reader) = ExportReader::new(&bytes).unwrap();
        let records = futures::stream::iter(reader);
        block_on(import_stream(&logical, &header, ImportMode::Fresh, records)).unwrap();
        assert_eq!(all(&logical, &p), all(&physical, &p));
    }
}

#[test]
fn statements_stay_within_durable_object_limits() {
    let conn = TestConn::memory();
    let s = SqlKvStore::open(conn.clone()).unwrap();
    let p = ns("limits");
    let keys: Vec<Key> = (0..300).map(|i| k(&format!("{i:04}"))).collect();
    for chunk in keys.chunks(100) {
        let batch = chunk
            .iter()
            .fold(Batch::new(), |b, key| b.put(key.clone(), v("1")));
        apply(&s, &p, batch).unwrap();
    }
    let got = block_on(s.get_many(&p, &keys)).unwrap();
    assert!(got.iter().all(Option::is_some));
    let guarded = keys[..100].iter().fold(Batch::new(), |b, key| {
        b.require(Precondition::Present(key.clone()))
    });
    apply(&s, &p, guarded).unwrap();
    block_on(s.scan(&p, &k(""), &k("\u{7f}"), None, 50)).unwrap();
    block_on(s.stats(&p)).unwrap();
    block_on(s.probe()).unwrap();
    let max = conn.knobs.max_params.load(Ordering::SeqCst);
    assert_eq!(max, mkit_server::sql::GET_MANY_CHUNK + 1);
    assert!(max <= MAX_BOUND_PARAMS);
    let statements = conn.knobs.statements.lock().unwrap();
    let control = ["BEG", "COMMI", "ROLLB", "SAVEP", "RELEASE", "END"];
    for sql in statements.iter() {
        let first = sql.split_whitespace().next().unwrap_or("").to_uppercase();
        assert!(!control.iter().any(|c| first.starts_with(c)), "{sql}");
        assert!(sql.len() < 100 * 1024);
    }
}
