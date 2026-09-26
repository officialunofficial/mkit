//! The storage-trait suite (PRD §5.1 part (a)): generic cases over the
//! key-level [`NamespaceStore`] contract, the [`BlobStore`] contract, the
//! [`mkit_server::ContentIndex`] layer, durability and export/import.
//!
//! Cases are small and deterministic: no wall-clock sleeps, no randomness
//! beyond a fixed-seed generator. Every case builds its own stores from the
//! harness and writes only its own partition (`n<case name>`) or its own
//! content objects, so a backend that shares one database across cases
//! (and runs them in parallel) still sees independent cases.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use mkit_server::{
    Batch, BatchOutcome, BlobStore, BoxFuture, Clock, Key, KeyClasses, NamespaceStore, Partition,
    StoreError, Value, Write, store::keys,
};

/// `ensure!(cond, "fmt", args)`: fail the case unless `cond`.
macro_rules! ensure {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(format!("{}:{}: {}", file!(), line!(), format_args!($($msg)+)));
        }
    };
}

/// `ensure_eq!(left, right)`: fail the case unless `left == right`.
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!(
                "{}:{}: `{}` = {:?}, expected {:?}",
                file!(),
                line!(),
                stringify!($left),
                left,
                right
            ));
        }
    }};
}

/// `ensure_err!(result, pattern)`: fail the case unless `result` is
/// `Err(pattern)`.
macro_rules! ensure_err {
    ($result:expr, $pat:pat) => {
        match $result {
            Err($pat) => {}
            other => {
                return Err(format!(
                    "{}:{}: `{}` = {:?}, expected Err({})",
                    file!(),
                    line!(),
                    stringify!($result),
                    other,
                    stringify!($pat)
                ));
            }
        }
    };
}

/// `ok!(result)`: the `Ok` value, or fail the case with the error.
macro_rules! ok {
    ($result:expr) => {
        $result.map_err(|e| format!("{}:{}: `{}`: {e}", file!(), line!(), stringify!($result)))?
    };
}

/// `gate!(check)`: return the skip a capability gate asks for.
macro_rules! gate {
    ($check:expr) => {
        if let Some(skip) = $check? {
            return Ok(skip);
        }
    };
}

pub mod blob;
pub mod content_index;
pub mod durability;
pub mod kv;
mod macros;

/// How a case ended, when it did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseResult {
    /// Every check held.
    Pass,
    /// Not applicable to this backend, with the reason.
    Skip(&'static str),
}

/// A case's result: `Err` carries the failure message.
pub type Outcome = Result<CaseResult, String>;

/// A case, type-erased for runners that iterate [`kv_cases`] or
/// [`blob_cases`].
pub type CaseFn<H> = fn(H) -> BoxFuture<'static, Outcome>;

/// A named case.
pub type Case<H> = (&'static str, CaseFn<H>);

/// What a [`NamespaceStore`] backend provides to the suite. Every method
/// returns a new, empty store (or a handle on an existing one, for
/// [`Self::open_at`]); the optional builders return `None` when the backend
/// cannot build that store, and the cases that need it skip with a reason.
pub trait KvHarness: Send + Sync + 'static {
    /// The store under test.
    type Store: NamespaceStore + 'static;

    /// A store as deployed: its own capabilities and clock.
    fn store(&self) -> Self::Store;

    /// A store whose `NotAfter` clock (normative rule 8) is `clock`. Without
    /// it, only the deadline cases that work on the real clock run.
    fn store_with_clock(&self, _clock: Arc<dyn Clock>) -> Option<Self::Store> {
        None
    }

    /// A store whose partitions hold about `bytes` bytes, then return
    /// [`StoreError::Full`] for batches that add data (rule 7).
    fn store_with_capacity(&self, _bytes: u64) -> Option<Self::Store> {
        None
    }

    /// Open the persistent store at `dir`, an empty directory the case
    /// owns: opening the same `dir` again, after every earlier handle was
    /// dropped without a clean shutdown, must see exactly the committed
    /// batches (rule 5).
    fn open_at(&self, _dir: &Path) -> Option<Self::Store> {
        None
    }

    /// Bring [`NamespaceStore::stats`] up to date, for backends whose stats
    /// may be stale.
    fn refresh_stats(&self, _store: &Self::Store) {}
}

/// What a [`BlobStore`] backend provides: a new, empty store per call. Any
/// `Fn() -> impl BlobStore` is one.
pub trait BlobHarness: Send + Sync + 'static {
    /// The store under test.
    type Store: BlobStore + 'static;

    /// A new, empty store.
    fn store(&self) -> Self::Store;
}

impl<F, B> BlobHarness for F
where
    F: Fn() -> B + Send + Sync + 'static,
    B: BlobStore + 'static,
{
    type Store = B;

    fn store(&self) -> B {
        self()
    }
}

/// Every key-level, durability and `ContentIndex` case, by name.
#[must_use]
pub fn kv_cases<H: KvHarness>() -> Vec<Case<H>> {
    crate::__with_kv_cases!(__case_registry { H })
}

/// Every blob case, by name.
#[must_use]
pub fn blob_cases<H: BlobHarness>() -> Vec<Case<H>> {
    crate::__with_blob_cases!(__case_registry { H })
}

/// The prefix of every key the generic cases write: the ref class, so the
/// same cases run on `RefsOnly` stores. The last component of a ref key
/// may hold any bytes.
const KEY_PREFIX: &[u8] = b"r\0conformance\0";

/// A case key: [`KEY_PREFIX`] then `suffix`.
pub(crate) fn k(suffix: &[u8]) -> Key {
    Key::new([KEY_PREFIX, suffix].concat())
}

/// A value.
pub(crate) fn v(bytes: &[u8]) -> Value {
    Value::new(bytes.to_vec())
}

/// `[start, end)` covering every [`k`] key.
pub(crate) fn range() -> (Key, Key) {
    let mut end = KEY_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last += 1;
    }
    (k(b""), Key::new(end))
}

/// The case's own partition: namespace `case`.
pub(crate) fn part(case: &str) -> Partition {
    Partition::decode(format!("n{case}\0").as_bytes()).expect("a case name is a valid namespace")
}

/// Apply `batch`, failing the case on a store error.
pub(crate) async fn outcome<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    batch: Batch,
) -> Result<BatchOutcome, String> {
    s.apply(p, batch).await.map_err(|e| format!("apply: {e}"))
}

/// Apply `batch`, failing the case unless it commits.
pub(crate) async fn commit<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    batch: Batch,
) -> Result<(), String> {
    match outcome(s, p, batch).await? {
        BatchOutcome::Committed => Ok(()),
        other => Err(format!("expected Committed, got {other:?}")),
    }
}

/// Put `rows`: 50 per batch on atomic stores, one per batch otherwise.
pub(crate) async fn put_all<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    rows: &[(Key, Value)],
) -> Result<(), String> {
    let per = if s.capabilities().atomic_multi_key {
        50
    } else {
        1
    };
    for chunk in rows.chunks(per) {
        let batch = chunk.iter().fold(Batch::new(), |b, (key, val)| {
            b.put(key.clone(), val.clone())
        });
        commit(s, p, batch).await?;
    }
    Ok(())
}

/// Every entry of `[start, end)`, paging `limit` at a time until `next` is
/// `None`. Checks each page: ascending, in range, strictly after the
/// previous page. Short pages with a `next` are allowed.
pub(crate) async fn scan_all<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    (start, end): (&Key, &Key),
    limit: u32,
) -> Result<Vec<(Key, Value)>, String> {
    let mut out: Vec<(Key, Value)> = Vec::new();
    let mut after = None;
    for _ in 0..10_000 {
        let page = ok!(s.scan(p, start, end, after.as_ref(), limit).await);
        ensure!(page.entries.len() <= limit as usize, "page over limit");
        for (key, val) in page.entries {
            ensure!(*start <= key && key < *end, "{key:?} outside the range");
            ensure!(out.last().is_none_or(|l| l.0 < key), "{key:?} out of order");
            out.push((key, val));
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(out),
        }
    }
    Err("scan never returned `next = None`".into())
}

/// Every [`k`] row of `p`.
pub(crate) async fn rows<S: NamespaceStore>(
    s: &S,
    p: &Partition,
) -> Result<Vec<(Key, Value)>, String> {
    let (start, end) = range();
    scan_all(s, p, (&start, &end), 7).await
}

/// A reference model of one partition.
pub(crate) type Model = BTreeMap<Key, Value>;

/// Apply `batch`'s writes to `model`, as a committed batch would.
pub(crate) fn model_apply(model: &mut Model, batch: &Batch) {
    for write in &batch.writes {
        match write {
            Write::Put(key, val) => model.insert(key.clone(), val.clone()),
            Write::Delete(key) => model.remove(key),
        };
    }
}

/// `model`'s rows, as [`rows`] returns them.
pub(crate) fn model_rows(model: &Model) -> Vec<(Key, Value)> {
    model.iter().map(|(a, b)| (a.clone(), b.clone())).collect()
}

/// A fixed-seed `SplitMix64` generator.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % n
    }

    pub(crate) fn byte(&mut self, n: u8) -> u8 {
        u8::try_from(self.below(u64::from(n))).unwrap_or(0)
    }
}

/// An injectable store clock that can also panic on its next reading.
#[derive(Debug, Default)]
pub(crate) struct TestClock {
    now: AtomicI64,
    panic_next: AtomicBool,
}

impl TestClock {
    pub(crate) fn set(&self, now_ms: i64) {
        self.now.store(now_ms, Ordering::SeqCst);
    }

    pub(crate) fn panic_next(&self) {
        self.panic_next.store(true, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        assert!(
            !self.panic_next.swap(false, Ordering::SeqCst),
            "conformance: injected clock panic"
        );
        self.now.load(Ordering::SeqCst)
    }
}

/// A store on a [`TestClock`] reading `now_ms`, if the harness can inject
/// one.
pub(crate) fn clocked<H: KvHarness>(h: &H, now_ms: i64) -> Option<(H::Store, Arc<TestClock>)> {
    let clock = Arc::new(TestClock::default());
    clock.set(now_ms);
    h.store_with_clock(clock.clone()).map(|s| (s, clock))
}

/// The skip for a case that needs an injected clock.
pub(crate) const NO_CLOCK: CaseResult = CaseResult::Skip("harness cannot inject the store clock");

/// Gate: skip unless the store has `atomic_multi_key`, after checking that
/// a two-write batch is `Unsupported` and writes nothing.
pub(crate) async fn need_atomic<S: NamespaceStore>(
    s: &S,
    p: &Partition,
) -> Result<Option<CaseResult>, String> {
    if s.capabilities().atomic_multi_key {
        return Ok(None);
    }
    let two = Batch::new()
        .put(k(b"gate/a"), v(b"1"))
        .put(k(b"gate/b"), v(b"1"));
    ensure_err!(s.apply(p, two).await, StoreError::Unsupported(_));
    ensure_eq!(ok!(s.get(p, &k(b"gate/a")).await), None);
    Ok(Some(CaseResult::Skip("store lacks atomic_multi_key")))
}

/// Gate: skip unless the store accepts every key class, after checking
/// that a non-ref key is `Unsupported` and writes nothing.
pub(crate) async fn need_all_classes<S: NamespaceStore>(
    s: &S,
    p: &Partition,
) -> Result<Option<CaseResult>, String> {
    if s.capabilities().key_classes == KeyClasses::All {
        return Ok(None);
    }
    let key = keys::grant_epoch();
    let batch = Batch::new().put(key.clone(), v(b"1"));
    ensure_err!(s.apply(p, batch).await, StoreError::Unsupported(_));
    Ok(Some(CaseResult::Skip("store accepts only ref keys")))
}

/// A directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("mkit-conformance-{}-{n}", std::process::id());
        let dir = std::env::temp_dir().join(name);
        ok!(std::fs::create_dir_all(&dir));
        Ok(Self(dir))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
