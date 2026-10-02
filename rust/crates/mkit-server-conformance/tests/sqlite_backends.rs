//! The storage suite against the `SQLite` backend: `SqlKvStore` over
//! `RusqliteConn`, run through `Blocking` as a native server runs it.
//!
//! - `sqlite_file`: a database file per store, and `open_at` reopens one
//!   from its directory after every handle dropped. Zero skips.
//! - `sqlite_memory`: `:memory:` databases, which cannot be reopened, so it
//!   declares the one crash/restart case as its only skip.
//!
//! Capacity is the store's soft limit (`Capacity`), with the default reserve
//! below the engine's hard page limit (`max_page_count`), as deployed.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mkit_server::Clock;
use mkit_server::sql::{Capacity, DEFAULT_PAGE_SIZE, SqlConn, SqlKvStore, reserve_floor};
use mkit_server_conformance::storage::KvHarness;
use mkit_server_conformance::storage_suite;
use mkit_server_native::{Blocking, RusqliteConn, SqliteKvStore};

/// Stores on files in `dir`, or in memory without one.
struct Sqlite {
    dir: Option<tempfile::TempDir>,
    next: AtomicU64,
}

impl Sqlite {
    fn file() -> Self {
        Self {
            dir: Some(tempfile::tempdir().expect("a temp dir")),
            next: AtomicU64::new(0),
        }
    }

    fn memory() -> Self {
        Self {
            dir: None,
            next: AtomicU64::new(0),
        }
    }

    /// A connection on a new, empty database.
    fn conn(&self) -> RusqliteConn {
        match &self.dir {
            Some(dir) => {
                let n = self.next.fetch_add(1, Ordering::Relaxed);
                RusqliteConn::open(dir.path().join(format!("store-{n}.sqlite3")))
            }
            None => RusqliteConn::open_in_memory(),
        }
        .expect("open a database")
    }
}

fn store(conn: RusqliteConn) -> SqliteKvStore {
    Blocking::new(SqlKvStore::open(conn).expect("migrate a database"))
}

impl KvHarness for Sqlite {
    type Store = SqliteKvStore;

    fn store(&self) -> SqliteKvStore {
        store(self.conn())
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<SqliteKvStore> {
        Some(store(self.conn().with_clock(clock)))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<SqliteKvStore> {
        let conn = self.conn();
        // A soft limit `bytes` above the migrated, empty schema, with the
        // default reserve between it and the engine's hard page limit.
        SqlKvStore::open(conn.clone()).expect("migrate a database");
        let empty = SqlConn::size_bytes(&conn).expect("database size");
        let reserve = reserve_floor(DEFAULT_PAGE_SIZE);
        let capacity = Capacity::new(empty + bytes + reserve).with_reserve(reserve);
        let s = SqlKvStore::open_with_capacity(conn, capacity).expect("migrate a database");
        Some(Blocking::new(s))
    }

    fn open_at(&self, dir: &Path) -> Option<SqliteKvStore> {
        self.dir.as_ref()?;
        let conn = RusqliteConn::open(dir.join("meta.sqlite3")).expect("open a database");
        Some(store(conn))
    }

    fn refresh_stats(&self, store: &SqliteKvStore) -> impl Future<Output = ()> + Send {
        store.inner().clear_stats_cache();
        async {}
    }

    fn expected_skips(&self) -> &'static [&'static str] {
        if self.dir.is_some() {
            &[]
        } else {
            &["dur_crash_restart_atomic_at_last_commit"]
        }
    }
}

storage_suite!(sqlite_file, kv = Sqlite::file());
storage_suite!(sqlite_memory, kv = Sqlite::memory());
