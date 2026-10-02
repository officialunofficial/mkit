//! Store-level fault injection (`test-faults` only). The pipeline's own
//! seam is `mkit_server::pipeline::FaultHooks` (M0-05b); these two cover
//! what only a backend can fail:
//!
//! - [`crate::r2::R2BlobStore::fail_final_chunk_once`]: the next commit
//!   fails at its withheld final byte, after the hash verified.
//! - [`FaultConn`]: a Durable Object batch that writes a key containing
//!   [`FAIL_ONCE_MARKER`] fails once, inside `transactionSync`, after its
//!   writes ran, proving they roll back. It maps vcs-worker's
//!   `refs/heads/__test_fail_once-*` behavior (M0-17 wires it).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use mkit_server::Redacted;
use mkit_server::sql::{Row, SqlConn, SqlError, SqlValue, TxFn};

/// A written key containing this fails its batch once.
pub const FAIL_ONCE_MARKER: &[u8] = b"__test_fail_once-";

#[derive(Debug, Default)]
struct Faults {
    /// Marker keys that already failed a batch.
    failed: HashSet<Vec<u8>>,
    /// The marker key the open transaction wrote, if any.
    pending: Option<Vec<u8>>,
}

/// A [`SqlConn`] that injects the fail-once fault (see the module docs).
#[derive(Debug, Clone)]
pub struct FaultConn<C> {
    inner: C,
    faults: Arc<Mutex<Faults>>,
}

impl<C> FaultConn<C> {
    /// `inner` with the fault armed.
    #[must_use]
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            faults: Arc::default(),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Faults) -> T) -> T {
        f(&mut self.faults.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn marker_key(params: &[SqlValue]) -> Option<Vec<u8>> {
    params.iter().find_map(|p| match p {
        SqlValue::Blob(b)
            if b.windows(FAIL_ONCE_MARKER.len())
                .any(|w| w == FAIL_ONCE_MARKER) =>
        {
            Some(b.clone())
        }
        _ => None,
    })
}

impl<C: SqlConn> SqlConn for FaultConn<C> {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        let changed = self.inner.exec(sql, params)?;
        if let Some(key) = marker_key(params) {
            self.with(|f| {
                f.pending.get_or_insert(key);
            });
        }
        Ok(changed)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        self.inner.query(sql, params)
    }

    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        let faults = self.faults.clone();
        let wrapped: TxFn<C, T> = Box::new(move |inner: C| {
            let conn = FaultConn { inner, faults };
            conn.with(|f| f.pending = None);
            let out = f(conn.clone())?;
            let fail = conn.with(|f| match f.pending.take() {
                Some(key) => f.failed.insert(key),
                None => false,
            });
            if fail {
                return Err(SqlError::Backend(Redacted::new(
                    "injected fault after the batch's writes",
                )));
            }
            Ok(out)
        });
        self.inner.transaction(wrapped)
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }

    fn size_bytes(&self) -> Result<u64, SqlError> {
        self.inner.size_bytes()
    }

    fn set_size_limit(&self, bytes: u64) -> Result<(), SqlError> {
        self.inner.set_size_limit(bytes)
    }
}
