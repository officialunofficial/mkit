//! `DoSqlConn` (wasm32): Durable Object `SQLite` as a [`SqlConn`], so every
//! partition's Durable Object runs `mkit-server`'s `SqlKvStore` unchanged:
//! the same statements, the same migrations. This module adds no SQL.
//!
//! - Statements run through `ctx.storage.sql.exec`. Cursors are
//!   materialized before a call returns and never held across a
//!   `transactionSync` boundary.
//! - [`SqlConn::transaction`](mkit_server::sql::SqlConn::transaction) runs its owned body inside
//!   `ctx.storage.transactionSync(callback)`: every statement of the body
//!   runs in that transaction, which commits if the body returns `Ok` and
//!   rolls back if it returns `Err` (the callback throws). There is no
//!   transaction-control SQL: Durable Objects reject it.
//! - Values map to JavaScript: blobs as `Uint8Array` (read back from
//!   `ArrayBuffer`), integers as numbers, so a bound integer outside
//!   ±(2^53 − 1) is refused rather than rounded. Durable Object SQL returns
//!   no `BigInt`s; a non-integral number in a result is corrupt (the schema
//!   has no `REAL`).
//! - `now_ms` is the Durable Object's own `Date.now()`, the clock `NotAfter`
//!   deadlines are checked against (normative rule 8).
//! - `size_bytes` is `ctx.storage.sql.databaseSize`. workerd computes it as
//!   `(page_count − freelist_count) × page_size`
//!   (`src/workerd/api/sql.c++`, `SqlStorage::getDatabaseSize`, since
//!   2023-05-17: "Taking into account `freelist_count` when calculating DB
//!   size … deleting data has no effect on the reported DB size until a
//!   vacuum"): pages in use, exactly the native backend's measure. So the
//!   soft cap recovers after a prune (freed pages leave the count at once)
//!   although a Durable Object allows neither `page_count` nor
//!   `freelist_count` pragmas nor a vacuum. The host tests prove the
//!   recovery against a simulated Durable Object with that measure.
//! - Size: a SQLite-backed Durable Object stores at most 10 GB on Workers
//!   Paid (1 GB on Free), and past that `SQLITE_FULL` fails writes. Inside
//!   a transaction workerd treats `SQLITE_FULL` as a critical error that
//!   resets the object, so the store must stop well before it: the default
//!   [`DO_CAPACITY`] keeps `SqlKvStore`'s reserve (1/64 of the cap) below
//!   the hard limit, and batches with a put stop at the soft limit. An
//!   error whose message names `SQLITE_FULL` still maps to
//!   [`SqlError::Full`].
//! - `backup_to` keeps the trait default, `Unsupported`: a Durable Object
//!   has no file to copy (Cloudflare's point-in-time recovery covers 30
//!   days; the portable export covers the rest).
//!
//! Limits that `SqlKvStore` already respects: at most 100 bound parameters
//! (it binds at most 65), 2 MB per row (values are at most 512 KiB), 100 KB
//! per statement.
//!
//! [`SqlConn`]: mkit_server::sql::SqlConn

use mkit_server::Redacted;
use mkit_server::sql::{Capacity, MAX_BOUND_PARAMS, SqlError, SqlValue};

/// The storage limit of a SQLite-backed Durable Object on Workers Paid:
/// 10 GB, read as 10^10 bytes (the smaller reading).
pub const DO_MAX_BYTES: u64 = 10_000_000_000;

/// The same limit on Workers Free: 1 GB.
pub const DO_FREE_MAX_BYTES: u64 = 1_000_000_000;

/// The default cap: [`DO_MAX_BYTES`] with `SqlKvStore`'s default reserve
/// (1/64, about 156 MB) below it, so batches with a put stop at about
/// 9.84 GB.
pub const DO_CAPACITY: Capacity = Capacity::new(DO_MAX_BYTES);

/// Largest integer JavaScript represents exactly, `2^53 − 1`.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// A Durable Object SQL value, the shape of workers-rs `SqlStorageValue`:
/// the host-testable half of the value mapping.
#[derive(Debug, Clone, PartialEq)]
pub enum DoValue {
    /// `null`.
    Null,
    /// A boolean (never produced by this schema).
    Bool(bool),
    /// A number that is a safe integer.
    Integer(i64),
    /// Any other number.
    Float(f64),
    /// A string.
    Text(String),
    /// Bytes.
    Blob(Vec<u8>),
}

/// A bound parameter as a Durable Object value.
///
/// # Errors
/// [`SqlError::Backend`] for an integer outside ±(2^53 − 1), which a
/// JavaScript number would round.
pub fn to_do(value: &SqlValue) -> Result<DoValue, SqlError> {
    Ok(match value {
        SqlValue::Null => DoValue::Null,
        SqlValue::Integer(n) if n.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() => {
            DoValue::Integer(*n)
        }
        SqlValue::Integer(_) => {
            return Err(SqlError::Backend(Redacted::new(
                "integer parameter outside the JavaScript safe range",
            )));
        }
        SqlValue::Text(s) => DoValue::Text(s.clone()),
        SqlValue::Blob(b) => DoValue::Blob(b.clone()),
    })
}

/// A result column from a Durable Object value.
///
/// # Errors
/// [`SqlError::Corrupt`] for a boolean, a non-integral number or an integer
/// outside the safe range.
pub fn from_do(value: DoValue) -> Result<SqlValue, SqlError> {
    Ok(match value {
        DoValue::Null => SqlValue::Null,
        DoValue::Integer(n) if n.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() => {
            SqlValue::Integer(n)
        }
        DoValue::Integer(_) | DoValue::Float(_) => {
            return Err(SqlError::Corrupt("unexpected non-integer number column"));
        }
        DoValue::Bool(_) => return Err(SqlError::Corrupt("unexpected boolean column")),
        DoValue::Text(s) => SqlValue::Text(s),
        DoValue::Blob(b) => SqlValue::Blob(b),
    })
}

/// Classify a Durable Object SQL exception by its message. workerd writes
/// `"<sqlite message>: <SQLITE_CODE>"` (`dbErrorMessage`): `SQLITE_FULL` is
/// [`SqlError::Full`], `SQLITE_CONSTRAINT` [`SqlError::Constraint`], the
/// rest a redacted [`SqlError::Backend`].
#[must_use]
pub fn classify_error(message: &str) -> SqlError {
    if message.contains("SQLITE_FULL") || message.contains("database or disk is full") {
        SqlError::Full
    } else if message.contains("SQLITE_CONSTRAINT") {
        SqlError::Constraint
    } else {
        SqlError::Backend(Redacted::new(message))
    }
}

/// Refuse a statement a Durable Object would reject for its parameter
/// count, before crossing into JavaScript.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn check_params(params: &[SqlValue]) -> Result<(), SqlError> {
    if params.len() > MAX_BOUND_PARAMS {
        return Err(SqlError::Backend(Redacted::new(
            "more bound parameters than a Durable Object allows",
        )));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub use conn::DoSqlConn;

#[cfg(target_arch = "wasm32")]
mod conn {
    use std::cell::RefCell;
    use std::rc::Rc;

    use mkit_server::Redacted;
    use mkit_server::sql::{Row, SqlConn, SqlError, SqlValue, TxFn};
    use worker::js_sys;
    use worker::wasm_bindgen::closure::Closure;
    use worker::wasm_bindgen::{JsCast, JsValue};
    use worker::{SqlStorage, SqlStorageValue, State};

    use super::{DoValue, check_params, classify_error, from_do, to_do};

    /// A Durable Object's `SQLite` as a [`SqlConn`] (see the module docs).
    /// Clones share the storage handles.
    #[derive(Debug, Clone)]
    pub struct DoSqlConn {
        sql: SqlStorage,
        /// `ctx.storage`, for `transactionSync`, which workers-rs does not
        /// wrap.
        storage: JsValue,
    }

    fn js_message(e: &JsValue) -> String {
        e.dyn_ref::<js_sys::Error>()
            .map(|e| String::from(e.message()))
            .or_else(|| e.as_string())
            .unwrap_or_else(|| format!("{e:?}"))
    }

    fn into_storage(v: DoValue) -> SqlStorageValue {
        match v {
            DoValue::Null => SqlStorageValue::Null,
            DoValue::Bool(b) => SqlStorageValue::Boolean(b),
            DoValue::Integer(n) => SqlStorageValue::Integer(n),
            DoValue::Float(f) => SqlStorageValue::Float(f),
            DoValue::Text(s) => SqlStorageValue::String(s),
            DoValue::Blob(b) => SqlStorageValue::Blob(b),
        }
    }

    fn from_storage(v: SqlStorageValue) -> DoValue {
        match v {
            SqlStorageValue::Null => DoValue::Null,
            SqlStorageValue::Boolean(b) => DoValue::Bool(b),
            SqlStorageValue::Integer(n) => DoValue::Integer(n),
            SqlStorageValue::Float(f) => DoValue::Float(f),
            SqlStorageValue::String(s) => DoValue::Text(s),
            SqlStorageValue::Blob(b) => DoValue::Blob(b),
        }
    }

    impl DoSqlConn {
        /// The connection of the Durable Object whose state is `state`;
        /// gives the state back. It takes the state by value because
        /// workers-rs wraps `transactionSync` nowhere: the raw
        /// `ctx.storage` object is reachable only through the raw state
        /// (the same bridge as `mkit_worker_common::replay::Ledger`).
        #[must_use]
        pub fn from_state(state: State) -> (Self, State) {
            let raw = state._inner();
            let storage = raw.storage().map_or(JsValue::UNDEFINED, JsValue::from);
            let state = State::from(raw);
            let sql = state.storage().sql();
            (Self { sql, storage }, state)
        }

        fn run(&self, sql: &str, params: &[SqlValue]) -> Result<worker::SqlCursor, SqlError> {
            check_params(params)?;
            let bindings = params
                .iter()
                .map(|p| to_do(p).map(into_storage))
                .collect::<Result<Vec<_>, _>>()?;
            self.sql
                .exec(sql, bindings)
                .map_err(|e| classify_error(&e.to_string()))
        }
    }

    impl SqlConn for DoSqlConn {
        fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            let cursor = self.run(sql, params)?;
            for row in cursor.raw() {
                row.map_err(|e| classify_error(&e.to_string()))?;
            }
            Ok(cursor.rows_written() as u64)
        }

        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
            let cursor = self.run(sql, params)?;
            cursor
                .raw()
                .map(|row| {
                    row.map_err(|e| classify_error(&e.to_string()))?
                        .into_iter()
                        .map(|v| from_do(from_storage(v)))
                        .collect()
                })
                .collect()
        }

        fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
            let out: Rc<RefCell<Option<Result<T, SqlError>>>> = Rc::default();
            let slot = out.clone();
            let conn = self.clone();
            let callback: Closure<dyn FnMut() -> Result<JsValue, JsValue>> =
                Closure::once(move || {
                    let result = f(conn);
                    let failed = result.is_err();
                    *slot.borrow_mut() = Some(result);
                    // Throwing rolls the transaction back.
                    if failed {
                        Err(JsValue::from_str("mkit transaction body failed"))
                    } else {
                        Ok(JsValue::UNDEFINED)
                    }
                });
            let function = js_sys::Reflect::get(&self.storage, &"transactionSync".into())
                .ok()
                .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
                .ok_or_else(|| SqlError::Backend(Redacted::new("transactionSync unavailable")))?;
            let called = function.call1(&self.storage, callback.as_ref());
            let result = out.borrow_mut().take();
            match (result, called) {
                // The body failed and was rolled back.
                (Some(Err(e)), _) => Err(e),
                (Some(Ok(value)), Ok(_)) => Ok(value),
                // The body succeeded but the commit failed.
                (Some(Ok(_)) | None, Err(e)) => Err(classify_error(&js_message(&e))),
                (None, Ok(_)) => Err(SqlError::Backend(Redacted::new(
                    "transaction body did not run",
                ))),
            }
        }

        fn now_ms(&self) -> u64 {
            worker::Date::now().as_millis()
        }

        fn size_bytes(&self) -> Result<u64, SqlError> {
            Ok(self.sql.database_size() as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_full_message_maps_to_full() {
        // workerd's `dbErrorMessage` shapes.
        for full in [
            "database or disk is full: SQLITE_FULL",
            "Error: database or disk is full: SQLITE_FULL",
            "SQLITE_FULL",
        ] {
            assert!(matches!(classify_error(full), SqlError::Full), "{full}");
        }
        assert!(matches!(
            classify_error("UNIQUE constraint failed: kv.key: SQLITE_CONSTRAINT"),
            SqlError::Constraint
        ));
        let other = classify_error("no such table: kv at offset 14: SQLITE_ERROR");
        assert!(matches!(other, SqlError::Backend(_)));
        assert!(!other.to_string().contains("kv"), "{other}");
        assert!(check_params(&vec![SqlValue::Null; MAX_BOUND_PARAMS]).is_ok());
        assert!(check_params(&vec![SqlValue::Null; MAX_BOUND_PARAMS + 1]).is_err());
    }

    #[test]
    fn sql_value_js_mapping_rejects_unsafe_integers() {
        let safe = (1_i64 << 53) - 1;
        for n in [0, 1, -1, safe, -safe] {
            assert_eq!(to_do(&SqlValue::Integer(n)).unwrap(), DoValue::Integer(n));
            assert_eq!(from_do(DoValue::Integer(n)).unwrap(), SqlValue::Integer(n));
        }
        for n in [safe + 1, -safe - 1, i64::MAX, i64::MIN] {
            assert!(matches!(
                to_do(&SqlValue::Integer(n)),
                Err(SqlError::Backend(_))
            ));
            assert!(matches!(
                from_do(DoValue::Integer(n)),
                Err(SqlError::Corrupt(_))
            ));
        }
        let blob = SqlValue::Blob(vec![0, 1, 255]);
        assert_eq!(from_do(to_do(&blob).unwrap()).unwrap(), blob);
        let text = SqlValue::Text("x".into());
        assert_eq!(from_do(to_do(&text).unwrap()).unwrap(), text);
        assert_eq!(
            from_do(to_do(&SqlValue::Null).unwrap()).unwrap(),
            SqlValue::Null
        );
        for bad in [
            DoValue::Float(0.5),
            DoValue::Float(1e300),
            DoValue::Bool(true),
        ] {
            assert!(matches!(from_do(bad), Err(SqlError::Corrupt(_))));
        }
    }

    #[test]
    fn default_capacity_stays_below_the_durable_object_limit() {
        assert_eq!(DO_CAPACITY.cap_bytes(), DO_MAX_BYTES);
        assert!(DO_CAPACITY.soft_limit() < DO_MAX_BYTES);
        assert_eq!(DO_CAPACITY.reserve_bytes(), DO_MAX_BYTES / 64);
        let free = Capacity::new(DO_FREE_MAX_BYTES);
        assert!(free.soft_limit() > 0 && free.soft_limit() < DO_FREE_MAX_BYTES);
    }
}
