//! Pure unit tests: value mapping, the migration list, and the statement
//! texts. The engine-backed tests live in `mkit-server-native`.

use super::kv::{
    DELETE, GET, PROBE, PUT, SCAN_AFTER, SCAN_FROM, STATS, TIMER_WINDOW_AFTER, TIMER_WINDOW_START,
    get_many_sql,
};
use super::schema::{BOOTSTRAP, MIGRATIONS, SCHEMA_VERSION};
use super::*;

/// Transaction-control keywords, assembled so this file never contains
/// them.
fn forbidden() -> Vec<String> {
    [
        ["BEG", "IN"],
        ["COM", "MIT"],
        ["ROLL", "BACK"],
        ["SAVE", "POINT"],
    ]
    .iter()
    .map(|parts| parts.concat())
    .collect()
}

/// The highest `?N` placeholder in `sql`.
fn max_param(sql: &str) -> usize {
    sql.split('?')
        .skip(1)
        .filter_map(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .max()
        .unwrap_or(0)
}

fn statements() -> Vec<String> {
    let mut all: Vec<String> = [
        GET,
        PUT,
        DELETE,
        SCAN_FROM,
        SCAN_AFTER,
        STATS,
        PROBE,
        TIMER_WINDOW_START,
        TIMER_WINDOW_AFTER,
    ]
    .iter()
    .chain(core::iter::once(&BOOTSTRAP))
    .map(|s| (*s).to_owned())
    .collect();
    all.extend(
        MIGRATIONS
            .iter()
            .flat_map(|m| m.statements.iter().map(|s| (*s).to_owned())),
    );
    all.extend((1..=GET_MANY_CHUNK).map(get_many_sql));
    all
}

#[test]
fn sources_and_statements_hold_no_transaction_control() {
    let sources = [
        include_str!("mod.rs"),
        include_str!("kv.rs"),
        include_str!("schema.rs"),
        include_str!("capacity.rs"),
    ];
    // Engine-specific statements live behind `SqlConn` hooks: no string
    // literal in sql/ holds one.
    for source in sources {
        let literals: Vec<&str> = source.split('"').skip(1).step_by(2).collect();
        for native_only in [["VAC", "UUM"], ["PRAG", "MA "], ["ATT", "ACH "]] {
            let word = native_only.concat();
            assert!(
                literals.iter().all(|t| !t.contains(&word)),
                "{word} in sql/"
            );
        }
    }
    for word in forbidden() {
        for source in sources {
            // Case-sensitive: `Committed` and prose may say "commit".
            assert!(!source.contains(&word), "{word} in sql/");
        }
        for sql in statements() {
            assert!(!sql.to_uppercase().contains(&word), "{word} in {sql}");
        }
    }
}

#[test]
fn every_statement_stays_within_bound_parameter_limit() {
    let widest = statements().iter().map(|s| max_param(s)).max().unwrap();
    assert_eq!(widest, GET_MANY_CHUNK + 1);
    assert!(widest <= MAX_BOUND_PARAMS);
    assert_eq!(max_param(&get_many_sql(3)), 4);
    assert_eq!(
        get_many_sql(2),
        "SELECT key, value FROM kv WHERE part = ?1 AND key IN (?2, ?3)"
    );
}

#[test]
fn migrations_are_ascending_unique_and_portable() {
    let versions: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
    assert!(versions.windows(2).all(|w| w[0] < w[1]), "{versions:?}");
    assert_eq!(versions.first(), Some(&1));
    assert_eq!(versions.last(), Some(&SCHEMA_VERSION));
    for m in MIGRATIONS {
        assert!(!m.statements.is_empty());
        for sql in m.statements {
            let upper = sql.to_uppercase();
            assert!(upper.contains("IF NOT EXISTS"), "not idempotent: {sql}");
            for banned in ["PRAGMA", "ATTACH"] {
                assert!(!upper.contains(banned), "{banned} in {sql}");
            }
        }
    }
}

#[test]
fn column_mapping() {
    let mut row: Row = vec![
        SqlValue::Blob(vec![1, 2]),
        SqlValue::Integer(7),
        SqlValue::Null,
        SqlValue::Text("x".into()),
        SqlValue::Integer(-1),
        SqlValue::Blob(vec![]),
    ];
    assert_eq!(blob(&mut row, 0).unwrap(), vec![1, 2]);
    assert_eq!(row[0], SqlValue::Blob(vec![]), "blob() moves the bytes out");
    assert_eq!(blob(&mut row, 5).unwrap(), Vec::<u8>::new());
    for i in [1, 2, 3, 9] {
        assert!(matches!(blob(&mut row, i), Err(SqlError::Corrupt(_))));
    }
    assert_eq!(count(&row, 1).unwrap(), 7);
    assert_eq!(count(&row, 2).unwrap(), 0, "NULL aggregate");
    for i in [3, 4, 5, 9] {
        assert!(matches!(count(&row, i), Err(SqlError::Corrupt(_))));
    }
}

#[test]
fn sql_errors_map_to_store_errors_without_leaking_text() {
    assert!(matches!(StoreError::from(SqlError::Full), StoreError::Full));
    assert!(matches!(
        StoreError::from(SqlError::Corrupt("row")),
        StoreError::Corrupt(_)
    ));
    let secret = SqlError::Backend(Redacted::new("disk /secret/path failed"));
    let mapped = StoreError::from(secret);
    assert!(matches!(mapped, StoreError::Unavailable(_)));
    assert!(!mapped.to_string().contains("secret"), "{mapped}");
    assert!(!format!("{mapped:?}").contains("secret"), "{mapped:?}");
    assert!(matches!(
        StoreError::from(SqlError::Constraint),
        StoreError::Unavailable(_)
    ));
}

#[test]
fn reserve_formula() {
    // (100 ops x 21 pages + 2 MiB / 4 KiB) x 4 KiB = 2,612 pages.
    assert_eq!(batch_growth_bytes(4096), 2_612 * 4096);
    assert_eq!(reserve_floor(4096), 2 * 2_612 * 4096);
    let small = Capacity::new(64 << 20);
    assert_eq!(small.reserve_bytes(), reserve_floor(DEFAULT_PAGE_SIZE));
    assert_eq!(small.soft_limit(), (64 << 20) - reserve_floor(4096));
    let durable_object = Capacity::new(10 << 30);
    assert_eq!(durable_object.reserve_bytes(), (10 << 30) / 64);
    let custom = Capacity::new(1 << 20).with_reserve(4096);
    assert_eq!(custom.cap_bytes(), 1 << 20);
    assert_eq!(custom.soft_limit(), (1 << 20) - 4096);
    assert_eq!(Capacity::new(1 << 20).soft_limit(), 0, "saturates");
}

#[test]
fn timer_window_predicate_matches_partial_index() {
    let index = MIGRATIONS[1].statements[0];
    let predicate = index.split_once("WHERE ").unwrap().1;
    for sql in [TIMER_WINDOW_START, TIMER_WINDOW_AFTER] {
        assert!(sql.contains(predicate));
        assert!(!sql.contains("GROUP BY"));
        assert!(!sql.contains("MIN("));
        assert!(sql.contains("ORDER BY key, part LIMIT"));
    }
}

type QueryCalls = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<SqlValue>)>>>;

#[derive(Clone, Default)]
struct TimerProbe {
    rows: std::sync::Arc<std::sync::Mutex<Vec<Row>>>,
    calls: QueryCalls,
}
impl SqlConn for TimerProbe {
    fn exec(&self, _: &str, _: &[SqlValue]) -> Result<u64, SqlError> {
        Ok(0)
    }
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        if [TIMER_WINDOW_START, TIMER_WINDOW_AFTER].contains(&sql) {
            self.calls
                .lock()
                .unwrap()
                .push((sql.to_owned(), params.to_vec()));
            Ok(self.rows.lock().unwrap().clone())
        } else {
            Ok(vec![vec![SqlValue::Integer(i64::from(SCHEMA_VERSION))]])
        }
    }
    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        f(self.clone())
    }
    fn now_ms(&self) -> u64 {
        0
    }
    fn size_bytes(&self) -> Result<u64, SqlError> {
        Ok(0)
    }
}

#[test]
fn timer_window_retains_raw_rows_and_binds_exact_exclusive_position() {
    use crate::{Key, NamespaceKey, Partition};
    let conn = TimerProbe::default();
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let part = partition.encode().unwrap().to_vec();
    // Multiple timers in the same logical partition are distinct index units;
    // malformed timer-prefix bytes are also visible to the driver's ledger.
    let raw_keys = [b"w\0".to_vec(), b"w\0invalid".to_vec()];
    *conn.rows.lock().unwrap() = raw_keys
        .iter()
        .map(|key| vec![SqlValue::Blob(part.clone()), SqlValue::Blob(key.clone())])
        .collect();
    let store = SqlKvStore::open(conn.clone()).unwrap();
    let rows = store.timer_window(None, 2).unwrap();
    assert_eq!(rows.len(), 2);
    for (row, raw) in rows.iter().zip(&raw_keys) {
        assert_eq!(row.partition, partition);
        assert_eq!(row.key.as_bytes(), raw);
    }
    let cursor = TimerCursor {
        key: Key::new(raw_keys[1].clone()),
        partition,
    };
    conn.rows.lock().unwrap().clear();
    assert!(store.timer_window(Some(&cursor), 1).unwrap().is_empty());
    assert!(store.timer_window(None, 0).is_err());
    let calls = conn.calls.lock().unwrap();
    assert_eq!(calls.len(), 2, "zero allowance must never dispatch a query");
    assert_eq!(
        calls[0],
        (TIMER_WINDOW_START.to_owned(), vec![SqlValue::Integer(2)])
    );
    assert_eq!(
        calls[1],
        (
            TIMER_WINDOW_AFTER.to_owned(),
            vec![
                SqlValue::Blob(raw_keys[1].clone()),
                SqlValue::Blob(part),
                SqlValue::Integer(1),
            ]
        )
    );
}

#[test]
fn timer_window_refuses_corrupt_partition_columns() {
    let conn = TimerProbe::default();
    *conn.rows.lock().unwrap() = vec![vec![
        SqlValue::Blob(b"invalid".to_vec()),
        SqlValue::Blob(b"w\0invalid".to_vec()),
    ]];
    let store = SqlKvStore::open(conn).unwrap();
    assert!(store.timer_window(None, 1).is_err());
}

#[test]
fn relay_capacity_exception_requires_exact_guarded_empty_timer_move() {
    use super::kv::is_relay_timer_reschedule;
    use crate::store::{Batch, Precondition, Value, keys};
    fn moved(old: crate::Key, new: crate::Key) -> Batch {
        Batch::new()
            .require(Precondition::Equals(old.clone(), Value::default()))
            .require(Precondition::Absent(new.clone()))
            .delete(old)
            .put(new, Value::default())
    }
    let relay_kind = crate::timers::registry::kinds::RELAY.get();
    let old = keys::timer(10, relay_kind, b"relay-source");
    let new = keys::timer(15, relay_kind, b"relay-source");
    let valid = moved(old.clone(), new.clone());
    assert!(is_relay_timer_reschedule(&valid));
    for incorrect in [
        keys::timer(10, relay_kind, b"relay-source"),
        keys::timer(15, 231, b"relay-source"),
        keys::timer(15, relay_kind, b"different-reference"),
    ] {
        assert!(!is_relay_timer_reschedule(&moved(old.clone(), incorrect)));
    }
    let mut missing_guard = valid.clone();
    missing_guard.preconditions.pop();
    assert!(!is_relay_timer_reschedule(&missing_guard));
    let mut wrong_guard = valid.clone();
    wrong_guard.preconditions[1] = Precondition::Absent(keys::timer(20, relay_kind, b"other"));
    assert!(!is_relay_timer_reschedule(&wrong_guard));
    let mut wrong_deleted = valid.clone();
    wrong_deleted.writes[0] = crate::Write::Delete(new.clone());
    assert!(!is_relay_timer_reschedule(&wrong_deleted));
    let mut old_payload = valid.clone();
    old_payload.preconditions[0] = Precondition::Equals(old, Value::new(b"opaque".to_vec()));
    assert!(!is_relay_timer_reschedule(&old_payload));
    let mut new_payload = valid.clone();
    new_payload.writes[1] = crate::Write::Put(new, Value::new(b"opaque".to_vec()));
    assert!(!is_relay_timer_reschedule(&new_payload));
    assert!(!is_relay_timer_reschedule(
        &valid.put(crate::Key::new(b"unrelated".to_vec()), Value::default())
    ));
}

#[test]
fn retry_capacity_exception_requires_exact_guarded_payload_move() {
    use super::kv::is_timer_retry_move;
    use crate::store::{Batch, Precondition, Value, keys};
    fn moved(old: crate::Key, new: crate::Key, value: Value) -> Batch {
        Batch::new()
            .require(Precondition::Equals(old.clone(), value.clone()))
            .require(Precondition::Absent(new.clone()))
            .delete(old)
            .put(new, value)
    }
    let value = Value::new(b"opaque kind-specific payload".to_vec());
    let old = keys::timer(10, 231, b"unknown-kind");
    let new = keys::timer_retry(15, 231, b"unknown-kind", 10, 1);
    let valid = moved(old.clone(), new.clone(), value.clone());
    assert!(is_timer_retry_move(&valid));
    for incorrect in [
        keys::timer_retry(10, 231, b"unknown-kind", 10, 1),
        keys::timer_retry(15, 232, b"unknown-kind", 10, 1),
        keys::timer_retry(15, 231, b"different-reference", 10, 1),
        keys::timer_retry(15, 231, b"unknown-kind", 11, 1),
        keys::timer_retry(15, 231, b"unknown-kind", 10, 2),
    ] {
        assert!(!is_timer_retry_move(&moved(
            old.clone(),
            incorrect,
            value.clone()
        )));
    }
    let saturated = moved(
        keys::timer_retry(20, 231, b"unknown-kind", 10, 8),
        keys::timer_retry(25, 231, b"unknown-kind", 10, 8),
        value.clone(),
    );
    assert!(is_timer_retry_move(&saturated));
    let mut no_destination_guard = valid.clone();
    no_destination_guard.preconditions.pop();
    assert!(!is_timer_retry_move(&no_destination_guard));
    let mut changed_payload = valid.clone();
    changed_payload.writes[1] = crate::Write::Put(new, Value::new(b"changed".to_vec()));
    assert!(!is_timer_retry_move(&changed_payload));
    assert!(!is_timer_retry_move(
        &valid.put(crate::Key::new(b"unrelated".to_vec()), value)
    ));
}

#[test]
fn timer_payload_boundary_guarantees_max_key_retry_fits_original_batch_cap() {
    use crate::store::{
        Batch, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_VALUE_BYTES, Precondition, StoreCapabilities,
        Value, keys,
    };
    let header = keys::timer(10, 231, b"").as_bytes().len();
    let reference = vec![0; MAX_KEY_BYTES - header];
    let old = keys::timer(10, 231, &reference);
    let new = keys::timer_retry(15, 231, &reference, 10, 1);
    assert_eq!(old.as_bytes().len(), MAX_KEY_BYTES);
    assert_eq!(new.as_bytes().len(), MAX_KEY_BYTES);
    let bound = (MAX_BATCH_BYTES - 4 * MAX_KEY_BYTES) / 2;
    assert_eq!(bound, 510 * 1024);
    let value = Value::new(vec![0; bound]);
    Batch::new()
        .put(old.clone(), value.clone())
        .validate(&StoreCapabilities::full())
        .unwrap();
    let moved = Batch::new()
        .require(Precondition::Equals(old.clone(), value.clone()))
        .require(Precondition::Absent(new.clone()))
        .delete(old.clone())
        .put(new, value);
    moved.validate(&StoreCapabilities::full()).unwrap();
    assert!(super::kv::is_timer_retry_move(&moved));
    assert_eq!(2 * bound + 4 * MAX_KEY_BYTES, MAX_BATCH_BYTES);
    let too_large = Value::new(vec![0; bound + 1]);
    assert!(
        Batch::new()
            .put(old.clone(), too_large.clone())
            .validate(&StoreCapabilities::full())
            .is_err()
    );
    assert!(
        Batch::new()
            .require(Precondition::Equals(old.clone(), too_large))
            .delete(old)
            .validate(&StoreCapabilities::full())
            .is_err()
    );
    Batch::new()
        .put(
            crate::Key::new(b"ordinary-metadata".to_vec()),
            Value::new(vec![0; MAX_VALUE_BYTES]),
        )
        .validate(&StoreCapabilities::full())
        .unwrap();
}
