//! Pure unit tests: value mapping, the migration list, and the statement
//! texts. The engine-backed tests live in `mkit-server-native`.

use super::kv::{DELETE, GET, PROBE, PUT, SCAN_AFTER, SCAN_FROM, STATS, get_many_sql};
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
    let mut all: Vec<String> = [GET, PUT, DELETE, SCAN_FROM, SCAN_AFTER, STATS, PROBE]
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
