//! A full source still has room to move its durable relay scan cursor.
#![allow(clippy::unwrap_used)]

use futures::executor::block_on;
use mkit_server::sql::{Capacity, SqlKvStore};
use mkit_server::store::{codec, keys};
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Partition, Precondition, RepoName,
    StoreError, Value,
};
use mkit_server_native::RusqliteConn;

fn source() -> Partition {
    Partition::Ref {
        ns: NamespaceKey::deployment_default(),
        repo: RepoName::new("relay-capacity").unwrap(),
        shard_ref: "refs/heads/main".into(),
    }
}

#[test]
fn sql_soft_limit_reserves_space_for_guarded_relay_scan_progress() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let uncapped = SqlKvStore::open(conn.clone()).unwrap();
    let source = source();
    let queued = keys::relay(1);
    let row = Value::new(b"queued relay".to_vec());
    assert_eq!(
        block_on(uncapped.apply(&source, Batch::new().put(queued.clone(), row.clone()))).unwrap(),
        BatchOutcome::Committed
    );
    drop(uncapped);

    // A zero soft limit makes every ordinary put Full; the engine still has
    // its hard-limit reserve for bounded relay progress and source cleanup.
    let capped =
        SqlKvStore::open_with_capacity(conn, Capacity::new(1 << 20).with_reserve(1 << 20)).unwrap();
    assert!(matches!(
        block_on(capped.apply(
            &source,
            Batch::new().put(Key::new(b"other".to_vec()), Value::default())
        )),
        Err(StoreError::Full)
    ));
    let rs = keys::relay_scan();
    let first = codec::encode_relay_scan(&codec::RelayScanV1 {
        cycle_end: 2,
        cursor: 1,
        blocked: vec![Partition::ContentShard(0)],
    })
    .unwrap();
    let second = codec::encode_relay_scan(&codec::RelayScanV1 {
        cycle_end: 2,
        cursor: 2,
        blocked: vec![Partition::ContentShard(0)],
    })
    .unwrap();
    assert_eq!(
        block_on(
            capped.apply(
                &source,
                Batch::new()
                    .require(Precondition::Absent(rs.clone()))
                    .put(rs.clone(), first.clone())
            )
        )
        .unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(
        block_on(
            capped.apply(
                &source,
                Batch::new()
                    .require(Precondition::Equals(rs.clone(), first))
                    .require(Precondition::Equals(queued.clone(), row))
                    .put(rs.clone(), second.clone())
                    .delete(queued.clone())
            )
        )
        .unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(block_on(capped.get(&source, &queued)).unwrap(), None);
    assert_eq!(block_on(capped.get(&source, &rs)).unwrap(), Some(second));

    // A caller cannot use an unguarded rs put or mix it with an unrelated put
    // to bypass the soft limit.
    assert!(matches!(
        block_on(capped.apply(&source, Batch::new().put(rs.clone(), Value::default()))),
        Err(StoreError::Full)
    ));
    assert!(matches!(
        block_on(
            capped.apply(
                &source,
                Batch::new()
                    .require(Precondition::Present(rs.clone()))
                    .put(rs, Value::default())
                    .put(Key::new(b"other".to_vec()), Value::default())
            )
        ),
        Err(StoreError::Full)
    ));
}

#[test]
fn sql_soft_limit_reserves_space_for_guarded_relay_timer_reschedule() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let source = source();
    let old_timer = keys::timer(1, 3, b"");
    let uncapped = SqlKvStore::open(conn.clone()).unwrap();
    assert_eq!(
        block_on(uncapped.apply(
            &source,
            Batch::new().put(old_timer.clone(), Value::default())
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
    drop(uncapped);
    let capped =
        SqlKvStore::open_with_capacity(conn, Capacity::new(1 << 20).with_reserve(1 << 20)).unwrap();
    let next_timer = keys::timer(2, 3, b"");
    let next_value = Value::default();
    assert_eq!(
        block_on(
            capped.apply(
                &source,
                Batch::new()
                    .require(Precondition::Equals(old_timer.clone(), Value::default()))
                    .delete(old_timer.clone())
                    .put(next_timer.clone(), next_value.clone())
            )
        )
        .unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(block_on(capped.get(&source, &old_timer)).unwrap(), None);
    assert_eq!(
        block_on(capped.get(&source, &next_timer)).unwrap(),
        Some(next_value)
    );
    assert!(matches!(
        block_on(
            capped.apply(
                &source,
                Batch::new()
                    .require(Precondition::Equals(next_timer.clone(), Value::default()))
                    .delete(next_timer)
                    .put(keys::timer(3, 2, b""), codec::encode_u64(2))
            )
        ),
        Err(StoreError::Full)
    ));
}
