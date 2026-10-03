#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-0");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-0", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-1");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-1", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-2");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-2", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-3");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-3", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-4");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-4", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-5");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-5", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Entry, "takedown-inventory-Entry-7");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Entry-7", b"");
    let row: Entry = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Head, "takedown-inventory-Head");
    let expected = crate::stored_golden::row_fixture!("takedown-inventory-Head", b"");
    let row: Head = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ =
        crate::stored_golden::json_fixture!(InventoryCursor, "takedown-inventory-InventoryCursor");
    let _ = crate::stored_golden::json_fixture!(PacklistFacts, "takedown-inventory-PacklistFacts");
}
#[test]
fn v050_binary_rows() {
    use futures_executor::block_on;
    let store = crate::MemoryKv::default();
    let pack = [1; 32];
    let raw = crate::stored_golden::row_fixture!("takedown-inventory-Head-sealed", b"");
    block_on(store.apply(
        &content_shard(&pack),
        Batch::new().put(head_key(&pack), raw.clone()),
    ))
    .unwrap();
    assert_eq!(
        block_on(seal(&store, &pack)).unwrap(),
        mkit_core::hash::hash(raw.as_bytes())
    );
    for (kind, body) in [
        (
            0,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-0.json"
            ))
            .as_slice(),
        ),
        (
            1,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-1.json"
            ))
            .as_slice(),
        ),
        (
            2,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-2.json"
            ))
            .as_slice(),
        ),
        (
            3,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-3.json"
            ))
            .as_slice(),
        ),
        (
            4,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-4.json"
            ))
            .as_slice(),
        ),
        (
            5,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-5.json"
            ))
            .as_slice(),
        ),
        (
            7,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/stored-v0.5.0/takedown-inventory-Entry-7.json"
            ))
            .as_slice(),
        ),
    ] {
        let id = [kind; 32];
        let raw = Value::new(body.to_vec());
        block_on(store.apply(
            &content_shard(&pack),
            Batch::new().put(entry_key(&pack, &id), raw.clone()).put(
                marker_key(&pack, &id),
                Value::new(entry_digest(&id, &raw).to_vec()),
            ),
        ))
        .unwrap();
        assert_eq!(
            block_on(entry(&store, &pack, &id)).unwrap().unwrap().kind,
            kind
        );
    }
}
