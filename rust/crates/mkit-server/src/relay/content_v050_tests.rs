#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_stored_encodings() {
    for (expected, ready) in [
        (
            crate::stored_golden::hex_fixture!("relay-ContentTakedownV1-pending"),
            None,
        ),
        (
            crate::stored_golden::hex_fixture!("relay-ContentTakedownV1-ready"),
            Some(6),
        ),
    ] {
        let row = ContentTakedownV1::decode(&expected).unwrap();
        assert_eq!(row.queued_at_ms, 5);
        assert_eq!(row.ready_at_ms, ready);
        assert_eq!(row.encode().unwrap(), expected);
    }
}
