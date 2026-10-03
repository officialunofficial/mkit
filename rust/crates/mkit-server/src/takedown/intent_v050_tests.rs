#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Draft, "takedown-intent-Draft");
    let expected = crate::stored_golden::row_fixture!("takedown-intent-Draft", b"");
    let row: Draft = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Record, "takedown-intent-Record");
    let expected = crate::stored_golden::row_fixture!("takedown-intent-Record", b"");
    let row: Record = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Reference, "takedown-intent-Reference");
}
