#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Head, "admin-ledger-Head");
    let expected = crate::stored_golden::row_fixture!("admin-ledger-Head", b"");
    let row: Head = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Nonce, "admin-ledger-Nonce");
    let expected = crate::stored_golden::row_fixture!("admin-ledger-Nonce", b"");
    let row: Nonce = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Operation, "admin-ledger-Operation");
    let expected = crate::stored_golden::row_fixture!("admin-ledger-Operation", b"");
    let row: Operation = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
}
