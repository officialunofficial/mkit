#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ =
        crate::stored_golden::json_fixture!(VerificationV1, "indexed-state-VerificationV1-pending");
    let expected =
        crate::stored_golden::row_fixture!("indexed-state-VerificationV1-pending", b"\x01");
    let row = decode(&expected).unwrap();
    assert_eq!(encode(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        VerificationV1,
        "indexed-state-VerificationV1-rejected"
    );
    let expected =
        crate::stored_golden::row_fixture!("indexed-state-VerificationV1-rejected", b"\x01");
    let row = decode(&expected).unwrap();
    assert_eq!(encode(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        VerificationV1,
        "indexed-state-VerificationV1-verified"
    );
    let expected =
        crate::stored_golden::row_fixture!("indexed-state-VerificationV1-verified", b"\x01");
    let row = decode(&expected).unwrap();
    assert_eq!(encode(&row), expected);
    let _ = crate::stored_golden::json_fixture!(
        VerificationV1,
        "indexed-state-VerificationV1-verified-publication"
    );
    let expected = crate::stored_golden::row_fixture!(
        "indexed-state-VerificationV1-verified-publication",
        b"\x01"
    );
    let row = decode(&expected).unwrap();
    assert_eq!(encode(&row), expected);
}
