#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Frame, "indexed-job-extraction-member-Frame");
    let expected =
        crate::stored_golden::row_fixture!("indexed-job-extraction-member-Frame", b"\x01");
    let row: Frame =
        decode(&expected).unwrap_or_else(|_| panic!("stored row failed decoding or encoding"));
    assert_eq!(
        encode(&row).unwrap_or_else(|_| panic!("stored row failed decoding or encoding")),
        expected
    );
    let _ = crate::stored_golden::json_fixture!(Lookup, "indexed-job-extraction-member-Lookup");
    let expected =
        crate::stored_golden::row_fixture!("indexed-job-extraction-member-Lookup", b"\x01");
    let row: Lookup =
        decode(&expected).unwrap_or_else(|_| panic!("stored row failed decoding or encoding"));
    assert_eq!(
        encode(&row).unwrap_or_else(|_| panic!("stored row failed decoding or encoding")),
        expected
    );
}
