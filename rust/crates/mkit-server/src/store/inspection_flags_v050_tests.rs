#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(FlagSource, "store-inspection_flags-FlagSource");
    let _ =
        crate::stored_golden::json_fixture!(FlagState, "store-inspection_flags-FlagState-flagged");
    let _ =
        crate::stored_golden::json_fixture!(FlagState, "store-inspection_flags-FlagState-released");
}
#[test]
fn v050_binary_rows() {
    for body in [
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stored-v0.5.0/store-inspection_flags-FlagV1-Flagged.json"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stored-v0.5.0/store-inspection_flags-FlagV1-Released.json"
        ))
        .as_slice(),
    ] {
        let expected = crate::stored_golden::value(body, b"\x01");
        let row = decode_flag(&expected).unwrap();
        assert_eq!(encode_flag(&row).unwrap(), expected);
    }
}
