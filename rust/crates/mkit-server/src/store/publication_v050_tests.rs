#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Advance, "store-publication-Advance");
    let expected = crate::stored_golden::row_fixture!("store-publication-Advance", b"\x01");
    let row: Advance = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-cleared");
    let _ = crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-held");
    let _ = crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-hit");
    let _ = crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-pending");
    let _ = crate::stored_golden::json_fixture!(Clearance, "store-publication-Clearance-resolved");
    let _ = crate::stored_golden::json_fixture!(Obligation, "store-publication-Obligation");
    let expected = crate::stored_golden::row_fixture!("store-publication-Obligation", b"\x01");
    let row: Obligation = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Pair, "store-publication-Pair");
    let expected = crate::stored_golden::row_fixture!("store-publication-Pair", b"\x01");
    let row: Pair = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
    let _ = crate::stored_golden::json_fixture!(Publication, "store-publication-Publication");
    let expected = crate::stored_golden::row_fixture!("store-publication-Publication", b"\x01");
    let row: Publication = decode(&expected).unwrap();
    assert_eq!(encode(&row).unwrap(), expected);
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for expected in [
        hex_fixture!("witness-0-0"),
        hex_fixture!("witness-0-1"),
        hex_fixture!("witness-1-0"),
        hex_fixture!("witness-1-1"),
    ] {
        assert_eq!(Witness::decode(&expected).unwrap().encode(), expected);
    }
    let row = Witness::decode(&hex_fixture!("immediate-membership")).unwrap();
    assert!(row.published && !row.held);
    assert_eq!((row.generation, row.sequence), (0, 0));
}
