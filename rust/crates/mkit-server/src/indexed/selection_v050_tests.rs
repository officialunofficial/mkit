#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ =
        crate::stored_golden::json_fixture!(SelectionFact, "indexed-selection-SelectionFact-Blob");
    let _ = crate::stored_golden::json_fixture!(
        SelectionFact,
        "indexed-selection-SelectionFact-Manifest"
    );
    let _ =
        crate::stored_golden::json_fixture!(SelectionFact, "indexed-selection-SelectionFact-Other");
    let _ =
        crate::stored_golden::json_fixture!(SelectionFact, "indexed-selection-SelectionFact-Tree");
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for expected in [
        hex_fixture!("selection-projection-0"),
        hex_fixture!("selection-projection-1"),
        hex_fixture!("selection-projection-2"),
        hex_fixture!("selection-projection-3"),
    ] {
        let row = Projection::decode(&[1; 32], &expected).unwrap();
        assert_eq!(row.encode(), expected);
        if row.kind == 1 {
            let page = hex_fixture!("selection-page");
            let ids: Vec<_> = row.decode_page(0, &page).unwrap().collect();
            assert_eq!(row.encode_page(0, &ids), page);
        }
    }
}
