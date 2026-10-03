#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("denial-pointer");
    assert_eq!(value(&[1; 32]), expected);
    let page = ScanPage {
        entries: vec![(key(&[1; 32]), expected)],
        next: None,
    };
    validate_page(0, &page).unwrap();
}
