#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("publication-recheck");
    let row = Progress::decode(&expected).unwrap();
    assert_eq!(row.position, 2);
    assert_eq!(row.encode(), expected);
}
