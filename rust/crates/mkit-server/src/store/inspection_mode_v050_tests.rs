#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("inspection-enabled");
    assert_eq!(compare(&expected, true), Outcome::Ok);
    assert_eq!(compare(&expected, false), Outcome::Disabled);
}
