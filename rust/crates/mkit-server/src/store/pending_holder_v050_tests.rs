#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("pending-holder");
    let row = PendingHolderV1::decode(&expected).unwrap();
    assert_eq!(row.object, [2; 32]);
    assert_eq!(row.encode().unwrap(), expected);
}
