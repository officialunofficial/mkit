#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("outcome-timer");
    let (attempt, cursor) = decode_timer(&expected).unwrap();
    assert_eq!(attempt, 2);
    assert_eq!(encode_timer(attempt, cursor.as_ref()).unwrap(), expected);
    assert_eq!(
        decode_timer(&hex_fixture!("outcome-timer-start")).unwrap(),
        (0, None)
    );
}
