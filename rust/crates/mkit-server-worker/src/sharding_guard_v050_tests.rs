#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for (mode, expected) in [
        (Sharding::Single, hex_fixture!("sharding-single")),
        (Sharding::D34, hex_fixture!("sharding-d34")),
    ] {
        assert_eq!(mode_name(mode).as_bytes(), expected.as_bytes());
        assert_eq!(compare(&expected, mode), Outcome::Ok);
    }
    for (mode, expected) in [
        (AddressingMode::Single, hex_fixture!("addressing-single")),
        (AddressingMode::Multi, hex_fixture!("addressing-multi")),
    ] {
        assert_eq!(mode.name().as_bytes(), expected.as_bytes());
        assert_eq!(compare_addressing(&expected, mode), Outcome::Ok);
    }
}
