#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_stored_encodings() {
    for (expected, dirty) in [
        (
            crate::stored_golden::hex_fixture!("published-view-State-clean"),
            false,
        ),
        (
            crate::stored_golden::hex_fixture!("published-view-State-dirty"),
            true,
        ),
    ] {
        let state = State::decode(&expected).unwrap();
        assert_eq!(state.generation, 2);
        assert_eq!(state.dirty, dirty);
        assert_eq!(state.due, 1000);
        assert_eq!(state.last_success, 900);
        assert_eq!(state.encode(), expected);
    }
}
