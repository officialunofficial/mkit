#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for expected in [hex_fixture!("hold-pending"), hex_fixture!("hold-complete")] {
        validate_advance_hold(&expected).unwrap();
    }
    for expected in [hex_fixture!("hold-manifest"), hex_fixture!("hold-released")] {
        let row = decode_manifest(Some(&expected)).unwrap();
        assert_eq!(encode_manifest_state(&row.ids, row.released), expected);
    }
}
