#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Checkpoint, "takedown-source-Checkpoint");
    let _ = crate::stored_golden::json_fixture!(Frame, "takedown-source-Frame");
    let _ = crate::stored_golden::json_fixture!(Lookup, "takedown-source-Lookup");
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    let expected = hex_fixture!("preservation-source-frame");
    let (id, located) = decode_frame(&expected).unwrap();
    let row = Frame {
        id,
        pack: located.pack,
        index: codec::encode_object_index(&id, &located.value)
            .unwrap()
            .as_bytes()
            .to_vec(),
    };
    assert_eq!(row.encode_row().unwrap(), expected);
}
