#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    for expected in [
        crate::stored_golden::row_fixture!("takedown-denial-ActionsV2", b""),
        crate::stored_golden::row_fixture!("takedown-denial-ActionsV2-populated", b""),
    ] {
        let rows = decode_actions(Some(&expected)).unwrap();
        assert_eq!(encode_actions(rows).unwrap(), expected);
    }
    let _ = crate::stored_golden::json_fixture!(ActionsV2, "takedown-denial-ActionsV2");
    let _ = crate::stored_golden::json_fixture!(BlockAction, "takedown-denial-BlockAction");
    let _ = crate::stored_golden::json_fixture!(ChunkPage, "takedown-denial-ChunkPage");
    let _ = crate::stored_golden::json_fixture!(StoredAction, "takedown-denial-StoredAction");
}
