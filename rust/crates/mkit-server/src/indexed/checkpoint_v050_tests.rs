#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(
        ExtractionGroupMember,
        "indexed-checkpoint-ExtractionGroupMember"
    );
    let _ = crate::stored_golden::json_fixture!(
        ExtractionSource,
        "indexed-checkpoint-ExtractionSource"
    );
    let _ = crate::stored_golden::json_fixture!(ExtractionV1, "indexed-checkpoint-ExtractionV1");
    let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-pack");
    let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-packlist");
    let _ = crate::stored_golden::json_fixture!(Kind, "indexed-checkpoint-Kind-unknown");
    let _ = crate::stored_golden::json_fixture!(MemberCursor, "indexed-checkpoint-MemberCursor");
    let _ = crate::stored_golden::json_fixture!(MemberLists, "indexed-checkpoint-MemberLists");
    let _ = crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-base_capped");
    let _ = crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-base_missing");
    let _ = crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-blocked");
    let _ =
        crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-closure_capped");
    let _ =
        crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-closure_missing");
    let _ =
        crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-decode_budget");
    let _ = crate::stored_golden::json_fixture!(
        Outcome,
        "indexed-checkpoint-Outcome-external_too_deep"
    );
    let _ = crate::stored_golden::json_fixture!(
        Outcome,
        "indexed-checkpoint-Outcome-extraction_unavailable"
    );
    let _ =
        crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-object_blocked");
    let _ = crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-open_closure");
    let _ =
        crate::stored_golden::json_fixture!(Outcome, "indexed-checkpoint-Outcome-packlist_missing");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-await_delivery");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-closure_resolve");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-decode");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-emit_index");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-extract");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-recheck");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-verify");
    let _ = crate::stored_golden::json_fixture!(Phase, "indexed-checkpoint-Phase-watch");
    let _ = crate::stored_golden::json_fixture!(VerifyJobV1, "indexed-checkpoint-VerifyJobV1");
    let expected = crate::stored_golden::row_fixture!("indexed-checkpoint-VerifyJobV1", b"\x01");
    let row = decode_job(&expected).unwrap();
    assert_eq!(encode_job(&row), expected);
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    for expected in [
        hex_fixture!("verification-frame"),
        hex_fixture!("verification-frame-external"),
    ] {
        let row = decode_frame(&[1; 32], &expected).unwrap();
        assert_eq!(encode_frame(&[1; 32], &row).unwrap(), expected);
    }
    let expected = hex_fixture!("verification-base");
    assert_eq!(encode_base(&decode_base(&expected).unwrap()), expected);
    let expected = hex_fixture!("window-cursor");
    assert_eq!(
        mkit_core::pack::window::WindowCursor::from_bytes(expected.as_bytes())
            .unwrap()
            .to_bytes(),
        expected.as_bytes()
    );
}
