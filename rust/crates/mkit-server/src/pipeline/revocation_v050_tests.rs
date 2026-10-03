use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(
        RevokeCheckpoint,
        "pipeline-revocation-RevokeCheckpoint"
    );
}
