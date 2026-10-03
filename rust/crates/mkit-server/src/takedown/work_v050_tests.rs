#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(ObjectInfo, "takedown-work-ObjectInfo");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Acquire");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Closure");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Discover");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Purged");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Purging");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Retain");
    let _ = crate::stored_golden::json_fixture!(Phase, "takedown-work-Phase-Seed");
    let _ = crate::stored_golden::json_fixture!(State, "takedown-work-State");
    let _ = crate::stored_golden::json_fixture!(
        Verification,
        "takedown-work-Verification-CanonicalPending"
    );
    let _ = crate::stored_golden::json_fixture!(
        Verification,
        "takedown-work-Verification-ManifestClosurePending"
    );
    let _ = crate::stored_golden::json_fixture!(
        Verification,
        "takedown-work-Verification-SourceCorrupt"
    );
    let _ =
        crate::stored_golden::json_fixture!(Verification, "takedown-work-Verification-Verified");
}
