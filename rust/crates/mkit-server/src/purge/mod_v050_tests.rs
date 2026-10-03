#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Request, "purge-Request");
    let _ = crate::stored_golden::json_fixture!(
        Trigger,
        "purge-Trigger-CACHE_PURGE_TRIGGER_LEASE_DELETION"
    );
    let _ =
        crate::stored_golden::json_fixture!(Trigger, "purge-Trigger-CACHE_PURGE_TRIGGER_MANUAL");
    let _ = crate::stored_golden::json_fixture!(
        Trigger,
        "purge-Trigger-CACHE_PURGE_TRIGGER_SUSPENSION"
    );
    let _ =
        crate::stored_golden::json_fixture!(Trigger, "purge-Trigger-CACHE_PURGE_TRIGGER_TAKEDOWN");
    let _ = crate::stored_golden::json_fixture!(
        Trigger,
        "purge-Trigger-CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE"
    );
}
