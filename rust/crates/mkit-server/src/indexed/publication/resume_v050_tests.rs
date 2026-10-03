#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ =
        crate::stored_golden::json_fixture!(BaseCursor, "indexed-publication-resume-BaseCursor");
    let _ = crate::stored_golden::json_fixture!(
        Exhaustion,
        "indexed-publication-resume-Exhaustion-DecodeBudget"
    );
    let _ = crate::stored_golden::json_fixture!(
        Exhaustion,
        "indexed-publication-resume-Exhaustion-IndexCalls"
    );
    let _ = crate::stored_golden::json_fixture!(
        Exhaustion,
        "indexed-publication-resume-Exhaustion-Traversal"
    );
    let _ = crate::stored_golden::json_fixture!(Progress, "indexed-publication-resume-Progress");
    let _ = crate::stored_golden::json_fixture!(
        TerminalFailure,
        "indexed-publication-resume-TerminalFailure-DeltaDepth"
    );
    let _ = crate::stored_golden::json_fixture!(
        TerminalFailure,
        "indexed-publication-resume-TerminalFailure-OpenClosure"
    );
}
