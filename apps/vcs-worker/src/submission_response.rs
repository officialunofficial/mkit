// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact bounded JSON response shapes shared by native vectors and Worker.

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Progress {
    pub inventory_entries: String,
    pub base_objects: String,
    pub changed_pairs: String,
    pub required_objects: String,
    pub candidate_objects: String,
    pub attempts: String,
    pub reserved_io_bytes: String,
    pub r2_operations: String,
}
impl Progress {
    pub(crate) fn checked(&self) -> bool {
        [
            &self.inventory_entries,
            &self.base_objects,
            &self.changed_pairs,
            &self.required_objects,
            &self.candidate_objects,
            &self.attempts,
            &self.reserved_io_bytes,
            &self.r2_operations,
        ]
        .into_iter()
        .all(|value| crate::access_policy::generation(value).is_ok())
    }
    pub(crate) fn zero() -> Self {
        Self {
            inventory_entries: "0".into(),
            base_objects: "0".into(),
            changed_pairs: "0".into(),
            required_objects: "0".into(),
            candidate_objects: "0".into(),
            attempts: "0".into(),
            reserved_io_bytes: "0".into(),
            r2_operations: "0".into(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct SubmissionReply {
    pub version: u8,
    pub operation_id: String,
    pub submission_id: String,
    pub submission_generation: String,
    pub revision: String,
    pub state: String,
    pub progress: Progress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct CleanupReply {
    pub version: u8,
    pub cleanup_revision: String,
    pub affected_rows: String,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected(name: &str) -> String {
        std::fs::read_to_string(format!("../../rust/tests/golden/hosted-submissions/{name}"))
            .unwrap()
            .trim_end()
            .to_owned()
    }
    #[test]
    fn producer_serialization_matches_committed_response_vectors() {
        for (name, state, revision) in [
            ("begin-response.json", "awaiting_upload", "0"),
            ("get-response.json", "awaiting_upload", "0"),
            ("continue-response.json", "validating", "1"),
        ] {
            let actual = SubmissionReply {
                version: 1,
                operation_id: "3".repeat(64),
                submission_id: "4".repeat(64),
                submission_generation: "1".into(),
                revision: revision.into(),
                state: state.into(),
                progress: Progress::zero(),
                code: None,
            };
            assert!(actual.progress.checked());
            assert_eq!(
                serde_json::to_string(&actual).unwrap(),
                expected(name),
                "{name}"
            );
        }
        let cleanup = CleanupReply {
            version: 1,
            cleanup_revision: "1".into(),
            affected_rows: "0".into(),
            has_more: false,
        };
        assert_eq!(
            serde_json::to_string(&cleanup).unwrap(),
            expected("cleanup-response.json")
        );
    }
}
