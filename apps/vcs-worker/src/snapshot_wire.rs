// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only, raw-body-signed hosted Snapshot job wire.
//! Parsing accepts ordinary JSON key order while rejecting duplicate fields.

use mkit_core::partial::PartialPath;
#[cfg(any(test, target_arch = "wasm32"))]
use mkit_core::partial::PartialError;
use serde::{Deserialize, Serialize};

use crate::{access_policy::generation, refs::is_valid_ref_name};

pub const MAX_SNAPSHOT_BODY: usize = 64 * 1024;
pub const MAX_DISCLOSURE_BODY: usize = 256 * 1024;
pub const MAX_SELECTED_PACKS: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginSnapshot {
    pub version: u8,
    pub job_id: String,
    pub r#ref: String,
    pub expected_head: String,
    pub expected_packmap: String,
    pub selected_pack_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinueSnapshot {
    pub version: u8,
    pub job_id: String,
    pub job_generation: String,
    pub expected_revision: String,
}

pub type CancelSnapshot = ContinueSnapshot;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetSnapshotJob {
    pub version: u8,
    pub job_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupSnapshots {
    pub version: u8,
    pub expected_cleanup_revision: String,
    pub max_rows: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobProgress {
    pub catalog_packs: String,
    pub catalog_entries: String,
    pub reached_objects: String,
    pub reached_bytes: String,
    pub work_units: String,
    pub attempts: String,
    pub reserved_io_bytes: String,
    pub r2_operations: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobReply {
    pub version: u8,
    pub job_id: String,
    pub job_generation: String,
    pub revision: String,
    pub state: String,
    pub progress: JobProgress,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupReply {
    pub version: u8,
    pub cleanup_revision: String,
    pub affected_rows: String,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingReply {
    pub version: u8,
    pub code: &'static str,
    pub job_id: String,
}

/// Subject-only private selection; the signed body is parsed again inside RefStore.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetWorkspace {
    pub version: u8,
    pub workspace_id: String,
    pub grant_id: String,
    pub grant_generation: String,
    pub expected_ref: String,
    pub expected_base: String,
    pub paths: Vec<Vec<String>>,
}

impl GetWorkspace {
    pub fn checked_paths(&self) -> Option<Vec<PartialPath>> {
        if self.version != 1
            || !id(&self.workspace_id)
            || !id(&self.grant_id)
            || !id(&self.expected_base)
            || generation(&self.grant_generation).is_err()
            || !self.expected_ref.starts_with("refs/heads/")
            || !is_valid_ref_name(&self.expected_ref)
            || self.paths.is_empty()
            || self.paths.len() > 256
        {
            return None;
        }
        Some(
            self.paths
                .iter()
                .map(|path| path.iter().map(|part| part.as_bytes().to_vec()).collect())
                .collect(),
        )
    }
}

pub fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl BeginSnapshot {
    pub fn validate(&self) -> bool {
        if self.version != 1
            || !id(&self.job_id)
            || self.job_id.bytes().all(|byte| byte == b'0')
            || !id(&self.expected_head)
            || !id(&self.expected_packmap)
            || self.r#ref.len() > 1024
            || !self.r#ref.starts_with("refs/heads/")
            || !is_valid_ref_name(&self.r#ref)
            || !(1..=MAX_SELECTED_PACKS).contains(&self.selected_pack_keys.len())
        {
            return false;
        }
        let mut previous = "";
        for key in &self.selected_pack_keys {
            if !id(key) || key.as_str() <= previous {
                return false;
            }
            previous = key;
        }
        true
    }

    pub fn packmap_ref(&self) -> String {
        format!("refs/mkit/packmap/{}", &self.r#ref["refs/heads/".len()..])
    }
}

impl ContinueSnapshot {
    pub fn validate(&self) -> bool {
        self.version == 1
            && id(&self.job_id)
            && generation(&self.job_generation).is_ok_and(|n| n > 0)
            && generation(&self.expected_revision).is_ok()
    }
}

impl GetSnapshotJob {
    pub fn validate(&self) -> bool {
        self.version == 1 && id(&self.job_id)
    }
}

impl CleanupSnapshots {
    pub fn validate(&self) -> bool {
        self.version == 1
            && generation(&self.expected_cleanup_revision).is_ok()
            && (1..=64).contains(&self.max_rows)
    }
}

pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, &'static str> {
    if body.len() > MAX_SNAPSHOT_BODY {
        return Err("snapshot body too large");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut deserializer).map_err(|_| "invalid snapshot JSON")?;
    deserializer.end().map_err(|_| "trailing snapshot JSON")?;
    Ok(value)
}

pub fn decode_disclosure(body: &[u8]) -> Result<GetWorkspace, &'static str> {
    if body.len() > MAX_DISCLOSURE_BODY {
        return Err("disclosure body too large");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value =
        GetWorkspace::deserialize(&mut deserializer).map_err(|_| "invalid disclosure JSON")?;
    deserializer.end().map_err(|_| "trailing disclosure JSON")?;
    Ok(value)
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn disclosure_builder_failure(error: &PartialError) -> (u16, &'static str) {
    match error {
        PartialError::WitnessTooLarge
        | PartialError::WorkspaceTooLarge
        | PartialError::ValidationBudgetExceeded => (429, "resource_exhausted"),
        PartialError::InvalidPath => (400, "invalid_argument"),
        PartialError::IncompleteSelection | PartialError::UnsupportedPartialOperation => {
            (422, "unsupported_profile")
        }
        _ => (503, "unavailable"),
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn disclosure_fence_failure(
    expired: bool,
    current: bool,
) -> Option<(u16, &'static str)> {
    if expired {
        Some((503, "unavailable"))
    } else if !current {
        Some((409, "conflict"))
    } else {
        None
    }
}

/// Buffer no more than the exact durable HEAD reservation, even if the
/// enclosing hosted profile would permit a larger object.
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn append_reserved(
    bytes: &mut Vec<u8>,
    part: &[u8],
    reserved_len: usize,
) -> Result<(), ()> {
    if part.len() > reserved_len.checked_sub(bytes.len()).ok_or(())? {
        return Err(());
    }
    bytes.extend_from_slice(part);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::{
        hash::from_hex,
        partial::{PartialLimits, PartialSnapshotBuilder, verify_partial_snapshot},
    };

    #[test]
    fn request_rejects_duplicate_unknown_and_noncanonical_fields() {
        let job_id = "1".repeat(64);
        let body = format!("{{\"version\":1,\"job_id\":\"{job_id}\",\"job_id\":\"{job_id}\"}}");
        assert!(decode::<GetSnapshotJob>(body.as_bytes()).is_err());
        let body = format!("{{\"version\":1,\"job_id\":\"{job_id}\",\"extra\":0}}");
        assert!(decode::<GetSnapshotJob>(body.as_bytes()).is_err());
        let body = format!("{{\"job_id\":\"{job_id}\",\"version\":1}} ");
        assert!(
            decode::<GetSnapshotJob>(body.as_bytes())
                .unwrap()
                .validate()
        );
        assert!(!id(&"A".repeat(64)));
        assert!(!id(&"1".repeat(63)));
        assert!(
            !ContinueSnapshot {
                version: 1,
                job_id,
                job_generation: "01".into(),
                expected_revision: "0".into()
            }
            .validate()
        );
    }

    #[test]
    fn streamed_get_never_retains_more_than_head_reservation() {
        let mut bytes = Vec::new();
        append_reserved(&mut bytes, b"ab", 3).unwrap();
        assert!(append_reserved(&mut bytes, b"cd", 3).is_err());
        assert_eq!(bytes, b"ab");
        append_reserved(&mut bytes, b"c", 3).unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn committed_subject_http_vectors_are_exact_and_strict() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rust/tests/golden/hosted-disclosure");
        let manifest = std::fs::read_to_string(root.join("MANIFEST.txt")).unwrap();
        let mut names = std::collections::BTreeSet::new();
        for line in manifest.lines().filter(|line| !line.starts_with('#')) {
            let (digest, name) = line.split_once("  ").unwrap();
            assert!(names.insert(name));
            let body = std::fs::read(root.join(name)).unwrap();
            assert_eq!(crate::hashing::blake3_hex(&body), digest, "{name}");
            assert!(body.ends_with(b"\n"));
        }
        assert_eq!(names.len(), 13);
        let parse = |name: &str| {
            let bytes = std::fs::read(root.join(name)).unwrap();
            decode_disclosure(&bytes).ok()
        };
        assert!(parse("get.json").unwrap().checked_paths().is_some());
        assert!(parse("wrong-base.json").unwrap().checked_paths().is_some());
        let duplicate_paths = parse("duplicate-path.json")
            .unwrap()
            .checked_paths()
            .unwrap();
        assert!(parse("duplicate-field.json").is_none());
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("get.meta.json")).unwrap()).unwrap();
        assert_eq!(meta["path"], "/mkit/partial/v1/GetWorkspace");
        assert_eq!(meta["status"], 200);
        let bundle = std::fs::read(root.join(meta["response_ref"].as_str().unwrap())).unwrap();
        assert_eq!(
            bundle.len(),
            meta["response_length"].as_u64().unwrap() as usize
        );
        assert_eq!(
            crate::hashing::blake3_hex(&bundle),
            meta["response_digest"].as_str().unwrap()
        );
        let base =
            from_hex("17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90").unwrap();
        let paths = vec![vec![b"shallow.txt".to_vec()]];
        let limits = PartialLimits {
            max_bundle_bytes: 4 * 1024 * 1024,
            max_witness_bytes: 1024 * 1024,
            max_total_selected_bytes: 1024 * 1024,
            max_selected_file_bytes: 256 * 1024,
            max_objects: 2_048,
            max_tree_visits: 2_048,
            max_base_object_bytes: 2 * 1024 * 1024,
            max_tree_object_bytes: 2 * 1024 * 1024,
            max_object_bytes: 2 * 1024 * 1024,
            ..PartialLimits::V1
        };
        assert!(PartialSnapshotBuilder::new(base, &duplicate_paths, &limits).is_err());
        assert!(verify_partial_snapshot(base, &paths, &bundle, &limits).is_ok());
    }

    #[test]
    fn disclosure_error_mapping_preserves_resource_and_deadline_codes() {
        assert_eq!(
            disclosure_fence_failure(true, true),
            Some((503, "unavailable"))
        );
        assert_eq!(
            disclosure_fence_failure(false, false),
            Some((409, "conflict"))
        );
        assert_eq!(disclosure_fence_failure(false, true), None);
        assert_eq!(
            disclosure_builder_failure(&PartialError::WorkspaceTooLarge),
            (429, "resource_exhausted")
        );
        assert_eq!(
            disclosure_builder_failure(&PartialError::WitnessTooLarge),
            (429, "resource_exhausted")
        );
        assert_eq!(
            disclosure_builder_failure(&PartialError::UnsupportedPartialOperation),
            (422, "unsupported_profile")
        );
    }
}
