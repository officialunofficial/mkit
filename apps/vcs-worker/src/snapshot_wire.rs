// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only, raw-body-signed hosted Snapshot job wire.
//! Parsing accepts ordinary JSON key order while rejecting duplicate fields.

use serde::{Deserialize, Serialize};

use crate::{access_policy::generation, refs::is_valid_ref_name};

pub const MAX_SNAPSHOT_BODY: usize = 64 * 1024;
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
}
