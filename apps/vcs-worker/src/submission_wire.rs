// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict service-only wire primitives for hosted staged submissions.
//!
//! This module parses bounded request bytes and the private MKSU carrier. It
//! does not authenticate callers, validate MKWU contents, or authorize work.

use mkit_core::{
    hash::{Hash, Hasher, from_hex},
    partial::{PartialLimits, PartialPath, PartialSnapshotBuilder},
    refs::validate_ref_name,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{access_policy::generation, snapshot_wire::id};

pub const MAX_BEGIN_BODY: usize = 256 * 1024;
pub const MAX_REQUEST_BODY: usize = 64 * 1024;
pub const MAX_UPDATE_BYTES: usize = 4 * 1024 * 1024;
pub const MKSU_PREFIX_LEN: usize = 85;
pub const MAX_UPLOAD_BODY: usize = MAX_UPDATE_BYTES + MKSU_PREFIX_LEN;

const BINDING_DOMAIN: &[u8] = b"mkit/hosted-submission-binding/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionWireError {
    Malformed,
    ResourceExhausted,
}

impl std::fmt::Display for SubmissionWireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed submission wire data",
            Self::ResourceExhausted => "submission wire resource limit exceeded",
        })
    }
}

impl std::error::Error for SubmissionWireError {}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginSubmission {
    pub version: u8,
    pub operation_id: String,
    pub workspace_id: String,
    pub grant_id: String,
    pub grant_generation: String,
    pub expected_ref: String,
    pub expected_base: String,
    pub update_digest: String,
    pub update_len: String,
    pub selected_paths: Vec<Vec<String>>,
}

impl BeginSubmission {
    /// Validate the request grammar and reuse the core path validator for its
    /// joined-byte ordering, component grammar, and portable path ceilings.
    pub fn validate(&self) -> Result<(), SubmissionWireError> {
        let update_len =
            generation(&self.update_len).map_err(|_| SubmissionWireError::Malformed)?;
        if self.version != 1
            || !id(&self.operation_id)
            || !id(&self.workspace_id)
            || !id(&self.grant_id)
            || generation(&self.grant_generation)
                .map(|value| value == 0)
                .unwrap_or(true)
            || !self.expected_ref.starts_with("refs/heads/")
            || self.expected_ref.len() > 1024
            || !validate_ref_name(&self.expected_ref)
            || !id(&self.expected_base)
            || !id(&self.update_digest)
        {
            return Err(SubmissionWireError::Malformed);
        }
        if update_len == 0 {
            return Err(SubmissionWireError::Malformed);
        }
        if update_len > MAX_UPDATE_BYTES as u64 {
            return Err(SubmissionWireError::ResourceExhausted);
        }
        if self.selected_paths.is_empty() || self.selected_paths.len() > 256 {
            return Err(SubmissionWireError::Malformed);
        }
        let base: Hash =
            from_hex(&self.expected_base).map_err(|_| SubmissionWireError::Malformed)?;
        let paths = partial_paths(&self.selected_paths);
        PartialSnapshotBuilder::new(base, &paths, &PartialLimits::V1)
            .map(|_| ())
            .map_err(|_| SubmissionWireError::Malformed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinueSubmission {
    pub version: u8,
    pub operation_id: String,
    pub submission_id: String,
    pub submission_generation: String,
    pub expected_revision: String,
}

impl ContinueSubmission {
    pub fn validate(&self) -> bool {
        self.version == 1
            && id(&self.operation_id)
            && id(&self.submission_id)
            && generation(&self.submission_generation).is_ok_and(|value| value > 0)
            && generation(&self.expected_revision).is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GetStagedSubmission {
    pub version: u8,
    pub operation_id: String,
}

impl GetStagedSubmission {
    pub fn validate(&self) -> bool {
        self.version == 1 && id(&self.operation_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupSubmissions {
    pub version: u8,
    pub expected_cleanup_revision: String,
    pub max_rows: u8,
}

impl CleanupSubmissions {
    pub fn validate(&self) -> bool {
        self.version == 1
            && generation(&self.expected_cleanup_revision).is_ok()
            && (1..=64).contains(&self.max_rows)
    }
}

fn partial_paths(paths: &[Vec<String>]) -> Vec<PartialPath> {
    paths
        .iter()
        .map(|path| {
            path.iter()
                .map(|component| component.as_bytes().to_vec())
                .collect()
        })
        .collect()
}

fn decode_json<T: DeserializeOwned>(body: &[u8], cap: usize) -> Result<T, SubmissionWireError> {
    if body.len() > cap {
        return Err(SubmissionWireError::ResourceExhausted);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut deserializer).map_err(|_| SubmissionWireError::Malformed)?;
    deserializer
        .end()
        .map_err(|_| SubmissionWireError::Malformed)?;
    Ok(value)
}

pub fn decode_begin(body: &[u8]) -> Result<BeginSubmission, SubmissionWireError> {
    let request: BeginSubmission = decode_json(body, MAX_BEGIN_BODY)?;
    request.validate()?;
    Ok(request)
}

pub fn decode_continue(body: &[u8]) -> Result<ContinueSubmission, SubmissionWireError> {
    let request: ContinueSubmission = decode_json(body, MAX_REQUEST_BODY)?;
    request
        .validate()
        .then_some(request)
        .ok_or(SubmissionWireError::Malformed)
}

pub fn decode_get(body: &[u8]) -> Result<GetStagedSubmission, SubmissionWireError> {
    let request: GetStagedSubmission = decode_json(body, MAX_REQUEST_BODY)?;
    request
        .validate()
        .then_some(request)
        .ok_or(SubmissionWireError::Malformed)
}

pub fn decode_cleanup(body: &[u8]) -> Result<CleanupSubmissions, SubmissionWireError> {
    let request: CleanupSubmissions = decode_json(body, MAX_REQUEST_BODY)?;
    request
        .validate()
        .then_some(request)
        .ok_or(SubmissionWireError::Malformed)
}

/// Parsed view of an MKSU carrier. `carrier` borrows the original HTTP body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadSubmission<'a> {
    pub operation_id: [u8; 32],
    pub submission_id: [u8; 32],
    pub generation: u64,
    pub declared_len: u64,
    pub carrier: &'a [u8],
}

pub fn decode_mksu(body: &[u8]) -> Result<UploadSubmission<'_>, SubmissionWireError> {
    if body.len() > MAX_UPLOAD_BODY {
        return Err(SubmissionWireError::ResourceExhausted);
    }
    if body.len() < MKSU_PREFIX_LEN || &body[..4] != b"MKSU" || body[4] != 1 {
        return Err(SubmissionWireError::Malformed);
    }
    let operation_id: [u8; 32] = body[5..37]
        .try_into()
        .map_err(|_| SubmissionWireError::Malformed)?;
    let submission_id: [u8; 32] = body[37..69]
        .try_into()
        .map_err(|_| SubmissionWireError::Malformed)?;
    let generation = u64::from_le_bytes(
        body[69..77]
            .try_into()
            .map_err(|_| SubmissionWireError::Malformed)?,
    );
    let declared_len = u64::from_le_bytes(
        body[77..85]
            .try_into()
            .map_err(|_| SubmissionWireError::Malformed)?,
    );
    if generation == 0 || declared_len == 0 {
        return Err(SubmissionWireError::Malformed);
    }
    if declared_len > MAX_UPDATE_BYTES as u64 {
        return Err(SubmissionWireError::ResourceExhausted);
    }
    let carrier_len =
        usize::try_from(declared_len).map_err(|_| SubmissionWireError::ResourceExhausted)?;
    let expected_len = MKSU_PREFIX_LEN
        .checked_add(carrier_len)
        .ok_or(SubmissionWireError::ResourceExhausted)?;
    if body.len() != expected_len {
        return Err(SubmissionWireError::Malformed);
    }
    Ok(UploadSubmission {
        operation_id,
        submission_id,
        generation,
        declared_len,
        carrier: &body[MKSU_PREFIX_LEN..],
    })
}

/// Bind a validated configured identity and the exact bounded Begin bytes.
/// Identity parsing caps the audience at 512 bytes and repository at 255.
pub fn binding_fingerprint(
    audience: &str,
    repository: &str,
    subject_key: &[u8; 32],
    begin_body: &[u8],
) -> Result<Hash, SubmissionWireError> {
    if audience.len() > 512 || repository.len() > 255 || begin_body.len() > MAX_BEGIN_BODY {
        return Err(SubmissionWireError::ResourceExhausted);
    }
    let mut hasher = Hasher::new();
    hasher.update(BINDING_DOMAIN);
    for value in [audience.as_bytes(), repository.as_bytes()] {
        let len = u32::try_from(value.len()).map_err(|_| SubmissionWireError::ResourceExhausted)?;
        hasher.update(&len.to_le_bytes());
        hasher.update(value);
    }
    hasher.update(subject_key);
    hasher.update(&1u32.to_le_bytes()); // Hosted profile v1.
    hasher.update(&1u32.to_le_bytes()); // Validator v1.
    hasher.update(&mkit_core::hash::hash(begin_body));
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rust/tests/golden/hosted-submissions");
        std::fs::read(root.join(name)).unwrap()
    }

    #[test]
    fn committed_manifest_routes_and_canonical_request_bytes_are_consumed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rust/tests/golden/hosted-submissions");
        let manifest = String::from_utf8(fixture("MANIFEST.txt")).unwrap();
        let expected_files = [
            "begin.json",
            "begin.meta.json",
            "begin-response.json",
            "binding.json",
            "cleanup.json",
            "cleanup.meta.json",
            "cleanup-response.json",
            "continue.json",
            "continue.meta.json",
            "continue-response.json",
            "get.json",
            "get.meta.json",
            "get-response.json",
            "upload.bin",
            "upload.meta.json",
        ];
        for name in expected_files {
            let contents = fixture(name);
            let expected = manifest
                .lines()
                .find_map(|line| {
                    let (digest, listed) = line.split_once("  ")?;
                    (listed == name).then_some(digest)
                })
                .expect("every fixture is pinned by MANIFEST.txt");
            assert_eq!(
                hex::encode(mkit_core::hash::hash(&contents)),
                expected,
                "{name}"
            );
            assert!(root.join(name).is_file());
        }
        assert!(!manifest.contains("BINDING_DIGEST"));

        let begin_bytes = fixture("begin.json");
        let begin = decode_begin(&begin_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&begin).unwrap().as_slice(),
            &begin_bytes[..begin_bytes.len() - 1]
        );
        for (file, decode) in [(
            "continue.json",
            decode_continue as fn(&[u8]) -> Result<ContinueSubmission, SubmissionWireError>,
        )] {
            let bytes = fixture(file);
            let request = decode(&bytes).unwrap();
            assert_eq!(
                serde_json::to_vec(&request).unwrap().as_slice(),
                &bytes[..bytes.len() - 1]
            );
        }
        let get_bytes = fixture("get.json");
        let get = decode_get(&get_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&get).unwrap().as_slice(),
            &get_bytes[..get_bytes.len() - 1]
        );
        let cleanup_bytes = fixture("cleanup.json");
        let cleanup = decode_cleanup(&cleanup_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&cleanup).unwrap().as_slice(),
            &cleanup_bytes[..cleanup_bytes.len() - 1]
        );

        for (file, path) in [
            ("begin.meta.json", "/mkit/partial/v1/BeginSubmission"),
            ("continue.meta.json", "/mkit/partial/v1/ContinueSubmission"),
            ("get.meta.json", "/mkit/partial/v1/GetStagedSubmission"),
            ("cleanup.meta.json", "/mkit/host/v1/CleanupSubmissions"),
            ("upload.meta.json", "/mkit/partial/v1/UploadSubmission"),
        ] {
            let meta: serde_json::Value = serde_json::from_slice(&fixture(file)).unwrap();
            assert_eq!(meta["path"], path, "{file}");
            assert_eq!(meta["method"], "POST", "{file}");
            if file != "upload.meta.json" {
                assert_eq!(meta["status"], 200, "{file}");
                assert!(
                    meta["response"]
                        .as_str()
                        .unwrap()
                        .ends_with("-response.json")
                );
            }
        }
        let upload_meta: serde_json::Value =
            serde_json::from_slice(&fixture("upload.meta.json")).unwrap();
        assert_eq!(upload_meta["prefix_bytes"], 85);
        assert_eq!(
            upload_meta["offsets"]["generation_le"],
            serde_json::json!([69, 77])
        );
        assert_eq!(
            upload_meta["offsets"]["carrier_len_le"],
            serde_json::json!([77, 85])
        );

        let binding: serde_json::Value = serde_json::from_slice(&fixture("binding.json")).unwrap();
        assert_eq!(binding["audience"], "https://host.example");
        assert_eq!(binding["repository"], "test-repository");
        assert_eq!(binding["subject_key"], "55".repeat(32));
        let expected = binding["binding_blake3"].as_str().unwrap();
        assert_eq!(
            expected,
            "defc5f656d29fc0e1d042028152184b9651b93bec1d9a3406093ef22006e79d1"
        );
        assert_eq!(
            binding["begin_body_blake3"],
            hex::encode(mkit_core::hash::hash(&begin_bytes))
        );
    }

    #[test]
    fn committed_submission_request_and_response_vectors_are_exact() {
        let begin_bytes = fixture("begin.json");
        let begin = decode_begin(&begin_bytes).unwrap();
        assert_eq!(begin.operation_id, "33".repeat(32));
        assert_eq!(begin.update_len, "8");
        assert_eq!(begin.selected_paths[0], ["docs", "a.md"]);
        assert_eq!(begin.selected_paths[1], ["src", "main.rs"]);
        assert_eq!(
            decode_continue(&fixture("continue.json"))
                .unwrap()
                .expected_revision,
            "0"
        );
        assert!(decode_get(&fixture("get.json")).unwrap().validate());
        assert!(decode_cleanup(&fixture("cleanup.json")).unwrap().validate());

        let reply: serde_json::Value =
            serde_json::from_slice(&fixture("begin-response.json")).unwrap();
        assert_eq!(reply["state"], "awaiting_upload");
        assert_eq!(reply["submission_generation"], "1");
        assert_eq!(reply["progress"]["attempts"], "0");
        let cleanup: serde_json::Value =
            serde_json::from_slice(&fixture("cleanup-response.json")).unwrap();
        assert_eq!(cleanup["cleanup_revision"], "1");
        assert_eq!(cleanup["affected_rows"], "0");
    }

    #[test]
    fn strict_json_rejects_duplicate_unknown_trailing_and_noncanonical_fields() {
        let valid = String::from_utf8(fixture("get.json")).unwrap();
        let duplicate = valid.replace(
            "\"operation_id\":",
            "\"operation_id\":\"33\",\"operation_id\":",
        );
        assert_eq!(
            decode_get(duplicate.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        assert_eq!(
            decode_get(format!("{valid}{{}}").as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        assert_eq!(
            decode_get(valid.replace("}", ",\"unknown\":1}").as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        let bad_decimal = fixture("continue.json");
        let bad_decimal = String::from_utf8(bad_decimal).unwrap().replace(
            "\"1\",\"expected_revision\":\"0\"",
            "\"01\",\"expected_revision\":\"0\"",
        );
        assert_eq!(
            decode_continue(bad_decimal.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        assert_eq!(
            decode_get(br#"{"version":2,"operation_id":"3333333333333333333333333333333333333333333333333333333333333333"}"#),
            Err(SubmissionWireError::Malformed)
        );
        let bad_hex = String::from_utf8(fixture("get.json"))
            .unwrap()
            .replace(&"3".repeat(64), &"g".repeat(64));
        assert_eq!(
            decode_get(bad_hex.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        assert_eq!(
            decode_begin(&vec![b' '; MAX_BEGIN_BODY + 1]),
            Err(SubmissionWireError::ResourceExhausted)
        );
        assert_eq!(
            decode_get(&vec![b' '; MAX_REQUEST_BODY + 1]),
            Err(SubmissionWireError::ResourceExhausted)
        );
    }

    #[test]
    fn begin_reuses_core_joined_path_validation_and_classifies_update_limit() {
        let body = String::from_utf8(fixture("begin.json")).unwrap();
        let valid = body.replace(
            "[[\"docs\",\"a.md\"],[\"src\",\"main.rs\"]]",
            "[[\"a-\",\"x\"],[\"a\",\"z\"]]",
        );
        assert!(decode_begin(valid.as_bytes()).is_ok());
        let unsorted = body.replace(
            "[[\"docs\",\"a.md\"],[\"src\",\"main.rs\"]]",
            "[[\"src\",\"main.rs\"],[\"docs\",\"a.md\"]]",
        );
        assert_eq!(
            decode_begin(unsorted.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        let oversized = body.replace("\"update_len\":\"8\"", "\"update_len\":\"4194305\"");
        assert_eq!(
            decode_begin(oversized.as_bytes()),
            Err(SubmissionWireError::ResourceExhausted)
        );
        let zero = body.replace("\"update_len\":\"8\"", "\"update_len\":\"0\"");
        assert_eq!(
            decode_begin(zero.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
        let invalid_component = body.replace("[\"docs\",\"a.md\"]", "[\"..\",\"a.md\"]");
        assert_eq!(
            decode_begin(invalid_component.as_bytes()),
            Err(SubmissionWireError::Malformed)
        );
    }

    #[test]
    fn mksu_vector_pins_offsets_full_width_and_borrowed_carrier() {
        let bytes = fixture("upload.bin");
        let parsed = decode_mksu(&bytes).unwrap();
        assert_eq!(parsed.operation_id, [0x33; 32]);
        assert_eq!(parsed.submission_id, [0x44; 32]);
        assert_eq!(parsed.generation, 1);
        assert_eq!(parsed.declared_len, 8);
        assert_eq!(parsed.carrier, b"MKWUdemo");
        assert_eq!(parsed.carrier.as_ptr(), bytes[MKSU_PREFIX_LEN..].as_ptr());

        // IDs follow the frozen 64-hex/raw32 grammar; zero is not reserved.
        let mut zero_ids = bytes.clone();
        zero_ids[5..69].fill(0);
        assert!(decode_mksu(&zero_ids).is_ok());

        let mut max_generation = bytes.clone();
        max_generation[69..77].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_mksu(&max_generation).unwrap().generation, u64::MAX);

        let mut bad_version = bytes.clone();
        bad_version[4] = 2;
        assert_eq!(
            decode_mksu(&bad_version),
            Err(SubmissionWireError::Malformed)
        );
        assert_eq!(
            decode_mksu(&bytes[..MKSU_PREFIX_LEN - 1]),
            Err(SubmissionWireError::Malformed)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_mksu(&trailing), Err(SubmissionWireError::Malformed));
        let mut bad_length = bytes.clone();
        bad_length[77..85].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(
            decode_mksu(&bad_length),
            Err(SubmissionWireError::Malformed)
        );
        let mut zero_generation = bytes.clone();
        zero_generation[69..77].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            decode_mksu(&zero_generation),
            Err(SubmissionWireError::Malformed)
        );
        let mut huge_len = bytes.clone();
        huge_len[77..85].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_mksu(&huge_len),
            Err(SubmissionWireError::ResourceExhausted)
        );
        let mut maximum = bytes.clone();
        maximum[77..85].copy_from_slice(&(MAX_UPDATE_BYTES as u64).to_le_bytes());
        maximum.resize(MAX_UPLOAD_BODY, 0);
        let maximum_parsed = decode_mksu(&maximum).unwrap();
        assert_eq!(maximum_parsed.carrier.len(), MAX_UPDATE_BYTES);
        assert_eq!(
            decode_mksu(&vec![0; MAX_UPLOAD_BODY + 1]),
            Err(SubmissionWireError::ResourceExhausted)
        );
    }

    #[test]
    fn binding_vector_and_exact_begin_bytes_are_pinned() {
        let begin = fixture("begin.json");
        let expected: Hash =
            from_hex("defc5f656d29fc0e1d042028152184b9651b93bec1d9a3406093ef22006e79d1").unwrap();
        let actual = binding_fingerprint(
            "https://host.example",
            "test-repository",
            &[0x55; 32],
            &begin,
        )
        .unwrap();
        assert_eq!(actual, expected);
        let changed = String::from_utf8(begin.clone())
            .unwrap()
            .replace("\"version\":1", "\"version\": 1");
        assert_ne!(
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap(),
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &[0x55; 32],
                changed.as_bytes()
            )
            .unwrap()
        );
        assert_ne!(
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap(),
            binding_fingerprint(
                "https://other.example",
                "test-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap()
        );
        assert_ne!(
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap(),
            binding_fingerprint(
                "https://host.example",
                "other-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap()
        );
        let mut other_subject = [0x55; 32];
        other_subject[0] ^= 1;
        assert_ne!(
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &[0x55; 32],
                &begin
            )
            .unwrap(),
            binding_fingerprint(
                "https://host.example",
                "test-repository",
                &other_subject,
                &begin
            )
            .unwrap()
        );
    }
}
