//! Portable partial-snapshot verification, replacement, signing, and update export.
//!
//! This module is deliberately an adapter: `mkit-core` verifies `MKWB`,
//! materializes selected file bytes from verified representations, rebuilds
//! authenticated trees, prepares/signs the ordinary Commit, and encodes
//! `MKWU`. JavaScript only supplies public inputs and a short-lived Ed25519
//! seed; it does not implement either wire format.

use wasm_bindgen::prelude::*;

use mkit_core::hash::{from_hex, to_hex};
use mkit_core::object::EntryMode;
use mkit_core::{
    FileReplacement, Identity, IdentityKind, KeyPair, Object, PartialCoverage, PartialError,
    PartialLimits, PartialPath, VerifiedPartialSnapshot, deserialize, export_partial_update,
    prepare_partial_commit, replace_files, serialize, sign_commit, verify_partial_snapshot,
};
use zeroize::Zeroizing;

const MAX_PATHS_JSON_BYTES: usize = 1024 * 1024;
const MAX_LIMITS_JSON_BYTES: usize = 16 * 1024;
// V1 permits 16 MiB of replacement occurrences. Hex doubles that, with room
// for at most 256 bounded path descriptors and JSON punctuation.
const MAX_REPLACEMENTS_JSON_BYTES: usize = 40 * 1024 * 1024;

/// Verify an `MKWB` snapshot, replace selected files, sign an ordinary
/// one-parent Commit, and export the explicit raw-only `MKWU` update.
///
/// `selected_paths_json` is an array of paths whose components are hex, for
/// example `[["737263","6d61696e2e7273"]]`. It must exactly match the
/// independently expected selection encoded in `bundle`.
///
/// `replacements_json` is an array containing exactly one content choice per
/// object:
///
/// ```text
/// {"path":["..."],"bytes_hex":"..."}
/// {"path":["..."],"reuse_selected":["..."]}
/// ```
///
/// `author_kind` is `"ed25519"`, `"did_key"`, or `"opaque"`. Author and
/// signer are deliberately independent; `author_bytes` need not name the key
/// derived from `seed`. The seed must contain exactly 32 bytes. Rust-side seed
/// storage is zeroized, but this function cannot erase the caller's JS
/// `ArrayBuffer`.
///
/// Errors are thrown with a JSON-serialized `{ "code", "message" }` payload
/// in the JavaScript `Error.message` field. Codes are stable snake-case
/// categories; messages are descriptive, not protocol data.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn partial_edit_and_export(
    bundle: &[u8],
    expected_base_hex: &str,
    selected_paths_json: &str,
    replacements_json: &str,
    author_kind: &str,
    author_bytes: &[u8],
    message: &[u8],
    timestamp: u64,
    seed: &[u8],
) -> Result<PartialEditResultJs, JsValue> {
    partial_edit_and_export_inner(
        bundle,
        expected_base_hex,
        selected_paths_json,
        replacements_json,
        author_kind,
        author_bytes,
        message,
        timestamp,
        seed,
        PartialLimits::V1,
    )
    .map(PartialEditResultJs::from)
    .map_err(BindingError::into_js)
}

/// Same pipeline as [`partial_edit_and_export`], with caller-lowered
/// [`PartialLimits`].
///
/// `limits_json` is a JSON object whose keys are the generic `PartialLimits`
/// field names. Omitted, empty, or null input uses the v1 profile. Present
/// fields replace v1 defaults. Unknown fields, non-integers, negatives,
/// overflows, values above v1, and input larger than 16 KiB are rejected.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn partial_edit_and_export_with_limits(
    bundle: &[u8],
    expected_base_hex: &str,
    selected_paths_json: &str,
    replacements_json: &str,
    author_kind: &str,
    author_bytes: &[u8],
    message: &[u8],
    timestamp: u64,
    seed: &[u8],
    limits_json: Option<String>,
) -> Result<PartialEditResultJs, JsValue> {
    match parse_limits_json(limits_json.as_deref()) {
        Ok(limits) => partial_edit_and_export_inner(
            bundle,
            expected_base_hex,
            selected_paths_json,
            replacements_json,
            author_kind,
            author_bytes,
            message,
            timestamp,
            seed,
            limits,
        )
        .map(PartialEditResultJs::from)
        .map_err(BindingError::into_js),
        Err(error) => Err(error.into_js()),
    }
}

/// Read-only verification of an `MKWB` snapshot.
///
/// Materializes only complete selected regular/executable file bytes from
/// verified representations. It does not take a signer, seed, network,
/// grant, or host profile. `limits_json` follows
/// [`partial_edit_and_export_with_limits`].
#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn partial_verify_snapshot(
    bundle: &[u8],
    expected_base_hex: &str,
    selected_paths_json: &str,
    limits_json: Option<String>,
) -> Result<PartialSnapshotJs, JsValue> {
    partial_verify_snapshot_inner(
        bundle,
        expected_base_hex,
        selected_paths_json,
        limits_json.as_deref(),
    )
    .map(PartialSnapshotJs::from)
    .map_err(BindingError::into_js)
}

#[derive(Debug, PartialEq, Eq)]
struct PartialEditOutput {
    root_hex: String,
    candidate_hex: String,
    signed_commit_bytes: Vec<u8>,
    update_bytes: Vec<u8>,
    coverage: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct PartialFileOutput {
    path_json: String,
    mode: &'static str,
    representation_id_hex: String,
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct PartialSnapshotOutput {
    coverage: &'static str,
    files: Vec<PartialFileOutput>,
}

#[allow(clippy::too_many_arguments)]
fn partial_edit_and_export_inner(
    bundle: &[u8],
    expected_base_hex: &str,
    selected_paths_json: &str,
    replacements_json: &str,
    author_kind: &str,
    author_bytes: &[u8],
    message: &[u8],
    timestamp: u64,
    seed: &[u8],
    limits: PartialLimits,
) -> Result<PartialEditOutput, BindingError> {
    let expected_base = from_hex(expected_base_hex)
        .map_err(|_| BindingError::new("invalid_base", "expected 64 hexadecimal characters"))?;
    if message.len() > limits.max_commit_message_bytes {
        return Err(BindingError::new(
            "validation_budget_exceeded",
            "commit message exceeds the partial-update limit",
        ));
    }
    let selected_paths = parse_paths_json(selected_paths_json, "selected paths", &limits)?;
    let replacements = parse_replacements_json(replacements_json, &limits)?;
    let author = parse_author(author_kind, author_bytes)?;
    validate_seed(seed)?;

    let verified = verify_partial_snapshot(expected_base, &selected_paths, bundle, &limits)
        .map_err(|error| BindingError::from_partial(&error))?;
    let prepared = replace_files(&verified, &replacements, &limits)
        .map_err(|error| BindingError::from_partial(&error))?;
    // Materialize the secret only after all public-data verification and
    // tree-building succeeds, then drop it immediately after signing.
    let key_pair = key_pair_from_seed(seed)?;
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        author,
        key_pair.public.0,
        message.to_vec(),
        timestamp,
        &limits,
    )
    .map_err(|error| BindingError::from_partial(&error))?;
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key_pair)
        .map_err(|error| BindingError::new("signing_failed", error.to_string()))?
        .0;
    // Do not retain signing material while serializing/exporting public data.
    drop(key_pair);

    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .map_err(|error| BindingError::from_partial(&error))?;
    let update_bytes = update
        .encode(&limits)
        .map_err(|error| BindingError::from_partial(&error))?;
    let signed_commit_bytes = serialize(&Object::Commit(signed))
        .map_err(|error| BindingError::new("serialization_failed", error.to_string()))?;

    Ok(PartialEditOutput {
        root_hex: to_hex(prepared.root_id()),
        candidate_hex: to_hex(update.candidate_id()),
        signed_commit_bytes,
        update_bytes,
        coverage: coverage_label(verified.coverage()),
    })
}

fn partial_verify_snapshot_inner(
    bundle: &[u8],
    expected_base_hex: &str,
    selected_paths_json: &str,
    limits_json: Option<&str>,
) -> Result<PartialSnapshotOutput, BindingError> {
    let limits = parse_limits_json(limits_json)?;
    let expected_base = from_hex(expected_base_hex)
        .map_err(|_| BindingError::new("invalid_base", "expected 64 hexadecimal characters"))?;
    let selected_paths = parse_paths_json(selected_paths_json, "selected paths", &limits)?;
    let verified = verify_partial_snapshot(expected_base, &selected_paths, bundle, &limits)
        .map_err(|error| BindingError::from_partial(&error))?;
    let files = materialize_selected_files(&verified, &limits)?;
    Ok(PartialSnapshotOutput {
        coverage: coverage_label(verified.coverage()),
        files,
    })
}

fn materialize_selected_files(
    verified: &VerifiedPartialSnapshot,
    limits: &PartialLimits,
) -> Result<Vec<PartialFileOutput>, BindingError> {
    let mut files = Vec::with_capacity(verified.files().len());
    let mut total = 0usize;
    for file in verified.files() {
        let bytes = materialize_selected_file(verified, file, limits)?;
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            BindingError::new("workspace_too_large", "selected file size overflow")
        })?;
        if total > limits.max_total_selected_bytes {
            return Err(BindingError::new(
                "workspace_too_large",
                "selected bytes exceed the aggregate selected-file limit",
            ));
        }
        files.push(PartialFileOutput {
            path_json: path_to_json(file.path())?,
            mode: match file.mode() {
                EntryMode::Blob => "blob",
                EntryMode::Executable => "exec",
                EntryMode::Tree | EntryMode::Symlink => {
                    return Err(BindingError::new(
                        "unsupported_partial_operation",
                        "selected path is not a regular or executable file",
                    ));
                }
            },
            representation_id_hex: to_hex(file.object_id()),
            bytes,
        });
    }
    Ok(files)
}

fn materialize_selected_file(
    verified: &VerifiedPartialSnapshot,
    file: &mkit_core::SelectedFile,
    limits: &PartialLimits,
) -> Result<Vec<u8>, BindingError> {
    let expected = usize::try_from(file.content_len()).map_err(|_| {
        BindingError::new(
            "workspace_too_large",
            "selected file exceeds the addressable size",
        )
    })?;
    if expected > limits.max_selected_file_bytes {
        return Err(BindingError::new(
            "workspace_too_large",
            "selected file exceeds the selected-file limit",
        ));
    }
    if file.chunk_ids().is_empty() {
        return blob_payload(verified, file.object_id(), expected);
    }
    let mut bytes = Vec::new();
    for chunk_id in file.chunk_ids() {
        let chunk = blob_payload(verified, chunk_id, usize::MAX)?;
        let next = bytes.len().checked_add(chunk.len()).ok_or_else(|| {
            BindingError::new("workspace_too_large", "chunk concatenation overflow")
        })?;
        if next > expected {
            return Err(BindingError::new(
                "invalid_chunk_layout",
                "chunk bytes exceed the verified file length",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != expected {
        return Err(BindingError::new(
            "invalid_chunk_layout",
            "chunk bytes do not equal the verified file length",
        ));
    }
    Ok(bytes)
}

fn blob_payload(
    verified: &VerifiedPartialSnapshot,
    id: &mkit_core::Hash,
    max_len: usize,
) -> Result<Vec<u8>, BindingError> {
    let object_bytes = verified.object_bytes(id).ok_or_else(|| {
        BindingError::new(
            "insufficient_witness",
            "verified snapshot lacks selected representation bytes",
        )
    })?;
    let Object::Blob(blob) = deserialize(object_bytes)
        .map_err(|error| BindingError::new("wrong_object_type", error.to_string()))?
    else {
        return Err(BindingError::new(
            "wrong_object_type",
            "selected representation is not a Blob",
        ));
    };
    if blob.data.len() > max_len {
        return Err(BindingError::new(
            "workspace_too_large",
            "blob payload exceeds the selected-file limit",
        ));
    }
    Ok(blob.data)
}

fn coverage_label(coverage: PartialCoverage) -> &'static str {
    match coverage {
        PartialCoverage::SelectedOnly => "selected-only",
    }
}

fn path_to_json(path: &PartialPath) -> Result<String, BindingError> {
    let encoded: Vec<String> = path.iter().map(hex::encode).collect();
    serde_json::to_string(&encoded)
        .map_err(|error| BindingError::new("invalid_selected_paths", error.to_string()))
}

fn parse_limits_json(input: Option<&str>) -> Result<PartialLimits, BindingError> {
    let Some(input) = input.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(PartialLimits::V1);
    };
    if input.len() > MAX_LIMITS_JSON_BYTES {
        return Err(BindingError::new(
            "invalid_limits",
            "limits JSON exceeds 16 KiB",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| BindingError::new("invalid_limits", format!("limits JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| BindingError::new("invalid_limits", "limits JSON must be an object"))?;
    let mut limits = PartialLimits::V1;
    for (key, value) in object {
        let slot = match key.as_str() {
            "max_selected_paths" => &mut limits.max_selected_paths,
            "max_path_depth" => &mut limits.max_path_depth,
            "max_component_bytes" => &mut limits.max_component_bytes,
            "max_path_bytes" => &mut limits.max_path_bytes,
            "max_total_path_bytes" => &mut limits.max_total_path_bytes,
            "max_selected_file_bytes" => &mut limits.max_selected_file_bytes,
            "max_total_selected_bytes" => &mut limits.max_total_selected_bytes,
            "max_base_object_bytes" => &mut limits.max_base_object_bytes,
            "max_tree_object_bytes" => &mut limits.max_tree_object_bytes,
            "max_tree_entries" => &mut limits.max_tree_entries,
            "max_witness_bytes" => &mut limits.max_witness_bytes,
            "max_tree_visits" => &mut limits.max_tree_visits,
            "max_bundle_bytes" => &mut limits.max_bundle_bytes,
            "max_objects" => &mut limits.max_objects,
            "max_object_bytes" => &mut limits.max_object_bytes,
            "max_update_bytes" => &mut limits.max_update_bytes,
            "max_raw_pack_bytes" => &mut limits.max_raw_pack_bytes,
            "max_update_objects" => &mut limits.max_update_objects,
            "max_commit_message_bytes" => &mut limits.max_commit_message_bytes,
            "max_changed_paths" => &mut limits.max_changed_paths,
            _ => {
                return Err(BindingError::new(
                    "invalid_limits",
                    format!("unknown limits field {key}"),
                ));
            }
        };
        *slot = parse_limit_usize(value, key)?;
    }
    if !limits.is_v1_subset() {
        return Err(BindingError::new(
            "invalid_limits",
            "limits may lower the v1 profile but must not exceed it",
        ));
    }
    Ok(limits)
}

fn parse_limit_usize(value: &serde_json::Value, key: &str) -> Result<usize, BindingError> {
    let Some(number) = value.as_u64() else {
        return Err(BindingError::new(
            "invalid_limits",
            format!("{key} must be a non-negative integer"),
        ));
    };
    usize::try_from(number).map_err(|_| {
        BindingError::new(
            "invalid_limits",
            format!("{key} exceeds the addressable size"),
        )
    })
}

fn key_pair_from_seed(seed: &[u8]) -> Result<KeyPair, BindingError> {
    validate_seed(seed)?;
    let mut owned = Zeroizing::new([0u8; 32]);
    owned.copy_from_slice(seed);
    Ok(KeyPair::from_seed_zeroizing(&owned))
}

fn validate_seed(seed: &[u8]) -> Result<(), BindingError> {
    if seed.len() != 32 {
        return Err(BindingError::new(
            "invalid_seed",
            "Ed25519 seed must contain exactly 32 bytes",
        ));
    }
    Ok(())
}

fn parse_author(kind: &str, bytes: &[u8]) -> Result<Identity, BindingError> {
    if bytes.len() > mkit_core::IDENTITY_MAX_LEN as usize {
        return Err(BindingError::new(
            "invalid_author",
            "author identity exceeds 4096 bytes",
        ));
    }
    let kind = match kind {
        "ed25519" => IdentityKind::Ed25519,
        "did_key" => IdentityKind::DidKey,
        "opaque" => IdentityKind::Opaque,
        _ => {
            return Err(BindingError::new(
                "invalid_author",
                "author kind must be ed25519, did_key, or opaque",
            ));
        }
    };
    let author = Identity {
        kind,
        bytes: bytes.to_vec(),
    };
    if !author.is_valid() {
        return Err(BindingError::new(
            "invalid_author",
            "author identity payload is invalid for its kind",
        ));
    }
    Ok(author)
}

fn parse_paths_json(
    input: &str,
    label: &str,
    limits: &PartialLimits,
) -> Result<Vec<PartialPath>, BindingError> {
    if input.len() > MAX_PATHS_JSON_BYTES {
        return Err(BindingError::new(
            "invalid_selected_paths",
            format!("{label} JSON exceeds 1 MiB"),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(input).map_err(|error| {
        BindingError::new("invalid_selected_paths", format!("{label} JSON: {error}"))
    })?;
    let paths = value.as_array().ok_or_else(|| {
        BindingError::new(
            "invalid_selected_paths",
            format!("{label} JSON must be an array"),
        )
    })?;
    if paths.len() > limits.max_selected_paths {
        return Err(BindingError::new(
            "invalid_selected_paths",
            format!("{label} contains too many paths"),
        ));
    }
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| parse_path(path, label, index, "invalid_selected_paths", limits))
        .collect()
}

fn parse_path(
    value: &serde_json::Value,
    label: &str,
    index: usize,
    code: &'static str,
    limits: &PartialLimits,
) -> Result<PartialPath, BindingError> {
    let components = value
        .as_array()
        .ok_or_else(|| BindingError::new(code, format!("{label}[{index}] must be an array")))?;
    if components.len() > limits.max_path_depth {
        return Err(BindingError::new(
            code,
            format!("{label}[{index}] has too many components"),
        ));
    }
    components
        .iter()
        .enumerate()
        .map(|(component_index, component)| {
            let encoded = component.as_str().ok_or_else(|| {
                BindingError::new(
                    code,
                    format!("{label}[{index}][{component_index}] must be a hex string"),
                )
            })?;
            if encoded.len() > limits.max_component_bytes.saturating_mul(2) {
                return Err(BindingError::new(
                    code,
                    format!("{label}[{index}][{component_index}] exceeds the component limit"),
                ));
            }
            hex::decode(encoded).map_err(|_| {
                BindingError::new(
                    code,
                    format!("{label}[{index}][{component_index}] is not valid hex"),
                )
            })
        })
        .collect()
}

fn parse_replacements_json(
    input: &str,
    limits: &PartialLimits,
) -> Result<Vec<FileReplacement>, BindingError> {
    if input.len() > MAX_REPLACEMENTS_JSON_BYTES {
        return Err(BindingError::new(
            "invalid_replacements",
            "replacements JSON exceeds 40 MiB",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(input).map_err(|error| {
        BindingError::new(
            "invalid_replacements",
            format!("replacements JSON: {error}"),
        )
    })?;
    let values = value.as_array().ok_or_else(|| {
        BindingError::new("invalid_replacements", "replacements JSON must be an array")
    })?;
    if values.len() > limits.max_changed_paths {
        return Err(BindingError::new(
            "invalid_replacements",
            "too many replacement records",
        ));
    }

    let mut total_bytes = 0usize;
    let mut replacements = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let object = value.as_object().ok_or_else(|| {
            BindingError::new(
                "invalid_replacements",
                format!("replacement[{index}] must be an object"),
            )
        })?;
        let path_value = object.get("path").ok_or_else(|| {
            BindingError::new(
                "invalid_replacements",
                format!("replacement[{index}].path is required"),
            )
        })?;
        let path = parse_path(
            path_value,
            "replacement path",
            index,
            "invalid_replacements",
            limits,
        )?;
        let bytes_hex = object.get("bytes_hex");
        let reuse_selected = object.get("reuse_selected");
        if object.len() != 2 || bytes_hex.is_some() == reuse_selected.is_some() {
            return Err(BindingError::new(
                "invalid_replacements",
                format!(
                    "replacement[{index}] must contain path and exactly one of bytes_hex or reuse_selected"
                ),
            ));
        }
        if let Some(value) = bytes_hex {
            let encoded = value.as_str().ok_or_else(|| {
                BindingError::new(
                    "invalid_replacements",
                    format!("replacement[{index}].bytes_hex must be a hex string"),
                )
            })?;
            if encoded.len() > limits.max_selected_file_bytes.saturating_mul(2) {
                return Err(BindingError::new(
                    "workspace_too_large",
                    format!("replacement[{index}] exceeds the selected-file limit"),
                ));
            }
            let decoded_len = encoded.len() / 2;
            total_bytes = total_bytes.checked_add(decoded_len).ok_or_else(|| {
                BindingError::new("workspace_too_large", "replacement size overflow")
            })?;
            if total_bytes > limits.max_total_selected_bytes {
                return Err(BindingError::new(
                    "workspace_too_large",
                    "replacement bytes exceed the aggregate selected-file limit",
                ));
            }
            let bytes = hex::decode(encoded).map_err(|_| {
                BindingError::new(
                    "invalid_replacements",
                    format!("replacement[{index}].bytes_hex is not valid hex"),
                )
            })?;
            replacements.push(FileReplacement::bytes(path, bytes));
        } else if let Some(value) = reuse_selected {
            let source = parse_path(
                value,
                "replacement reuse_selected",
                index,
                "invalid_replacements",
                limits,
            )?;
            replacements.push(FileReplacement::reuse_selected(path, source));
        }
    }
    Ok(replacements)
}

#[derive(Debug, PartialEq, Eq)]
struct BindingError {
    code: &'static str,
    message: String,
}

impl BindingError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn from_partial(error: &PartialError) -> Self {
        let code = match error {
            PartialError::UnsupportedVersion(_) => "unsupported_version",
            PartialError::NonCanonical => "non_canonical",
            PartialError::BaseMismatch => "base_mismatch",
            PartialError::SelectionMismatch => "selection_mismatch",
            PartialError::InsufficientWitness => "insufficient_witness",
            PartialError::WrongObjectType => "wrong_object_type",
            PartialError::InvalidSignature => "invalid_signature",
            PartialError::InvalidChunkLayout => "invalid_chunk_layout",
            PartialError::IncompleteSelection => "incomplete_selection",
            PartialError::UnsupportedPartialOperation => "unsupported_partial_operation",
            PartialError::WitnessTooLarge => "witness_too_large",
            PartialError::WorkspaceTooLarge => "workspace_too_large",
            PartialError::ValidationBudgetExceeded => "validation_budget_exceeded",
            PartialError::NoChanges => "no_changes",
            PartialError::CommitMismatch => "commit_mismatch",
            PartialError::SubmissionTooLarge => "submission_too_large",
            PartialError::InvalidUpdatePack => "invalid_update_pack",
            PartialError::InvalidPath => "invalid_path",
            PartialError::Source(_) => "source_error",
        };
        Self::new(code, error.to_string())
    }

    fn into_js(self) -> JsValue {
        let serialized = serde_json::json!({
            "code": self.code,
            "message": self.message,
        })
        .to_string();
        JsError::new(&serialized).into()
    }
}

/// Result of the shared core partial-edit pipeline.
#[wasm_bindgen]
#[derive(Debug)]
pub struct PartialEditResultJs {
    root_hex: String,
    candidate_hex: String,
    signed_commit_bytes: Vec<u8>,
    update_bytes: Vec<u8>,
    coverage: String,
}

impl From<PartialEditOutput> for PartialEditResultJs {
    fn from(output: PartialEditOutput) -> Self {
        Self {
            root_hex: output.root_hex,
            candidate_hex: output.candidate_hex,
            signed_commit_bytes: output.signed_commit_bytes,
            update_bytes: output.update_bytes,
            coverage: output.coverage.to_string(),
        }
    }
}

#[wasm_bindgen]
impl PartialEditResultJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn root_hex(&self) -> String {
        self.root_hex.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn candidate_hex(&self) -> String {
        self.candidate_hex.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signed_commit_bytes(&self) -> Box<[u8]> {
        self.signed_commit_bytes.clone().into_boxed_slice()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn update_bytes(&self) -> Box<[u8]> {
        self.update_bytes.clone().into_boxed_slice()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn coverage(&self) -> String {
        self.coverage.clone()
    }
}

/// Read-only selected-file snapshot. Witness objects are not retained.
#[wasm_bindgen]
#[derive(Debug)]
pub struct PartialSnapshotJs {
    coverage: String,
    files: Vec<PartialSelectedFileJs>,
}

impl From<PartialSnapshotOutput> for PartialSnapshotJs {
    fn from(output: PartialSnapshotOutput) -> Self {
        Self {
            coverage: output.coverage.to_string(),
            files: output
                .files
                .into_iter()
                .map(PartialSelectedFileJs::from)
                .collect(),
        }
    }
}

#[wasm_bindgen]
impl PartialSnapshotJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn coverage(&self) -> String {
        self.coverage.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn file_count(&self) -> u32 {
        crate::common::js_vec_count(&self.files)
    }

    #[wasm_bindgen]
    #[must_use]
    pub fn file(&self, index: u32) -> Option<PartialSelectedFileJs> {
        crate::common::js_vec_get(&self.files, index)
    }
}

/// One verified selected regular or executable file.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct PartialSelectedFileJs {
    path_json: String,
    mode: String,
    representation_id_hex: String,
    bytes: Vec<u8>,
}

impl From<PartialFileOutput> for PartialSelectedFileJs {
    fn from(output: PartialFileOutput) -> Self {
        Self {
            path_json: output.path_json,
            mode: output.mode.to_string(),
            representation_id_hex: output.representation_id_hex,
            bytes: output.bytes,
        }
    }
}

#[wasm_bindgen]
impl PartialSelectedFileJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn path_json(&self) -> String {
        self.path_json.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn representation_id_hex(&self) -> String {
        self.representation_id_hex.clone()
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        self.bytes.clone().into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_BUNDLE: &[u8] =
        include_bytes!("../../../tests/golden/partial_workspace/plain_file.bin");
    const CHUNKED_BUNDLE: &[u8] =
        include_bytes!("../../../tests/golden/partial_workspace/chunked_file.bin");
    const BASE: &str = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
    const PATHS: &str = r#"[["7368616c6c6f772e747874"]]"#;
    const CHUNKED_PATHS: &str = r#"[["6368756e6b65642e62696e"]]"#;
    const REPLACEMENTS: &str =
        r#"[{"path":["7368616c6c6f772e747874"],"bytes_hex":"7761736d20706172697479"}]"#;

    #[test]
    fn partial_pipeline_matches_direct_core_output_and_allows_distinct_author() {
        let seed = [0x41; 32];
        let author = b"browser-agent";
        let message = b"partial edit";
        let output = partial_edit_and_export_inner(
            PLAIN_BUNDLE,
            BASE,
            PATHS,
            REPLACEMENTS,
            "opaque",
            author,
            message,
            1_750_000_000,
            &seed,
            PartialLimits::V1,
        )
        .unwrap();

        let limits = PartialLimits::V1;
        let base = from_hex(BASE).unwrap();
        let paths = vec![vec![b"shallow.txt".to_vec()]];
        let verified = verify_partial_snapshot(base, &paths, PLAIN_BUNDLE, &limits).unwrap();
        let replacements = vec![FileReplacement::bytes(
            paths[0].clone(),
            b"wasm parity".to_vec(),
        )];
        let prepared = replace_files(&verified, &replacements, &limits).unwrap();
        let key_pair = KeyPair::from_seed(seed);
        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(author.to_vec()),
            key_pair.public.0,
            message.to_vec(),
            1_750_000_000,
            &limits,
        )
        .unwrap();
        let mut signed = unsigned.clone();
        signed.signature = sign_commit(&signed, &key_pair).unwrap().0;
        let update =
            export_partial_update(&verified, &prepared, &unsigned, &signed, &limits).unwrap();

        assert_ne!(signed.author.bytes.as_slice(), signed.signer.as_slice());
        assert_eq!(output.root_hex, to_hex(prepared.root_id()));
        assert_eq!(output.candidate_hex, to_hex(update.candidate_id()));
        assert_eq!(
            output.signed_commit_bytes,
            serialize(&Object::Commit(signed)).unwrap()
        );
        assert_eq!(output.update_bytes, update.encode(&limits).unwrap());
        assert_eq!(output.coverage, "selected-only");
    }

    #[test]
    fn omitted_limits_match_default_edit_export() {
        let seed = [0x41; 32];
        let author = b"browser-agent";
        let message = b"partial edit";
        let defaulted = partial_edit_and_export_inner(
            PLAIN_BUNDLE,
            BASE,
            PATHS,
            REPLACEMENTS,
            "opaque",
            author,
            message,
            1_750_000_000,
            &seed,
            parse_limits_json(None).unwrap(),
        )
        .unwrap();
        let explicit = partial_edit_and_export_inner(
            PLAIN_BUNDLE,
            BASE,
            PATHS,
            REPLACEMENTS,
            "opaque",
            author,
            message,
            1_750_000_000,
            &seed,
            parse_limits_json(Some("{}")).unwrap(),
        )
        .unwrap();
        assert_eq!(defaulted, explicit);
    }

    #[test]
    fn read_only_verify_materializes_plain_file_without_signing() {
        let snapshot = partial_verify_snapshot_inner(PLAIN_BUNDLE, BASE, PATHS, None).unwrap();
        assert_eq!(snapshot.coverage, "selected-only");
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].path_json, r#"["7368616c6c6f772e747874"]"#);
        assert_eq!(snapshot.files[0].mode, "blob");
        assert!(!snapshot.files[0].representation_id_hex.is_empty());
        assert!(!snapshot.files[0].bytes.is_empty());
    }

    #[test]
    fn read_only_verify_materializes_chunked_selected_file() {
        let snapshot =
            partial_verify_snapshot_inner(CHUNKED_BUNDLE, BASE, CHUNKED_PATHS, None).unwrap();
        assert_eq!(snapshot.coverage, "selected-only");
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].path_json, r#"["6368756e6b65642e62696e"]"#);
        assert!(snapshot.files[0].bytes.len() > 1024);
        let verified = verify_partial_snapshot(
            from_hex(BASE).unwrap(),
            &[vec![b"chunked.bin".to_vec()]],
            CHUNKED_BUNDLE,
            &PartialLimits::V1,
        )
        .unwrap();
        assert_eq!(
            snapshot.files[0].bytes.len() as u64,
            verified.files()[0].content_len()
        );
        assert!(!verified.files()[0].chunk_ids().is_empty());
    }

    #[test]
    fn stricter_limits_and_malformed_options_are_rejected() {
        let error = partial_verify_snapshot_inner(
            PLAIN_BUNDLE,
            BASE,
            PATHS,
            Some(r#"{"max_bundle_bytes":100}"#),
        )
        .unwrap_err();
        assert_eq!(error.code, "workspace_too_large");

        let error = parse_limits_json(Some(r#"{"unknown":1}"#)).unwrap_err();
        assert_eq!(error.code, "invalid_limits");
        let error = parse_limits_json(Some(r#"{"max_bundle_bytes":-1}"#)).unwrap_err();
        assert_eq!(error.code, "invalid_limits");
        let error = parse_limits_json(Some(r#"{"max_bundle_bytes":1.5}"#)).unwrap_err();
        assert_eq!(error.code, "invalid_limits");
        let error = parse_limits_json(Some(r#"{"max_bundle_bytes":999999999999}"#)).unwrap_err();
        assert_eq!(error.code, "invalid_limits");
        let oversized = format!("{{\"max_bundle_bytes\":1{}}}", " ".repeat(16 * 1024));
        let error = parse_limits_json(Some(&oversized)).unwrap_err();
        assert_eq!(error.code, "invalid_limits");
    }

    #[test]
    fn partial_pipeline_reports_typed_core_and_adapter_errors() {
        let wrong_base = "a5".repeat(32);
        let error = partial_edit_and_export_inner(
            PLAIN_BUNDLE,
            &wrong_base,
            PATHS,
            REPLACEMENTS,
            "opaque",
            b"browser-agent",
            b"partial edit",
            1,
            &[0x41; 32],
            PartialLimits::V1,
        )
        .unwrap_err();
        assert_eq!(error.code, "base_mismatch");

        let error = parse_replacements_json(
            r#"[{"path":["00"],"bytes_hex":"00","reuse_selected":["00"]}]"#,
            &PartialLimits::V1,
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_replacements");
    }
}
