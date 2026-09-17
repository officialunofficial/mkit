//! Portable partial-snapshot replacement, signing, and update export.
//!
//! This module is deliberately an adapter: `mkit-core` verifies `MKWB`,
//! rebuilds authenticated trees, prepares/signs the ordinary Commit, and
//! encodes `MKWU`. JavaScript only supplies public inputs and a short-lived
//! Ed25519 seed; it does not implement either wire format.

use wasm_bindgen::prelude::*;

use mkit_core::hash::{from_hex, to_hex};
use mkit_core::{
    FileReplacement, Identity, IdentityKind, KeyPair, Object, PartialCoverage, PartialError,
    PartialLimits, PartialPath, export_partial_update, prepare_partial_commit, replace_files,
    serialize, sign_commit, verify_partial_snapshot,
};
use zeroize::Zeroizing;

const MAX_PATHS_JSON_BYTES: usize = 1024 * 1024;
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
    )
    .map(PartialEditResultJs::from)
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
) -> Result<PartialEditOutput, BindingError> {
    let limits = PartialLimits::V1;
    let expected_base = from_hex(expected_base_hex)
        .map_err(|_| BindingError::new("invalid_base", "expected 64 hexadecimal characters"))?;
    if message.len() > limits.max_commit_message_bytes {
        return Err(BindingError::new(
            "validation_budget_exceeded",
            "commit message exceeds the 4 KiB partial-update limit",
        ));
    }
    let selected_paths = parse_paths_json(selected_paths_json, "selected paths")?;
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
    let coverage = match verified.coverage() {
        PartialCoverage::SelectedOnly => "selected-only",
    };

    Ok(PartialEditOutput {
        root_hex: to_hex(prepared.root_id()),
        candidate_hex: to_hex(update.candidate_id()),
        signed_commit_bytes,
        update_bytes,
        coverage,
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

fn parse_paths_json(input: &str, label: &str) -> Result<Vec<PartialPath>, BindingError> {
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
    if paths.len() > PartialLimits::V1.max_selected_paths {
        return Err(BindingError::new(
            "invalid_selected_paths",
            format!("{label} contains too many paths"),
        ));
    }
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| parse_path(path, label, index, "invalid_selected_paths"))
        .collect()
}

fn parse_path(
    value: &serde_json::Value,
    label: &str,
    index: usize,
    code: &'static str,
) -> Result<PartialPath, BindingError> {
    let components = value
        .as_array()
        .ok_or_else(|| BindingError::new(code, format!("{label}[{index}] must be an array")))?;
    if components.len() > PartialLimits::V1.max_path_depth {
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
            if encoded.len() > PartialLimits::V1.max_component_bytes * 2 {
                return Err(BindingError::new(
                    code,
                    format!("{label}[{index}][{component_index}] exceeds 255 bytes"),
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

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_BUNDLE: &[u8] =
        include_bytes!("../../../tests/golden/partial_workspace/plain_file.bin");
    const BASE: &str = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
    const PATHS: &str = r#"[["7368616c6c6f772e747874"]]"#;
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
