//! External signer — subprocess-based [`Signer`] impl driven over
//! the mkit-rpc signer protocol (length-prefixed buffa frames on
//! stdin/stdout). See `rust/crates/mkit-rpc/proto/signer.proto` and
//! `docs/SPEC-EXTERNAL-SIGNER.md`.
//!
//! Conversation per sign call:
//!
//! ```text
//! parent → child:    Hello{ protocol = v1, want_capabilities = false }
//!                    SignRequest{ algorithm, key_form, key_ref, payload }
//! child  → parent:   HelloResponse{ ... }   (capabilities; we discard)
//!                    SignResponse{ signature, public_key, key_id }
//!                      OR
//!                    Error{ code, message }
//! ```
//!
//! `keyid` is only known after the first sign call; `keyid()` before
//! that returns `Error::KeyIdNotKnownUntilFirstSign`.

// `ref_option` flags `&Option<T>` arguments. Wire-frame fields are
// `Option<T>` (Edition 2023 explicit presence); passing references
// through helpers is the natural shape.
#![allow(clippy::ref_option)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use mkit_rpc::mkit::rpc::v1::signer::{Hello, SignRequest, SignerFrame, signer_frame};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, KeyForm, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, write_frame};

use crate::Error;
use crate::algorithm::Algorithm;
use crate::signer::Signer;

/// Cap for child-stderr drain. 1 MiB is generous; stderr is advisory.
const MAX_STDERR_DRAIN: usize = 1024 * 1024;

#[derive(Debug)]
pub struct ExternalSigner {
    binary_path: PathBuf,
    cached_keyid: Option<String>,
    algorithm: Algorithm,
    args: Vec<String>,
}

impl ExternalSigner {
    /// Construct an external signer wrapping `binary_path`.
    ///
    /// The path MUST be absolute. A relative path is rejected with
    /// [`Error::ExternalSignerRelativePath`]: at spawn time, a relative
    /// path would resolve against the current `PATH` (or CWD on
    /// Windows) and pick up a same-named binary planted by an attacker
    /// earlier in the search order. Forcing absolute paths at
    /// construction closes that TOCTOU hole.
    ///
    /// # Errors
    /// [`Error::ExternalSignerRelativePath`] if `binary_path` is not
    /// absolute.
    pub fn new(binary_path: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::with_algorithm(binary_path, Algorithm::Ed25519)
    }

    /// Like [`Self::new`] but records a caller-asserted algorithm.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn with_algorithm(
        binary_path: impl Into<PathBuf>,
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        let binary_path = binary_path.into();
        if !binary_path.is_absolute() {
            return Err(Error::ExternalSignerRelativePath(
                binary_path.display().to_string(),
            ));
        }
        Ok(Self {
            binary_path,
            cached_keyid: None,
            algorithm,
            args: Vec::new(),
        })
    }

    /// Attach extra argv tokens to be passed verbatim to the child
    /// process on every sign call. Each element is one argv entry —
    /// no shell interpolation. Calling this replaces any previously-set
    /// args.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }
}

impl Signer for ExternalSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn keyid(&self) -> Result<String, Error> {
        self.cached_keyid
            .clone()
            .ok_or(Error::KeyIdNotKnownUntilFirstSign)
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        let mut child = Command::new(&self.binary_path)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::ExternalSignerSpawn(e.to_string()))?;

        // Build the request: Hello + SignRequest. We fire both before
        // reading any response so the signer can pipeline.
        let hello = SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(
                Hello::default()
                    .with_protocol(ProtocolVersion::PROTOCOL_VERSION_1)
                    .with_caller_id(format!("mkit-attest/{}", env!("CARGO_PKG_VERSION")))
                    .with_want_capabilities(false),
            ))),
            ..Default::default()
        };
        let sign_req = SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(rpc_algorithm_for(self.algorithm))
                    .with_key_form(rpc_key_form_for(self.algorithm))
                    .with_key_ref(Vec::new())
                    .with_payload(pae.to_vec())
                    .with_context(Vec::new()),
            ))),
            ..Default::default()
        };

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| Error::ExternalSignerSpawn("stdin not piped".into()))?;
            write_frame(stdin, &hello)
                .map_err(|e| Error::ExternalSignerSpawn(format!("write hello: {e}")))?;
            write_frame(stdin, &sign_req)
                .map_err(|e| Error::ExternalSignerSpawn(format!("write sign request: {e}")))?;
        }
        // Drop stdin handle so the child sees EOF.
        drop(child.stdin.take());

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::ExternalSignerSpawn("stdout not piped".into()))?;

        // Drain HelloResponse + SignResponse | Error. We tolerate
        // signers that emit only the response (skipping the hello) by
        // peeking at the first frame.
        let resp = read_frame_or_err(&mut stdout)?;
        let (signature, key_id) = match resp.body {
            Some(signer_frame::Body::HelloResponse(_)) => {
                // Read next frame: SignResponse | Error.
                let next = read_frame_or_err(&mut stdout)?;
                extract_signature(next)?
            }
            Some(signer_frame::Body::SignResponse(_) | signer_frame::Body::Error(_)) => {
                extract_signature(resp)?
            }
            other => {
                return Err(Error::ExternalSignerBadResponse(format!(
                    "unexpected first frame: {}",
                    frame_name(&other),
                )));
            }
        };

        // Drain stderr for diagnostic surfacing on non-zero exit.
        let stderr = drain_capped(
            child
                .stderr
                .take()
                .ok_or_else(|| Error::ExternalSignerSpawn("stderr not piped".into()))?,
        )?;

        let status = child
            .wait()
            .map_err(|e| Error::ExternalSignerSpawn(format!("wait: {e}")))?;

        if !status.success() {
            // Surface the child's stderr to the caller — even if we
            // got a successful response frame, a non-zero exit
            // signals the signer didn't trust its own output.
            let msg = String::from_utf8_lossy(&stderr).into_owned();
            return Err(Error::ExternalSignerFailed(msg));
        }

        self.cached_keyid = Some(key_id);
        Ok(signature)
    }
}

fn rpc_algorithm_for(a: Algorithm) -> RpcAlgorithm {
    match a {
        Algorithm::Ed25519 => RpcAlgorithm::ALGORITHM_ED25519,
        Algorithm::Secp256k1 => RpcAlgorithm::ALGORITHM_SECP256K1,
        Algorithm::P256 => RpcAlgorithm::ALGORITHM_P256,
    }
}

fn rpc_key_form_for(_a: Algorithm) -> KeyForm {
    // Default to RAW_BYTES — the file signer reads from disk; hardware
    // signers will populate `key_ref` with their own opaque handle and
    // ignore the form anyway.
    KeyForm::KEY_FORM_RAW_BYTES
}

fn read_frame_or_err<R: Read>(r: &mut R) -> Result<SignerFrame, Error> {
    match read_frame::<_, SignerFrame>(r) {
        Ok(f) => Ok(f),
        Err(FrameError::LengthTruncated) => Err(Error::ExternalSignerBadResponse(
            "child closed stdout before sending a frame".into(),
        )),
        Err(FrameError::LengthTooLarge(n)) => Err(Error::ExternalSignerBadResponse(format!(
            "frame length {n} exceeds 1 MiB cap"
        ))),
        Err(FrameError::BodyTruncated { expected, .. }) => Err(Error::ExternalSignerBadResponse(
            format!("frame body truncated (expected {expected} bytes)"),
        )),
        Err(FrameError::DecodeFailed) => Err(Error::ExternalSignerBadResponse(
            "frame failed to decode as SignerFrame".into(),
        )),
        Err(FrameError::Io(e)) => Err(Error::ExternalSignerSpawn(format!("read frame: {e}"))),
    }
}

fn extract_signature(frame: SignerFrame) -> Result<(Vec<u8>, String), Error> {
    match frame.body {
        Some(signer_frame::Body::SignResponse(sr)) => {
            let signature = sr.signature.ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing signature".into())
            })?;
            let key_id = sr.key_id.ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing key_id".into())
            })?;
            Ok((signature, key_id))
        }
        Some(signer_frame::Body::Error(e)) => {
            let msg = e.message.unwrap_or_default();
            Err(Error::ExternalSignerFailed(msg))
        }
        other => Err(Error::ExternalSignerBadResponse(format!(
            "expected SignResponse or Error, got {}",
            frame_name(&other),
        ))),
    }
}

fn frame_name(b: &Option<signer_frame::Body>) -> &'static str {
    use signer_frame::Body;
    match b {
        Some(Body::Hello(_)) => "hello",
        Some(Body::HelloResponse(_)) => "hello_response",
        Some(Body::SignRequest(_)) => "sign_request",
        Some(Body::SignResponse(_)) => "sign_response",
        Some(Body::PinPrompt(_)) => "pin_prompt",
        Some(Body::PinResponse(_)) => "pin_response",
        Some(Body::Error(_)) => "error",
        None => "(empty body)",
    }
}

fn drain_capped<R: Read>(mut r: R) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = r
            .read(&mut chunk)
            .map_err(|e| Error::ExternalSignerSpawn(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_STDERR_DRAIN {
            return Err(Error::ExternalSignerOutputTooLarge);
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_relative_path() {
        let err = ExternalSigner::new("mkit-signer").unwrap_err();
        assert!(matches!(err, Error::ExternalSignerRelativePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_absolute_path() {
        ExternalSigner::new("/usr/bin/foo").expect("absolute path accepted");
    }
}
