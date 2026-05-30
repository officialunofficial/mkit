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

use mkit_rpc::mkit::rpc::v1::signer::{
    Hello, SignRequest, SignResponse, SignerFrame, signer_frame,
};
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
                extract_signature(next, self.algorithm, pae)?
            }
            Some(signer_frame::Body::SignResponse(_) | signer_frame::Body::Error(_)) => {
                extract_signature(resp, self.algorithm, pae)?
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
        // External-signer dispatch for BLS threshold isn't wired
        // yet — the Phase-1 holder runs in-process. But the proto
        // wire integer is reserved so a future external signer can
        // claim ALGORITHM_BLS12381_THRESHOLD and the mapping
        // already exists.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => RpcAlgorithm::ALGORITHM_BLS12381_THRESHOLD,
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

fn extract_signature(
    frame: SignerFrame,
    expected_algorithm: Algorithm,
    pae: &[u8],
) -> Result<(Vec<u8>, String), Error> {
    match frame.body {
        Some(signer_frame::Body::SignResponse(sr)) => {
            let signature = sr.signature.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing signature".into())
            })?;
            let key_id = sr.key_id.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing key_id".into())
            })?;
            validate_sign_response(&sr, expected_algorithm, pae, &signature, &key_id)?;
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

fn validate_sign_response(
    sr: &SignResponse,
    expected_algorithm: Algorithm,
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    let actual_algorithm = sr
        .algorithm
        .as_ref()
        .ok_or_else(|| Error::ExternalSignerBadResponse("SignResponse missing algorithm".into()))?
        .to_i32();
    let expected_rpc = rpc_algorithm_for(expected_algorithm) as i32;
    if actual_algorithm != expected_rpc {
        return Err(Error::ExternalSignerBadResponse(format!(
            "SignResponse algorithm mismatch: got {actual_algorithm}, expected {expected_rpc}"
        )));
    }

    if sr.webauthn.is_set() {
        return Ok(());
    }

    let public_key = sr.public_key.as_deref().ok_or_else(|| {
        Error::ExternalSignerBadResponse("SignResponse missing public_key".into())
    })?;

    match expected_algorithm {
        Algorithm::Ed25519 => validate_ed25519_response(public_key, pae, signature, key_id),
        Algorithm::Secp256k1 => validate_secp256k1_response(public_key, pae, signature, key_id),
        Algorithm::P256 => validate_p256_response(public_key, pae, signature, key_id),
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Ok(()),
    }
}

fn validate_ed25519_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-ed25519")]
    {
        use crate::verify::{Reason, verify_ed25519};

        let pk: [u8; 32] = public_key.try_into().map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a 32-byte Ed25519 key".into(),
            )
        })?;
        if verify_ed25519(pk, signature, pae) != Reason::Ok {
            return Err(Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            ));
        }

        let digest = mkit_core::hash::hash(public_key);
        let blake3_keyid = format!("blake3:{}", mkit_core::hash::to_hex(&digest));
        let raw_keyid = format!("ed25519:{}", hex_lower(public_key));
        require_matching_canonical_keyid(
            key_id,
            &[("blake3", &blake3_keyid), ("ed25519", &raw_keyid)],
        )
    }
    #[cfg(not(feature = "algo-ed25519"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::Ed25519))
    }
}

fn validate_secp256k1_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-secp256k1")]
    {
        use crate::signer_k256::verify_secp256k1;
        use k256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a valid secp256k1 SEC1 key".into(),
            )
        })?;
        verify_secp256k1(public_key, pae, signature).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            )
        })?;

        let compressed = vk.to_encoded_point(true);
        let canonical = format!("secp256k1:{}", hex_lower(compressed.as_bytes()));
        require_matching_canonical_keyid(key_id, &[("secp256k1", &canonical)])
    }
    #[cfg(not(feature = "algo-secp256k1"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::Secp256k1))
    }
}

fn validate_p256_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-p256")]
    {
        use crate::signer_p256::verify_p256;
        use p256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a valid P-256 SEC1 key".into(),
            )
        })?;
        verify_p256(public_key, pae, signature).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            )
        })?;

        let compressed = vk.to_encoded_point(true);
        let canonical = format!("p256:{}", hex_lower(compressed.as_bytes()));
        require_matching_canonical_keyid(key_id, &[("p256", &canonical)])
    }
    #[cfg(not(feature = "algo-p256"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::P256))
    }
}

fn require_matching_canonical_keyid(
    key_id: &str,
    canonical_by_prefix: &[(&str, &str)],
) -> Result<(), Error> {
    let Some((prefix, _)) = key_id.split_once(':') else {
        return Ok(());
    };
    if let Some((_, canonical)) = canonical_by_prefix
        .iter()
        .find(|(canonical_prefix, _)| *canonical_prefix == prefix)
        && key_id != *canonical
    {
        return Err(Error::ExternalSignerBadResponse(format!(
            "SignResponse key_id mismatch: got {key_id}, expected {canonical}"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
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
    use mkit_rpc::mkit::rpc::v1::Algorithm as RpcAlgorithm;
    use mkit_rpc::mkit::rpc::v1::signer::WebAuthnData;

    const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

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

    #[cfg(feature = "algo-ed25519")]
    fn ed25519_response(key_id: String) -> (SignResponse, Vec<u8>, String) {
        use ed25519_dalek::{Signer as _, SigningKey};

        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sig = sk.sign(PAE).to_bytes().to_vec();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(pk)
            .with_algorithm(RpcAlgorithm::ALGORITHM_ED25519)
            .with_key_id(key_id.clone());
        (sr, sig, key_id)
    }

    #[cfg(feature = "algo-ed25519")]
    fn ed25519_keyid(public_key: &[u8]) -> String {
        let digest = mkit_core::hash::hash(public_key);
        format!("blake3:{}", mkit_core::hash::to_hex(&digest))
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_algorithm_mismatch() {
        let (mut sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        sr.algorithm = Some(RpcAlgorithm::ALGORITHM_P256.into());

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("algorithm mismatch"));
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_missing_public_key_for_raw_response() {
        let (mut sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        sr.public_key = None;

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("missing public_key"));
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_allows_webauthn_response_without_raw_public_key() {
        let key_id = "opaque:ctap".to_owned();
        let signature = vec![0u8; 64];
        let mut sr = SignResponse::default()
            .with_signature(signature.clone())
            .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
            .with_key_id(key_id.clone());
        sr.webauthn = buffa::MessageField::some(
            WebAuthnData::default()
                .with_authenticator_data(vec![0u8; 37])
                .with_client_data_json(b"{}".to_vec()),
        );

        validate_sign_response(&sr, Algorithm::P256, PAE, &signature, &key_id)
            .expect("WebAuthn response preserves hardware compatibility");
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_signature_mismatch() {
        let (mut sr, mut sig, key_id) = ed25519_response("opaque:test".to_owned());
        sig[0] ^= 0x01;
        sr.signature = Some(sig.clone());

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("signature does not verify"));
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_checks_ed25519_canonical_keyids_but_allows_opaque() {
        let (sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id)
            .expect("opaque key_id remains allowed");

        let public_key = sr.public_key.as_deref().unwrap();
        let canonical_keyid = ed25519_keyid(public_key);
        let (sr, sig, key_id) = ed25519_response(canonical_keyid);
        validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id)
            .expect("canonical key_id matches returned public key");

        let (sr, sig, key_id) = ed25519_response("blake3:00".to_owned());
        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }

    #[cfg(feature = "algo-secp256k1")]
    #[test]
    fn response_validation_checks_secp256k1_canonical_keyid() {
        use crate::signer_k256::Secp256k1Signer;

        let mut secret = [0u8; 32];
        secret[31] = 7;
        let signer = Secp256k1Signer::new(secret).unwrap();
        let sig = signer.sign_dsse(PAE).unwrap();
        let key_id = signer.keyid_string();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::ALGORITHM_SECP256K1)
            .with_key_id(key_id.clone());
        validate_sign_response(&sr, Algorithm::Secp256k1, PAE, &sig, &key_id)
            .expect("canonical secp256k1 key_id matches returned public key");

        let bad_key_id = "secp256k1:00".to_owned();
        let bad = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::ALGORITHM_SECP256K1)
            .with_key_id(bad_key_id.clone());
        let err =
            validate_sign_response(&bad, Algorithm::Secp256k1, PAE, &sig, &bad_key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_checks_p256_canonical_keyid() {
        use crate::signer_p256::P256Signer;

        let secret = [0x33; 32];
        let signer = P256Signer::new(secret).unwrap();
        let sig = signer.sign_dsse(PAE).unwrap();
        let key_id = signer.keyid();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
            .with_key_id(key_id.clone());
        validate_sign_response(&sr, Algorithm::P256, PAE, &sig, &key_id)
            .expect("canonical P-256 key_id matches returned public key");

        let bad_key_id = "p256:00".to_owned();
        let bad = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
            .with_key_id(bad_key_id.clone());
        let err =
            validate_sign_response(&bad, Algorithm::P256, PAE, &sig, &bad_key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }
}
