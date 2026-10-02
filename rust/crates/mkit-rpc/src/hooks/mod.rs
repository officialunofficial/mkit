//! Public `mkit.server.hooks.v1` messages and `mkit-hook:v1` authentication.
//!
//! # Credential safety
//!
//! **Never log or Debug-print AdmitRequest, Header values, raw request bodies,
//! or responses containing payment credentials or receipts.** Generated Debug
//! implementations print every field. buffa 0.9.1 supports redaction through
//! the proto `debug_redact` option only; adding that option would modify the
//! frozen schema. This surface deliberately preserves the canonical schema.
//! Hook services must redact their own wrappers and bound reads before decoding.
//!
//! # Additive evolution
//!
//! Build messages with `..Default::default()` so new wire fields can be added
//! without changing callers. Decode JSON with serde_json; use buffa::Message
//! for protobuf. Signing and verification cover the exact received body bytes,
//! not a reserialized message. Verify required headers before reading a body,
//! then call HookVerifier::verify with all field lines and the receiving path.
//! Enable nonce replay protection for signed services; shared deployments must
//! provide equivalent replay protection across instances.

mod sign;
mod verify;

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/hooks/_hooks.rs"));
}

pub use proto::mkit::server::hooks::v1::*;
pub use sign::{DEFAULT_VALIDITY, DOMAIN, HookSigner, MAX_VALIDITY, SignerError};
pub use verify::{
    HookVerifier, KeyListError, MAX_CLOCK_LEAD_MS, Verified, VerifierKey, VerifyError,
};
