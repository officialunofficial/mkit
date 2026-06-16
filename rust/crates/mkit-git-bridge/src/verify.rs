//! Shallow signature verification (SPEC-GIT-BRIDGE §10).
//!
//! Shallow mode rebuilds the mkit object from a single bridge-emitted
//! git commit/tag (self-contained: the carried headers include the
//! mkit tree/parent/target hashes) and checks its Ed25519 signature
//! under the proper domain via mkit-core's strict verifier. It proves
//! the carried fields are exactly what the original signer signed; it
//! does NOT prove the surrounding git graph corresponds to those
//! BLAKE3 hashes — that is deep verification (full [`crate::reconstruct`]
//! over the closure, driven by the caller).

use crate::error::BridgeError;
use crate::gitobj::{GitObject, GitType};
use crate::reconstruct;
use mkit_core::object::Object;

/// Outcome of a shallow check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShallowVerdict {
    /// Signature verifies under the object's signing domain.
    Verified,
    /// All-zero signature: the unsigned convention (SPEC-SIGNING §4a).
    /// Report as "unsigned", never as tampered.
    Unsigned,
    /// A non-zero signature that does not verify.
    Failed,
}

/// Shallow-verify a bridge-emitted git commit or tag.
pub fn shallow_verify(obj: &GitObject) -> Result<ShallowVerdict, BridgeError> {
    let rec = match obj.gtype {
        GitType::Commit => reconstruct::reconstruct_commit(&obj.body)?,
        GitType::Tag => reconstruct::reconstruct_tag(&obj.body)?,
        GitType::Blob | GitType::Tree => {
            return Err(BridgeError::NotBridgeObject(
                "shallow verification applies to commits and tags only".into(),
            ));
        }
    };
    Ok(match rec.object {
        Object::Commit(ref c) => {
            if c.signature == [0u8; 64] {
                ShallowVerdict::Unsigned
            } else if mkit_core::sign::verify_commit(c).is_ok() {
                ShallowVerdict::Verified
            } else {
                ShallowVerdict::Failed
            }
        }
        Object::Tag(ref t) => {
            if t.signature == [0u8; 64] {
                ShallowVerdict::Unsigned
            } else if mkit_core::sign::verify_tag(t).is_ok() {
                ShallowVerdict::Verified
            } else {
                ShallowVerdict::Failed
            }
        }
        _ => unreachable!("reconstruct_commit/tag return Commit/Tag"),
    })
}
