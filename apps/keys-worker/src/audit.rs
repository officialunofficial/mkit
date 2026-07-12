// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Accepted/rejected-write audit-record derivation for `PUT /name/<pubkey>` —
// keys-worker's only write. Pure and host-testable, mirroring
// apps/repo-worker/src/audit.rs's split (decision logic here, Analytics
// Engine I/O in lib.rs's `set_name`) so `cargo test` catches a regression in
// what gets logged without needing a live/mocked Workers runtime.
//
// keys-worker has no interceptor (see #695's Implementation Notes — its
// single signed handler validates the envelope inline), so this module is
// called directly from `set_name` rather than from a shared middleware.
//
// Deliberately excluded: the raw signature, the full envelope body, and any
// other header material beyond what's below.

use crate::envelope::VerifyEnvelope;

/// One structured accepted/rejected-write record for `PUT /name/<pubkey>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteAudit {
    Accepted {
        procedure: String,
        signer_pubkey: String,
        bytes: u64,
    },
    Rejected {
        procedure: String,
        reason: String,
        status: u16,
    },
}

impl WriteAudit {
    /// Build the record for an accepted write (`VerifyEnvelope::Ok`).
    #[must_use]
    pub fn accepted(procedure: &str, signer_pubkey: &str, bytes: u64) -> Self {
        WriteAudit::Accepted {
            procedure: procedure.to_owned(),
            signer_pubkey: signer_pubkey.to_owned(),
            bytes,
        }
    }

    /// Build the record for a rejected write (`VerifyEnvelope::Err`).
    #[must_use]
    pub fn rejected(procedure: &str, status: u16, reason: &str) -> Self {
        WriteAudit::Rejected {
            procedure: procedure.to_owned(),
            reason: reason.to_owned(),
            status,
        }
    }
}

/// Derive the audit outcome straight from a `verify_envelope` result — the
/// SAME decision `set_name` makes to pick `Response::ok` vs
/// `Response::error`, reused here so the logged outcome can never drift from
/// the enforced one.
#[must_use]
pub fn audit_for(procedure: &str, bytes: u64, result: &VerifyEnvelope) -> WriteAudit {
    match result {
        VerifyEnvelope::Ok { public_key } => WriteAudit::accepted(procedure, public_key, bytes),
        VerifyEnvelope::Err { status, error } => WriteAudit::rejected(procedure, *status, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCEDURE: &str = "/mkit.keys.v1.Keys/SetName";

    #[test]
    fn accepted_carries_procedure_pubkey_bytes() {
        let audit = WriteAudit::accepted(PROCEDURE, "ab".repeat(32).as_str(), 64);
        assert_eq!(
            audit,
            WriteAudit::Accepted {
                procedure: PROCEDURE.to_owned(),
                signer_pubkey: "ab".repeat(32),
                bytes: 64,
            }
        );
    }

    #[test]
    fn rejected_carries_procedure_reason_status_and_no_pubkey() {
        let audit = WriteAudit::rejected(PROCEDURE, 401, "invalid signature");
        assert_eq!(
            audit,
            WriteAudit::Rejected {
                procedure: PROCEDURE.to_owned(),
                reason: "invalid signature".to_owned(),
                status: 401,
            }
        );
        // Type-level guarantee: `Rejected` has no signer_pubkey field to
        // accidentally populate from an unverified request.
        match audit {
            WriteAudit::Rejected { .. } => {}
            WriteAudit::Accepted { .. } => panic!("rejected envelope must not produce Accepted"),
        }
    }

    #[test]
    fn audit_for_ok_builds_accepted() {
        let ok = VerifyEnvelope::Ok {
            public_key: "cd".repeat(32),
        };
        let audit = audit_for(PROCEDURE, 17, &ok);
        assert_eq!(
            audit,
            WriteAudit::Accepted {
                procedure: PROCEDURE.to_owned(),
                signer_pubkey: "cd".repeat(32),
                bytes: 17,
            }
        );
    }

    #[test]
    fn audit_for_err_builds_rejected() {
        let err = VerifyEnvelope::Err {
            status: 400,
            error: "body digest mismatch",
        };
        let audit = audit_for(PROCEDURE, 17, &err);
        assert_eq!(
            audit,
            WriteAudit::Rejected {
                procedure: PROCEDURE.to_owned(),
                reason: "body digest mismatch".to_owned(),
                status: 400,
            }
        );
    }
}
