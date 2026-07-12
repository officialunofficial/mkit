// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Accepted/rejected-write audit-record derivation for the write path
// (PutObject / UpdateRef / PostMessage / React). Pure and host-testable —
// deliberately kept OUT of `worker_impl` (which is
// `#[cfg(target_arch = "wasm32")]`-gated end to end for its Durable Object /
// `#[event(fetch)]` macros) so a regression in *what gets logged* is caught
// by `cargo test` on every contributor's machine and in CI, not only on a
// live Cloudflare deploy. `worker_impl::auth::AuthInterceptor` calls
// `WriteAudit::accepted`/`rejected` and nothing else to decide what to write
// to Analytics Engine — see its module doc.
//
// Deliberately excluded: the raw signature, the full envelope body, and any
// other header material beyond what's below (see issue #695 "Implementation
// Notes" — do not duplicate sensitive header material into Analytics
// Engine).

use crate::envelope::VerifyEnvelope;

/// One structured accepted/rejected-write record.
///
/// `Accepted` only exists for a write whose envelope verified: `room` is
/// read from the request body's `room` field, which is only trustworthy
/// once the signature over that body has checked out. A `Rejected` write's
/// envelope did NOT verify, so no room is logged (and none is decoded) —
/// `procedure`/`reason`/`status` is enough to see credential-stuffing or
/// envelope-forgery probing against the write path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteAudit {
    Accepted {
        room: String,
        procedure: String,
        author_pubkey: String,
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
    pub fn accepted(procedure: &str, room: &str, author_pubkey: &str, bytes: u64) -> Self {
        WriteAudit::Accepted {
            room: room.to_owned(),
            procedure: procedure.to_owned(),
            author_pubkey: author_pubkey.to_owned(),
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
/// SAME decision `AuthInterceptor` makes to pick `ConnectError::invalid_argument`
/// vs `unauthenticated`, reused here so the logged outcome can never drift
/// from the enforced one. `room`/`bytes` are only consulted on `Ok` (see
/// `WriteAudit` doc); callers pass a closure for `room` because reading it
/// requires decoding the request payload, which is wasted work on the
/// (unauthenticated) rejection path.
#[must_use]
pub fn audit_for(
    procedure: &str,
    bytes: u64,
    result: &VerifyEnvelope,
    room: impl FnOnce() -> String,
) -> WriteAudit {
    match result {
        VerifyEnvelope::Ok { public_key, .. } => {
            WriteAudit::accepted(procedure, &room(), public_key, bytes)
        }
        VerifyEnvelope::Err { status, error } => WriteAudit::rejected(procedure, *status, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCEDURE: &str = "/mkit.repo.v1.RepoService/UpdateRef";

    #[test]
    fn accepted_carries_room_procedure_pubkey_bytes() {
        let audit = WriteAudit::accepted(PROCEDURE, "lobby", "ab".repeat(32).as_str(), 128);
        assert_eq!(
            audit,
            WriteAudit::Accepted {
                room: "lobby".to_owned(),
                procedure: PROCEDURE.to_owned(),
                author_pubkey: "ab".repeat(32),
                bytes: 128,
            }
        );
    }

    #[test]
    fn rejected_carries_procedure_reason_status_and_no_room_or_pubkey() {
        let audit = WriteAudit::rejected(PROCEDURE, 401, "invalid signature");
        assert_eq!(
            audit,
            WriteAudit::Rejected {
                procedure: PROCEDURE.to_owned(),
                reason: "invalid signature".to_owned(),
                status: 401,
            }
        );
        // Type-level guarantee, not just a runtime check: `Rejected` has no
        // room/author_pubkey field to accidentally populate from an
        // unverified body.
        match audit {
            WriteAudit::Rejected { .. } => {}
            WriteAudit::Accepted { .. } => panic!("rejected envelope must not produce Accepted"),
        }
    }

    #[test]
    fn audit_for_ok_calls_room_and_builds_accepted() {
        let ok = VerifyEnvelope::Ok {
            public_key: "cd".repeat(32),
            body_digest: "ef".repeat(32),
            idempotency_key: "idem-1".to_owned(),
        };
        let mut room_calls = 0;
        let audit = audit_for(PROCEDURE, 42, &ok, || {
            room_calls += 1;
            "room-a".to_owned()
        });
        assert_eq!(
            room_calls, 1,
            "room() must be called exactly once on the accepted path"
        );
        assert_eq!(
            audit,
            WriteAudit::Accepted {
                room: "room-a".to_owned(),
                procedure: PROCEDURE.to_owned(),
                author_pubkey: "cd".repeat(32),
                bytes: 42,
            }
        );
    }

    #[test]
    fn audit_for_err_never_calls_room_and_builds_rejected() {
        let err = VerifyEnvelope::Err {
            status: 400,
            error: "body digest mismatch",
        };
        let audit = audit_for(PROCEDURE, 42, &err, || {
            panic!(
                "room() must not be called on the rejected path — the body isn't authenticated yet"
            )
        });
        assert_eq!(
            audit,
            WriteAudit::Rejected {
                procedure: PROCEDURE.to_owned(),
                reason: "body digest mismatch".to_owned(),
                status: 400,
            }
        );
    }

    #[test]
    fn different_procedures_produce_different_records() {
        let ok = VerifyEnvelope::Ok {
            public_key: "11".repeat(32),
            body_digest: "22".repeat(32),
            idempotency_key: String::new(),
        };
        let put = audit_for("/mkit.repo.v1.RepoService/PutObject", 1, &ok, || {
            "r".to_owned()
        });
        let update = audit_for("/mkit.repo.v1.RepoService/UpdateRef", 1, &ok, || {
            "r".to_owned()
        });
        assert_ne!(put, update);
    }
}
