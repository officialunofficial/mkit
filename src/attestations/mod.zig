// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Attestations — mkit's native, predicate-agnostic proof primitive.
//
// The format stack (see docs/SPEC-ATTESTATIONS.md):
//
//     ┌─ DSSE envelope ─────────────────────────────────────────────┐
//     │ payloadType = "application/vnd.in-toto+json"                │
//     │ payload     = base64(JCS(in-toto v1 Statement))             │
//     │ signatures  = [{ keyid, sig }, ...]                         │
//     └─────────────────────────────────────────────────────────────┘
//
// This module is the public face of the subsystem. Downstream consumers
// (and the `mkit attest` CLI) should import from here, not from the
// individual files — the file layout may be refactored.

const std = @import("std");

pub const jcs = @import("jcs.zig");
pub const statement = @import("statement.zig");
pub const envelope = @import("envelope.zig");
pub const store = @import("store.zig");

/// Re-exports so callers can write `attestations.Statement`, etc.
pub const Statement = statement.Statement;
pub const Subject = statement.Subject;
pub const Envelope = envelope.Envelope;
pub const Signature = envelope.Signature;
pub const DecodedEnvelope = envelope.DecodedEnvelope;

pub const IN_TOTO_TYPE = statement.IN_TOTO_TYPE;
pub const PAYLOAD_TYPE_IN_TOTO = envelope.PAYLOAD_TYPE_IN_TOTO;

/// The attestation ID is BLAKE3 over the canonical DSSE envelope bytes.
/// Re-exported for callers that only want the ID computation.
pub const attestationId = envelope.attestationId;

test {
    _ = jcs;
    _ = statement;
    _ = envelope;
    _ = store;
}
