// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Generic, non-leaking client-facing error mapping for this Worker's R2/DO
// storage-layer calls (`worker_impl/service.rs`).
//
// Mirrors `mkit-transport-connect::error::map_transport_error`'s pattern: an
// explicit, exhaustive mapping from an internal error category onto the
// Connect error the client actually sees, so a real backend failure (R2/DO
// SDK text — which can embed bucket keys, JS exception text, or other
// backend detail) never reaches the client verbatim. Before this module
// existed, `service.rs` mapped every storage failure via
// `format!("R2 put: {e}")`-style strings straight into
// `ConnectError::internal`, leaking that detail (issue #794).
//
// This lives OUTSIDE `worker_impl` (which is `#[cfg(target_arch =
// "wasm32")]`-gated) specifically so the mapping is host-testable under
// plain `cargo test --lib` — mirrors the same split in apps/repo-worker.

use connectrpc::ConnectError;

/// Every storage/DO-backend operation `service.rs` performs. Each variant
/// identifies *what* failed — used only in the server-side log line
/// `describe_and_map` builds, never sent to the client. Keeping this
/// exhaustively matched (see `client_message` below) means a new operation
/// added later must be assigned a client message explicitly, the same
/// "can't silently fall through unmapped" property
/// `mkit-transport-connect::error::map_transport_error`'s doc comment calls
/// out for its own mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOp {
    /// `env.bucket(STORAGE_BUCKET)` failed to resolve (misconfigured binding).
    StorageBinding,
    /// An R2 `put` (write) failed.
    R2Put,
    /// An R2 `get` (read) failed.
    R2Get,
    /// Reading an R2 object's body bytes (or a missing body) failed.
    R2Read,
    /// An R2 `head` (existence check) failed.
    R2Head,
    /// `env.durable_object(REFSTORE_BINDING)` failed to resolve.
    RefstoreBinding,
    /// Deriving or fetching the RefStore DO stub (`id_from_name`/`get_stub`)
    /// failed.
    RefstoreStub,
    /// Building the JSON POST request to the DO failed.
    RefstoreRequest,
    /// The DO `fetch_with_request` call itself failed (network/JS error, not
    /// an HTTP 4xx/5xx from the DO, which is handled separately as
    /// `invalid_argument`).
    RefstoreFetch,
    /// Decoding the DO's JSON response body failed.
    RefstoreDecode,
    /// Serializing an outgoing DO request body to JSON failed (this is our
    /// own request, not backend detail — grouped separately since it can
    /// never actually contain SDK/bucket detail).
    RequestSerialize,
}

impl StorageOp {
    /// Every variant — used by tests to exhaustively check the mapping.
    #[cfg(test)]
    const ALL: &'static [StorageOp] = &[
        StorageOp::StorageBinding,
        StorageOp::R2Put,
        StorageOp::R2Get,
        StorageOp::R2Read,
        StorageOp::R2Head,
        StorageOp::RefstoreBinding,
        StorageOp::RefstoreStub,
        StorageOp::RefstoreRequest,
        StorageOp::RefstoreFetch,
        StorageOp::RefstoreDecode,
        StorageOp::RequestSerialize,
    ];

    /// Label for the server-side log line ONLY — never sent to the client.
    fn label(self) -> &'static str {
        match self {
            StorageOp::StorageBinding => "STORAGE binding",
            StorageOp::R2Put => "R2 put",
            StorageOp::R2Get => "R2 get",
            StorageOp::R2Read => "R2 read",
            StorageOp::R2Head => "R2 head",
            StorageOp::RefstoreBinding => "REFSTORE binding",
            StorageOp::RefstoreStub => "REFSTORE stub",
            StorageOp::RefstoreRequest => "REFSTORE request build",
            StorageOp::RefstoreFetch => "REFSTORE fetch",
            StorageOp::RefstoreDecode => "REFSTORE decode",
            StorageOp::RequestSerialize => "request serialize",
        }
    }

    /// The ONE client-facing message for this operation's family — a small,
    /// fixed set of generic strings that never varies with the underlying
    /// error's actual content.
    fn client_message(self) -> &'static str {
        match self {
            StorageOp::StorageBinding
            | StorageOp::R2Put
            | StorageOp::R2Get
            | StorageOp::R2Read
            | StorageOp::R2Head => "object storage request failed",
            StorageOp::RefstoreBinding
            | StorageOp::RefstoreStub
            | StorageOp::RefstoreRequest
            | StorageOp::RefstoreFetch
            | StorageOp::RefstoreDecode => "ref store request failed",
            StorageOp::RequestSerialize => "internal request encoding failed",
        }
    }
}

/// Build the server-side log line and the client-facing [`ConnectError`] for
/// a failed storage/DO operation.
///
/// `detail` — the raw underlying error (R2/DO SDK text, which can embed
/// bucket keys, account ids, JS stack fragments, etc.) — is folded into the
/// RETURNED log line only. The `ConnectError`'s message is always exactly
/// `op.client_message()`, a fixed string that does not depend on `detail` in
/// any way; the function signature itself is the guarantee that `detail`
/// cannot leak into the client-facing half of the return value.
///
/// The only real caller is `worker_impl::service::ce_storage`, which logs
/// the returned line via `worker::console_error!` (wasm32-only) and returns
/// the `ConnectError` to the client.
#[must_use]
pub fn describe_and_map(op: StorageOp, detail: impl std::fmt::Display) -> (String, ConnectError) {
    let log_line = format!("{}: {detail}", op.label());
    (log_line, ConnectError::internal(op.client_message()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_op_maps_to_one_of_the_fixed_generic_messages() {
        const ALLOWED: &[&str] = &[
            "object storage request failed",
            "ref store request failed",
            "internal request encoding failed",
        ];
        for &op in StorageOp::ALL {
            assert!(
                ALLOWED.contains(&op.client_message()),
                "{op:?} has an unexpected client message: {}",
                op.client_message()
            );
        }
    }

    /// The core regression test for issue #794: a simulated storage/SDK
    /// failure — with bucket names, account ids, and JS-style error text, the
    /// kind of detail a real `worker::Error`'s `Display` embeds — must be
    /// captured in the server-side log line but must NEVER appear, in whole
    /// or in part, in the client-facing `ConnectError` message.
    #[test]
    fn simulated_storage_failure_is_logged_but_never_reaches_the_client() {
        let raw_detail = "R2Error: bucket 'mkit-prod-packs-9c1e' access denied \
            for account 4f8e21a9-c3b2-4d11-9e77-1a2b3c4d5e6f \
            (JsValue: TypeError at fetch_r2_binding@worker.js:1842)";

        for &op in StorageOp::ALL {
            let (log_line, err) = describe_and_map(op, raw_detail);

            // The server-side log line captures the real error...
            assert!(
                log_line.contains(raw_detail),
                "{op:?}: log line dropped the real error detail: {log_line:?}"
            );

            // ...but the client-facing message never does, in whole...
            let client_msg = err.message.clone().unwrap_or_default();
            assert!(
                !client_msg.contains(raw_detail),
                "{op:?}: leaked the full raw storage error to the client: {client_msg:?}"
            );
            // ...or in any distinguishing part (bucket name, account id).
            assert!(
                !client_msg.contains("mkit-prod-packs-9c1e"),
                "{op:?}: leaked the bucket name to the client: {client_msg:?}"
            );
            assert!(
                !client_msg.contains("4f8e21a9-c3b2-4d11-9e77-1a2b3c4d5e6f"),
                "{op:?}: leaked the account id to the client: {client_msg:?}"
            );
            assert!(
                !client_msg.contains("worker.js"),
                "{op:?}: leaked JS stack detail to the client: {client_msg:?}"
            );
            assert_eq!(err.code, connectrpc::ErrorCode::Internal);
        }
    }
}
