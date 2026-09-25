//! Storage-failure redaction (issue #794).
//!
//! A backend failure (R2, Durable Object, `SQLite` or filesystem error text)
//! can embed bucket keys, account ids or JS exception text. It goes to the
//! server-side log only; the client sees one fixed message per
//! [`StorageOp`] family. The mapping is exhaustive, so a new operation must
//! be given a public message explicitly.
//!
//! The canonical copy of `apps/vcs-worker/src/storage_error.rs`, with the
//! operations generalized from R2 and the ref-store Durable Object to any
//! blob or metadata store. The old copy goes when `vcs-worker` switches in
//! WP-M0-17. `apps/repo-worker` keeps its own copy (planner decision Q11).

use std::fmt;

use crate::error::ServerError;

/// A storage-backend operation that can fail. It names what failed in the
/// server-side log line and picks the client-facing message; the backend's
/// own error text never reaches the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageOp {
    /// Resolving the blob store (for example an R2 bucket binding) failed.
    BlobBinding,
    /// A blob write failed.
    BlobPut,
    /// A blob read request failed.
    BlobGet,
    /// Reading a blob's body failed, or the body was missing.
    BlobRead,
    /// A blob existence check failed.
    BlobHead,
    /// Resolving the metadata store (for example a Durable Object binding)
    /// failed.
    MetaBinding,
    /// Deriving or fetching a metadata-store stub failed.
    MetaStub,
    /// Building a metadata-store request failed.
    MetaRequest,
    /// The metadata-store call itself failed (a network or runtime error,
    /// not an error answer from the store).
    MetaCall,
    /// Decoding a metadata-store response failed.
    MetaDecode,
    /// Serializing an outgoing request body failed. Our own request, so it
    /// never carries backend detail.
    RequestSerialize,
    /// A SQL statement failed.
    SqlExec,
    /// A filesystem operation failed.
    FsIo,
}

impl StorageOp {
    /// Every variant, for exhaustive checks.
    pub const ALL: [Self; 13] = [
        Self::BlobBinding,
        Self::BlobPut,
        Self::BlobGet,
        Self::BlobRead,
        Self::BlobHead,
        Self::MetaBinding,
        Self::MetaStub,
        Self::MetaRequest,
        Self::MetaCall,
        Self::MetaDecode,
        Self::RequestSerialize,
        Self::SqlExec,
        Self::FsIo,
    ];

    /// Label for the server-side log line only.
    const fn label(self) -> &'static str {
        match self {
            Self::BlobBinding => "blob store binding",
            Self::BlobPut => "blob put",
            Self::BlobGet => "blob get",
            Self::BlobRead => "blob read",
            Self::BlobHead => "blob head",
            Self::MetaBinding => "metadata store binding",
            Self::MetaStub => "metadata store stub",
            Self::MetaRequest => "metadata store request build",
            Self::MetaCall => "metadata store call",
            Self::MetaDecode => "metadata store decode",
            Self::RequestSerialize => "request serialize",
            Self::SqlExec => "sql exec",
            Self::FsIo => "filesystem io",
        }
    }

    /// The fixed client-facing message for this operation's family. It never
    /// depends on the underlying error.
    #[must_use]
    pub const fn public_message(self) -> &'static str {
        match self {
            Self::BlobBinding | Self::BlobPut | Self::BlobGet | Self::BlobRead | Self::BlobHead => {
                "object storage request failed"
            }
            Self::MetaBinding
            | Self::MetaStub
            | Self::MetaRequest
            | Self::MetaCall
            | Self::MetaDecode
            | Self::SqlExec => "ref store request failed",
            Self::RequestSerialize => "internal request encoding failed",
            Self::FsIo => "storage request failed",
        }
    }
}

/// The server-side log line and the client-facing error for a failed
/// storage operation.
///
/// `detail`, the backend's raw error, appears only in the log line and in
/// the error's redacted [`ServerError::log_detail`]. The public message is
/// always [`StorageOp::public_message`], with code
/// [`crate::Code::Internal`].
#[must_use]
pub fn describe_and_map(op: StorageOp, detail: impl fmt::Display) -> (String, ServerError) {
    let log_line = format!("{}: {detail}", op.label());
    let err = ServerError::internal(op.public_message(), &log_line);
    (log_line, err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;

    // Ported from apps/vcs-worker/src/storage_error.rs, with the fourth
    // message added for `FsIo`.
    #[test]
    fn every_op_maps_to_one_of_the_fixed_generic_messages() {
        const ALLOWED: &[&str] = &[
            "object storage request failed",
            "ref store request failed",
            "internal request encoding failed",
            "storage request failed",
        ];
        for op in StorageOp::ALL {
            assert!(
                ALLOWED.contains(&op.public_message()),
                "{op:?} has an unexpected client message: {}",
                op.public_message()
            );
        }
    }

    // Ported from apps/vcs-worker/src/storage_error.rs: the regression test
    // for issue #794.
    #[test]
    fn simulated_storage_failure_is_logged_but_never_reaches_the_client() {
        let raw_detail = "R2Error: bucket 'mkit-prod-packs-9c1e' access denied \
            for account 4f8e21a9-c3b2-4d11-9e77-1a2b3c4d5e6f \
            (JsValue: TypeError at fetch_r2_binding@worker.js:1842)";

        for op in StorageOp::ALL {
            let (log_line, err) = describe_and_map(op, raw_detail);
            assert!(
                log_line.contains(raw_detail),
                "{op:?}: log line dropped the real error detail: {log_line:?}"
            );
            assert_eq!(err.code(), Code::Internal);
            assert_eq!(err.public_message(), op.public_message());
            assert_eq!(err.log_detail(), Some(log_line.as_str()));
            let shown = [format!("{err}"), format!("{err:?}"), format!("{err:#?}")];
            for client in [err.public_message()]
                .into_iter()
                .chain(shown.iter().map(String::as_str))
            {
                for secret in [
                    raw_detail,
                    "mkit-prod-packs-9c1e",
                    "4f8e21a9-c3b2-4d11-9e77-1a2b3c4d5e6f",
                    "worker.js",
                ] {
                    assert!(
                        !client.contains(secret),
                        "{op:?} leaked {secret:?}: {client}"
                    );
                }
            }
        }
    }
}
