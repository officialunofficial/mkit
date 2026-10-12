//! A [`RemoteSource`] over [`mkit_client::Client`], for `mkit+https` and
//! `mkit+http` remotes.
//!
//! `mkit-client` is asynchronous and runtime-independent; the fetch engine is
//! synchronous. [`ClientSource`] joins them through an [`Executor`] that
//! drives one future to completion. The client is constructed by the caller,
//! anonymous or signed: an injected [`mkit_client::Signer`] and
//! [`mkit_client::Clock`] are what authenticate a private read, and nothing is
//! read from the environment or from user config.

use std::future::Future;

use mkit_client::{Client, Clock, Error as ClientError, HttpTransport, Signer};
use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, TransportError};
use mkit_core::refs::Ref;

use crate::source::RemoteSource;

/// Drives one future to completion on the calling thread.
pub trait Executor {
    /// Run `future` to completion.
    fn block_on<F: Future>(&self, future: F) -> F::Output;
}

/// An executor with no reactor, for transports whose futures need none (an
/// in-process or host-provided channel). A transport built on a runtime, such
/// as `NativeHttp`, is its own executor: pairing it (or `NativeClock`) with
/// this one panics at the first call, because there is no reactor to drive it.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuturesExecutor;

impl Executor for FuturesExecutor {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        futures_executor::block_on(future)
    }
}

/// Most pages of a branch listing followed before the listing is refused.
const MAX_LIST_PAGES: u32 = 4096;
/// A packmap node is small; this is the response cap `mkit-client` uses.
const NODE_LIMIT: u64 = 1024 * 1024;

/// The read side of a remote repository reached through a [`Client`]. The
/// engine calls it one operation at a time.
pub struct ClientSource<'a, T, S, C, E> {
    client: &'a Client<'a, T, S, C>,
    executor: &'a E,
}

impl<T, S, C, E> std::fmt::Debug for ClientSource<'_, T, S, C, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSource")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl<'a, T, S, C, E> ClientSource<'a, T, S, C, E> {
    /// `executor` drives every call. When the transport is built on an async
    /// runtime, pass the transport itself if it is an [`Executor`].
    #[must_use]
    pub fn new(client: &'a Client<'a, T, S, C>, executor: &'a E) -> Self {
        Self { client, executor }
    }
}

/// Map a client failure to the transport vocabulary the engine reports in.
/// A missing or invisible repository is `not_found` on the wire and maps to
/// [`TransportError::PackNotFound`], which the engine turns into a
/// repository-not-found error with the address.
fn transport_error(error: ClientError) -> TransportError {
    match error {
        ClientError::Remote(remote) => match remote.code.as_str() {
            "not_found" => TransportError::PackNotFound,
            "unauthenticated" | "permission_denied" => TransportError::AccessDenied,
            "failed_precondition" => TransportError::RefConflict,
            _ => TransportError::RemoteError(remote.message),
        },
        // Keep the cause: a refused redirect, an oversized or undecodable body,
        // a TLS failure and a timeout are different problems, and the first
        // two are deterministic, so they must not look like a retryable
        // connection failure.
        ClientError::Transport(cause) => TransportError::RemoteError(format!("transport: {cause}")),
        ClientError::PaymentRequired(required) => TransportError::AdmissionRequired(required),
        ClientError::Limit(_)
        | ClientError::Invalid(_)
        | ClientError::Pack(_)
        | ClientError::Packlist(_)
        | ClientError::Sink(_)
        | ClientError::Signature { .. } => TransportError::InvalidResponse,
        other => TransportError::RemoteError(other.to_string()),
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, E: Executor> RemoteSource
    for ClientSource<'_, T, S, C, E>
{
    fn list_branches(&self) -> Result<Vec<Ref>, TransportError> {
        let listed = self
            .executor
            .block_on(self.client.list_all_refs("refs/heads/", MAX_LIST_PAGES))
            .map_err(transport_error)?;
        Ok(listed
            .into_iter()
            .map(|named| Ref {
                name: named.name,
                hash: Some(named.id),
            })
            .collect())
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, TransportError> {
        self.executor
            .block_on(self.client.read_ref(name, None))
            .map(|reply| reply.value)
            .map_err(transport_error)
    }

    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.executor
            .block_on(
                self.client
                    .download_pack(&key.into_hash(), Some(ref_name), NODE_LIMIT, None),
            )
            .map(|reply| reply.value)
            .map_err(transport_error)
    }

    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.executor
            .block_on(self.client.download_pack(
                &key.into_hash(),
                Some(ref_name),
                mkit_core::protocol::PACK_BODY_LIMIT,
                None,
            ))
            .map(|reply| reply.value)
            .map_err(transport_error)
    }

    fn repository_address(&self) -> Option<(String, String)> {
        let destination = self.client.destination();
        Some((
            destination.repository().to_owned(),
            destination.origin().to_owned(),
        ))
    }
}
