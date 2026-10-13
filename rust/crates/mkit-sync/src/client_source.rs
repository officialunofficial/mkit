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
const MAX_LIST_PAGES: u32 = 100_000;
/// Cumulative size (names plus 32-byte ids) a listing may reach before it is
/// refused, as in the Connect transport.
const MAX_LISTED_BYTES: usize = 128 * 1024 * 1024;
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
///
/// A transport failure keeps its cause as `RemoteError("transport: ...")`, not
/// a retryable connection failure: the channel's refusals (an oversized or
/// undecodable body, a refused redirect) are deterministic, so match on
/// `RemoteError` rather than expecting `ConnectionFailed`.
/// A missing or invisible repository is `not_found` on the wire and maps to
/// [`TransportError::PackNotFound`], which the engine turns into a
/// repository-not-found error with the address.
fn transport_error(error: ClientError) -> TransportError {
    match error {
        ClientError::Remote(remote) => match remote.code.as_str() {
            "not_found" => TransportError::PackNotFound,
            "unauthenticated" | "permission_denied" => TransportError::AccessDenied,
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
        // The same checks as the Connect transport's listing: names strictly
        // ascending within and across pages (so no duplicate branch reaches the
        // engine), a cumulative size cap, and no repeated cursor.
        let mut out: Vec<Ref> = Vec::new();
        let mut token = String::new();
        let mut seen = std::collections::HashSet::new();
        let mut listed_bytes = 0usize;
        for _ in 0..MAX_LIST_PAGES {
            let reply = self
                .executor
                .block_on(self.client.list_refs("refs/heads/", 0, &token, None))
                .map_err(transport_error)?
                .value;
            let next = reply.next_page_token;
            let page: Vec<Ref> = reply
                .refs
                .into_iter()
                .map(|named| Ref {
                    name: named.name,
                    hash: Some(named.id),
                })
                .collect();
            let overlaps = matches!(
                (out.last(), page.first()),
                (Some(last), Some(first)) if first.name <= last.name
            );
            if overlaps || page.windows(2).any(|pair| pair[0].name >= pair[1].name) {
                return Err(TransportError::InvalidResponse);
            }
            listed_bytes = page.iter().fold(listed_bytes, |total, r| {
                total.saturating_add(r.name.len()).saturating_add(32)
            });
            if listed_bytes > MAX_LISTED_BYTES {
                return Err(TransportError::InvalidResponse);
            }
            out.extend(page);
            match next {
                None => return Ok(out),
                // Any repeated cursor, not only the previous one, is a cycle.
                Some(next) if !seen.insert(next.clone()) => {
                    return Err(TransportError::InvalidResponse);
                }
                Some(next) => token = next,
            }
        }
        Err(TransportError::InvalidResponse)
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

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use http::{Request, Response};
    use mkit_client::{Destination, proto};
    use std::cell::RefCell;

    fn remote(code: &str, message: &str) -> ClientError {
        ClientError::Remote(Box::new(mkit_client::RemoteError {
            code: code.to_owned(),
            message: message.to_owned(),
            details: Vec::new(),
            status: 0,
            headers: http::HeaderMap::new(),
        }))
    }

    #[test]
    fn remote_codes_map_to_the_engines_vocabulary() {
        assert!(matches!(
            transport_error(remote("not_found", "x")),
            TransportError::PackNotFound
        ));
        for code in ["unauthenticated", "permission_denied"] {
            assert!(matches!(
                transport_error(remote(code, "x")),
                TransportError::AccessDenied
            ));
        }
        assert!(matches!(
            transport_error(remote("internal", "boom")),
            TransportError::RemoteError(m) if m == "boom"
        ));
        assert!(matches!(
            transport_error(ClientError::Invalid("x")),
            TransportError::InvalidResponse
        ));
        assert!(matches!(
            transport_error(ClientError::Transport("redirect refused".to_owned())),
            TransportError::RemoteError(m) if m == "transport: redirect refused"
        ));
    }

    // Scripted pages for the listing tests.
    struct Pages(RefCell<Vec<Vec<u8>>>);
    impl HttpTransport for Pages {
        async fn send(
            &self,
            _request: Request<Vec<u8>>,
            _limit: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            let body = self.0.borrow_mut().remove(0);
            Ok(Response::builder()
                .status(200)
                .header("content-type", "application/proto")
                .body(body)
                .unwrap())
        }
    }

    fn page(names: &[&str], next: Option<&str>) -> Vec<u8> {
        proto::ListRefsResponse {
            refs: names
                .iter()
                .map(|n| proto::RefEntry {
                    name: Some((*n).to_owned()),
                    object_id: Some(vec![7; 32]),
                    ..Default::default()
                })
                .collect(),
            next_page_token: next.map(str::to_owned),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn source_over(pages: Vec<Vec<u8>>) -> (Pages, Destination) {
        (
            Pages(RefCell::new(pages)),
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap(),
        )
    }

    #[test]
    fn a_listing_follows_page_tokens() {
        let (transport, dest) =
            source_over(vec![page(&["a", "b"], Some("t1")), page(&["c"], None)]);
        let client = Client::anonymous(&transport, dest);
        let source = ClientSource::new(&client, &FuturesExecutor);
        let names: Vec<String> = source
            .list_branches()
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[test]
    fn duplicate_or_unordered_names_are_refused() {
        for pages in [
            vec![page(&["a", "b"], Some("t1")), page(&["b", "c"], None)],
            vec![page(&["b", "a"], None)],
            vec![page(&["a", "a"], None)],
        ] {
            let (transport, dest) = source_over(pages);
            let client = Client::anonymous(&transport, dest);
            let source = ClientSource::new(&client, &FuturesExecutor);
            assert!(matches!(
                source.list_branches(),
                Err(TransportError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn a_repeated_page_token_is_refused_not_looped() {
        let pages = vec![
            page(&["a"], Some("t")),
            page(&["b"], Some("t")),
            page(&["c"], None),
        ];
        let (transport, dest) = source_over(pages);
        let client = Client::anonymous(&transport, dest);
        let source = ClientSource::new(&client, &FuturesExecutor);
        assert!(matches!(
            source.list_branches(),
            Err(TransportError::InvalidResponse)
        ));
    }
}
