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
use std::sync::Arc;

mod write;
pub use write::{ClientSession, NoWriteRecovery, UploadEvent, WriteRecovery};

use mkit_client::{
    Client, Clock, Error as ClientError, HttpTransport, NoObserver, NoRequestPolicy, Observer,
    RequestPolicy, Signer,
};
use mkit_core::hash::Hash;
use mkit_core::protocol::PackKey;
use mkit_core::refs::Ref;

use crate::SourceError;
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

/// A packmap node is small; this is the response cap `mkit-client` uses.
const NODE_LIMIT: u64 = 1024 * 1024;

/// A remote repository reached through a [`Client`]. The
/// engine calls it one operation at a time.
pub struct ClientSource<
    'a,
    T,
    S,
    C,
    E,
    O = NoObserver,
    P: ?Sized = NoRequestPolicy,
    R: ?Sized = NoWriteRecovery,
> {
    client: &'a Client<'a, T, S, C, O, P>,
    executor: &'a E,
    writes: write::WriteState,
    session: Option<&'a ClientSession>,
    recovery: Option<&'a R>,
}

impl<T, S, C, E, O, P: ?Sized, R: ?Sized> std::fmt::Debug
    for ClientSource<'_, T, S, C, E, O, P, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSource")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl<'a, T, S, C, E, O, P: ?Sized> ClientSource<'a, T, S, C, E, O, P> {
    /// `executor` drives every call. When the transport is built on an async
    /// runtime, pass the transport itself if it is an [`Executor`].
    #[must_use]
    pub fn new(client: &'a Client<'a, T, S, C, O, P>, executor: &'a E) -> Self {
        Self {
            client,
            executor,
            writes: write::WriteState::default(),
            session: None,
            recovery: None,
        }
    }
}

impl<'a, T, S, C, E, O, P: ?Sized, R: ?Sized> ClientSource<'a, T, S, C, E, O, P, R> {
    fn write_state(&self) -> &write::WriteState {
        self.session.map_or(&self.writes, |session| &session.state)
    }

    /// Persist acknowledged parts through a caller-owned durable store.
    #[must_use]
    pub fn with_receipt_store(self, store: Arc<dyn mkit_client::PartReceiptStore>) -> Self {
        self.write_state().receipts.replace(store);
        self
    }

    /// Let the host schedule typed failures and supply admission recovery.
    #[must_use]
    pub fn with_write_recovery<R2: WriteRecovery + ?Sized>(
        self,
        recovery: &'a R2,
    ) -> ClientSource<'a, T, S, C, E, O, P, R2> {
        ClientSource {
            client: self.client,
            executor: self.executor,
            writes: self.writes,
            session: self.session,
            recovery: Some(recovery),
        }
    }
}

/// Preserve client outcomes without scheduling work in the sync engine.
fn source_error(error: ClientError) -> SourceError {
    match error {
        ClientError::Remote(remote) => SourceError::Remote(Box::new(crate::RemoteFailure {
            code: remote.code,
            message: remote.message,
            details: remote
                .details
                .into_iter()
                .map(|detail| crate::RemoteDetail {
                    type_url: detail.type_url,
                    value: detail.value,
                })
                .collect(),
            status: remote.status,
            headers: remote
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
        })),
        // HttpTransport does not classify its string errors. Refused redirects
        // and malformed/oversized responses must not become transient failures.
        ClientError::Connection(_) => SourceError::ServerError { status: 503 },
        ClientError::RequestTimeout(cause) => SourceError::RemoteError(cause),
        ClientError::Transport(cause) => SourceError::RemoteError(format!("transport: {cause}")),
        ClientError::PaymentRequired(challenges) => SourceError::PaymentRequired { challenges },
        ClientError::PendingVerification { retry_after } => {
            SourceError::PendingVerification { retry_after }
        }
        ClientError::MembershipNotVisible => SourceError::MembershipNotVisible,
        ClientError::RetryAfter { ms } => SourceError::RetryAfter { ms },
        ClientError::Signing(reason) => SourceError::Signing(reason),
        ClientError::SignerRefused(reason) => SourceError::SignerRefused(reason),
        ClientError::Vetoed(reason) => SourceError::Vetoed(reason),
        ClientError::ReservedHeader(name) => SourceError::ReservedHeader(name),
        ClientError::EnvelopeExpired => SourceError::EnvelopeExpired,
        ClientError::Deadline => SourceError::Deadline,
        ClientError::Limit(_)
        | ClientError::Invalid(_)
        | ClientError::Pack(_)
        | ClientError::Packlist(_)
        | ClientError::Sink(_)
        | ClientError::Signature { .. } => SourceError::InvalidResponse,
        // A future unclassified client variant is terminal, never retryable.
        other => SourceError::RemoteError(other.to_string()),
    }
}

impl<
    'a,
    T: HttpTransport,
    S: Signer,
    C: Clock,
    E: Executor,
    O: Observer,
    P: RequestPolicy + ?Sized,
    R: WriteRecovery + ?Sized,
> ClientSource<'a, T, S, C, E, O, P, R>
{
    /// Reuse cached upload tickets and capabilities across borrowed clients.
    /// A session binds to this destination and public key on first use.
    /// Configure its receipt store on the session or after selecting it.
    ///
    /// # Errors
    /// A session already bound to another destination or signer is refused.
    pub fn with_session(mut self, session: &'a ClientSession) -> Result<Self, SourceError> {
        let destination = self.client.destination();
        session.bind(
            destination.origin(),
            destination.repository(),
            self.client.public_key(),
        )?;
        self.session = Some(session);
        Ok(self)
    }

    /// Download a pack without a read-your-writes ref hint.
    ///
    /// # Errors
    /// Transport, remote, size or content-integrity failures.
    pub fn download_pack_unhinted(&self, key: &PackKey) -> Result<Vec<u8>, SourceError> {
        self.write_call("DownloadPack", false, None, |identity| {
            self.executor.block_on(self.client.download_pack(
                &key.into_hash(),
                None,
                mkit_core::protocol::PACK_BODY_LIMIT,
                identity,
            ))
        })
        .map(|reply| reply.value)
    }

    /// Test pack membership without a ref hint.
    ///
    /// # Errors
    /// Transport, remote or invalid-response failures.
    pub fn pack_exists(&self, key: &PackKey) -> Result<bool, SourceError> {
        self.pack_exists_with_hint(key, None)
    }

    /// Test pack membership with a read-your-writes ref hint.
    ///
    /// # Errors
    /// Transport, remote or invalid-response failures.
    pub fn pack_exists_via_ref(&self, key: &PackKey, name: &str) -> Result<bool, SourceError> {
        self.pack_exists_with_hint(key, Some(name))
    }

    fn pack_exists_with_hint(
        &self,
        key: &PackKey,
        hint: Option<&str>,
    ) -> Result<bool, SourceError> {
        match self.write_call("PackExists", false, None, |identity| {
            self.executor
                .block_on(self.client.pack_exists(&key.into_hash(), hint, identity))
        }) {
            Ok(reply) => Ok(reply.value),
            Err(SourceError::Remote(remote)) if remote.code == "not_found" => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn list_branches_with_page_limit(&self, max_pages: u32) -> Result<Vec<Ref>, SourceError> {
        self.list_refs_with_page_limit("refs/heads/", max_pages)
    }

    /// List every ref under `prefix`, following bounded, ordered pages.
    ///
    /// # Errors
    /// Remote failures or an invalid, repeated or unordered listing page.
    pub fn list_refs(&self, prefix: &str) -> Result<Vec<Ref>, SourceError> {
        self.list_refs_with_page_limit(prefix, mkit_core::ref_listing::MAX_PAGES)
    }

    /// List refs with an explicit maximum number of pages.
    ///
    /// # Errors
    /// Remote failures, invalid page ordering or an exhausted page bound.
    pub fn list_refs_with_page_limit(
        &self,
        prefix: &str,
        max_pages: u32,
    ) -> Result<Vec<Ref>, SourceError> {
        let mut listing = mkit_core::ref_listing::RefListing::new(max_pages);
        while listing.can_request() {
            let reply = self
                .write_call("ListRefs", false, None, |identity| {
                    self.executor.block_on(self.client.list_refs(
                        prefix,
                        0,
                        listing.cursor(),
                        identity,
                    ))
                })?
                .value;
            let page = reply
                .refs
                .into_iter()
                .map(|named| Ref {
                    name: named.name,
                    hash: Some(named.id),
                })
                .collect();
            if listing
                .push(page, reply.next_page_token, |entry: &mut Ref| {
                    &mut entry.name
                })
                .map_err(|_| SourceError::InvalidResponse)?
            {
                return listing.finish().map_err(|_| SourceError::InvalidResponse);
            }
        }
        Err(SourceError::InvalidResponse)
    }
}

impl<
    T: HttpTransport,
    S: Signer,
    C: Clock,
    E: Executor,
    O: Observer,
    P: RequestPolicy + ?Sized,
    R: WriteRecovery + ?Sized,
> RemoteSource for ClientSource<'_, T, S, C, E, O, P, R>
{
    fn supports_push(&self) -> bool {
        self.client.supports_writes()
    }

    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        if !self.client.supports_writes() {
            return Err(SourceError::ProtocolError);
        }
        self.write_upload(bytes, key, name)
    }

    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        if !self.client.supports_writes() {
            return Err(SourceError::ProtocolError);
        }
        self.write_upload(bytes, key, name)
    }

    fn update_ref(
        &self,
        name: &str,
        condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        if !self.client.supports_writes() {
            return Err(SourceError::ProtocolError);
        }
        self.write_update_ref(name, condition, tip)
    }

    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: mkit_core::refs::RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: mkit_core::refs::RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<mkit_core::protocol::CommitOutcome, SourceError> {
        if !self.client.supports_writes() {
            return Err(SourceError::ProtocolError);
        }
        self.write_advance_refs_committing(
            head,
            head_condition,
            tip,
            packmap,
            packmap_condition,
            node,
            keys,
        )
    }

    fn upload_limits(&self) -> mkit_core::protocol::UploadLimits {
        self.write_upload_limits()
    }

    fn supports_atomic_advance(&self) -> bool {
        self.write_supports_atomic_advance()
    }

    fn atomic_advance_status(&self) -> Option<bool> {
        self.write_atomic_advance_status()
    }

    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        self.list_branches_with_page_limit(mkit_core::ref_listing::MAX_PAGES)
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        match self.write_call("ReadRef", false, None, |identity| {
            self.executor.block_on(self.client.read_ref(name, identity))
        }) {
            Ok(reply) => Ok(reply.value),
            Err(SourceError::Remote(remote)) if remote.code == "not_found" => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.write_call("DownloadPack", false, None, |identity| {
            self.executor.block_on(self.client.download_pack(
                &key.into_hash(),
                Some(ref_name),
                NODE_LIMIT,
                identity,
            ))
        })
        .map(|reply| reply.value)
    }

    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.write_call("DownloadPack", false, None, |identity| {
            self.executor.block_on(self.client.download_pack(
                &key.into_hash(),
                Some(ref_name),
                mkit_core::protocol::PACK_BODY_LIMIT,
                identity,
            ))
        })
        .map(|reply| reply.value)
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

    struct TestSigner;
    impl Signer for TestSigner {
        fn public_key(&self) -> [u8; 32] {
            [1; 32]
        }
        async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
            Ok([2; 64])
        }
    }
    struct TestClock;
    impl Clock for TestClock {
        fn now_ms(&self) -> i64 {
            1000
        }
        fn nonce(&self) -> Result<Hash, String> {
            Ok([3; 32])
        }
        async fn wait(&self, _: std::time::Duration) {
            panic!("source must never wait")
        }
    }
    struct ReadObserver;
    impl Observer for ReadObserver {
        async fn before_dispatch(
            &self,
            _: &mkit_client::WriteIntent<'_>,
            _: &mkit_client::Attempt,
        ) -> Result<mkit_client::AttemptHeaders, mkit_client::Veto> {
            panic!("reads must not invoke the write observer")
        }
    }

    #[test]
    fn default_source_and_session_retain_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        struct SyncChannel;
        impl HttpTransport for SyncChannel {
            async fn send(
                &self,
                _: Request<Vec<u8>>,
                _: usize,
            ) -> Result<Response<Vec<u8>>, String> {
                Err("no network expected".into())
            }
        }
        let transport = SyncChannel;
        let client = Client::anonymous(
            &transport,
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap(),
        );
        let source = ClientSource::new(&client, &FuturesExecutor);
        assert_send_sync(&source);
        assert_send_sync(&ClientSession::default());
    }

    #[test]
    fn source_accepts_explicit_thread_local_policy_and_recovery() {
        use std::cell::Cell;
        struct LocalPolicy(Cell<u32>);
        impl RequestPolicy for LocalPolicy {
            fn headers(
                &self,
                _: &mkit_client::RequestContext<'_>,
            ) -> Result<mkit_client::RequestHeaders, mkit_client::Veto> {
                self.0.set(self.0.get() + 1);
                Ok(mkit_client::RequestHeaders::new())
            }
        }
        struct LocalRecovery(Cell<u32>);
        impl WriteRecovery for LocalRecovery {
            fn recover(&self, _: &str, _: &SourceError, _: u32) -> Result<bool, SourceError> {
                self.0.set(self.0.get() + 1);
                Ok(false)
            }
        }
        let (transport, destination) = source_over(Vec::new());
        let policy = LocalPolicy(Cell::new(0));
        let recovery = LocalRecovery(Cell::new(0));
        let policy_ref: &dyn RequestPolicy = &policy;
        let recovery_ref: &dyn WriteRecovery = &recovery;
        let client = Client::anonymous(&transport, destination).with_request_policy(policy_ref);
        let source = ClientSource::new(&client, &FuturesExecutor).with_write_recovery(recovery_ref);
        assert!(!source.supports_push());
        assert_eq!(policy.0.get(), 0);
        assert_eq!(recovery.0.get(), 0);
    }

    #[test]
    fn anonymous_source_writes_refuse_before_any_network_call() {
        let (transport, dest) = source_over(Vec::new());
        let client = Client::anonymous(&transport, dest);
        let source = ClientSource::new(&client, &FuturesExecutor);
        let key = PackKey::from_hash([4; 32]);
        assert!(!source.supports_push());
        for result in [
            source.upload_pack_via_ref(&[0], &key, "refs/heads/main"),
            source.upload_blob_via_ref(&[0], &key, "refs/heads/main"),
            source.update_ref(
                "refs/heads/main",
                mkit_core::refs::RefWriteCondition::Missing,
                &[4; 32],
            ),
            source
                .advance_refs_committing(
                    "refs/heads/main",
                    mkit_core::refs::RefWriteCondition::Missing,
                    &[4; 32],
                    "refs/mkit/packmap/main",
                    mkit_core::refs::RefWriteCondition::Missing,
                    &[4; 32],
                    &[],
                )
                .map(|_| ()),
        ] {
            assert!(matches!(result, Err(SourceError::ProtocolError)));
        }
    }

    #[test]
    fn observed_signed_client_composes_as_source() {
        let (transport, dest) = source_over(vec![page(&["main"], None)]);
        let client =
            Client::signed(&transport, dest, &TestSigner, &TestClock).with_observer(&ReadObserver);
        let source = ClientSource::new(&client, &FuturesExecutor);
        assert_eq!(source.list_branches().unwrap()[0].name, "main");
    }

    struct FailureResponse(RefCell<Option<Response<Vec<u8>>>>);
    impl HttpTransport for FailureResponse {
        async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
            Ok(self.0.borrow_mut().take().expect("source must never retry"))
        }
    }

    fn failure_response(body: &str, retry_after: Option<&str>) -> Response<Vec<u8>> {
        let mut response = Response::builder()
            .status(503)
            .header("content-type", "application/json");
        if let Some(value) = retry_after {
            response = response.header("retry-after", value);
        }
        response.body(body.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn every_resumable_outcome_survives_client_source_and_sync() {
        use crate::{FailureClass, SyncError};
        use std::time::Duration;
        // A PendingVerification proto with retry_after_ms = 2000 (field 1).
        use base64::Engine as _;
        let pending = base64::engine::general_purpose::STANDARD.encode(
            proto::PendingVerification {
                retry_after_ms: Some(2000),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let bodies = [
            format!(r#"{{"code":"unavailable","details":[{{"type":"mkit.transport.v1.PendingVerification","value":"{pending}"}}]}}"#),
            r#"{"code":"unavailable","details":[{"type":"mkit.transport.v1.MembershipNotVisible","value":""}]}"#.into(),
            r#"{"code":"unavailable","message":"busy"}"#.into(),
        ];
        for (i, body) in bodies.iter().enumerate() {
            let transport = FailureResponse(RefCell::new(Some(failure_response(
                body,
                (i == 2).then_some("3"),
            ))));
            let dest =
                Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
            let client = Client::signed(&transport, dest, &TestSigner, &TestClock);
            let source = ClientSource::new(&client, &FuturesExecutor);
            let error = source.list_branches().unwrap_err();
            assert_eq!(error.class(), FailureClass::Resumable);
            let SyncError::Source(error) = source.repository_error(error) else {
                panic!("outcome flattened")
            };
            match (i, error) {
                (0, SourceError::PendingVerification { retry_after }) => {
                    assert_eq!(retry_after, Duration::from_secs(2));
                }
                (1, SourceError::MembershipNotVisible) => (),
                (2, SourceError::RetryAfter { ms }) => assert_eq!(ms, 3000),
                other => panic!("unexpected {other:?}"),
            }
            assert!(transport.0.borrow().is_none());
        }
        let response = Response::builder()
            .status(402)
            .header("www-authenticate", "Payment opaque")
            .header("payment-required", "opaque-payment")
            .body(Vec::new())
            .unwrap();
        let transport = FailureResponse(RefCell::new(Some(response)));
        let dest = Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client = Client::anonymous(&transport, dest);
        let source = ClientSource::new(&client, &FuturesExecutor);
        let SyncError::Source(SourceError::PaymentRequired { challenges }) =
            source.repository_error(source.list_branches().unwrap_err())
        else {
            panic!("payment flattened")
        };
        assert_eq!(challenges.www_authenticate, ["Payment opaque"]);
        assert_eq!(challenges.payment_required, ["opaque-payment"]);
    }

    #[test]
    fn client_source_preserves_all_payment_challenges() {
        use base64::Engine as _;
        let detail = mkit_core::admission::encode_admission_challenge(
            &[("mpp", "first"), ("x402", "second")],
            "pay to read",
        );
        let value = base64::engine::general_purpose::STANDARD.encode(detail);
        let body = format!(
            r#"{{"code":"permission_denied","details":[{{"type":"mkit.transport.v1.AdmissionChallenge","value":"{value}"}}]}}"#
        );
        let mut response = failure_response(&body, None);
        *response.status_mut() = http::StatusCode::PAYMENT_REQUIRED;
        let transport = FailureResponse(RefCell::new(Some(response)));
        let dest = Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
        let client = Client::anonymous(&transport, dest);
        let source = ClientSource::new(&client, &FuturesExecutor);
        let crate::SyncError::Source(SourceError::PaymentRequired { challenges }) =
            source.repository_error(source.read_ref("refs/heads/main").unwrap_err())
        else {
            panic!("payment flattened")
        };
        assert_eq!(challenges.description, "pay to read");
        assert_eq!(
            challenges
                .challenges
                .iter()
                .map(|entry| (entry.scheme.as_str(), entry.value.as_str()))
                .collect::<Vec<_>>(),
            [("mpp", "first"), ("x402", "second")]
        );
    }

    #[test]
    fn remote_evidence_and_overload_classification_survive() {
        use crate::{FailureClass, SyncError};
        for code in [
            "resource_exhausted",
            "unavailable",
            "aborted",
            "permission_denied",
            "not_found",
            "internal",
        ] {
            let body = format!(
                r#"{{"code":"{code}","message":"message","details":[{{"type":"example.Detail","value":"opaque"}}]}}"#
            );
            let mut response = failure_response(&body, None);
            response
                .headers_mut()
                .append("x-evidence", "one".parse().unwrap());
            response
                .headers_mut()
                .append("x-evidence", "two".parse().unwrap());
            let transport = FailureResponse(RefCell::new(Some(response)));
            let dest =
                Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
            let client = Client::anonymous(&transport, dest);
            let source = ClientSource::new(&client, &FuturesExecutor);
            let error = source.repository_error(source.list_branches().unwrap_err());
            let source = match error {
                SyncError::Source(source) | SyncError::RepositoryNotFound { source, .. } => source,
                other => panic!("metadata lost: {other:?}"),
            };
            let SourceError::Remote(remote) = source else {
                panic!("metadata flattened")
            };
            assert_eq!(remote.code, code);
            assert_eq!(remote.message, "message");
            assert_eq!(remote.status, 503);
            assert_eq!(remote.details[0].value.as_deref(), Some("opaque"));
            assert_eq!(
                remote
                    .headers
                    .iter()
                    .filter(|(name, _)| name == "x-evidence")
                    .cloned()
                    .collect::<Vec<_>>(),
                [
                    ("x-evidence".into(), b"one".to_vec()),
                    ("x-evidence".into(), b"two".to_vec())
                ]
            );
            let error = SourceError::Remote(remote);
            assert_eq!(
                error.class(),
                if matches!(code, "resource_exhausted" | "unavailable" | "aborted") {
                    FailureClass::Transient
                } else {
                    FailureClass::Refusal
                }
            );
        }
    }

    #[test]
    fn signing_and_channel_refusals_are_terminal_and_typed() {
        use crate::FailureClass;
        assert!(
            matches!(source_error(ClientError::Signing("key unavailable".into())), SourceError::Signing(reason) if reason == "key unavailable")
        );
        assert!(
            matches!(source_error(ClientError::SignerRefused("policy".into())), SourceError::SignerRefused(reason) if reason == "policy")
        );
        for error in [
            ClientError::Transport("redirect refused".into()),
            ClientError::Invalid("body"),
            ClientError::SignerRefused("policy".into()),
            ClientError::Signing("key".into()),
        ] {
            assert_eq!(source_error(error).class(), FailureClass::Refusal);
        }
    }

    // Scripted pages for the listing tests.
    struct Pages(RefCell<std::collections::VecDeque<Vec<u8>>>);
    impl HttpTransport for Pages {
        async fn send(
            &self,
            _request: Request<Vec<u8>>,
            _limit: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            let body = self.0.borrow_mut().pop_front().unwrap();
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
            Pages(RefCell::new(pages.into())),
            Destination::new("https://vcs.example.org".into(), "default".into()).unwrap(),
        )
    }

    #[test]
    fn shared_session_refuses_destination_or_signer_changes() {
        let (transport, destination) = source_over(Vec::new());
        let session = ClientSession::default();
        let first = Client::anonymous(&transport, destination.clone());
        ClientSource::new(&first, &FuturesExecutor)
            .with_session(&session)
            .unwrap();
        let fresh = Client::anonymous(&transport, destination.clone());
        ClientSource::new(&fresh, &FuturesExecutor)
            .with_session(&session)
            .unwrap();
        for (origin, repository) in [
            ("https://other.example.org", "default"),
            ("https://vcs.example.org", "another"),
        ] {
            let changed = Client::anonymous(
                &transport,
                Destination::new(origin.into(), repository.into()).unwrap(),
            );
            assert!(matches!(
                ClientSource::new(&changed, &FuturesExecutor).with_session(&session),
                Err(SourceError::InvalidResponse)
            ));
        }
        let signed = Client::signed(&transport, destination, &TestSigner, &TestClock);
        assert!(matches!(
            ClientSource::new(&signed, &FuturesExecutor).with_session(&session),
            Err(SourceError::InvalidResponse)
        ));
        assert!(transport.0.borrow().is_empty());
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
                Err(SourceError::InvalidResponse)
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
            Err(SourceError::InvalidResponse)
        ));
    }
    use mkit_test_util::ref_listing::listing_cases;
    #[test]
    fn shared_listing_adversaries() {
        for case in listing_cases() {
            let pages = case
                .pages
                .iter()
                .map(|(names, token)| {
                    page(
                        &names.iter().map(String::as_str).collect::<Vec<_>>(),
                        token.as_deref(),
                    )
                })
                .collect();
            let (transport, dest) = source_over(pages);
            let client = Client::anonymous(&transport, dest);
            let result = ClientSource::new(&client, &FuturesExecutor)
                .list_branches_with_page_limit(case.max_pages);
            assert!(transport.0.borrow().is_empty(), "{}", case.name);
            if case.valid {
                let refs = result.unwrap();
                assert!(refs.iter().all(|entry| entry.hash == Some([7; 32])));
                assert_eq!(
                    refs.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
                    ["a", "b", "c"]
                );
            } else {
                assert!(
                    matches!(result, Err(SourceError::InvalidResponse)),
                    "{}",
                    case.name
                );
            }
        }
    }
}
