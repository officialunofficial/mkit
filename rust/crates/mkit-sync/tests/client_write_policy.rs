//! Host-owned grants and admission recovery on both Connect backends.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

mod support;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use buffa::Message;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_attest::grant::{
    Capabilities, Grant, Namespace, OwnerScheme, RefFlags, RefPattern, RefScopes, RepoScope,
    RepositoryIdentity, SignedHeader,
};
use mkit_client::{Clock, RequestContext, RequestHeaders, RequestPolicy, Veto, proto};
use mkit_core::{
    hash::{Hash, hash, to_hex, to_hex_bytes},
    layout::RepoLayout,
    protocol::PackKey,
    refs::{self, RefWriteCondition},
    serialize::serialize,
    store::ObjectStore,
};
use mkit_sync::{
    ClientSource, NativeClock, NativeHttp, PushLease, PushOptions, PushTarget, RemoteSource,
    SourceError, TransportSource, WriteRecovery,
};
use mkit_transport_connect::admission::{
    AdmissionContext, AdmissionPolicy, AdmissionResponder, AdmissionResponderError,
};
use mkit_transport_connect::{
    ConnectTransport, EnvelopeSigner, GrantOperation, GrantRequest, GrantSource,
};
use support::{
    Dalek, Live, READER_SEED, WRITER_SEED, build_commit, destination, self_certifying_namespace,
};

struct Envelope(SigningKey);
impl EnvelopeSigner for Envelope {
    fn public_key_hex(&self) -> String {
        to_hex(self.0.verifying_key().as_bytes())
    }
    fn sign_hex(&self, digest: &Hash) -> Result<String, String> {
        Ok(to_hex_bytes(&self.0.sign(digest).to_bytes()))
    }
}
fn transport(origin: &str, repository: &str, seed: u8) -> ConnectTransport {
    ConnectTransport::connect_with_signer(
        &format!("mkit+{origin}/{repository}"),
        Some(Arc::new(Envelope(SigningKey::from_bytes(&[seed; 32])))),
    )
    .unwrap()
}

struct StoredGrant {
    encoded: String,
    operations: Mutex<Vec<String>>,
}
impl GrantSource for StoredGrant {
    fn select(&self, request: &GrantRequest<'_>) -> Option<String> {
        assert_eq!(
            request.public_key_hex,
            to_hex(&support::public_key(READER_SEED))
        );
        self.operations.lock().unwrap().push(
            match request.operation {
                GrantOperation::Read => "read",
                GrantOperation::BeginUpload { .. } => "begin",
                GrantOperation::Write { .. } => "write",
                GrantOperation::Part => panic!("ticket credentials must not consult grants"),
                _ => panic!("unexpected grant operation"),
            }
            .into(),
        );
        Some(self.encoded.clone())
    }
}
impl RequestPolicy for StoredGrant {
    fn headers(&self, request: &RequestContext<'_>) -> Result<RequestHeaders, Veto> {
        assert_eq!(request.public_key, support::public_key(READER_SEED));
        let method = request.signing.procedure.rsplit('/').next().unwrap();
        if matches!(method, "UploadPart" | "CompleteUpload")
            || request
                .intent
                .is_some_and(|intent| intent.ticketed && method == "UploadPack")
        {
            return Ok(RequestHeaders::new());
        }
        self.operations.lock().unwrap().push(
            if request.intent.is_some() {
                "write"
            } else {
                "read"
            }
            .into(),
        );
        Ok(RequestHeaders::new().with_write_grant(self.encoded.clone()))
    }
}
fn grant(origin: &str, repository: &str) -> Arc<StoredGrant> {
    let namespace = Namespace::parse(&self_certifying_namespace()).unwrap();
    let now = NativeClock.now_ms();
    let statement = Grant {
        namespace,
        scope: RepoScope::Repository(
            RepositoryIdentity::new(Some(namespace), repository.rsplit('/').next().unwrap())
                .unwrap(),
        ),
        grantee: support::public_key(READER_SEED),
        capabilities: Capabilities::ReadWrite,
        audiences: vec![origin.into()],
        ref_scopes: Some(
            RefScopes::new(vec![(
                RefPattern::parse("refs/heads/*").unwrap(),
                RefFlags::parse("cuf").unwrap(),
            )])
            .unwrap(),
        ),
        epoch: 0,
        created_ms: now - 1000,
        expiry_ms: now + 300_000,
        nonce: [7; 32],
    }
    .encode()
    .unwrap();
    let signature = SigningKey::from_bytes(&[WRITER_SEED; 32])
        .sign(&hash(&statement))
        .to_bytes()
        .to_vec();
    Arc::new(StoredGrant {
        encoded: SignedHeader {
            statement,
            scheme: OwnerScheme::Ed25519,
            blob: signature,
        }
        .encode()
        .unwrap(),
        operations: Mutex::new(Vec::new()),
    })
}

#[test]
fn grant_authorized_push_and_fresh_requests_match_both_backends() {
    let mut published = Vec::new();
    for client_backend in [false, true] {
        let live = Live::self_certifying_with_grants();
        let repository = format!("{}/grantee", self_certifying_namespace());
        let grants = grant(&live.origin, &repository);
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        let (objects, tip) = build_commit(WRITER_SEED, None, &[("file", b"grant-authorized")], 1);
        for object in objects {
            store.write(&serialize(&object).unwrap()).unwrap();
        }
        refs::write_ref(&layout, "main", &tip).unwrap();
        let run = |source: &dyn RemoteSource| {
            let report = mkit_sync::push(
                dir.path(),
                source,
                &PushOptions::default().with_target(PushTarget::Branch {
                    local: "main".into(),
                    remote: "main".into(),
                    lease: PushLease::FastForward,
                }),
            )
            .unwrap();
            assert_eq!(report.tip, Some(tip));
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
            let packmap = source.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
            // Signed reads consult current grants again rather than caching a request's selection.
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
            (tip, packmap)
        };
        published.push(if client_backend {
            let http = NativeHttp::new().unwrap();
            let signer = Dalek::new(READER_SEED);
            let client = mkit_client::Client::signed(
                &http,
                destination(&live.origin, &repository),
                &signer,
                &NativeClock,
            )
            .with_request_policy(grants.as_ref());
            run(&ClientSource::new(&client, &http))
        } else {
            let tx =
                transport(&live.origin, &repository, READER_SEED).with_grant_source(grants.clone());
            run(&TransportSource::new(&tx))
        });
        let calls = grants.operations.lock().unwrap();
        assert!(
            calls
                .iter()
                .filter(|operation| operation.as_str() == "read")
                .count()
                >= 3
        );
        assert!(calls.iter().any(|operation| operation == "write"));
    }
    assert_eq!(published[0], published[1]);
}

#[derive(Debug)]
struct Captured {
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    path: String,
}
fn capture(stream: &TcpStream) -> Captured {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let path = line.split_whitespace().nth(1).unwrap().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.trim_end().split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value == "chunked")
    {
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
            if size == 0 {
                reader.read_line(&mut String::new()).unwrap();
                break;
            }
            let offset = body.len();
            body.resize(offset + size, 0);
            reader.read_exact(&mut body[offset..]).unwrap();
            reader.read_exact(&mut [0; 2]).unwrap();
        }
    } else if let Some(length) = headers.get("content-length") {
        body.resize(length.parse().unwrap(), 0);
        reader.read_exact(&mut body).unwrap();
    }
    Captured {
        headers,
        body,
        path,
    }
}
struct WireResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}
fn ok(message: &impl Message) -> WireResponse {
    WireResponse {
        status: 200,
        content_type: "application/proto",
        body: message.encode_to_vec(),
    }
}
fn challenge() -> WireResponse {
    let detail = STANDARD_NO_PAD.encode(mkit_core::admission::encode_admission_challenge(
        &[("payment", "opaque-offer")],
        "payment required",
    ));
    WireResponse {
        status: 402,
        content_type: "application/json",
        body: format!(
            r#"{{"code":"permission_denied","message":"payment required","details":[{{"type":"mkit.transport.v1.AdmissionChallenge","value":"{detail}"}}]}}"#
        ).into_bytes(),
    }
}

struct FaultServer {
    origin: String,
    requests: Arc<Mutex<Vec<Captured>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl FaultServer {
    fn new(
        count: usize,
        response: impl Fn(usize, &Captured) -> WireResponse + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let saved = requests.clone();
        let thread = std::thread::spawn(move || {
            // A connection-pool race may establish a socket that never carries
            // a request. Keep accepting while those sockets are idle; request
            // order follows readable HTTP messages, not TCP acceptance order.
            let mut connections = Vec::<TcpStream>::new();
            for index in 0..count {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut stream = loop {
                    loop {
                        match listener.accept() {
                            Ok((connection, _)) => {
                                connection.set_nonblocking(true).unwrap();
                                connections.push(connection);
                                assert!(connections.len() <= 64, "too many idle connections");
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) => panic!("accept failed: {error}"),
                        }
                    }
                    let mut ready = None;
                    let mut connection = 0;
                    while connection < connections.len() {
                        match connections[connection].peek(&mut [0; 1]) {
                            Ok(0) => {
                                connections.swap_remove(connection);
                            }
                            Ok(_) => {
                                ready = Some(connection);
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                connection += 1;
                            }
                            Err(error) => panic!("request readiness failed: {error}"),
                        }
                    }
                    if let Some(ready) = ready {
                        break connections.swap_remove(ready);
                    }
                    assert!(Instant::now() < deadline, "expected request {index}");
                    std::thread::sleep(Duration::from_millis(5));
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let request = capture(&stream);
                let response = response(index, &request);
                saved.lock().unwrap().push(request);
                write!(stream, "HTTP/1.1 {} Result\r\nContent-Type: {}\r\nContent-Length: {}\r\nWWW-Authenticate: Payment challenge\r\nPAYMENT-REQUIRED: opaque-challenge\r\nConnection: close\r\n\r\n", response.status, response.content_type, response.body.len()).unwrap();
                stream.write_all(&response.body).unwrap();
            }
        });
        Self {
            origin,
            requests,
            thread: Some(thread),
        }
    }
}
impl Drop for FaultServer {
    fn drop(&mut self) {
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

#[test]
fn force_push_refuses_unknown_discovery_before_reads_or_writes_on_all_connect_sources() {
    for backend in 0..3 {
        for code in [None, Some("not_found"), Some("unimplemented")] {
            let server = FaultServer::new(2, move |index, request| {
                if index == 0 {
                    assert!(request.path.ends_with("/GetServerInfo"));
                    return code.map_or_else(
                        || ok(&proto::GetServerInfoResponse::default()),
                        |code| WireResponse {
                            status: 404,
                            content_type: "application/json",
                            body: format!(r#"{{"code":"{code}"}}"#).into_bytes(),
                        },
                    );
                }
                // A non-force push still reaches exactly its existing head
                // read even after the same discovery failure was cached.
                assert!(request.path.ends_with("/ReadRef"));
                WireResponse {
                    status: 400,
                    content_type: "application/json",
                    body: br#"{"code":"invalid_argument"}"#.to_vec(),
                }
            });
            let dir = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(dir.path());
            ObjectStore::init(&layout).unwrap();
            let store = ObjectStore::open(&layout).unwrap();
            let run = |source: &dyn RemoteSource| {
                let push = |condition| {
                    mkit_sync::push::push_branch_steps(
                        source,
                        &store,
                        "main",
                        [8; 32],
                        condition,
                        64,
                        mkit_core::pack::MAX_TOTAL_PAYLOAD,
                        &mkit_sync::push::PushControl::default(),
                        &mut |_| panic!("nothing was published"),
                    )
                };
                // A cached miss must not be reinterpreted as known false.
                assert!(!source.supports_atomic_advance());
                for _ in 0..2 {
                    assert!(matches!(
                        push(RefWriteCondition::Any),
                        Err(mkit_sync::PushError::ForceCapabilityUnknown)
                    ));
                }
                assert!(matches!(
                    push(RefWriteCondition::Missing),
                    Err(mkit_sync::PushError::Sync(mkit_sync::SyncError::Source(_)))
                ));
            };
            if backend == 0 {
                let http = NativeHttp::new().unwrap();
                let signer = Dalek::new(WRITER_SEED);
                let client = mkit_client::Client::signed(
                    &http,
                    destination(&server.origin, "default"),
                    &signer,
                    &NativeClock,
                );
                run(&ClientSource::new(&client, &http));
            } else {
                let tx = transport(&server.origin, "default", WRITER_SEED);
                if backend == 1 {
                    run(&TransportSource::new(&tx));
                } else {
                    tx.with_source(run).unwrap();
                }
            }
            assert_eq!(server.requests.lock().unwrap().len(), 2);
        }
    }
}

#[test]
fn fault_server_reads_requests_while_an_earlier_connection_is_idle() {
    let server = FaultServer::new(1, |_, request| {
        assert_eq!(request.path, "/probe");
        ok(&proto::UpdateRefResponse::default())
    });
    let address = server.origin.strip_prefix("http://").unwrap();
    let _idle = TcpStream::connect(address).unwrap();
    let mut active = TcpStream::connect(address).unwrap();
    active
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    active
        .write_all(b"POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    active.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

struct HostAdmission {
    origin: String,
    runs: AtomicUsize,
    headers: Mutex<Vec<(String, String)>>,
}
impl HostAdmission {
    fn new(origin: &str) -> Self {
        Self {
            origin: origin.into(),
            runs: AtomicUsize::new(0),
            headers: Mutex::new(Vec::new()),
        }
    }
}
impl AdmissionResponder for HostAdmission {
    fn respond(
        &self,
        context: &AdmissionContext<'_>,
    ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
        assert!(context.procedure.ends_with("/UpdateRef"));
        assert_eq!(context.origin, self.origin);
        assert_eq!(context.repository, "default");
        assert_eq!(context.required.challenges.len(), 1);
        assert_eq!(context.required.challenges[0].scheme, "payment");
        assert_eq!(context.required.challenges[0].value, "opaque-offer");
        assert_eq!(context.required.www_authenticate, ["Payment challenge"]);
        assert_eq!(context.required.payment_required, ["opaque-challenge"]);
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(vec![(
            "payment-authorization".into(),
            "approved-payment".into(),
        )])
    }
}
impl RequestPolicy for HostAdmission {
    fn unsigned_headers(
        &self,
        _: &mkit_client::UnsignedRequestContext<'_>,
    ) -> Result<RequestHeaders, Veto> {
        Ok(self
            .headers
            .lock()
            .unwrap()
            .iter()
            .fold(RequestHeaders::new(), |out, (name, value)| {
                out.with(name.clone(), value.clone())
            }))
    }

    fn headers(&self, request: &RequestContext<'_>) -> Result<RequestHeaders, Veto> {
        if request.signing.procedure.ends_with("/UploadPack") {
            assert!(request.intent.unwrap().ticketed);
        }
        Ok(self
            .headers
            .lock()
            .unwrap()
            .iter()
            .fold(RequestHeaders::new(), |out, (name, value)| {
                out.with(name.clone(), value.clone())
            }))
    }
}
impl WriteRecovery for HostAdmission {
    fn before_call(&self, _: &str) -> Result<(), SourceError> {
        self.headers.lock().unwrap().clear();
        Ok(())
    }

    fn recover(
        &self,
        procedure: &str,
        error: &SourceError,
        attempt: u32,
    ) -> Result<bool, SourceError> {
        let SourceError::PaymentRequired { challenges } = error else {
            return Ok(false);
        };
        if attempt != 1 {
            return Ok(false);
        }
        let response = self
            .respond(&AdmissionContext {
                origin: &self.origin,
                repository: "default",
                procedure,
                required: challenges,
            })
            .unwrap();
        let filtered = mkit_transport_connect::admission::filter_headers(
            response,
            &std::collections::HashSet::default(),
            &http::HeaderMap::default(),
            false,
        )
        .unwrap();
        *self.headers.lock().unwrap() = filtered
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
            .collect();
        Ok(true)
    }
}

#[test]
fn admission_402_runs_host_responder_once_and_replays_identical_write_on_both_backends() {
    let mut bodies = Vec::new();
    for client_backend in [false, true] {
        let server = FaultServer::new(2, |index, request| {
            assert!(request.path.ends_with("/UpdateRef"));
            if index == 0 {
                assert!(!request.headers.contains_key("payment-authorization"));
                challenge()
            } else {
                assert_eq!(request.headers["payment-authorization"], "approved-payment");
                ok(&proto::UpdateRefResponse::default())
            }
        });
        let host = Arc::new(HostAdmission::new(&server.origin));
        if client_backend {
            let http = NativeHttp::new().unwrap();
            let signer = Dalek::new(WRITER_SEED);
            let client = mkit_client::Client::signed(
                &http,
                destination(&server.origin, "default"),
                &signer,
                &NativeClock,
            )
            .with_request_policy(host.as_ref());
            ClientSource::new(&client, &http)
                .with_write_recovery(host.as_ref())
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &[8; 32])
                .unwrap();
        } else {
            let tx = transport(&server.origin, "default", WRITER_SEED)
                .with_admission(AdmissionPolicy::new(host.clone()));
            TransportSource::new(&tx)
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &[8; 32])
                .unwrap();
        }
        assert_eq!(host.runs.load(Ordering::SeqCst), 1);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(
            requests[0].headers["idempotency-key"],
            requests[1].headers["idempotency-key"]
        );
        bodies.push(requests[0].body.clone());
    }
    assert_eq!(bodies[0], bodies[1]);
}

#[test]
fn ticketed_upload_402_never_runs_admission_helper_on_either_backend() {
    for client_backend in [false, true] {
        let server = FaultServer::new(3, |index, request| match index {
            0 => {
                assert!(request.path.contains("GetServerInfo"));
                ok(&proto::GetServerInfoResponse {
                    protocol: Some("mkit.transport.v1".into()),
                    spec_version: Some(2),
                    max_pack_bytes: Some(32 << 20),
                    part_size: Some(8 << 20),
                    max_parts: Some(4),
                    max_list_refs_page_size: Some(100),
                    begin_upload_threshold_bytes: Some(0),
                    ..Default::default()
                })
            }
            1 => {
                assert!(request.path.ends_with("/BeginUpload"));
                ok(&proto::BeginUploadResponse {
                    result: Some(proto::begin_upload_response::Result::Ticket(Box::new(
                        proto::UploadTicket {
                            id: Some([9; 32].to_vec()),
                            token: Some(vec![1, 2, 3]),
                            part_size: Some(8 << 20),
                            expires_unix_ms: Some(i64::MAX),
                            ..Default::default()
                        },
                    ))),
                    ..Default::default()
                })
            }
            _ => {
                assert!(request.path.ends_with("/UploadPack"));
                challenge()
            }
        });
        let host = Arc::new(HostAdmission::new(&server.origin));
        let bytes = [7; 100];
        let key = PackKey::from(mkit_core::pack::pack_key(&bytes));
        let error = if client_backend {
            let http = NativeHttp::new().unwrap();
            let signer = Dalek::new(WRITER_SEED);
            let client = mkit_client::Client::signed(
                &http,
                destination(&server.origin, "default"),
                &signer,
                &NativeClock,
            )
            .with_request_policy(host.as_ref());
            ClientSource::new(&client, &http)
                .with_write_recovery(host.as_ref())
                .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
                .unwrap_err()
        } else {
            let tx = transport(&server.origin, "default", WRITER_SEED)
                .with_admission(AdmissionPolicy::new(host.clone()));
            TransportSource::new(&tx)
                .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
                .unwrap_err()
        };
        assert!(matches!(error, SourceError::PaymentRequired { .. }));
        assert_eq!(host.runs.load(Ordering::SeqCst), 0);
        assert_eq!(server.requests.lock().unwrap().len(), 3);
    }
}

#[test]
fn unsigned_admission_recovery_matches_both_backends_without_synthetic_signer() {
    struct UnsignedPolicy<'a> {
        host: &'a HostAdmission,
        calls: AtomicUsize,
    }
    impl RequestPolicy for UnsignedPolicy<'_> {
        fn headers(&self, _: &RequestContext<'_>) -> Result<RequestHeaders, Veto> {
            panic!("an unsigned write must not invoke signed policy");
        }
        fn unsigned_headers(
            &self,
            request: &mkit_client::UnsignedRequestContext<'_>,
        ) -> Result<RequestHeaders, Veto> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.host.unsigned_headers(request)
        }
    }
    let mut bodies = Vec::new();
    for client_backend in [false, true] {
        let server = FaultServer::new(2, |index, request| {
            assert!(request.path.ends_with("/UpdateRef"));
            let nonce = &request.headers["idempotency-key"];
            assert_eq!(nonce.len(), 64);
            assert!(
                nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            let created = request.headers["x-created-at"].parse::<i64>().unwrap();
            let expires = request.headers["x-expires-at"].parse::<i64>().unwrap();
            assert!(expires > created);
            assert!(expires - created <= mkit_core::write_auth::MAX_VALIDITY_MS);
            assert!(!request.headers.contains_key("x-public-key"));
            assert!(!request.headers.contains_key("x-signature"));
            if index == 0 {
                challenge()
            } else {
                assert_eq!(request.headers["payment-authorization"], "approved-payment");
                ok(&proto::UpdateRefResponse::default())
            }
        });
        let host = Arc::new(HostAdmission::new(&server.origin));
        if client_backend {
            let http = NativeHttp::new().unwrap();
            let policy = UnsignedPolicy {
                host: host.as_ref(),
                calls: AtomicUsize::new(0),
            };
            let client = mkit_client::Client::anonymous_with_clock(
                &http,
                destination(&server.origin, "default"),
                &NativeClock,
            )
            .with_unsigned_writes()
            .with_request_policy(&policy);
            assert!(client.public_key().is_none());
            ClientSource::new(&client, &http)
                .with_write_recovery(host.as_ref())
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &[8; 32])
                .unwrap();
            assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
        } else {
            let tx = ConnectTransport::connect(&format!("mkit+{}/default", server.origin))
                .unwrap()
                .with_admission(AdmissionPolicy::new(host.clone()));
            TransportSource::new(&tx)
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &[8; 32])
                .unwrap();
        }
        assert_eq!(host.runs.load(Ordering::SeqCst), 1);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        for name in ["idempotency-key", "x-created-at", "x-expires-at"] {
            assert_eq!(requests[0].headers[name], requests[1].headers[name]);
        }
        bodies.push(requests[0].body.clone());
    }
    assert_eq!(bodies[0], bodies[1]);
}
