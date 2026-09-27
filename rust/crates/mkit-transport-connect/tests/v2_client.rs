//! STC v2 client behavior over real HTTP and generated Connect dispatch.

use std::sync::{Arc, Mutex, mpsc};

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_transport_connect::{ConnectTransport, ServerInfoView, generated};

const DATA: &[u8] = b"v2 pack bytes";

#[derive(Clone)]
enum Discovery {
    Response(Box<generated::GetServerInfoResponse>),
    Error(ErrorCode),
}

fn info(atomic: Option<bool>) -> generated::GetServerInfoResponse {
    generated::GetServerInfoResponse {
        protocol: Some("mkit.transport.v1".into()),
        spec_version: Some(2),
        part_size: Some(8 << 20),
        max_list_refs_page_size: Some(1000),
        atomic_advance: atomic,
        ..Default::default()
    }
}

#[derive(Clone, Debug)]
struct Captured {
    rpc: &'static str,
    repository: Option<String>,
    hint: Option<String>,
    list: Option<generated::ListRefsRequest>,
    /// Public key, signature, created-at and idempotency key, when signed.
    signed: Option<[String; 4]>,
}

struct State {
    discovery: Discovery,
    pages: Vec<generated::ListRefsResponse>,
    fail_page_once: Option<String>,
    missing: bool,
    read_failures: usize,
    download_failures: usize,
    update_failures: usize,
    requests: Vec<Captured>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            discovery: Discovery::Response(Box::new(info(Some(true)))),
            pages: vec![generated::ListRefsResponse::default()],
            fail_page_once: None,
            missing: false,
            read_failures: 0,
            download_failures: 0,
            update_failures: 0,
            requests: Vec::new(),
        }
    }
}

struct TestService(Arc<Mutex<State>>);

impl TestService {
    fn capture(&self, rpc: &'static str, ctx: &RequestContext) {
        let header = |name| {
            ctx.headers()
                .get(name)
                .map(|value| value.to_str().expect("ASCII header").to_owned())
        };
        self.0.lock().unwrap().requests.push(Captured {
            rpc,
            repository: header("x-repository"),
            hint: header("x-mkit-ref"),
            list: None,
            signed: header("x-signature").map(|signature| {
                [
                    header("x-public-key").unwrap_or_default(),
                    signature,
                    header("x-created-at").unwrap_or_default(),
                    header("idempotency-key").unwrap_or_default(),
                ]
            }),
        });
    }
}

#[allow(refining_impl_trait)]
impl generated::TransportService for TestService {
    async fn get_server_info(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetServerInfoRequest>,
    ) -> ServiceResult<generated::GetServerInfoResponse> {
        self.capture("GetServerInfo", &ctx);
        match &self.0.lock().unwrap().discovery {
            Discovery::Response(response) => Ok(Response::new((**response).clone())),
            Discovery::Error(code) => Err(ConnectError::new(*code, "discovery error")),
        }
    }

    async fn list_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        self.capture("ListRefs", &ctx);
        let message = request.to_owned_message();
        let mut state = self.0.lock().unwrap();
        state.requests.last_mut().unwrap().list = Some(message.clone());
        if state.missing {
            return Err(ConnectError::not_found("repository missing"));
        }
        let token = message.page_token.as_deref().unwrap_or_default();
        if state.fail_page_once.as_deref() == Some(token) {
            state.fail_page_once = None;
            return Err(ConnectError::unavailable("transient page failure"));
        }
        let index = if token.is_empty() {
            0
        } else {
            state
                .pages
                .iter()
                .position(|page| page.next_page_token.as_deref() == Some(token))
                .expect("known token")
                + 1
        };
        Ok(Response::new(state.pages[index].clone()))
    }

    async fn read_ref(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        self.capture("ReadRef", &ctx);
        let mut state = self.0.lock().unwrap();
        if state.read_failures > 0 {
            state.read_failures -= 1;
            return Err(ConnectError::new(ErrorCode::Aborted, "replay in flight"));
        }
        if state.missing {
            return Err(ConnectError::not_found("repository missing"));
        }
        Ok(Response::new(generated::ReadRefResponse {
            exists: Some(false),
            ..Default::default()
        }))
    }

    async fn pack_exists(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        self.capture("PackExists", &ctx);
        if self.0.lock().unwrap().missing {
            return Err(ConnectError::not_found("pack missing"));
        }
        Ok(Response::new(generated::PackExistsResponse {
            exists: Some(true),
            ..Default::default()
        }))
    }

    async fn download_pack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        self.capture("DownloadPack", &ctx);
        let mut state = self.0.lock().unwrap();
        if state.download_failures > 0 {
            state.download_failures -= 1;
            return Err(ConnectError::unavailable("transient download failure"));
        }
        if state.missing {
            return Err(ConnectError::not_found("pack missing"));
        }
        let header = generated::DownloadPackResponse {
            body: Some(
                generated::DownloadPackHeader {
                    total_bytes: Some(DATA.len() as u64),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let chunk = generated::DownloadPackResponse {
            body: Some(
                generated::PackChunk {
                    pack_id: request.to_owned_message().pack_id,
                    offset: Some(0),
                    data: Some(DATA.to_vec()),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        Response::stream_ok(futures::stream::iter([Ok(header), Ok(chunk)]))
    }

    async fn update_ref(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        self.capture("UpdateRef", &ctx);
        let mut state = self.0.lock().unwrap();
        if state.update_failures > 0 {
            state.update_failures -= 1;
            return Err(ConnectError::new(ErrorCode::Aborted, "replay in flight"));
        }
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn begin_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn upload_part(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        Err(ConnectError::unimplemented("unused"))
    }

    async fn complete_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        Err(ConnectError::unimplemented("unused"))
    }
}

struct Served {
    port: u16,
    state: Arc<Mutex<State>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Served {
    fn new(state: State) -> Self {
        let state = Arc::new(Mutex::new(state));
        let service = Arc::new(TestService(Arc::clone(&state)));
        let (port_tx, port_rx) = mpsc::channel();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let bound = Server::bind("127.0.0.1:0").await.unwrap();
                    port_tx.send(bound.local_addr().unwrap().port()).unwrap();
                    bound
                        .serve_with_graceful_shutdown(Router::new().add_service(service), async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
        });
        Self {
            port: port_rx.recv().unwrap(),
            state,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    fn client(&self) -> ConnectTransport {
        ConnectTransport::connect_for_test(
            format!("http://127.0.0.1:{}", self.port).parse().unwrap(),
        )
    }

    fn calls(&self, rpc: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|request| request.rpc == rpc)
            .count()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn page(names: &[&str], token: Option<&str>) -> generated::ListRefsResponse {
    generated::ListRefsResponse {
        refs: names
            .iter()
            .map(|name| generated::RefEntry {
                name: Some((*name).into()),
                object_id: Some(hash(name.as_bytes()).to_vec()),
                ..Default::default()
            })
            .collect(),
        next_page_token: token.map(str::to_owned),
        ..Default::default()
    }
}

#[test]
fn atomic_advance_uses_cached_advertisement() {
    for atomic in [Some(true), Some(false), None] {
        let served = Served::new(State {
            discovery: Discovery::Response(Box::new(info(atomic))),
            ..Default::default()
        });
        let client = served.client();
        assert_eq!(served.calls("GetServerInfo"), 0, "construction is lazy");
        assert_eq!(client.supports_atomic_advance(), atomic == Some(true));
        served.state.lock().unwrap().discovery =
            Discovery::Response(Box::new(info(atomic.map(|value| !value))));
        assert_eq!(client.supports_atomic_advance(), atomic == Some(true));
        let ServerInfoView::V2(response) = client.server_info() else {
            panic!("valid v2 advertisement")
        };
        assert_eq!(response.atomic_advance, atomic);
        assert_eq!(served.calls("GetServerInfo"), 1);
        assert_eq!(
            served.state.lock().unwrap().requests[0]
                .repository
                .as_deref(),
            Some("default")
        );
    }
}

#[test]
fn discovery_is_once_even_for_concurrent_callers() {
    let served = Served::new(State::default());
    let client = served.client();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| assert!(client.supports_atomic_advance()));
        }
    });
    assert_eq!(served.calls("GetServerInfo"), 1);
}

#[test]
fn legacy_and_exhausted_discovery_remain_conservative() {
    for (code, expected_calls) in [
        (ErrorCode::Unimplemented, 1),
        (ErrorCode::Unavailable, 6),
        (ErrorCode::NotFound, 1),
    ] {
        let served = Served::new(State {
            discovery: Discovery::Error(code),
            ..Default::default()
        });
        let client = served.client();
        assert!(!client.supports_atomic_advance());
        served.state.lock().unwrap().discovery = Discovery::Response(Box::new(info(Some(true))));
        assert!(!client.supports_atomic_advance());
        if code == ErrorCode::Unimplemented {
            assert!(matches!(client.server_info(), ServerInfoView::Legacy));
        } else {
            assert!(matches!(client.server_info(), ServerInfoView::Unknown));
        }
        assert_eq!(served.calls("GetServerInfo"), expected_calls);
    }
}

#[test]
fn invalid_discovery_fields_never_enable_atomic_advance() {
    let valid = info(Some(true));
    let invalid = [
        generated::GetServerInfoResponse {
            protocol: Some("other.protocol".into()),
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            protocol: None,
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            spec_version: Some(1),
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            spec_version: None,
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            part_size: Some(4 << 20),
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            part_size: Some((8 << 20) + 1),
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            part_size: None,
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            max_list_refs_page_size: Some(0),
            ..valid.clone()
        },
        generated::GetServerInfoResponse {
            max_list_refs_page_size: None,
            ..valid
        },
    ];
    for response in invalid {
        let served = Served::new(State {
            discovery: Discovery::Response(Box::new(response)),
            ..Default::default()
        });
        let client = served.client();
        assert!(!client.supports_atomic_advance());
        assert!(matches!(client.server_info(), ServerInfoView::Unknown));
        assert_eq!(served.calls("GetServerInfo"), 1);
    }
}

#[test]
fn newer_valid_spec_version_is_supported() {
    let served = Served::new(State {
        discovery: Discovery::Response(Box::new(generated::GetServerInfoResponse {
            spec_version: Some(3),
            ..info(Some(true))
        })),
        ..Default::default()
    });
    assert!(served.client().supports_atomic_advance());
}

#[test]
fn pages_concatenate_and_each_page_retries_the_same_request() {
    let served = Served::new(State {
        pages: vec![
            page(&["refs/heads/a"], Some("page-2")),
            page(&["refs/heads/b"], Some("page-3")),
            page(&["refs/heads/c"], Some("")),
        ],
        fail_page_once: Some("page-2".into()),
        ..Default::default()
    });
    let client = served.client();
    let refs = client.list_refs("refs/heads/").unwrap();
    assert_eq!(
        refs.iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/a", "refs/heads/b", "refs/heads/c"]
    );
    let state = served.state.lock().unwrap();
    let requests: Vec<_> = state
        .requests
        .iter()
        .map(|capture| capture.list.as_ref().unwrap())
        .collect();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].page_token.as_deref(), Some("page-2"));
    assert_eq!(requests[2].page_token, requests[1].page_token);
    for request in &requests {
        assert_eq!(request.prefix.as_deref(), Some("refs/heads/"));
        assert_eq!(request.page_size, None, "server selects its page cap");
    }
    assert!(
        state
            .requests
            .iter()
            .all(|request| request.repository.as_deref() == Some("default"))
    );
    drop(state);
    assert_eq!(
        served.calls("GetServerInfo"),
        0,
        "listing never discovers capabilities"
    );
}

#[test]
fn repeated_token_and_nonincreasing_page_boundary_are_rejected() {
    for pages in [
        vec![
            page(&["refs/heads/a"], Some("next")),
            page(&["refs/heads/b"], Some("next")),
        ],
        vec![
            page(&["refs/heads/b"], Some("next")),
            page(&["refs/heads/a"], None),
        ],
        vec![
            page(&["refs/heads/a"], Some("next")),
            page(&["refs/heads/a"], None),
        ],
    ] {
        let served = Served::new(State {
            pages,
            ..Default::default()
        });
        assert!(matches!(
            served.client().list_refs(""),
            Err(TransportError::InvalidResponse)
        ));
        assert_eq!(served.calls("ListRefs"), 2);
    }
}

/// Deterministic stand-in signer: the "signature" is the signing digest, so
/// equal signatures mean an equal canonical string.
struct DigestSigner;

impl mkit_transport_connect::EnvelopeSigner for DigestSigner {
    fn public_key_hex(&self) -> String {
        "11".repeat(32)
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        let hex: String = message.iter().map(|b| format!("{b:02x}")).collect();
        Ok(hex.repeat(2))
    }
}

#[test]
fn aborted_signed_write_retries_with_the_same_nonce_and_signature() {
    let served = Served::new(State {
        update_failures: 1,
        ..Default::default()
    });
    let client = ConnectTransport::connect_for_test_with_signer(
        format!("http://127.0.0.1:{}", served.port).parse().unwrap(),
        Some(Arc::new(DigestSigner)),
    );
    client
        .update_ref(
            "refs/heads/main",
            mkit_core::protocol::RefWriteCondition::Any,
            &hash(DATA),
        )
        .unwrap();
    let state = served.state.lock().unwrap();
    let attempts: Vec<_> = state
        .requests
        .iter()
        .filter(|capture| capture.rpc == "UpdateRef")
        .map(|capture| capture.signed.clone().expect("signed write"))
        .collect();
    assert_eq!(attempts.len(), 2, "one aborted attempt, one retry");
    assert!(attempts[0].iter().all(|value| !value.is_empty()));
    assert_eq!(attempts[0], attempts[1]);
}

#[test]
fn cursor_cycles_and_unordered_pages_are_rejected() {
    // Empty pages cycling A -> B -> A: the repeat is two pages back.
    let served = Served::new(State {
        pages: vec![
            page(&["refs/heads/a"], Some("A")),
            page(&[], Some("B")),
            page(&[], Some("A")),
        ],
        ..Default::default()
    });
    assert!(matches!(
        served.client().list_refs(""),
        Err(TransportError::InvalidResponse)
    ));
    assert_eq!(served.calls("ListRefs"), 3);

    // Out-of-order names within one page.
    let served = Served::new(State {
        pages: vec![page(&["refs/heads/b", "refs/heads/a"], None)],
        ..Default::default()
    });
    assert!(matches!(
        served.client().list_refs(""),
        Err(TransportError::InvalidResponse)
    ));
    assert_eq!(served.calls("ListRefs"), 1);
}

#[test]
fn ref_hints_survive_retry_and_invalid_hints_are_dropped() {
    let served = Served::new(State {
        download_failures: 1,
        ..Default::default()
    });
    let client = served.client();
    let key = PackKey::new(hash(DATA));
    assert_eq!(
        client
            .download_pack_via_ref(&key, "refs/heads/main")
            .unwrap(),
        DATA
    );
    assert_eq!(
        client
            .download_blob_via_ref(&key, "refs/heads/main")
            .unwrap(),
        DATA
    );
    assert!(client.pack_exists_via_ref(&key, "refs/heads/main").unwrap());
    assert_eq!(client.download_pack(&key).unwrap(), DATA);
    assert_eq!(client.download_blob(&key).unwrap(), DATA);
    assert!(client.pack_exists(&key).unwrap());
    for hint in ["../bad", "refs/heads/bad\nheader"] {
        assert_eq!(client.download_pack_via_ref(&key, hint).unwrap(), DATA);
        assert_eq!(client.download_blob_via_ref(&key, hint).unwrap(), DATA);
        assert!(client.pack_exists_via_ref(&key, hint).unwrap());
    }
    let state = served.state.lock().unwrap();
    assert_eq!(state.requests.len(), 13);
    for (index, request) in state.requests.iter().enumerate() {
        assert_eq!(request.repository.as_deref(), Some("default"));
        assert_eq!(
            request.hint.as_deref(),
            (index < 4).then_some("refs/heads/main")
        );
    }
    drop(state);
    assert_eq!(served.calls("GetServerInfo"), 0);
}

#[test]
fn not_found_means_absent_ref_and_pack_but_listing_still_errors() {
    let served = Served::new(State {
        missing: true,
        ..Default::default()
    });
    let client = served.client();
    let key = PackKey::new(hash(DATA));
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), None);
    assert!(!client.pack_exists(&key).unwrap());
    assert!(matches!(
        client.download_pack(&key),
        Err(TransportError::PackNotFound)
    ));
    assert!(matches!(
        client.list_refs(""),
        Err(TransportError::PackNotFound)
    ));
    assert_eq!(
        served.state.lock().unwrap().requests.len(),
        4,
        "not_found is never retried"
    );
}

#[test]
fn aborted_is_retried_without_capability_discovery() {
    let served = Served::new(State {
        read_failures: 2,
        ..Default::default()
    });
    assert_eq!(served.client().read_ref("refs/heads/main").unwrap(), None);
    assert_eq!(served.calls("ReadRef"), 3);
    assert_eq!(served.calls("GetServerInfo"), 0);
}
