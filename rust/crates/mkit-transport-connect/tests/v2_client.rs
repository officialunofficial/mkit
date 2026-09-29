//! STC v2 client behavior over real HTTP and generated Connect dispatch.

use base64::Engine as _;
use buffa::Message as _;
use futures::StreamExt as _;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use generated::__buffa::oneof::upload_part_request::Msg as PartBody;
use mkit_core::hash::hash;
use mkit_core::protocol::{
    AdvanceOutcome, CommitOutcome, PackKey, RefWriteCondition, Transport, TransportError,
    TransportResult,
};
use mkit_core::upload_parts::PartPlan;
use mkit_transport_connect::{
    ConnectTransport, GrantRequest, GrantSource, MemoryPartReceiptStore, PartReceiptStore,
    ServerInfoView, StoredPart, TicketMetadata, UploadEvent, generated,
};

const DATA: &[u8] = b"v2 pack bytes";

#[derive(Clone)]
enum Discovery {
    Response(Box<generated::GetServerInfoResponse>),
    Error(ErrorCode),
}

#[derive(Clone)]
enum BeginMode {
    Ticket,
    Present,
    Unimplemented,
    Cap,
}

fn info(atomic: Option<bool>) -> generated::GetServerInfoResponse {
    generated::GetServerInfoResponse {
        protocol: Some("mkit.transport.v1".into()),
        spec_version: Some(2),
        part_size: Some(8 << 20),
        max_parts: Some(512),
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
    grant: Option<String>,
    commitment: Option<String>,
    begin: Option<generated::BeginUploadRequest>,
    advance: Option<generated::AdvanceRefsRequest>,
    upload_token: Option<Vec<u8>>,
    part_index: Option<u32>,
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
    begin_modes: VecDeque<BeginMode>,
    begin_expiries: VecDeque<i64>,
    upload_ticket_failure_once: bool,
    advance_errors: VecDeque<(ErrorCode, String)>,
    advance_outcomes: VecDeque<generated::AdvanceOutcome>,
    advance_pending_once: bool,
    part_fail_once: Option<u32>,
    part_ticket_fail_once: Option<u32>,
    complete_invalid_once: bool,
    completed_receipts: Vec<Vec<u8>>,
    ticket_id: [u8; 32],
    ticket_ids: VecDeque<[u8; 32]>,
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
            begin_modes: VecDeque::new(),
            begin_expiries: VecDeque::new(),
            upload_ticket_failure_once: false,
            advance_errors: VecDeque::new(),
            advance_outcomes: VecDeque::new(),
            advance_pending_once: false,
            part_fail_once: None,
            part_ticket_fail_once: None,
            complete_invalid_once: false,
            completed_receipts: Vec::new(),
            ticket_id: [7; 32],
            ticket_ids: VecDeque::new(),
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
            grant: header("x-write-grant"),
            commitment: header("x-content-commitment"),
            begin: None,
            advance: None,
            upload_token: None,
            part_index: None,
        });
    }
}

#[allow(refining_impl_trait)]
impl generated::TransportService for TestService {
    async fn get_receipt(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetReceiptRequest>,
    ) -> ServiceResult<generated::GetReceiptResponse> {
        Err(ConnectError::unimplemented("not implemented yet"))
    }

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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        self.capture("AdvanceRefs", &ctx);
        let mut state = self.0.lock().unwrap();
        state.requests.last_mut().unwrap().advance = Some(request.to_owned_message());
        if state.advance_pending_once {
            state.advance_pending_once = false;
            let bytes = generated::PendingVerification {
                retry_after_ms: Some(1_000),
                ..Default::default()
            }
            .encode_to_vec();
            return Err(
                ConnectError::unavailable("verification pending").with_detail(
                    connectrpc::ErrorDetail {
                        type_url: "mkit.transport.v1.PendingVerification".into(),
                        value: Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)),
                        debug: None,
                    },
                ),
            );
        }
        if let Some((code, message)) = state.advance_errors.pop_front() {
            return Err(ConnectError::new(code, message));
        }
        Ok(Response::new(generated::AdvanceRefsResponse {
            outcome: Some(
                state
                    .advance_outcomes
                    .pop_front()
                    .unwrap_or(generated::AdvanceOutcome::Committed)
                    .into(),
            ),
            ..Default::default()
        }))
    }

    async fn upload_pack(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        self.capture("UploadPack", &ctx);
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("missing header"))??;
        let Some(UploadBody::Header(header)) = first.to_owned_message().body else {
            return Err(ConnectError::invalid_argument("missing header"));
        };
        let mut received = 0_u64;
        while let Some(message) = requests.next().await {
            let message = message?.to_owned_message();
            if let Some(UploadBody::Chunk(chunk)) = message.body {
                received += chunk.data.as_ref().map_or(0, |data| data.len()) as u64;
                if chunk.last == Some(true) {
                    break;
                }
            }
        }
        if received != header.total_bytes.unwrap_or(0) {
            return Err(ConnectError::invalid_argument("length mismatch"));
        }
        let mut state = self.0.lock().unwrap();
        state.requests.last_mut().unwrap().upload_token = header.ticket_token;
        if state.upload_ticket_failure_once {
            state.upload_ticket_failure_once = false;
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "ticket expired",
            ));
        }
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn begin_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        self.capture("BeginUpload", &ctx);
        let mut state = self.0.lock().unwrap();
        state.requests.last_mut().unwrap().begin = Some(request.to_owned_message());
        match state.begin_modes.pop_front().unwrap_or(BeginMode::Ticket) {
            BeginMode::Present => Ok(Response::new(generated::BeginUploadResponse {
                result: Some(BeginResult::AlreadyPresent(Box::default())),
                ..Default::default()
            })),
            BeginMode::Unimplemented => Err(ConnectError::unimplemented("unused")),
            BeginMode::Cap => Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "too many open upload tickets",
            )),
            BeginMode::Ticket => Ok(Response::new(generated::BeginUploadResponse {
                result: Some(BeginResult::Ticket(Box::new(generated::UploadTicket {
                    id: Some(
                        state
                            .ticket_ids
                            .pop_front()
                            .unwrap_or(state.ticket_id)
                            .to_vec(),
                    ),
                    part_size: Some(8 << 20),
                    expires_unix_ms: Some(state.begin_expiries.pop_front().unwrap_or(i64::MAX)),
                    token: Some(vec![8, 9]),
                    ..Default::default()
                }))),
                ..Default::default()
            })),
        }
    }

    async fn upload_part(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        self.capture("UploadPart", &ctx);
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("missing part header"))??;
        let Some(PartBody::Header(header)) = first.to_owned_message().msg else {
            return Err(ConnectError::invalid_argument("missing part header"));
        };
        let index = header.index.unwrap_or(0);
        let mut bytes = 0_usize;
        while let Some(message) = requests.next().await {
            if let Some(PartBody::Chunk(chunk)) = message?.to_owned_message().msg {
                bytes += chunk.len();
            }
        }
        if bytes == 0 {
            return Err(ConnectError::invalid_argument("empty part"));
        }
        let mut state = self.0.lock().unwrap();
        state.requests.last_mut().unwrap().part_index = Some(index);
        if state.part_ticket_fail_once == Some(index) {
            state.part_ticket_fail_once = None;
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "ticket expired",
            ));
        }
        if state.part_fail_once == Some(index) {
            state.part_fail_once = None;
            return Err(ConnectError::permission_denied("injected part failure"));
        }
        Ok(Response::new(generated::UploadPartResponse {
            receipt: Some(vec![index as u8, 1]),
            ..Default::default()
        }))
    }

    async fn complete_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        self.capture("CompleteUpload", &ctx);
        let mut state = self.0.lock().unwrap();
        state.completed_receipts = request.to_owned_message().receipts;
        if state.complete_invalid_once {
            state.complete_invalid_once = false;
            return Err(ConnectError::invalid_argument("invalid receipt"));
        }
        Ok(Response::new(generated::CompleteUploadResponse::default()))
    }

    async fn get_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetGrantEpochRequest>,
    ) -> ServiceResult<generated::GetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetGrantEpochRequest>,
    ) -> ServiceResult<generated::SetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_repo_visibility(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetRepoVisibilityRequest>,
    ) -> ServiceResult<generated::SetRepoVisibilityResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn issue_object_url(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::IssueObjectUrlRequest>,
    ) -> ServiceResult<generated::IssueObjectUrlResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
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

    fn signed_client(&self) -> ConnectTransport {
        ConnectTransport::connect_for_test_with_signer(
            format!("http://127.0.0.1:{}", self.port).parse().unwrap(),
            Some(Arc::new(DigestSigner)),
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
fn begin_upload_ticket_and_advance_commit_set() {
    let served = Served::new(State {
        ticket_ids: [[7; 32], [8; 32]].into(),
        ..Default::default()
    });
    let client = served.signed_client();
    let key = PackKey::new(hash(DATA));
    client
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    let stale = PackKey::new(hash(b"stale packmap node"));
    client
        .upload_blob_via_ref(b"stale packmap node", &stale, "refs/heads/main")
        .unwrap();
    let state = served.state.lock().unwrap();
    let begin = state
        .requests
        .iter()
        .find(|r| r.rpc == "BeginUpload")
        .unwrap();
    assert_eq!(
        begin.begin.as_ref().unwrap().r#ref.as_deref(),
        Some("refs/heads/main")
    );
    assert!(begin.signed.is_some());
    let upload = state
        .requests
        .iter()
        .find(|r| r.rpc == "UploadPack")
        .unwrap();
    assert_eq!(upload.upload_token.as_deref(), Some(&[8, 9][..]));
    drop(state);
    let result = client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"head"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"map"),
            &[key],
        )
        .unwrap();
    assert_eq!(
        result,
        CommitOutcome::Advanced(mkit_core::protocol::AdvanceOutcome::Committed)
    );
    let advance = served
        .state
        .lock()
        .unwrap()
        .requests
        .iter()
        .find(|r| r.rpc == "AdvanceRefs")
        .unwrap()
        .advance
        .clone()
        .unwrap();
    assert_eq!(advance.ticket_ids, vec![vec![7; 32]]);
    client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"head"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"map"),
            &[key],
        )
        .unwrap();
    let state = served.state.lock().unwrap();
    let advances: Vec<_> = state
        .requests
        .iter()
        .filter_map(|r| r.advance.as_ref())
        .collect();
    assert!(
        advances[1].ticket_ids.is_empty(),
        "committed ticket was evicted"
    );
    drop(state);
    client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"head"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"map"),
            &[stale],
        )
        .unwrap();
    let state = served.state.lock().unwrap();
    assert_eq!(
        state
            .requests
            .iter()
            .filter_map(|r| r.advance.as_ref())
            .next_back()
            .unwrap()
            .ticket_ids,
        vec![vec![8; 32]],
    );
}

#[test]
fn ticket_is_retained_after_typed_conflict() {
    let served = Served::new(State {
        advance_outcomes: [generated::AdvanceOutcome::PackmapConflict].into(),
        ..Default::default()
    });
    let client = served.signed_client();
    let key = PackKey::new(hash(DATA));
    client
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    for expected in [AdvanceOutcome::PackmapConflict, AdvanceOutcome::Committed] {
        assert_eq!(
            client
                .advance_refs_committing(
                    "refs/heads/main",
                    RefWriteCondition::Missing,
                    &hash(b"head"),
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    &hash(b"map"),
                    &[key],
                )
                .unwrap(),
            CommitOutcome::Advanced(expected),
        );
    }
    let state = served.state.lock().unwrap();
    let advances: Vec<_> = state
        .requests
        .iter()
        .filter_map(|r| r.advance.as_ref())
        .collect();
    assert_eq!(advances.len(), 2);
    assert_eq!(advances[0].ticket_ids, vec![vec![7; 32]]);
    assert_eq!(advances[1].ticket_ids, vec![vec![7; 32]]);
}

#[test]
fn already_present_cap_and_upload_side_ticket_failure() {
    let key = PackKey::new(hash(DATA));
    let served = Served::new(State {
        begin_modes: VecDeque::from([BeginMode::Present]),
        ..Default::default()
    });
    served
        .signed_client()
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("UploadPack"), 0);

    let served = Served::new(State {
        begin_modes: VecDeque::from([BeginMode::Cap]),
        ..Default::default()
    });
    assert!(
        served
            .signed_client()
            .upload_pack_via_ref(DATA, &key, "refs/heads/main")
            .unwrap_err()
            .to_string()
            .contains("too many open upload tickets")
    );
    assert_eq!(served.calls("BeginUpload"), 1);

    let served = Served::new(State {
        upload_ticket_failure_once: true,
        ..Default::default()
    });
    served
        .signed_client()
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("BeginUpload"), 2);
    assert_eq!(served.calls("UploadPack"), 2);
}

#[test]
fn ticketed_advance_rejects_bad_local_commit_sets_and_classifies_server_errors() {
    let served = Served::new(State::default());
    let client = served.signed_client();
    let key = PackKey::new(hash(DATA));
    client
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    let advance = |refs: (&str, &str), keys: &[PackKey]| {
        client.advance_refs_committing(
            refs.0,
            RefWriteCondition::Missing,
            &hash(b"head"),
            refs.1,
            RefWriteCondition::Missing,
            &hash(b"map"),
            keys,
        )
    };
    assert!(matches!(
        advance(("refs/heads/main", "refs/mkit/packmap/other"), &[key]),
        Err(TransportError::InvalidRef(_))
    ));
    assert!(matches!(
        advance(("refs/heads/main", "refs/mkit/packmap/main"), &[key, key]),
        Err(TransportError::InvalidRef(_))
    ));
    assert!(matches!(
        advance(("refs/heads/main", "refs/mkit/packmap/main"), &[key; 8]),
        Err(TransportError::InvalidRef(_))
    ));
    assert_eq!(served.calls("AdvanceRefs"), 0);
    for (code, message, expected) in [
        (
            ErrorCode::FailedPrecondition,
            "ticket expired",
            CommitOutcome::TicketRejected,
        ),
        (
            ErrorCode::FailedPrecondition,
            "delta base not available in this repository",
            CommitOutcome::DeltaBaseUnavailable,
        ),
        (
            ErrorCode::InvalidArgument,
            "packlist lists a pack that is not in this repository",
            CommitOutcome::PacklistNotInRepository,
        ),
    ] {
        served
            .state
            .lock()
            .unwrap()
            .advance_errors
            .push_back((code, message.into()));
        assert_eq!(
            advance(("refs/heads/main", "refs/mkit/packmap/main"), &[key]).unwrap(),
            expected
        );
    }
}

#[test]
fn multipart_receipts_resume_after_part_two() {
    let served = Served::new(State {
        part_fail_once: Some(2),
        ..Default::default()
    });
    let bytes = vec![3; (16 << 20) + 1];
    let key = PackKey::new(hash(&bytes));
    let receipts = Arc::new(MemoryPartReceiptStore::default());
    let first = served.signed_client().with_receipt_store(receipts.clone());
    assert!(
        first
            .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
            .is_err()
    );
    drop(first);
    let second = served.signed_client().with_receipt_store(receipts);
    second
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    let state = served.state.lock().unwrap();
    let indices: Vec<_> = state.requests.iter().filter_map(|r| r.part_index).collect();
    assert_eq!(indices, [0, 1, 2, 2]);
    assert_eq!(
        state.completed_receipts,
        vec![vec![0, 1], vec![1, 1], vec![2, 1]]
    );
    drop(state);
    assert_eq!(served.calls("UploadPack"), 0);
}

#[test]
fn upload_part_ticket_failure_restarts_with_one_new_ticket() {
    let served = Served::new(State {
        ticket_ids: [[7; 32], [8; 32]].into(),
        part_ticket_fail_once: Some(0),
        ..Default::default()
    });
    let bytes = vec![4; (8 << 20) + 1];
    let key = PackKey::new(hash(&bytes));
    served
        .signed_client()
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("BeginUpload"), 2);
    let indices: Vec<_> = served
        .state
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter_map(|r| r.part_index)
        .collect();
    assert_eq!(indices, [0, 0, 1]);
}

#[test]
fn exact_part_boundary_uses_upload_pack_and_excess_respects_max_parts() {
    let bytes = vec![4; 8 << 20];
    let key = PackKey::new(hash(&bytes));
    let served = Served::new(State::default());
    served
        .signed_client()
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("UploadPack"), 1);
    assert_eq!(served.calls("UploadPart"), 0);

    let mut limited = info(Some(true));
    limited.max_parts = Some(1);
    let served = Served::new(State {
        discovery: Discovery::Response(Box::new(limited)),
        ..Default::default()
    });
    let excess = vec![4; (8 << 20) + 1];
    let key = PackKey::new(hash(&excess));
    let error = served
        .signed_client()
        .upload_pack_via_ref(&excess, &key, "refs/heads/main")
        .unwrap_err();
    assert!(error.to_string().contains("maximum number of upload parts"));
    assert_eq!(served.calls("UploadPack"), 0);
    assert_eq!(served.calls("UploadPart"), 0);
}

#[derive(Default)]
struct RestartedReceiptStore(MemoryPartReceiptStore);

impl PartReceiptStore for RestartedReceiptStore {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>> {
        let mut parts = self.0.load(ticket, plan)?;
        for part in &mut parts {
            part.from_disk = true;
        }
        Ok(parts)
    }
    fn put(&self, ticket: &TicketMetadata, part: &StoredPart) -> TransportResult<()> {
        self.0.put(ticket, part)
    }
    fn forget(&self, ticket_id: &[u8; 32]) -> TransportResult<()> {
        self.0.forget(ticket_id)
    }
    fn sweep(&self, now_ms: i64) -> TransportResult<()> {
        self.0.sweep(now_ms)
    }
}

#[test]
fn disk_receipt_invalid_argument_resends_all_but_fresh_receipt_fails() {
    let served = Served::new(State {
        complete_invalid_once: true,
        ..Default::default()
    });
    let bytes = vec![4; (8 << 20) + 1];
    let key = PackKey::new(hash(&bytes));
    let store = Arc::new(RestartedReceiptStore::default());
    let first = served
        .signed_client()
        .with_receipt_store(store.clone())
        .with_upload_observer(|event| !matches!(event, UploadEvent::PartSent { index: 0, .. }));
    assert!(
        first
            .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
            .is_err()
    );
    let restarted = served.signed_client().with_receipt_store(store);
    restarted
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    let indices: Vec<_> = served
        .state
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter_map(|r| r.part_index)
        .collect();
    assert_eq!(indices, [0, 1, 0, 1]);

    let served = Served::new(State {
        complete_invalid_once: true,
        ..Default::default()
    });
    let err = served
        .signed_client()
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap_err();
    assert!(matches!(err, TransportError::ProtocolError));
}

#[test]
fn discovery_fallback_matrix_latches_unknown_only() {
    let key = PackKey::new(hash(DATA));
    let served = Served::new(State::default());
    assert!(
        served
            .client()
            .upload_pack_via_ref(DATA, &key, "refs/heads/main")
            .unwrap_err()
            .to_string()
            .contains("transport_auth = envelope")
    );
    assert_eq!(served.calls("BeginUpload"), 0);

    let mut below_threshold = info(Some(true));
    below_threshold.begin_upload_threshold_bytes = Some(1024);
    let served = Served::new(State {
        discovery: Discovery::Response(Box::new(below_threshold)),
        ..Default::default()
    });
    served
        .client()
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("BeginUpload"), 0);
    assert_eq!(served.calls("UploadPack"), 1);

    let served = Served::new(State {
        discovery: Discovery::Error(ErrorCode::Unimplemented),
        ..Default::default()
    });
    served
        .client()
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("BeginUpload"), 0);

    let served = Served::new(State {
        discovery: Discovery::Error(ErrorCode::NotFound),
        begin_modes: VecDeque::from([BeginMode::Unimplemented]),
        ..Default::default()
    });
    let client = served.signed_client();
    client
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    client
        .upload_pack_via_ref(DATA, &key, "refs/heads/main")
        .unwrap();
    assert_eq!(served.calls("BeginUpload"), 1);
    assert_eq!(served.calls("UploadPack"), 2);

    let served = Served::new(State {
        begin_modes: VecDeque::from([BeginMode::Unimplemented]),
        ..Default::default()
    });
    let bytes = vec![5; (8 << 20) + 1];
    let key = PackKey::new(hash(&bytes));
    assert!(
        served
            .signed_client()
            .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
            .unwrap_err()
            .to_string()
            .contains("server storage cannot accept packs over part_size")
    );
    assert_eq!(served.calls("UploadPack"), 0);
}

#[test]
fn client_part_commitment_matches_auth_v2_golden() {
    let served = Served::new(State {
        ticket_id: [0x5a; 32],
        ..Default::default()
    });
    let bytes: Vec<u8> = (0..(8 << 20) + 1).map(|i| (i % 251) as u8).collect();
    let key = PackKey::new(hash(&bytes));
    served
        .signed_client()
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/golden/auth-v2/part.json")).unwrap();
    let state = served.state.lock().unwrap();
    let commitment = state
        .requests
        .iter()
        .find(|request| request.part_index == Some(1))
        .unwrap()
        .commitment
        .as_deref()
        .unwrap();
    assert_eq!(commitment, golden["commitment"].as_str().unwrap());
}

struct TestGrant;
impl GrantSource for TestGrant {
    fn select(&self, _request: &GrantRequest<'_>) -> Option<String> {
        Some("grant-value".into())
    }
}

static GRANT_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);
fn grant_now() -> i64 {
    GRANT_CLOCK.load(Ordering::SeqCst)
}
fn advance_grant_clock(_: std::time::Duration) {
    GRANT_CLOCK.fetch_add(270_000, Ordering::SeqCst);
}
fn short_backoff() -> mkit_core::protocol::BackoffIterator {
    mkit_core::protocol::BackoffIterator::with(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(1),
        5,
    )
}

static LAG_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);
fn lag_now() -> i64 {
    LAG_CLOCK.load(Ordering::SeqCst)
}
fn lag_sleep(duration: std::time::Duration) {
    LAG_CLOCK.fetch_add(duration.as_millis() as i64, Ordering::SeqCst);
}

#[test]
fn membership_lag_polls_same_nonce_and_honors_sixty_second_limit() {
    let lag = || {
        (
            ErrorCode::Unavailable,
            "repository membership not yet visible".to_owned(),
        )
    };
    LAG_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let served = Served::new(State {
        advance_errors: [lag(), lag()].into(),
        ..Default::default()
    });
    let client = served
        .signed_client()
        .with_clock_for_test(lag_now)
        .with_retry_hooks_for_test(short_backoff, lag_sleep);
    let bytes = b"lag pack";
    let key = PackKey::new(hash(bytes));
    client
        .upload_pack_via_ref(bytes, &key, "refs/heads/main")
        .unwrap();
    let outcome = client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"tip"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"node"),
            &[key],
        )
        .unwrap();
    assert_eq!(outcome, CommitOutcome::Advanced(AdvanceOutcome::Committed));
    let state = served.state.lock().unwrap();
    let calls: Vec<_> = state
        .requests
        .iter()
        .filter(|r| r.rpc == "AdvanceRefs")
        .collect();
    assert_eq!(calls.len(), 3);
    assert!(
        calls
            .windows(2)
            .all(|pair| pair[0].signed.as_ref().unwrap()[3] == pair[1].signed.as_ref().unwrap()[3])
    );
    assert_eq!(LAG_CLOCK.load(Ordering::SeqCst), 1_700_000_004_000);
    drop(state);

    LAG_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let served = Served::new(State {
        advance_errors: (0..32).map(|_| lag()).collect(),
        ..Default::default()
    });
    let client = served
        .signed_client()
        .with_clock_for_test(lag_now)
        .with_retry_hooks_for_test(short_backoff, lag_sleep);
    client
        .upload_pack_via_ref(bytes, &key, "refs/heads/main")
        .unwrap();
    let error = client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"tip"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"node"),
            &[key],
        )
        .unwrap_err();
    assert!(
        matches!(error, TransportError::RemoteError(message) if message.contains("60 seconds"))
    );
    assert_eq!(LAG_CLOCK.load(Ordering::SeqCst), 1_700_000_060_000);

    LAG_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let served = Served::new(State {
        advance_errors: [lag()].into(),
        ..Default::default()
    });
    let client = served
        .signed_client()
        .with_clock_for_test(lag_now)
        .with_retry_hooks_for_test(short_backoff, lag_sleep)
        .with_pending_observer(|_| false);
    client
        .upload_pack_via_ref(bytes, &key, "refs/heads/main")
        .unwrap();
    assert!(
        client
            .advance_refs_committing(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &hash(b"tip"),
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &hash(b"node"),
                &[key],
            )
            .is_err()
    );
    assert_eq!(served.calls("AdvanceRefs"), 1);
    assert_eq!(LAG_CLOCK.load(Ordering::SeqCst), 1_700_000_000_000);
}

#[test]
fn advance_deadline_uses_earliest_ticket_expiry() {
    let start = 1_700_000_000_000;
    LAG_CLOCK.store(start, Ordering::SeqCst);
    let served = Served::new(State {
        begin_expiries: [start + 5_000, start + 3_000].into(),
        ticket_ids: [[7; 32], [8; 32]].into(),
        advance_errors: (0..4)
            .map(|_| {
                (
                    ErrorCode::Unavailable,
                    "repository membership not yet visible".to_owned(),
                )
            })
            .collect(),
        ..Default::default()
    });
    let client = served
        .signed_client()
        .with_clock_for_test(lag_now)
        .with_retry_hooks_for_test(short_backoff, lag_sleep);
    let first = PackKey::new(hash(b"first"));
    let second = PackKey::new(hash(b"second"));
    client
        .upload_pack_via_ref(b"first", &first, "refs/heads/main")
        .unwrap();
    client
        .upload_pack_via_ref(b"second", &second, "refs/heads/main")
        .unwrap();
    let error = client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"tip"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"node"),
            &[first, second],
        )
        .unwrap_err();
    assert!(
        matches!(error, TransportError::RemoteError(message) if message.contains("deadline expired"))
    );
    assert_eq!(LAG_CLOCK.load(Ordering::SeqCst), start + 3_000);
    assert_eq!(served.calls("AdvanceRefs"), 2);
}

#[test]
fn non_owner_grant_survives_begin_parts_pending_poll_and_resign() {
    GRANT_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let served = Served::new(State {
        advance_pending_once: true,
        ..Default::default()
    });
    let uri = format!(
        "http://127.0.0.1:{}/0x8ba1f109551bd432803012645ac136ddd64dba72/photos",
        served.port,
    )
    .parse()
    .unwrap();
    let client = ConnectTransport::connect_for_test_with_signer(uri, Some(Arc::new(DigestSigner)))
        .with_grant_source(Arc::new(TestGrant))
        .with_clock_for_test(grant_now)
        .with_retry_hooks_for_test(short_backoff, advance_grant_clock);
    let bytes = vec![4; (8 << 20) + 1];
    let key = PackKey::new(hash(&bytes));
    client
        .upload_pack_via_ref(&bytes, &key, "refs/heads/main")
        .unwrap();
    client
        .advance_refs_committing(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"head"),
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &hash(b"map"),
            &[key],
        )
        .unwrap();
    let state = served.state.lock().unwrap();
    let begin = state
        .requests
        .iter()
        .find(|r| r.rpc == "BeginUpload")
        .unwrap();
    assert_eq!(begin.grant.as_deref(), Some("grant-value"));
    assert!(
        state
            .requests
            .iter()
            .filter(|r| r.rpc == "UploadPart" || r.rpc == "CompleteUpload")
            .all(|r| r.grant.is_none())
    );
    let advances: Vec<_> = state
        .requests
        .iter()
        .filter(|r| r.rpc == "AdvanceRefs")
        .collect();
    assert_eq!(advances.len(), 2);
    assert!(
        advances
            .iter()
            .all(|r| r.grant.as_deref() == Some("grant-value"))
    );
    assert_ne!(
        advances[0].signed.as_ref().unwrap()[3],
        advances[1].signed.as_ref().unwrap()[3]
    );
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
            max_parts: Some(0),
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
