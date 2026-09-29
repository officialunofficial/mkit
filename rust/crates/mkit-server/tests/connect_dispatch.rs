//! `connect::service` driven through real Connect HTTP requests on the host
//! (`tower::ServiceExt::oneshot`, as `apps/vcs-worker/tests/
//! health_check_dispatch.rs` does), over the memory stores: the unary JSON
//! and binary codecs, `connect+proto` stream framing, auth, health and the
//! error-shaping path.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use buffa::Message;
use bytes::Bytes;
use connectrpc::ConnectRpcService;
use ed25519_dalek::{Signer, SigningKey};
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_core::write_auth::{Context as AuthContext, Operation as SignedOp};
use mkit_server::Procedure;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::upload_part_request::Msg as PartMsg;
use mkit_server::connect::proto::mkit::transport::v1::{
    AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
    CompleteUploadRequest, DownloadPackRequest, DownloadPackResponse, GetServerInfoRequest,
    GetServerInfoResponse, ListRefsRequest, ListRefsResponse, PackChunk, PackExistsRequest,
    PackExistsResponse, ReadRefRequest, ReadRefResponse, RefExpectation, UploadPackHeader,
    UploadPackRequest, UploadPartHeader, UploadPartRequest,
};
use mkit_server::connect::proto::mkit::transport::v1::{
    GetGrantEpochRequest, IssueObjectUrlRequest, SetGrantEpochRequest, SetRepoVisibilityRequest,
};
use mkit_server::connect::{self};
use mkit_server::pipeline::{
    AuthMode, Authorizer, DefaultAdmission, HookSet, Hooks, NoOutcomes, NoPreReceive, NoReceipts,
    Pipeline, PipelineConfig,
};
use mkit_server::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value, codec, keys,
};
use mkit_server::upload::UploadLimits;
use mkit_server::upload::token::{TicketClaims, TicketKeys};
use mkit_server::{
    Addressing, AuthzFacts, ErrorDetail, METRIC_REQUESTS, ManualClock, MemoryBlobStore,
    MemoryFault, MemoryKv, Metrics, NamespaceKey, Operation, Redacted, RepoId, RepoName,
    ServerError,
};
use mkit_server::{BlobKey, MultipartBlobStore};
use tower::ServiceExt;

const AUDIENCE: &str = "https://api.example.test";
const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;
const TOKEN: &str = "s3cr3t-token";
const HEAD: &str = "refs/heads/main";
const PACKMAP: &str = "refs/mkit/packmap/main";
const A: [u8; 32] = [0xaa; 32];
const B: [u8; 32] = [0xbb; 32];
const JSON: &str = "application/json";
const PROTO: &str = "application/proto";
const STREAM: &str = "application/connect+proto";

struct SpyStore {
    inner: MemoryKv,
    writes: Arc<AtomicUsize>,
}

impl NamespaceStore for SpyStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

// ------------------------------------------------------------- server

/// Every `(procedure, code)` request metric, in order.
#[derive(Default)]
struct Codes(Mutex<Vec<(String, String)>>);

impl Metrics for Codes {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], _by: u64) {
        if name != METRIC_REQUESTS {
            return;
        }
        let get = |k: &str| labels.iter().find(|(n, _)| *n == k).unwrap().1.to_owned();
        self.0.lock().unwrap().push((get("procedure"), get("code")));
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}

struct Server {
    svc: ConnectRpcService,
    codes: Arc<Codes>,
}

struct Setup<H = Hooks> {
    auth: AuthMode,
    hooks: H,
    meta: Option<MemoryKv>,
    chunk_max: usize,
    list_cap: Option<u32>,
    addressing: Option<Addressing>,
}

fn setup(auth: AuthMode) -> Setup {
    Setup {
        auth,
        hooks: Hooks::new(),
        meta: None,
        chunk_max: 4,
        list_cap: None,
        addressing: None,
    }
}

fn spy_server(auth: AuthMode) -> (Server, Arc<AtomicUsize>) {
    let clock = Arc::new(ManualClock::new(T0));
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    };
    let cfg = PipelineConfig::new(
        Addressing::Single { repo },
        auth,
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    let writes = Arc::new(AtomicUsize::new(0));
    let meta = SpyStore {
        inner: MemoryKv::with_clock(clock.clone()),
        writes: writes.clone(),
    };
    let codes = Arc::new(Codes::default());
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta,
        Hooks::new(),
        cfg,
        clock,
        codes.clone(),
    )
    .unwrap();
    (
        Server {
            svc: connect::service(Arc::new(pipe)),
            codes,
        },
        writes,
    )
}

impl<H: HookSet + 'static> Setup<H> {
    fn pipeline(self) -> (Pipeline<MemoryBlobStore, MemoryKv, H>, Arc<Codes>) {
        let clock = Arc::new(ManualClock::new(T0));
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(REPO).unwrap(),
        };
        let limits = UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        };
        let addressing = self.addressing.unwrap_or(Addressing::Single { repo });
        let mut cfg = PipelineConfig::new(addressing, self.auth, limits);
        if matches!(cfg.addressing, Addressing::Multi(_)) {
            cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
        }
        cfg.download_chunk_max = self.chunk_max;
        if let Some(cap) = self.list_cap {
            cfg.max_list_refs_page_size = cap;
        }
        let meta = self
            .meta
            .unwrap_or_else(|| MemoryKv::with_clock(clock.clone()));
        let codes = Arc::new(Codes::default());
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            meta,
            self.hooks,
            cfg,
            clock,
            codes.clone(),
        )
        .unwrap();
        (pipe, codes)
    }

    /// Route by `X-Repository` instead of the configured repository.
    fn multi(mut self) -> Self {
        self.addressing = Some(Addressing::Multi(mkit_server::MultiAddressing::new()));
        self
    }

    fn serve(self) -> Server {
        let (pipe, codes) = self.pipeline();
        Server {
            svc: connect::service(Arc::new(pipe)),
            codes,
        }
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// The Connect error code of a unary error body.
    fn code(&self) -> String {
        assert_ne!(self.status, StatusCode::OK, "expected an error");
        self.json()["code"].as_str().unwrap().to_owned()
    }

    fn decode<M: Message>(&self) -> M {
        assert_eq!(self.status, StatusCode::OK, "{:?}", self.body);
        M::decode_from_slice(&self.body).unwrap()
    }

    /// A stream response: its message payloads and its end-stream JSON.
    fn frames(&self) -> (Vec<Bytes>, serde_json::Value) {
        assert_eq!(self.status, StatusCode::OK);
        let (mut rest, mut messages) = (self.body.clone(), Vec::new());
        loop {
            let flags = rest[0];
            let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
            let payload = rest.slice(5..5 + len);
            rest = rest.slice(5 + len..);
            if flags & 0x02 != 0 {
                assert!(rest.is_empty(), "bytes after end-stream");
                return (messages, serde_json::from_slice(&payload).unwrap());
            }
            messages.push(payload);
        }
    }
}

fn frame(msg: &impl Message) -> Vec<u8> {
    let payload = msg.encode_to_vec();
    let mut out = vec![0];
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

impl Server {
    async fn post(
        &self,
        method: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Reply {
        let mut req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://localhost/{method}"))
            .header("content-type", content_type)
            .header("connect-protocol-version", "1");
        for (name, value) in headers {
            req = req.header(*name, value);
        }
        let req = req.body(Full::new(Bytes::from(body))).unwrap();
        let resp = self.svc.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }

    /// A transport RPC with a binary body.
    async fn unary(&self, rpc: &str, msg: &impl Message, headers: &[(&str, String)]) -> Reply {
        let path = format!("mkit.transport.v1.TransportService/{rpc}");
        self.post(&path, PROTO, headers, msg.encode_to_vec()).await
    }

    /// A transport RPC with a JSON body.
    async fn json(&self, rpc: &str, body: &serde_json::Value, headers: &[(&str, String)]) -> Reply {
        let path = format!("mkit.transport.v1.TransportService/{rpc}");
        let body = serde_json::to_vec(body).unwrap();
        self.post(&path, JSON, headers, body).await
    }

    async fn upload(&self, msgs: &[UploadPackRequest], headers: &[(&str, String)]) -> Reply {
        let body = msgs.iter().flat_map(frame).collect();
        let path = "mkit.transport.v1.TransportService/UploadPack";
        self.post(path, STREAM, headers, body).await
    }

    async fn download(&self, id: &[u8], headers: &[(&str, String)]) -> Reply {
        let req = DownloadPackRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        };
        let path = "mkit.transport.v1.TransportService/DownloadPack";
        self.post(path, STREAM, headers, frame(&req)).await
    }

    async fn exists(&self, id: &[u8]) -> bool {
        let req = PackExistsRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        };
        let reply = self.unary("PackExists", &req, &[]).await;
        reply.decode::<PackExistsResponse>().exists.unwrap()
    }

    async fn read(&self, name: &str) -> ReadRefResponse {
        let req = ReadRefRequest {
            name: Some(name.to_owned()),
            ..Default::default()
        };
        self.unary("ReadRef", &req, &[]).await.decode()
    }

    fn codes(&self, procedure: &str) -> Vec<String> {
        let codes = self.codes.0.lock().unwrap();
        let hits = codes.iter().filter(|(p, _)| p == procedure);
        hits.map(|(_, c)| c.clone()).collect()
    }
}

// ------------------------------------------------------------- helpers

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn update_json(name: &str, expectation: &str, new: &[u8]) -> serde_json::Value {
    serde_json::json!({ "name": name, "expectation": expectation, "newId": b64(new) })
}

fn header(pack: &[u8]) -> UploadPackRequest {
    UploadPackRequest {
        body: Some(UploadBody::Header(Box::new(UploadPackHeader {
            pack_id: Some(hash(pack).to_vec()),
            total_bytes: Some(pack.len() as u64),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

fn chunk(id: &[u8], offset: usize, data: &[u8], last: bool) -> UploadPackRequest {
    UploadPackRequest {
        body: Some(UploadBody::Chunk(Box::new(PackChunk {
            pack_id: Some(id.to_vec()),
            offset: Some(offset as u64),
            data: Some(data.to_vec()),
            last: Some(last),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// A header, then `pack` in chunks of at most `size` bytes.
fn upload_msgs(pack: &[u8], size: usize) -> Vec<UploadPackRequest> {
    let id = hash(pack);
    let mut msgs = vec![header(pack)];
    let pieces: Vec<_> = pack.chunks(size).collect();
    for (i, piece) in pieces.iter().enumerate() {
        let offset = i * size;
        msgs.push(chunk(&id, offset, piece, i + 1 == pieces.len()));
    }
    msgs
}

fn pack(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap())
        .collect()
}

/// Auth v2 headers over `commitment`, signed at `T0` by seed `seed`.
fn signed(seed: u8, rpc: &str, commitment: &str, nonce: u32) -> Vec<(&'static str, String)> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let procedure = format!("/mkit.transport.v1.TransportService/{rpc}");
    let nonce = format!("{nonce:064x}");
    let expires = T0 + 300_000;
    let op = SignedOp {
        context: AuthContext {
            audience: AUDIENCE,
            repository: REPO,
        },
        procedure: &procedure,
        commitment,
        created_at: T0,
        expires_at: expires,
        nonce: &nonce,
    };
    let signature = key.sign(&op.digest().unwrap());
    vec![
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", AUDIENCE.to_owned()),
        ("x-repository", REPO.to_owned()),
        ("x-public-key", to_hex(key.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", commitment.to_owned()),
        ("x-created-at", T0.to_string()),
        ("x-expires-at", expires.to_string()),
        ("idempotency-key", nonce),
    ]
}

/// Auth v2 headers for exactly `body`.
fn signed_body(seed: u8, rpc: &str, body: &[u8], nonce: u32) -> Vec<(&'static str, String)> {
    let digest = to_hex(&hash(body));
    let mut headers = signed(seed, rpc, &format!("body:{digest}"), nonce);
    headers.push(("x-digest", digest));
    headers
}

fn authv2() -> AuthMode {
    AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap())
}

// --------------------------------------------------------------- refs

#[tokio::test]
async fn list_refs_json_strips_prefix() {
    let server = setup(AuthMode::Open).serve();
    for (name, id) in [
        ("refs/heads/main", A),
        ("refs/heads/dev", B),
        ("refs/tags/v1", A),
    ] {
        let reply = server
            .json(
                "UpdateRef",
                &update_json(name, "REF_EXPECTATION_ANY", &id),
                &[],
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    }
    let reply = server
        .json(
            "ListRefs",
            &serde_json::json!({ "prefix": "refs/heads/" }),
            &[],
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let mut refs: Vec<(String, String)> = reply.json()["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let name = r["name"].as_str().unwrap().to_owned();
            (name, r["objectId"].as_str().unwrap().to_owned())
        })
        .collect();
    refs.sort();
    assert_eq!(
        refs,
        [("dev".to_owned(), b64(&B)), ("main".to_owned(), b64(&A))]
    );
}

#[tokio::test]
async fn read_ref_absent_exists_false() {
    let server = setup(AuthMode::Open).serve();
    let absent = server.read(HEAD).await;
    assert_eq!(absent.exists, Some(false));
    assert!(absent.object_id.unwrap_or_default().is_empty());
    let reply = server
        .json(
            "UpdateRef",
            &update_json(HEAD, "REF_EXPECTATION_MISSING", &A),
            &[],
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let present = server.read(HEAD).await;
    assert_eq!(present.exists, Some(true));
    assert_eq!(present.object_id.as_deref(), Some(&A[..]));
    let bad = ReadRefRequest {
        name: Some("refs/heads/..bad".to_owned()),
        ..Default::default()
    };
    let reply = server.unary("ReadRef", &bad, &[]).await;
    assert_eq!(reply.code(), "invalid_argument");
}

#[tokio::test]
async fn update_ref_any_ok_and_conflict_is_failed_precondition() {
    let server = setup(AuthMode::Open).serve();
    let any = update_json(HEAD, "REF_EXPECTATION_ANY", &A);
    assert_eq!(
        server.json("UpdateRef", &any, &[]).await.status,
        StatusCode::OK
    );
    let missing = update_json(HEAD, "REF_EXPECTATION_MISSING", &B);
    let reply = server.json("UpdateRef", &missing, &[]).await;
    assert_eq!(reply.code(), "failed_precondition");
    assert!(reply.json().get("details").is_none(), "no current value");
    let mut stale = update_json(HEAD, "REF_EXPECTATION_MATCH", &B);
    stale["expectedId"] = b64(&B).into();
    let reply = server.json("UpdateRef", &stale, &[]).await;
    assert_eq!(reply.code(), "failed_precondition");
    assert_eq!(server.read(HEAD).await.object_id.as_deref(), Some(&A[..]));
}

#[tokio::test]
async fn update_ref_unspecified_is_invalid_argument() {
    let server = setup(AuthMode::Open).serve();
    let body = serde_json::json!({ "name": HEAD, "newId": b64(&A) });
    let reply = server.json("UpdateRef", &body, &[]).await;
    assert_eq!(reply.code(), "invalid_argument");
    assert_eq!(
        reply.json()["message"],
        "expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED"
    );
    // A non-empty expected_id with ANY, and a short new_id.
    let mut any = update_json(HEAD, "REF_EXPECTATION_ANY", &A);
    any["expectedId"] = b64(&B).into();
    assert_eq!(
        server.json("UpdateRef", &any, &[]).await.code(),
        "invalid_argument"
    );
    let short = update_json(HEAD, "REF_EXPECTATION_ANY", &[1, 2]);
    assert_eq!(
        server.json("UpdateRef", &short, &[]).await.code(),
        "invalid_argument"
    );
    assert_eq!(server.read(HEAD).await.exists, Some(false));
}

fn advance(
    head: (RefExpectation, Option<[u8; 32]>),
    packmap: (RefExpectation, Option<[u8; 32]>),
) -> AdvanceRefsRequest {
    AdvanceRefsRequest {
        head_ref: Some(HEAD.to_owned()),
        head_expectation: Some(head.0.into()),
        head_expected_id: head.1.map(|id| id.to_vec()),
        head_new_id: Some(B.to_vec()),
        packmap_ref: Some(PACKMAP.to_owned()),
        packmap_expectation: Some(packmap.0.into()),
        packmap_expected_id: packmap.1.map(|id| id.to_vec()),
        packmap_new_id: Some(B.to_vec()),
        ..Default::default()
    }
}

#[tokio::test]
async fn advance_refs_conflicts_are_typed_outcomes_not_errors() {
    use RefExpectation::{REF_EXPECTATION_ANY as ANY, REF_EXPECTATION_MATCH as MATCH};
    let server = setup(AuthMode::Open).serve();
    let outcome = |reply: Reply| {
        reply
            .decode::<AdvanceRefsResponse>()
            .outcome
            .unwrap()
            .to_i32()
    };
    let reply = server
        .unary("AdvanceRefs", &advance((ANY, None), (ANY, None)), &[])
        .await;
    assert_eq!(
        outcome(reply),
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED as i32
    );
    let reply = server
        .unary("AdvanceRefs", &advance((MATCH, Some(A)), (ANY, None)), &[])
        .await;
    assert_eq!(
        outcome(reply),
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT as i32
    );
    let reply = server
        .unary("AdvanceRefs", &advance((ANY, None), (MATCH, Some(A))), &[])
        .await;
    assert_eq!(
        outcome(reply),
        AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT as i32
    );
}

// --------------------------------------------------------------- packs

#[tokio::test]
async fn pack_exists_false_then_true_after_upload() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(10);
    assert!(!server.exists(&hash(&data)).await);
    let reply = server.upload(&upload_msgs(&data, 4), &[]).await;
    let (messages, end) = reply.frames();
    assert_eq!(messages.len(), 1, "{end}");
    assert!(end.get("error").is_none(), "{end}");
    assert!(server.exists(&hash(&data)).await);
}

#[tokio::test]
async fn upload_pack_multi_chunk_roundtrip_then_download_matches() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(11);
    let (_, end) = server.upload(&upload_msgs(&data, 3), &[]).await.frames();
    assert!(end.get("error").is_none(), "{end}");
    let (messages, end) = server.download(&hash(&data), &[]).await.frames();
    assert!(end.get("error").is_none(), "{end}");
    let messages: Vec<_> = messages
        .iter()
        .map(|m| {
            DownloadPackResponse::decode_from_slice(m)
                .unwrap()
                .body
                .unwrap()
        })
        .collect();
    let DownloadBody::Header(header) = &messages[0] else {
        panic!("first message is not the header");
    };
    assert_eq!(header.total_bytes, Some(11));
    let (mut got, mut lasts) = (Vec::new(), Vec::new());
    for message in &messages[1..] {
        let DownloadBody::Chunk(c) = message else {
            panic!("a second header");
        };
        assert_eq!(c.pack_id.as_deref(), Some(&hash(&data)[..]));
        assert_eq!(c.offset, Some(got.len() as u64));
        got.extend_from_slice(c.data.as_deref().unwrap());
        lasts.push(c.last.unwrap());
    }
    assert_eq!(got, data);
    assert_eq!(
        lasts,
        [false, false, true],
        "4-byte chunks, last only at the end"
    );
    assert_eq!(server.codes("UploadPack"), ["ok"]);
    assert_eq!(server.codes("DownloadPack"), ["ok"]);
}

#[tokio::test]
async fn upload_pack_first_message_not_header_is_invalid_argument() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(4);
    let reply = server
        .upload(&[chunk(&hash(&data), 0, &data, true)], &[])
        .await;
    let (messages, end) = reply.frames();
    assert!(messages.is_empty());
    assert_eq!(end["error"]["code"], "invalid_argument");
    assert_eq!(
        end["error"]["message"],
        "UploadPack: first message MUST be `header`"
    );
    let (_, end) = server.upload(&[], &[]).await.frames();
    assert_eq!(end["error"]["message"], "UploadPack: empty request stream");
    // A second header, and a stream that ends before `last`.
    let msgs = [header(&data), header(&data)];
    let (_, end) = server.upload(&msgs, &[]).await.frames();
    assert_eq!(end["error"]["code"], "invalid_argument");
    let msgs = [header(&data), chunk(&hash(&data), 0, &data[..2], false)];
    let (_, end) = server.upload(&msgs, &[]).await.frames();
    assert_eq!(end["error"]["code"], "invalid_argument");
    // A message with no body after the header.
    let msgs = [header(&data), UploadPackRequest::default()];
    let (_, end) = server.upload(&msgs, &[]).await.frames();
    assert_eq!(
        end["error"]["message"],
        "UploadPack: message with neither `header` nor `chunk` set"
    );
    assert!(!server.exists(&hash(&data)).await);
    // Errors before the header are the binding's own and go unrecorded;
    // after it, each request is recorded with the code the client got,
    // never `canceled`.
    assert_eq!(
        server.codes("UploadPack"),
        ["invalid_argument", "invalid_argument", "invalid_argument"]
    );
}

#[tokio::test]
async fn upload_pack_broken_stream_records_the_code_sent() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(4);
    // The header, then an envelope that claims 16 bytes and carries 2.
    let mut body = frame(&header(&data));
    body.extend_from_slice(&[0, 0, 0, 0, 16, 1, 2]);
    let path = "mkit.transport.v1.TransportService/UploadPack";
    let (messages, end) = server.post(path, STREAM, &[], body).await.frames();
    assert!(messages.is_empty());
    let code = end["error"]["code"].as_str().unwrap();
    assert_ne!(code, "canceled");
    assert_eq!(server.codes("UploadPack"), [code]);
    assert!(!server.exists(&hash(&data)).await);
}

#[tokio::test]
async fn upload_pack_hash_mismatch_is_invalid_argument_and_not_stored() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(8);
    let id = hash(&data);
    let msgs = [header(&data), chunk(&id, 0, &[0; 8], true)];
    let (messages, end) = server.upload(&msgs, &[]).await.frames();
    assert!(messages.is_empty());
    assert_eq!(end["error"]["code"], "invalid_argument");
    assert_eq!(
        end["error"]["message"],
        "UploadPack: BLAKE3(received bytes) does not equal header.pack_id"
    );
    assert!(!server.exists(&id).await);
    let (messages, end) = server.download(&id, &[]).await.frames();
    assert!(messages.is_empty());
    assert_eq!(end["error"]["code"], "not_found");
}

#[tokio::test]
async fn download_missing_is_not_found_with_no_messages() {
    let server = setup(AuthMode::Open).serve();
    let (messages, end) = server.download(&[9; 32], &[]).await.frames();
    assert!(messages.is_empty(), "no header before not_found");
    assert_eq!(end["error"]["code"], "not_found");
    let (_, end) = server.download(&[9; 3], &[]).await.frames();
    assert_eq!(end["error"]["code"], "invalid_argument");
    assert_eq!(server.codes("DownloadPack"), ["not_found"]);
}

// ---------------------------------------------------------------- auth

#[tokio::test]
async fn auth_v2_write_without_headers_is_unauthenticated() {
    let server = setup(authv2()).serve();
    let body = update_json(HEAD, "REF_EXPECTATION_ANY", &A);
    assert_eq!(
        server.json("UpdateRef", &body, &[]).await.code(),
        "unauthenticated"
    );
    let (_, end) = server.upload(&upload_msgs(&pack(4), 4), &[]).await.frames();
    assert_eq!(end["error"]["code"], "unauthenticated");
    // Reads stay unsigned.
    assert_eq!(server.read(HEAD).await.exists, Some(false));
    // Stage 0 rejections are counted like any failed request.
    assert_eq!(server.codes("UpdateRef"), ["unauthenticated"]);
    assert_eq!(server.codes("UploadPack"), ["unauthenticated"]);
    assert_eq!(server.codes("ReadRef"), ["ok"]);
}

/// Deflate `data` into a gzip member.
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[tokio::test]
async fn auth_v2_gzip_signed_request_fails_closed() {
    // SPEC-WRITE-GRANTS §9.2: `body:` commits to the exact HTTP body bytes,
    // here the gzip member. The binding verifies the decompressed bytes,
    // so a compressed signed request never verifies: it is rejected, never
    // accepted on a digest the client did not sign.
    let server = setup(authv2()).serve();
    let json = serde_json::to_vec(&update_json(HEAD, "REF_EXPECTATION_ANY", &A)).unwrap();
    let body = gzip(&json);
    let mut headers = signed_body(7, "UpdateRef", &body, 1);
    headers.push(("content-encoding", "gzip".to_owned()));
    let path = "mkit.transport.v1.TransportService/UpdateRef";
    let reply = server.post(path, JSON, &headers, body).await;
    assert_eq!(reply.code(), "unauthenticated");
    assert_eq!(server.read(HEAD).await.exists, Some(false));
    assert_eq!(server.codes("UpdateRef"), ["unauthenticated"]);
}

#[tokio::test]
async fn auth_v2_signed_unary_ok_and_replayed() {
    let server = setup(authv2()).serve();
    let body = serde_json::to_vec(&update_json(HEAD, "REF_EXPECTATION_MISSING", &A)).unwrap();
    let headers = signed_body(7, "UpdateRef", &body, 1);
    let path = "mkit.transport.v1.TransportService/UpdateRef";
    let first = server.post(path, JSON, &headers, body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    // The same signed request again is answered from the replay record: a
    // second execution would fail MISSING.
    let replay = server.post(path, JSON, &headers, body.clone()).await;
    assert_eq!(replay.status, StatusCode::OK, "{:?}", replay.body);
    // A different body under the same signature fails its commitment.
    let mut other = body;
    other.push(b' ');
    let tampered = server.post(path, JSON, &headers, other).await;
    assert_eq!(tampered.code(), "unauthenticated");
    // A signed upload.
    let data = pack(6);
    let commitment = format!("pack:{}:6", to_hex(&hash(&data)));
    let headers = signed(7, "UploadPack", &commitment, 2);
    let (_, end) = server
        .upload(&upload_msgs(&data, 4), &headers)
        .await
        .frames();
    assert!(end.get("error").is_none(), "{end}");
    assert!(server.exists(&hash(&data)).await);
}

/// The `auth-v2/read.json` fixture entry's headers verbatim (the
/// repository is a namespaced `ed25519-…/photos` identity, so callers
/// must serve Multi).
fn golden_read_headers(index: usize) -> Vec<(&'static str, String)> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/golden/auth-v2/read.json")).unwrap();
    let fixture = &fixtures[index];
    let field = |name: &str| fixture[name].as_str().unwrap().to_owned();
    vec![
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", field("audience")),
        ("x-repository", field("repository")),
        ("x-public-key", field("public_key")),
        ("x-signature", field("signature")),
        ("x-digest", field("body_digest")),
        ("x-content-commitment", field("commitment")),
        (
            "x-created-at",
            fixture["created_at"].as_i64().unwrap().to_string(),
        ),
        (
            "x-expires-at",
            fixture["expires_at"].as_i64().unwrap().to_string(),
        ),
        ("idempotency-key", field("nonce")),
    ]
}

#[tokio::test]
async fn signed_unary_reads_verify_at_stage_0() {
    let server = setup(authv2()).serve();
    let body = serde_json::to_vec(&serde_json::json!({ "name": HEAD })).unwrap();
    let headers = signed_body(7, "ReadRef", &body, 40);
    let reply = server
        .post(
            "mkit.transport.v1.TransportService/ReadRef",
            JSON,
            &headers,
            body.clone(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    // A forged signature and a lone marker header both fail closed.
    let mut forged = headers.clone();
    forged.retain(|(n, _)| *n != "x-signature");
    forged.push(("x-signature", "ff".repeat(64)));
    let reply = server
        .post(
            "mkit.transport.v1.TransportService/ReadRef",
            JSON,
            &forged,
            body,
        )
        .await;
    assert_eq!(reply.code(), "unauthenticated");
    let reply = server
        .json(
            "ListRefs",
            &serde_json::json!({}),
            &[("x-signature", "ab".to_owned())],
        )
        .await;
    assert_eq!(reply.code(), "unauthenticated");
}

#[tokio::test]
async fn signed_download_pack_verifies_the_framed_request() {
    let server = setup(authv2()).multi().serve();
    let headers = golden_read_headers(1);
    // The signature commits to `0x00‖be32(len)‖message`; it verifies, then
    // the read fails on the unregistered repository (not unauthenticated).
    let (_, end) = server.download(&[0xcd; 32], &headers).await.frames();
    assert_eq!(end["error"]["code"], "not_found", "{end}");
    // A forged signature fails closed.
    let mut forged = headers.clone();
    forged.retain(|(n, _)| *n != "x-signature");
    forged.push(("x-signature", "ff".repeat(64)));
    let (_, end) = server.download(&[0xcd; 32], &forged).await.frames();
    assert_eq!(end["error"]["code"], "unauthenticated", "{end}");
    // A signed request under a declared compression fails closed too:
    // the reconstructed frame cannot match the compressed bytes signed.
    let mut compressed = headers;
    compressed.push(("connect-content-encoding", "gzip".to_owned()));
    let (_, end) = server.download(&[0xcd; 32], &compressed).await.frames();
    assert_eq!(end["error"]["code"], "unauthenticated", "{end}");
}

#[tokio::test]
async fn non_utf8_auth_header_on_a_read_fails_closed() {
    let (pipe, _) = setup(authv2()).pipeline();
    let svc = connect::service(Arc::new(pipe));
    let body = ReadRefRequest {
        name: Some(HEAD.to_owned()),
        ..Default::default()
    }
    .encode_to_vec();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/mkit.transport.v1.TransportService/ReadRef")
        .header("content-type", PROTO)
        .header("connect-protocol-version", "1")
        .header(
            "x-signature",
            http::HeaderValue::from_bytes(&[0xff]).unwrap(),
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = svc.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "unauthenticated");
}

#[tokio::test]
async fn grant_header_on_an_unsigned_multi_read_is_unauthenticated() {
    // SPEC-WRITE-GRANTS §4.2 on any procedure, Multi deployments only.
    let server = setup(authv2()).multi().serve();
    let grant = [("x-write-grant", "scheme.body".to_owned())];
    let reply = server
        .unary("ReadRef", &ReadRefRequest::default(), &grant)
        .await;
    assert_eq!(reply.code(), "unauthenticated");
    let (_, end) = server.download(&[0xcd; 32], &grant).await.frames();
    assert_eq!(end["error"]["code"], "unauthenticated");
}

#[tokio::test]
async fn bearer_mode_rejects_missing_token_on_streaming_and_unary() {
    let auth = AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    };
    let server = setup(auth).serve();
    let list = serde_json::json!({});
    let reply = server.json("ListRefs", &list, &[]).await;
    assert_eq!(reply.code(), "unauthenticated");
    let wrong = [("authorization", "Bearer nope".to_owned())];
    assert_eq!(
        server.json("ListRefs", &list, &wrong).await.code(),
        "unauthenticated"
    );
    let (messages, end) = server.download(&[9; 32], &[]).await.frames();
    assert!(messages.is_empty());
    assert_eq!(end["error"]["code"], "unauthenticated");
    let (_, end) = server.upload(&upload_msgs(&pack(4), 4), &[]).await.frames();
    assert_eq!(end["error"]["code"], "unauthenticated");
    let good = [("authorization", format!("Bearer {TOKEN}"))];
    assert_eq!(
        server.json("ListRefs", &list, &good).await.status,
        StatusCode::OK
    );
    let (_, end) = server.download(&[9; 32], &good).await.frames();
    assert_eq!(end["error"]["code"], "not_found");
    assert_eq!(
        server.codes("ListRefs"),
        ["unauthenticated", "unauthenticated", "ok"]
    );
    assert_eq!(
        server.codes("DownloadPack"),
        ["unauthenticated", "not_found"]
    );
}

#[tokio::test]
async fn transport_identity_comes_from_request_extensions() {
    let (pipe, _) = setup(AuthMode::TransportIdentity).pipeline();
    let svc = connect::service(Arc::new(pipe));
    let request = |principal: Option<mkit_server::Principal>| {
        let mut req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://localhost/mkit.transport.v1.TransportService/ListRefs")
            .header("content-type", JSON)
            .header("connect-protocol-version", "1")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        if let Some(p) = principal {
            req.extensions_mut().insert(p);
        }
        req
    };
    let resp = svc.clone().oneshot(request(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let peer = mkit_server::Principal::TransportPeer { ed25519: [1; 32] };
    let resp = svc.oneshot(request(Some(peer))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// -------------------------------------------------------------- health

#[tokio::test]
async fn health_check_serving_and_unknown_service_not_found() {
    // Health is not authenticated, even in bearer mode.
    let auth = AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    };
    let server = setup(auth).serve();
    let check = |service: &str| serde_json::to_vec(&serde_json::json!({ "service": service }));
    for service in ["", "mkit.transport.v1.TransportService"] {
        let reply = server
            .post(
                "grpc.health.v1.Health/Check",
                JSON,
                &[],
                check(service).unwrap(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        assert_eq!(reply.json()["status"], "SERVING");
    }
    let reply = server
        .post(
            "grpc.health.v1.Health/Check",
            JSON,
            &[],
            check("other").unwrap(),
        )
        .await;
    assert_eq!(reply.code(), "not_found");
    let reply = server
        .post(
            "grpc.health.v1.Health/Watch",
            "application/connect+json",
            &[],
            {
                let payload = check("").unwrap();
                let mut body = vec![0];
                body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
                body.extend_from_slice(&payload);
                body
            },
        )
        .await;
    let (_, end) = reply.frames();
    assert_eq!(end["error"]["code"], "unimplemented");
}

// -------------------------------------------------------------- errors

#[tokio::test]
async fn internal_store_error_message_is_generic() {
    let clock = Arc::new(ManualClock::new(T0));
    let mut s = setup(AuthMode::Open);
    s.meta = Some(MemoryKv::with_clock(clock).with_fault(MemoryFault::ApplyBefore));
    let server = s.serve();
    let reply = server
        .json(
            "UpdateRef",
            &update_json(HEAD, "REF_EXPECTATION_ANY", &A),
            &[],
        )
        .await;
    assert_eq!(reply.code(), "internal");
    let json = reply.json();
    assert_eq!(json["message"], "ref store request failed");
    assert!(json.get("details").is_none());
    let raw = String::from_utf8_lossy(&reply.body);
    assert!(
        !raw.contains("injected") && !raw.contains("ApplyBefore"),
        "{raw}"
    );
}

/// Denies everything with the M3 payment shape.
struct PaymentRequired;

impl Authorizer for PaymentRequired {
    async fn authorize(&self, _op: &Operation) -> Result<AuthzFacts, ServerError> {
        Err(ServerError::permission_denied("payment required")
            .with_http_status(402)
            .with_header("WWW-Authenticate", "Payment id=x")
            .with_detail(ErrorDetail {
                type_name: mkit_server::ADMISSION_CHALLENGE_TYPE.to_owned(),
                value: Bytes::from_static(b"\x0a\x01x"),
            }))
    }
}

#[tokio::test]
async fn error_shaping_reaches_the_wire() {
    let server = Setup {
        auth: AuthMode::Open,
        hooks: Hooks {
            authorizer: PaymentRequired,
            admission: DefaultAdmission,
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        meta: None,
        chunk_max: 4,
        list_cap: None,
        addressing: None,
    }
    .serve();
    let reply = server
        .json(
            "UpdateRef",
            &update_json(HEAD, "REF_EXPECTATION_ANY", &A),
            &[],
        )
        .await;
    assert_eq!(reply.status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(reply.headers["www-authenticate"], "Payment id=x");
    let json = reply.json();
    assert_eq!(json["code"], "permission_denied");
    assert_eq!(json["message"], "payment required");
    let details = json["details"].as_array().unwrap();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0]["type"], mkit_server::ADMISSION_CHALLENGE_TYPE);
    assert_eq!(details[0]["value"], "CgF4");
}

// --------------------------------------------------------- test-faults

/// Headers the `test-faults` seam reads; release builds ignore them.
fn fault_headers(fault: &str, skew: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-mkit-test-fault", fault.to_owned()),
        ("x-mkit-test-clock-skew-ms", skew.to_owned()),
    ]
}

#[cfg(not(feature = "test-faults"))]
#[tokio::test]
async fn test_fault_header_ignored_without_feature() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(5);
    let mut headers = fault_headers("after-put", "not-a-number");
    headers.push(("x-mkit-test-timer-ms", "not-a-number".into()));
    headers.push(("x-mkit-test-run-timers", "bad ref".into()));
    let (_, end) = server
        .upload(&upload_msgs(&data, 4), &headers)
        .await
        .frames();
    assert!(end.get("error").is_none(), "{end}");
    assert!(server.exists(&hash(&data)).await);
}

#[cfg(not(feature = "test-faults"))]
#[tokio::test]
async fn timer_headers_are_unknown_without_test_faults() {
    let server = setup(AuthMode::Open).serve();
    for header in [
        "x-mkit-test-timer-ms",
        "x-mkit-test-run-timers",
        "x-unknown-test-header",
    ] {
        let headers = [(header, "malformed value".to_owned())];
        let reply = server
            .json(
                "UpdateRef",
                &update_json(HEAD, "REF_EXPECTATION_ANY", &A),
                &headers,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        let reply = server
            .json(
                "ListRefs",
                &serde_json::json!({"prefix": "refs/heads/"}),
                &headers,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(server.read(HEAD).await.object_id.as_deref(), Some(&A[..]));
    }
}

#[cfg(feature = "test-faults")]
#[tokio::test]
async fn test_fault_header_honored_with_feature() {
    use mkit_server::pipeline::FailOnce;
    let (pipe, _) = setup(AuthMode::Open).pipeline();
    let server = Server {
        svc: connect::service(Arc::new(pipe.with_faults(FailOnce::new()))),
        codes: Arc::default(),
    };
    let data = pack(5);
    let msgs = upload_msgs(&data, 4);
    let (_, end) = server
        .upload(&msgs, &fault_headers("after-put", "not-a-number"))
        .await
        .frames();
    assert_eq!(end["error"]["code"], "invalid_argument", "malformed skew");
    let headers = fault_headers("after-put", "0");
    let (_, end) = server.upload(&msgs, &headers).await.frames();
    assert_eq!(end["error"]["code"], "internal");
    assert_eq!(end["error"]["message"], "injected test fault");
    let (_, end) = server.upload(&msgs, &headers).await.frames();
    assert!(end.get("error").is_none(), "fires once: {end}");
}

// -------------------------------------------------------------- M1 stubs

fn assert_unimplemented(reply: &Reply) {
    assert_eq!(reply.code(), "unimplemented");
    assert_eq!(reply.json()["message"], "not implemented yet");
}

#[test]
fn multipart_paths_are_authenticated_procedures() {
    // GetServerInfo is permanently outside Procedure: no auth or resolution.
    assert_eq!(
        Procedure::from_connect_path("/mkit.transport.v1.TransportService/GetServerInfo"),
        None
    );
    assert_eq!(
        Procedure::from_connect_path("/mkit.transport.v1.TransportService/BeginUpload"),
        Some(Procedure::BeginUpload)
    );
    assert_eq!(
        Procedure::from_connect_path("/mkit.transport.v1.TransportService/UploadPart"),
        Some(Procedure::UploadPart)
    );
    assert_eq!(
        Procedure::from_connect_path("/mkit.transport.v1.TransportService/CompleteUpload"),
        Some(Procedure::CompleteUpload)
    );
}

#[test]
fn grant_epoch_paths_are_permanently_outside_procedure() {
    // SPEC-WRITE-GRANTS §5.3, §9.2: the epoch RPCs are unsigned forever.
    for rpc in ["GetGrantEpoch", "SetGrantEpoch"] {
        let path = format!("/mkit.transport.v1.TransportService/{rpc}");
        assert_eq!(Procedure::from_connect_path(&path), None, "{rpc}");
    }
}

#[test]
fn m2_paths_are_authenticated_procedures() {
    // WP-2.9 classified these RPCs; their handlers land with the WP.
    for (rpc, procedure) in [
        ("GetReceipt", Procedure::GetReceipt),
        ("SetRepoVisibility", Procedure::SetRepoVisibility),
        ("IssueObjectUrl", Procedure::IssueObjectUrl),
    ] {
        let path = format!("/mkit.transport.v1.TransportService/{rpc}");
        assert_eq!(
            Procedure::from_connect_path(&path),
            Some(procedure),
            "{rpc}"
        );
    }
}

#[tokio::test]
async fn m2_stubs_reject_binary_and_json_without_writes_in_both_auth_modes() {
    for auth in [
        authv2(),
        AuthMode::Bearer {
            token: Redacted::new(TOKEN),
        },
    ] {
        let auth_v2 = matches!(auth, AuthMode::AuthV2(_));
        let (server, writes) = spy_server(auth);
        assert_unimplemented(
            &server
                .unary(
                    "GetGrantEpoch",
                    &GetGrantEpochRequest {
                        namespace: Some("namespace".into()),
                        ..Default::default()
                    },
                    &[],
                )
                .await,
        );
        assert_unimplemented(
            &server
                .unary(
                    "SetGrantEpoch",
                    &SetGrantEpochRequest {
                        signed_statement: Some("statement.scheme.blob".into()),
                        ..Default::default()
                    },
                    &[],
                )
                .await,
        );
        // The WP-2.9/2.11 procedures authenticate at stage 0 now: under
        // auth v2 an unsigned SetRepoVisibility passes anonymously
        // (statement mode) to the unimplemented handler, IssueObjectUrl
        // is never anonymous, and under Bearer every call needs a token.
        let stub = if auth_v2 {
            "unimplemented"
        } else {
            "unauthenticated"
        };
        for rpc in ["SetRepoVisibility", "GetReceipt"] {
            assert_eq!(
                server
                    .unary(rpc, &SetRepoVisibilityRequest::default(), &[])
                    .await
                    .code(),
                stub,
                "{rpc}"
            );
            assert_eq!(
                server.json(rpc, &serde_json::json!({}), &[]).await.code(),
                stub,
                "{rpc} json"
            );
        }
        assert_eq!(
            server
                .unary("IssueObjectUrl", &IssueObjectUrlRequest::default(), &[])
                .await
                .code(),
            "unauthenticated"
        );
        for rpc in ["GetGrantEpoch", "SetGrantEpoch", "IssueObjectUrl"] {
            assert_eq!(
                server.json(rpc, &serde_json::json!({}), &[]).await.code(),
                if rpc == "IssueObjectUrl" {
                    "unauthenticated"
                } else {
                    "unimplemented"
                },
                "{rpc} json"
            );
        }
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn complete_upload_requires_authentication() {
    let server = setup(AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    })
    .serve();
    assert_eq!(
        server
            .unary(
                "CompleteUpload",
                &CompleteUploadRequest {
                    ticket_token: Some(vec![1]),
                    receipts: vec![vec![2]],
                    ..Default::default()
                },
                &[],
            )
            .await
            .code(),
        "unauthenticated",
    );
    // Exercise JSON dispatch too.
    for rpc in ["CompleteUpload"] {
        assert_eq!(
            server.json(rpc, &serde_json::json!({}), &[]).await.code(),
            "unauthenticated"
        );
    }
}

#[tokio::test]
async fn begin_upload_requires_authentication_and_configured_keys() {
    let request = BeginUploadRequest {
        r#ref: Some(HEAD.into()),
        pack_id: Some(A.to_vec()),
        bytes: Some(8),
        ..Default::default()
    };
    for auth in [
        authv2(),
        AuthMode::Bearer {
            token: Redacted::new(TOKEN),
        },
    ] {
        let server = setup(auth).serve();
        assert_eq!(
            server.unary("BeginUpload", &request, &[]).await.code(),
            "unauthenticated"
        );
        assert_eq!(
            server
                .json("BeginUpload", &serde_json::json!({}), &[])
                .await
                .code(),
            "unauthenticated"
        );
    }
    let server = setup(authv2()).serve();
    let auth = signed_body(7, "BeginUpload", &request.encode_to_vec(), 91);
    let reply = server.unary("BeginUpload", &request, &auth).await;
    assert_eq!(reply.code(), "unimplemented");
    assert_eq!(reply.json()["message"], "upload tickets are not configured");
    let server = setup(AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    })
    .serve();
    let reply = server
        .unary(
            "BeginUpload",
            &request,
            &[("authorization", format!("Bearer {TOKEN}"))],
        )
        .await;
    assert_eq!(reply.code(), "unimplemented");
    assert_eq!(reply.json()["message"], "BeginUpload requires auth v2");
}

#[tokio::test]
async fn upload_part_requires_authentication_before_stream_contents() {
    let server = setup(AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    })
    .serve();
    let header = UploadPartRequest {
        msg: Some(PartMsg::Header(Box::new(UploadPartHeader {
            ticket_token: Some(vec![1]),
            index: Some(2),
            ..Default::default()
        }))),
        ..Default::default()
    };
    let chunk = UploadPartRequest {
        msg: Some(PartMsg::Chunk(vec![3, 4])),
        ..Default::default()
    };
    let mut full = frame(&header);
    full.extend(frame(&chunk));
    // Authentication precedes all stream decoding.
    for body in [full, vec![], vec![0, 0, 0, 0, 16, 1, 2]] {
        let reply = server
            .post(
                "mkit.transport.v1.TransportService/UploadPart",
                STREAM,
                &[],
                body,
            )
            .await;
        let (messages, end) = reply.frames();
        assert!(messages.is_empty());
        assert_eq!(end["error"]["code"], "unauthenticated");
    }
}

#[tokio::test]
async fn upload_part_stream_rejects_chunk_before_header_and_empty_chunk() {
    let clock = Arc::new(ManualClock::new(T0));
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    };
    let mut cfg = PipelineConfig::new(
        Addressing::Single { repo },
        authv2(),
        UploadLimits {
            max_total_bytes: 3 * MIN_PART_SIZE,
            max_chunks: 1024,
        },
    );
    let keys = TicketKeys::new(vec![("active".into(), [7; 32])]).unwrap();
    cfg.ticket_keys = Some(keys.clone());
    let blobs = MemoryBlobStore::default();
    let data = vec![3; usize::try_from(MIN_PART_SIZE).unwrap() + 1];
    let id = hash(&data);
    let session = blobs
        .begin_multipart(BlobKey::pack(id), data.len() as u64, MIN_PART_SIZE)
        .await
        .unwrap();
    let claims = TicketClaims {
        ticket_id: [0x11; 32],
        audience: AUDIENCE.into(),
        repository: REPO.into(),
        signer: *SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes(),
        pack_id: id,
        bytes: data.len() as u64,
        part_size: MIN_PART_SIZE,
        expires_at_ms: T0 as u64 + 86_400_000,
        upload_session: session,
    };
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let cv = part_subtree_cv(&plan, 0, &data[..usize::try_from(MIN_PART_SIZE).unwrap()]).unwrap();
    let commitment = format!(
        "part:{}:0:{}:{MIN_PART_SIZE}",
        to_hex(&claims.ticket_id),
        to_hex(&cv)
    );
    let headers = signed(7, "UploadPart", &commitment, 219);
    let pipe = Pipeline::new(
        blobs,
        MemoryKv::with_clock(clock.clone()),
        Hooks::new(),
        cfg,
        clock,
        Arc::new(Codes::default()),
    )
    .unwrap();
    let server = Server {
        svc: connect::service(Arc::new(pipe)),
        codes: Arc::new(Codes::default()),
    };
    let header = UploadPartRequest {
        msg: Some(PartMsg::Header(Box::new(UploadPartHeader {
            ticket_token: Some(keys.mint(&claims)),
            index: Some(0),
            ..Default::default()
        }))),
        ..Default::default()
    };
    let empty = UploadPartRequest {
        msg: Some(PartMsg::Chunk(Vec::new())),
        ..Default::default()
    };
    let path = "mkit.transport.v1.TransportService/UploadPart";
    let (_, end) = server
        .post(path, STREAM, &headers, frame(&empty))
        .await
        .frames();
    assert_eq!(end["error"]["code"], "invalid_argument");
    assert_eq!(
        end["error"]["message"],
        "UploadPart: first message MUST be `header`"
    );
    let mut body = frame(&header);
    body.extend(frame(&empty));
    let (_, end) = server.post(path, STREAM, &headers, body).await.frames();
    assert_eq!(end["error"]["code"], "invalid_argument");
}

#[tokio::test]
async fn deletion_and_ticket_errors_precede_pipeline_writes() {
    for (rpc, extra) in [
        ("UpdateRef", serde_json::json!({ "delete": true })),
        ("AdvanceRefs", serde_json::json!({ "delete": true })),
        (
            "AdvanceRefs",
            serde_json::json!({ "ticketIds": [b64(&A), b64(&A)] }),
        ),
    ] {
        let mut config = setup(AuthMode::Open);
        config.meta = Some(
            MemoryKv::with_clock(Arc::new(ManualClock::new(T0)))
                .with_fault(MemoryFault::ApplyBefore),
        );
        let server = config.serve();
        assert_eq!(
            server.json(rpc, &extra, &[]).await.code(),
            "invalid_argument"
        );
        let mut valid = if rpc == "UpdateRef" {
            update_json(HEAD, "REF_EXPECTATION_ANY", &A)
        } else {
            serde_json::json!({
                "headRef": HEAD, "headExpectation": "REF_EXPECTATION_ANY", "headNewId": b64(&A),
                "packmapRef": PACKMAP, "packmapExpectation": "REF_EXPECTATION_ANY", "packmapNewId": b64(&B)
            })
        };
        valid
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            server.json(rpc, &valid, &[]).await.code(),
            "invalid_argument"
        );
        assert_eq!(server.read(HEAD).await.exists, Some(false));
        assert_eq!(server.read(PACKMAP).await.exists, Some(false));
        assert!(
            server.codes(rpc).is_empty(),
            "wire validation must not call the pipeline"
        );
        // The one-shot apply fault is still armed: validation reached no write.
        let legacy = update_json(HEAD, "REF_EXPECTATION_ANY", &A);
        assert_eq!(
            server.json("UpdateRef", &legacy, &[]).await.code(),
            "internal"
        );
        assert_eq!(
            server.json("UpdateRef", &legacy, &[]).await.status,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn m1_ticketed_upload_pack_validates_header_before_mode_and_never_reads_chunks() {
    let server = setup(AuthMode::Open).serve();
    let data = pack(8);
    let ticketed = UploadPackRequest {
        body: Some(UploadBody::Header(Box::new(UploadPackHeader {
            pack_id: Some(hash(&data).to_vec()),
            total_bytes: Some(data.len() as u64),
            ticket_token: Some(vec![1]),
            ..Default::default()
        }))),
        ..Default::default()
    };
    let invalid = UploadPackRequest {
        body: Some(UploadBody::Header(Box::new(UploadPackHeader {
            ticket_token: Some(vec![1]),
            ..Default::default()
        }))),
        ..Default::default()
    };
    for (msg, code, message) in [
        (
            ticketed,
            "unimplemented",
            "ticketed UploadPack requires auth v2",
        ),
        (
            invalid,
            "invalid_argument",
            "expected a 32-byte digest, got 0 bytes",
        ),
    ] {
        let mut body = frame(&msg);
        // If chunks were read, this truncated frame would fail decoding.
        body.extend([0, 0, 0, 0, 16, 1, 2]);
        let reply = server
            .post(
                "mkit.transport.v1.TransportService/UploadPack",
                STREAM,
                &[],
                body,
            )
            .await;
        let (messages, end) = reply.frames();
        assert!(messages.is_empty());
        assert_eq!(end["error"]["code"], code);
        assert_eq!(end["error"]["message"], message);
    }
    assert!(!server.exists(&hash(&data)).await);
    assert_eq!(
        server.codes("UploadPack"),
        ["unimplemented", "invalid_argument"]
    );
}

#[tokio::test]
async fn m1_list_refs_paging_tokens_and_page_sizes() {
    let mut config = setup(AuthMode::Open);
    config.list_cap = Some(2);
    let server = config.serve();
    for (name, id) in [(HEAD, A), ("refs/heads/dev", B), ("refs/heads/other", A)] {
        assert_eq!(
            server
                .json(
                    "UpdateRef",
                    &update_json(name, "REF_EXPECTATION_ANY", &id),
                    &[]
                )
                .await
                .status,
            StatusCode::OK
        );
    }
    let invalid = server
        .unary(
            "ListRefs",
            &ListRefsRequest {
                prefix: Some("refs/heads/".into()),
                page_token: Some("next".into()),
                ..Default::default()
            },
            &[],
        )
        .await;
    assert_eq!(invalid.code(), "invalid_argument");
    let original = list_heads_page(&server, None, None).await;
    let bounded = list_heads_page(&server, Some(1), None).await;
    assert_eq!(original.refs.len(), 2);
    assert_eq!(bounded.refs.len(), 1);
    assert!(bounded.next_page_token.is_some());
    let second = list_heads_page(&server, Some(1), bounded.next_page_token.clone()).await;
    assert_eq!(second.refs.len(), 1);
    assert!(second.next_page_token.is_some());
    assert!(bounded.refs[0].name < second.refs[0].name);
    let third = list_heads_page(&server, Some(1), second.next_page_token.clone()).await;
    assert_eq!(third.refs.len(), 1);
    assert_eq!(third.next_page_token, None);
    assert!(second.refs[0].name < third.refs[0].name);
    let zero = list_heads_page(&server, Some(0), None).await;
    let above = list_heads_page(&server, Some(100), None).await;
    assert_eq!(original, zero);
    assert_eq!(original, above);
    for (prefix, token) in [
        ("refs/tags/", bounded.next_page_token.clone().unwrap()),
        ("refs/heads/", "A".repeat(800)),
    ] {
        let reply = server
            .unary(
                "ListRefs",
                &ListRefsRequest {
                    prefix: Some(prefix.into()),
                    page_token: Some(token),
                    ..Default::default()
                },
                &[],
            )
            .await;
        assert_eq!(reply.code(), "invalid_argument");
    }
    let json = server
        .json("ListRefs", &serde_json::json!({ "pageSize": 1 }), &[])
        .await;
    assert_eq!(json.json()["refs"].as_array().unwrap().len(), 1);
    assert!(json.json().get("nextPageToken").is_some());
}

async fn list_heads_page(
    server: &Server,
    page_size: Option<u32>,
    page_token: Option<String>,
) -> ListRefsResponse {
    server
        .unary(
            "ListRefs",
            &ListRefsRequest {
                prefix: Some("refs/heads/".into()),
                page_size,
                page_token,
                ..Default::default()
            },
            &[],
        )
        .await
        .decode()
}

#[tokio::test]
async fn m1_list_refs_wire_pages_stop_at_two_mib() {
    let meta = MemoryKv::default();
    let repo = RepoName::new(REPO).unwrap();
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    for base in (0..5_000).step_by(100) {
        let mut batch = Batch::new();
        for i in base..base + 100 {
            let name = format!("refs/heads/{i:05}{}", "a".repeat(490));
            batch = batch.put(keys::ref_key(&repo, &name), codec::encode_ref_id(&A));
        }
        meta.apply(&partition, batch).await.unwrap();
    }
    let mut config = setup(AuthMode::Open);
    config.list_cap = Some(10_000);
    config.meta = Some(meta);
    let server = config.serve();
    let mut token = None;
    let mut count = 0;
    let mut pages = 0;
    let mut last = String::new();
    loop {
        let reply = server
            .unary(
                "ListRefs",
                &ListRefsRequest {
                    prefix: Some("refs/heads/".into()),
                    page_size: Some(10_000),
                    page_token: token,
                    ..Default::default()
                },
                &[],
            )
            .await;
        assert!(reply.body.len() <= 2 * 1024 * 1024);
        let page: ListRefsResponse = reply.decode();
        pages += 1;
        for entry in page.refs {
            let name = entry.name.unwrap();
            assert!(name > last);
            last = name;
            count += 1;
        }
        match page.next_page_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(count, 5_000);
    assert!(pages >= 2, "the encoded cap must cut a 5,000-ref page");
    let json = server
        .json(
            "ListRefs",
            &serde_json::json!({
                "prefix": "refs/heads/", "pageSize": 10_000
            }),
            &[],
        )
        .await;
    assert_eq!(json.status, StatusCode::OK);
    assert!(json.body.len() <= 2 * 1024 * 1024);
    assert!(json.json()["nextPageToken"].is_string());
}

#[tokio::test]
async fn m1_explicit_default_fields_keep_the_legacy_path() {
    let server = setup(AuthMode::Open).serve();
    let mut update = update_json(HEAD, "REF_EXPECTATION_ANY", &A);
    update
        .as_object_mut()
        .unwrap()
        .insert("delete".into(), serde_json::json!(false));
    assert_eq!(
        server.json("UpdateRef", &update, &[]).await.status,
        StatusCode::OK
    );
    let advance = serde_json::json!({
        "headRef": HEAD, "headExpectation": "REF_EXPECTATION_ANY", "headNewId": b64(&B),
        "packmapRef": PACKMAP, "packmapExpectation": "REF_EXPECTATION_ANY", "packmapNewId": b64(&A),
        "delete": false, "ticketIds": []
    });
    assert_eq!(
        server.json("AdvanceRefs", &advance, &[]).await.status,
        StatusCode::OK
    );
    let listed = server
        .json(
            "ListRefs",
            &serde_json::json!({ "prefix": "refs/heads/", "pageToken": "" }),
            &[],
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.json()["refs"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn server_info_is_public_ignores_repository_and_sets_cache_header() {
    for auth in [
        AuthMode::Open,
        AuthMode::Bearer {
            token: Redacted::new(TOKEN),
        },
        authv2(),
    ] {
        let server = setup(auth).serve();
        let original = server
            .unary("GetServerInfo", &GetServerInfoRequest::default(), &[])
            .await;
        let info: GetServerInfoResponse = original.decode();
        assert_eq!(info.protocol.as_deref(), Some("mkit.transport.v1"));
        assert_eq!(info.spec_version, Some(2));
        assert_eq!(info.indexed_mode, Some(false));
        assert_eq!(info.max_delta_chain_depth, Some(0));
        assert_eq!(info.admission, Some(false));
        assert_eq!(info.begin_upload_threshold_bytes, Some(u64::MAX));
        assert_eq!(info.receipt_public_key, Some(vec![]));
        assert_eq!(info.receipt_key_id.as_deref(), Some(""));
        assert!(info.grant_schemes.is_empty());
        assert_eq!(original.headers["cache-control"], "private, max-age=60");
        for repository in ["not-here", "ed25519:bad/../invalid"] {
            let reply = server
                .unary(
                    "GetServerInfo",
                    &GetServerInfoRequest::default(),
                    &[("x-repository", repository.to_owned())],
                )
                .await;
            assert_eq!(reply.status, StatusCode::OK);
            assert_eq!(reply.body, original.body);
        }
        let json = server
            .json("GetServerInfo", &serde_json::json!({}), &[])
            .await;
        assert_eq!(json.status, StatusCode::OK);
        assert_eq!(json.json()["protocol"], "mkit.transport.v1");
        assert_eq!(json.json()["maxDeltaChainDepth"], 0);
        assert_eq!(
            json.json()["beginUploadThresholdBytes"],
            u64::MAX.to_string()
        );
        assert_eq!(json.headers["cache-control"], "private, max-age=60");
        assert!(server.codes.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn non_utf8_ref_hint_is_ignored_before_pack_reads() {
    let server = setup(AuthMode::Open).serve();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/mkit.transport.v1.TransportService/PackExists")
        .header("content-type", JSON)
        .header("connect-protocol-version", "1")
        .header(
            "x-mkit-ref",
            http::HeaderValue::from_bytes(b"refs/heads/\xff").unwrap(),
        )
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&serde_json::json!({"packId": STANDARD.encode(A)})).unwrap(),
        )))
        .unwrap();
    let reply = server.svc.oneshot(request).await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let body = reply.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_ne!(value["exists"], true);
}
