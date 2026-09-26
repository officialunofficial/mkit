//! `connect::service` driven through real Connect HTTP requests on the host
//! (`tower::ServiceExt::oneshot`, as `apps/vcs-worker/tests/
//! health_check_dispatch.rs` does), over the memory stores: the unary JSON
//! and binary codecs, `connect+proto` stream framing, auth, health and the
//! error-shaping path.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

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
use mkit_core::write_auth::{Context as AuthContext, Operation as SignedOp};
use mkit_server::Procedure;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_server::connect::proto::mkit::transport::v1::__buffa::oneof::upload_part_request::Msg as PartMsg;
use mkit_server::connect::proto::mkit::transport::v1::{
    AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
    CompleteUploadRequest, DownloadPackRequest, DownloadPackResponse, GetServerInfoRequest,
    ListRefsRequest, ListRefsResponse, PackChunk, PackExistsRequest, PackExistsResponse,
    ReadRefRequest, ReadRefResponse, RefExpectation, UploadPackHeader, UploadPackRequest,
    UploadPartHeader, UploadPartRequest,
};
use mkit_server::connect::{self};
use mkit_server::pipeline::{
    AuthMode, Authorizer, DefaultAdmission, HookSet, Hooks, NoOutcomes, NoPreReceive, NoReceipts,
    Pipeline, PipelineConfig,
};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, AuthzFacts, ErrorDetail, METRIC_REQUESTS, ManualClock, MemoryBlobStore,
    MemoryFault, MemoryKv, Metrics, NamespaceKey, Operation, Redacted, RepoId, RepoName,
    ServerError,
};
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
}

fn setup(auth: AuthMode) -> Setup {
    Setup {
        auth,
        hooks: Hooks::new(),
        meta: None,
        chunk_max: 4,
    }
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
        let mut cfg = PipelineConfig::new(Addressing::Single { repo }, self.auth, limits);
        cfg.download_chunk_max = self.chunk_max;
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
    let headers = fault_headers("after-put", "not-a-number");
    let (_, end) = server
        .upload(&upload_msgs(&data, 4), &headers)
        .await
        .frames();
    assert!(end.get("error").is_none(), "{end}");
    assert!(server.exists(&hash(&data)).await);
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
fn m1_stub_paths_are_not_authenticated_procedures_yet() {
    // WP-1.6, WP-1.9 and WP-1.11 must flip these as their handlers land.
    // GetServerInfo remains public by spec §2.1, with an explicit Procedure.
    for rpc in [
        "GetServerInfo",
        "BeginUpload",
        "UploadPart",
        "CompleteUpload",
    ] {
        let path = format!("/mkit.transport.v1.TransportService/{rpc}");
        assert_eq!(Procedure::from_connect_path(&path), None, "{rpc}");
    }
}

#[tokio::test]
async fn m1_new_unary_rpcs_reach_stubs_without_auth_headers() {
    let server = setup(AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    })
    .serve();
    assert_unimplemented(
        &server
            .unary("GetServerInfo", &GetServerInfoRequest::default(), &[])
            .await,
    );
    assert_unimplemented(
        &server
            .unary(
                "BeginUpload",
                &BeginUploadRequest {
                    r#ref: Some(HEAD.into()),
                    pack_id: Some(A.to_vec()),
                    bytes: Some(8),
                    ..Default::default()
                },
                &[],
            )
            .await,
    );
    assert_unimplemented(
        &server
            .unary(
                "CompleteUpload",
                &CompleteUploadRequest {
                    ticket_token: Some(vec![1]),
                    receipts: vec![vec![2]],
                    ..Default::default()
                },
                &[],
            )
            .await,
    );
    // Exercise JSON dispatch too.
    for rpc in ["GetServerInfo", "BeginUpload", "CompleteUpload"] {
        assert_unimplemented(&server.json(rpc, &serde_json::json!({}), &[]).await);
    }
}

#[tokio::test]
async fn m1_upload_part_stub_ignores_stream_contents_without_auth() {
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
    // Malformed frame, and no header at all: neither is validated by the handler.
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
        assert_eq!(end["error"]["code"], "unimplemented");
        assert_eq!(end["error"]["message"], "not implemented yet");
    }
}

#[tokio::test]
async fn m1_ref_stubs_precede_validation_and_never_write() {
    for (rpc, extra) in [
        ("UpdateRef", serde_json::json!({ "delete": true })),
        ("AdvanceRefs", serde_json::json!({ "delete": true })),
        ("AdvanceRefs", serde_json::json!({ "ticketIds": [b64(&A)] })),
    ] {
        let mut config = setup(AuthMode::Open);
        config.meta = Some(
            MemoryKv::with_clock(Arc::new(ManualClock::new(T0)))
                .with_fault(MemoryFault::ApplyBefore),
        );
        let server = config.serve();
        // Missing required legacy fields would fail validation if the stub were late.
        assert_unimplemented(&server.json(rpc, &extra, &[]).await);
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
        assert_unimplemented(&server.json(rpc, &valid, &[]).await);
        assert_eq!(server.read(HEAD).await.exists, Some(false));
        assert_eq!(server.read(PACKMAP).await.exists, Some(false));
        assert!(
            server.codes(rpc).is_empty(),
            "stub must not call the pipeline"
        );
        // The one-shot apply fault is still armed: neither stub reached a write.
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
async fn m1_ticketed_upload_pack_rejects_before_chunks_and_header_validation() {
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
    for msg in [ticketed, invalid] {
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
        assert_eq!(end["error"]["code"], "unimplemented");
        assert_eq!(end["error"]["message"], "not implemented yet");
    }
    assert!(!server.exists(&hash(&data)).await);
    assert!(server.codes("UploadPack").is_empty());
}

#[tokio::test]
async fn m1_list_refs_paging_token_rejected_and_page_size_ignored() {
    let server = setup(AuthMode::Open).serve();
    for (name, id) in [(HEAD, A), ("refs/heads/dev", B)] {
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
    // An invalid prefix must not reach validation when a token is supplied.
    assert_unimplemented(
        &server
            .unary(
                "ListRefs",
                &ListRefsRequest {
                    prefix: Some("invalid".into()),
                    page_token: Some("next".into()),
                    ..Default::default()
                },
                &[],
            )
            .await,
    );
    let list = |page_size| ListRefsRequest {
        prefix: Some("refs/heads/".into()),
        page_size,
        ..Default::default()
    };
    let original = server
        .unary("ListRefs", &list(None), &[])
        .await
        .decode::<ListRefsResponse>();
    let bounded = server
        .unary("ListRefs", &list(Some(1)), &[])
        .await
        .decode::<ListRefsResponse>();
    assert_eq!(bounded, original);
    assert_eq!(bounded.refs.len(), 2);
    // Keep the legacy response bytes unchanged: absent means an empty token.
    assert_eq!(bounded.next_page_token, None);
    let json = server
        .json("ListRefs", &serde_json::json!({ "pageSize": 1 }), &[])
        .await;
    assert_eq!(json.json()["refs"].as_array().unwrap().len(), 2);
    assert!(json.json().get("nextPageToken").is_none());
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
