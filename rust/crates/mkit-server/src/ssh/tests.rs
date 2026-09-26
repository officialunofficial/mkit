//! Frame-level tests of the ssh session over the pipeline, with in-memory
//! frame sources and sinks, over the memory stores and (feature `fs`) the
//! `.mkit` layout stores.
//!
//! "Ported from" cites `rust/crates/mkit-cli/src/commands/serve/tests.rs`
//! at the WP-M0-12 base (`serve_loop` over `FileTransport`).

// The frame builders return `Option<Body>`, a frame's body, so a script can
// also hold the empty frame (`None`).
#![allow(clippy::unnecessary_wraps)]

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::{Hash, hash};
use mkit_core::protocol::PackKey;
use mkit_core::refs::RefWriteCondition;
use mkit_rpc::mkit::common::v1::RefExpectation;
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPack, DownloadPackHeader, Hello, ListRefs, PackChunk, PackExists, ReadRef, SshFrame,
    UpdateRef, UploadPack, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode, ProtocolVersion};

use super::*;
use crate::error::Redacted;
use crate::pipeline::{AuthMode, HookSet, Hooks, Pipeline, PipelineConfig};
use crate::principal::Principal;
use crate::repo::{Addressing, NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::{BlobKey, BlobStore, Key, NamespaceStore, Partition};
use crate::telemetry::NoopMetrics;
use crate::upload::UploadError;
use crate::{MemoryBlobStore, MemoryFault, MemoryKv};

type Body = ssh_frame::Body;

/// The `server_id` `mkit serve` 0.4.2 sent when the golden session was
/// captured.
const SERVER_ID: &str = "mkit serve/0.4.2";
const T0: i64 = 1_700_000_000_000;

// ---------------------------------------------------------------- harness

/// A scripted frame source; once the script runs out it reports a clean
/// end of stream.
struct VecSource(VecDeque<Result<SshFrame, FrameIoError>>);

impl FrameSource for VecSource {
    async fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        self.0.pop_front().unwrap_or(Err(FrameIoError::Eof))
    }
}

/// Collects frames; fails every send once `fail_after` frames are in.
#[derive(Default)]
struct VecSink {
    frames: Vec<SshFrame>,
    fail_after: Option<usize>,
}

impl FrameSink for VecSink {
    async fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError> {
        if self.fail_after.is_some_and(|n| self.frames.len() >= n) {
            return Err(FrameIoError::Io(Redacted::new("peer closed")));
        }
        self.frames.push(frame.clone());
        Ok(())
    }
}

fn frame(body: Option<Body>) -> SshFrame {
    SshFrame {
        body,
        ..Default::default()
    }
}

fn hello() -> Option<Body> {
    let hello = Hello::default().with_proto(ProtocolVersion::ProtocolVersion1);
    Some(Body::Hello(Box::new(hello)))
}

/// A source: `Hello`, then `bodies`.
fn script(bodies: impl IntoIterator<Item = Option<Body>>) -> VecSource {
    let frames = core::iter::once(hello()).chain(bodies);
    VecSource(frames.map(|b| Ok(frame(b))).collect())
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("room-a").unwrap(),
    }
}

fn cfg(auth: AuthMode) -> PipelineConfig {
    PipelineConfig::new(Addressing::Single { repo: repo() }, auth, upload_limits())
}

fn pipeline<B: BlobStore, N: NamespaceStore>(blobs: B, meta: N, auth: AuthMode) -> Pipeline<B, N> {
    let clock = Arc::new(ManualClock::new(T0));
    let metrics = Arc::new(NoopMetrics);
    Pipeline::new(blobs, meta, Hooks::new(), cfg(auth), clock, metrics).unwrap()
}

/// A memory pipeline; the blob store is a shared handle into it.
fn mem() -> (Pipeline<MemoryBlobStore, MemoryKv>, MemoryBlobStore) {
    let blobs = MemoryBlobStore::default();
    let clock = Arc::new(ManualClock::new(T0));
    let meta = MemoryKv::with_clock(clock);
    let pipe = pipeline(blobs.clone(), meta, AuthMode::TransportIdentity);
    (pipe, blobs)
}

fn principal() -> Principal {
    Principal::SshForcedCommand { key: None }
}

fn serve<B: BlobStore, N: NamespaceStore, H: HookSet>(
    pipe: &Pipeline<B, N, H>,
    mut src: VecSource,
    sink: &mut VecSink,
    cfg: &SessionConfig,
) -> SessionEnd {
    block_on(serve_session(pipe, principal(), &mut src, sink, cfg))
}

/// Run a session: `Hello`, then `bodies`. Returns how it ended and every
/// frame after the `HelloResponse`, which it checks.
fn run<B: BlobStore, N: NamespaceStore, H: HookSet>(
    pipe: &Pipeline<B, N, H>,
    bodies: impl IntoIterator<Item = Option<Body>>,
) -> (SessionEnd, Vec<SshFrame>) {
    let mut sink = VecSink::default();
    let end = serve(
        pipe,
        script(bodies),
        &mut sink,
        &SessionConfig::new(SERVER_ID),
    );
    let mut frames = sink.frames.into_iter();
    let first = frames.next().expect("a HelloResponse");
    let Some(Body::HelloResponse(resp)) = first.body else {
        panic!("expected HelloResponse, got {:?}", first.body);
    };
    assert_eq!(resp.server_id.as_deref(), Some(SERVER_ID));
    (end, frames.collect())
}

/// The frame's error, which it must be.
#[track_caller]
fn error(f: &SshFrame) -> &RpcError {
    match &f.body {
        Some(Body::Error(e)) => e,
        other => panic!("expected an Error frame, got {other:?}"),
    }
}

/// Assert `f` is `Error{code, message}` with empty `details`.
#[track_caller]
fn assert_error(f: &SshFrame, code: ErrorCode, message: &str) {
    let e = error(f);
    assert!(e.code.is_some_and(|c| c == code), "code of {e:?}");
    assert_eq!(e.message.as_deref(), Some(message));
    assert_eq!(e.details.as_deref().map_or(0, <[u8]>::len), 0);
}

fn upload_header(id: &[u8], total: Option<u64>) -> Option<Body> {
    Some(Body::UploadPack(Box::new(UploadPack {
        pack_id: Some(id.to_vec()),
        total_bytes: total,
        ..Default::default()
    })))
}

fn chunk(id: &[u8], offset: Option<u64>, data: &[u8], last: bool) -> Option<Body> {
    Some(Body::PackChunk(Box::new(PackChunk {
        pack_id: Some(id.to_vec()),
        offset,
        data: Some(data.to_vec()),
        last: Some(last),
        ..Default::default()
    })))
}

fn update(
    name: &str,
    new: &[u8],
    expectation: Option<RefExpectation>,
    expected: Option<&[u8]>,
) -> Option<Body> {
    let mut req = UpdateRef::default()
        .with_name(name)
        .with_new_id(new.to_vec());
    if let Some(e) = expectation {
        req = req.with_expectation(e);
    }
    if let Some(e) = expected {
        req = req.with_expected_id(e.to_vec());
    }
    Some(Body::UpdateRef(Box::new(req)))
}

fn read_ref(name: &str) -> Option<Body> {
    Some(Body::ReadRef(Box::new(ReadRef::default().with_name(name))))
}

fn list_refs(prefix: Option<&str>) -> Option<Body> {
    let mut req = ListRefs::default();
    if let Some(p) = prefix {
        req = req.with_prefix(p);
    }
    Some(Body::ListRefs(Box::new(req)))
}

fn exists(id: &[u8]) -> Option<Body> {
    let req = PackExists::default().with_pack_id(id.to_vec());
    Some(Body::PackExists(Box::new(req)))
}

fn download(id: Option<&[u8]>) -> Option<Body> {
    let mut req = DownloadPack::default();
    if let Some(id) = id {
        req = req.with_pack_id(id.to_vec());
    }
    Some(Body::DownloadPack(Box::new(req)))
}

fn close() -> Option<Body> {
    Some(Body::Close(Box::default()))
}

fn pack_bytes(len: usize, seed: u8) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Seed `pipe` through the ssh session itself: `refs` with `ANY` and the
/// packs, each in one chunk.
fn seed<B: BlobStore, N: NamespaceStore, H: HookSet>(
    pipe: &Pipeline<B, N, H>,
    refs: &[(&str, Hash)],
    packs: &[&[u8]],
) {
    let mut bodies = Vec::new();
    for (name, id) in refs {
        bodies.push(update(name, id, Some(RefExpectation::Any), None));
    }
    for pack in packs {
        let id = hash(pack);
        bodies.push(upload_header(&id, Some(pack.len() as u64)));
        bodies.push(chunk(&id, Some(0), pack, true));
    }
    let (end, frames) = run(pipe, bodies);
    assert_eq!(end, SessionEnd::Clean);
    let ok = |f: &SshFrame| {
        matches!(
            f.body,
            Some(Body::UpdateRefResponse(_) | Body::UploadPackResponse(_))
        )
    };
    assert!(frames.iter().all(ok), "seeding failed: {frames:?}");
}

fn blob_present(blobs: &impl BlobStore, id: Hash) -> bool {
    block_on(blobs.head(&BlobKey::new(id))).unwrap().is_some()
}

fn valid_pack() -> (Vec<u8>, Hash) {
    let bytes = b"valid pack bytes".to_vec();
    let id = hash(&bytes);
    (bytes, id)
}

// ------------------------------------------------------------- handshake

#[test]
fn handshake_rejects_non_hello_first_frame() {
    let (pipe, _) = mem();
    let src = VecSource(VecDeque::from([Ok(frame(list_refs(None)))]));
    let mut sink = VecSink::default();
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(sink.frames.len(), 1);
    assert_error(
        &sink.frames[0],
        ErrorCode::InvalidRequest,
        "first frame must be Hello",
    );
}

#[test]
fn handshake_rejects_unsupported_proto() {
    let (pipe, _) = mem();
    let unspecified = Some(Body::Hello(Box::default()));
    let src = VecSource(VecDeque::from([Ok(frame(unspecified))]));
    let mut sink = VecSink::default();
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(sink.frames.len(), 1);
    assert_error(
        &sink.frames[0],
        ErrorCode::InvalidRequest,
        "unsupported proto_version 0",
    );
}

/// `mkit serve`'s handshake answers an unreadable first frame, even a
/// clean end of stream, with no frame and `PROTOCOL_ERROR`.
#[test]
fn handshake_read_failure_is_silent_protocol_error() {
    let (pipe, _) = mem();
    for err in [FrameIoError::Eof, FrameIoError::Malformed] {
        let mut sink = VecSink::default();
        let src = VecSource(VecDeque::from([Err(err)]));
        let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
        assert_eq!(end, SessionEnd::ProtocolError);
        assert!(sink.frames.is_empty());
    }
    let mut sink = VecSink {
        fail_after: Some(0),
        ..VecSink::default()
    };
    let end = serve(&pipe, script([]), &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::ProtocolError, "HelloResponse write failed");
}

#[test]
fn stop_after_hello_ends_clean() {
    let (pipe, _) = mem();
    let mut cfg = SessionConfig::new(SERVER_ID);
    cfg.stop_after_hello = true;
    let mut sink = VecSink::default();
    let end = serve(&pipe, script([list_refs(None)]), &mut sink, &cfg);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(sink.frames.len(), 1, "only the HelloResponse");
    assert!(matches!(sink.frames[0].body, Some(Body::HelloResponse(_))));
}

#[test]
fn close_and_eof_end_clean() {
    let (pipe, _) = mem();
    let (end, frames) = run(&pipe, [close(), list_refs(None)]);
    assert_eq!(end, SessionEnd::Clean);
    assert!(frames.is_empty(), "nothing after Close is answered");
    let (end, frames) = run(&pipe, []);
    assert_eq!(end, SessionEnd::Clean);
    assert!(frames.is_empty());
}

#[test]
fn pipeline_outside_transport_identity_is_refused() {
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(blobs, MemoryKv::default(), AuthMode::Open);
    let mut src = script([]);
    let mut sink = VecSink::default();
    let cfg = SessionConfig::new(SERVER_ID);
    let end = block_on(serve_session(&pipe, principal(), &mut src, &mut sink, &cfg));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert!(sink.frames.is_empty(), "refused before the handshake");
    assert_eq!(src.0.len(), 1, "the Hello is still unread");
}

// ------------------------------------------------------ loop and budgets

#[test]
fn malformed_frame_emits_parse_error_and_ends() {
    let (pipe, _) = mem();
    for err in [
        FrameIoError::Malformed,
        FrameIoError::Io(Redacted::new("reset")),
    ] {
        let mut src = script([]);
        src.0.push_back(Err(err));
        src.0.push_back(Ok(frame(list_refs(None))));
        let mut sink = VecSink::default();
        let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
        assert_eq!(end, SessionEnd::ProtocolError);
        assert_eq!(sink.frames.len(), 2);
        assert_error(
            &sink.frames[1],
            ErrorCode::InvalidRequest,
            "frame parse error",
        );
    }
}

#[test]
fn timeout_from_source_ends_timeout() {
    let (pipe, blobs) = mem();
    // At the handshake.
    let mut sink = VecSink::default();
    let src = VecSource(VecDeque::from([Err(FrameIoError::Timeout)]));
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert!(sink.frames.is_empty());

    // Between verbs: no error frame.
    let mut src = script([list_refs(None)]);
    src.0.push_back(Err(FrameIoError::Timeout));
    let mut sink = VecSink::default();
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert_eq!(sink.frames.len(), 2, "HelloResponse and ListRefsResponse");

    // Inside an upload: the pack never becomes visible.
    let (bytes, id) = valid_pack();
    let mut src = script([
        upload_header(&id, Some(bytes.len() as u64)),
        chunk(&id, Some(0), &bytes[..4], false),
    ]);
    src.0.push_back(Err(FrameIoError::Timeout));
    let mut sink = VecSink::default();
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::Timeout);
    assert_eq!(sink.frames.len(), 1, "only the HelloResponse");
    assert!(!blob_present(&blobs, id));
}

#[test]
fn sink_failure_after_handshake_ends_io_error() {
    let (pipe, _) = mem();
    let mut sink = VecSink {
        fail_after: Some(1),
        ..VecSink::default()
    };
    let src = script([list_refs(None), list_refs(None)]);
    let end = serve(&pipe, src, &mut sink, &SessionConfig::new(SERVER_ID));
    assert_eq!(end, SessionEnd::IoError);
    assert_eq!(sink.frames.len(), 1);
}

#[test]
fn frame_budget_exceeded_ends_protocol_error() {
    let (pipe, _) = mem();
    let n = MAX_FRAMES_PER_CONN as usize;
    // Empty frames cost no pipeline call; each is answered "empty frame".
    let (end, frames) = run(&pipe, core::iter::repeat_n(None, n + 2));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(frames.len(), n + 1);
    assert_error(&frames[n - 1], ErrorCode::InvalidRequest, "empty frame");
    assert_error(
        &frames[n],
        ErrorCode::InvalidRequest,
        "per-connection frame budget exceeded",
    );
}

#[test]
fn byte_budget_exceeded_ends_protocol_error() {
    let (pipe, _) = mem();
    let header = |total| {
        Some(Body::DownloadPackHeader(Box::new(DownloadPackHeader {
            total_bytes: Some(total),
            ..Default::default()
        })))
    };
    // A client-sent header is charged its declared size, then rejected.
    let half = MAX_BYTES_PER_CONN / 2 + 1;
    let (end, frames) = run(&pipe, [header(half), header(half), list_refs(None)]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_eq!(frames.len(), 2);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "unexpected request frame",
    );
    assert_error(
        &frames[1],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );

    // An upload header is charged before its own size check.
    let (_, id) = valid_pack();
    let (end, frames) = run(&pipe, [upload_header(&id, Some(u64::MAX))]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );
}

#[test]
fn frame_byte_estimate_matches_mkit_serve() {
    let est = |body| frame_byte_estimate(&frame(body));
    assert_eq!(est(chunk(&[0; 32], Some(0), &[7; 100], false)), 100);
    assert_eq!(est(upload_header(&[0; 32], Some(12_345))), 12_345);
    assert_eq!(est(upload_header(&[0; 32], None)), 0);
    assert_eq!(est(list_refs(None)), 64);
    assert_eq!(est(None), 64);
    assert_eq!(
        upload_limits(),
        crate::upload::UploadLimits {
            max_total_bytes: 1024 * 1024 * 1024,
            max_chunks: 10_000,
        }
    );
}

#[test]
fn misplaced_frames_get_mkit_serve_errors() {
    let (pipe, _) = mem();
    let (end, frames) = run(
        &pipe,
        [
            chunk(&[1; 32], Some(0), b"x", true),
            hello(),
            None,
            Some(Body::HelloResponse(Box::default())),
            Some(Body::Error(Box::default())),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    let want = [
        "PackChunk arrived without UploadPack header",
        "Hello after handshake",
        "empty frame",
        "unexpected request frame",
        "unexpected request frame",
    ];
    assert_eq!(frames.len(), want.len());
    for (f, message) in frames.iter().zip(want) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
}

// ------------------------------------------------------------- simple verbs

/// Ported from `pack_key_from_id_rejects_bad_length_as_invalid_request`
/// (tests.rs:943): the decoder behind `PackExists` and `DownloadPack`,
/// here through the frames it answers.
#[test]
fn pack_key_from_id_rejects_bad_length_as_invalid_request() {
    let (pipe, _) = mem();
    let missing = Some(Body::PackExists(Box::default()));
    let (end, frames) = run(
        &pipe,
        [
            exists(&[0; 16]),
            missing,
            download(Some(&[0; 16])),
            download(None),
            exists(&[7; 32]),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    let bad = [
        "pack_id must be 32 bytes",
        "pack_id missing",
        "pack_id must be 32 bytes",
        "pack_id missing",
    ];
    for (f, message) in frames.iter().zip(bad) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
    let Some(Body::PackExistsResponse(resp)) = &frames[4].body else {
        panic!("a correct 32-byte id still decodes");
    };
    assert_eq!(resp.exists, Some(false));
}

#[test]
fn update_ref_field_errors_keep_ssh_messages() {
    let (pipe, _) = mem();
    let main = "refs/heads/main";
    let (end, frames) = run(
        &pipe,
        [
            update(main, &[1; 5], Some(RefExpectation::Any), None),
            update(main, &[1; 32], None, None),
            update(main, &[1; 32], Some(RefExpectation::Match), None),
            update(main, &[1; 32], Some(RefExpectation::Match), Some(&[2; 31])),
            // `new_id` is checked before the expectation.
            update(main, &[], None, None),
            update(
                "refs/heads/.hidden",
                &[1; 32],
                Some(RefExpectation::Any),
                None,
            ),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    let want = [
        "new_id must be 32 bytes",
        "UpdateRef.expectation is required",
        "MATCH expectation requires a 32-byte expected_id",
        "MATCH expectation requires a 32-byte expected_id",
        "new_id must be 32 bytes",
        "update ref failed",
    ];
    assert_eq!(frames.len(), want.len());
    for (f, message) in frames.iter().zip(want) {
        assert_error(f, ErrorCode::InvalidRequest, message);
    }
}

/// SPEC-TRANSPORT §4.2.1: the ssh wire ignores `expected_id` for `ANY` and
/// `MISSING` (M0-04's `UnusedExpectedId::Ignore`).
#[test]
fn any_and_missing_ignore_expected_id() {
    let (pipe, _) = mem();
    let (end, frames) = run(
        &pipe,
        [
            update(
                "refs/heads/a",
                &[1; 32],
                Some(RefExpectation::Any),
                Some(&[9; 3]),
            ),
            update(
                "refs/heads/b",
                &[1; 32],
                Some(RefExpectation::Missing),
                Some(&[9; 32]),
            ),
            read_ref("refs/heads/b"),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    assert!(matches!(frames[1].body, Some(Body::UpdateRefResponse(_))));
    let Some(Body::ReadRefResponse(resp)) = &frames[2].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[1; 32][..]));
}

#[test]
fn read_and_list_refs() {
    let (pipe, _) = mem();
    seed(
        &pipe,
        &[("refs/heads/main", [1; 32]), ("refs/tags/v1", [2; 32])],
        &[],
    );
    let (end, frames) = run(
        &pipe,
        [
            read_ref("refs/heads/main"),
            read_ref("refs/heads/absent"),
            read_ref("refs/heads/.hidden"),
            list_refs(Some("refs/heads/")),
            list_refs(None),
            list_refs(Some("/bad")),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    let read = |f: &SshFrame| match &f.body {
        Some(Body::ReadRefResponse(r)) => r.object_id.clone(),
        other => panic!("expected ReadRefResponse, got {other:?}"),
    };
    assert_eq!(read(&frames[0]), Some(vec![1; 32]));
    assert_eq!(read(&frames[1]), Some(Vec::new()), "absent is empty");
    assert_error(&frames[2], ErrorCode::Internal, "read ref failed");
    let listed = |f: &SshFrame| match &f.body {
        Some(Body::ListRefsResponse(r)) => r
            .refs
            .iter()
            .map(|e| (e.name.clone().unwrap(), e.object_id.clone().unwrap()))
            .collect::<Vec<_>>(),
        other => panic!("expected ListRefsResponse, got {other:?}"),
    };
    assert_eq!(listed(&frames[3]), [("main".to_owned(), vec![1; 32])]);
    assert_eq!(
        listed(&frames[4]),
        [
            ("refs/heads/main".to_owned(), vec![1; 32]),
            ("refs/tags/v1".to_owned(), vec![2; 32]),
        ]
    );
    assert_error(&frames[5], ErrorCode::Internal, "list refs failed");
}

/// Ported from `serve_loop_cas_conflict_carries_current_id_in_details`
/// (tests.rs:284): two writers race a create-only update; the loser's
/// reply carries the winner's id in `details` and classifies as
/// `RefConflict` through the shared client mapping.
#[test]
fn serve_loop_cas_conflict_carries_current_id_in_details() {
    let (pipe, _) = mem();
    let (winner, loser) = ([0xA1u8; 32], [0xB2u8; 32]);
    let main = "refs/heads/main";
    let (end, frames) = run(
        &pipe,
        [
            update(main, &winner, Some(RefExpectation::Missing), None),
            update(main, &loser, Some(RefExpectation::Missing), None),
            read_ref(main),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    let err = error(&frames[1]).clone();
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref(), Some(&winner[..]));
    assert!(matches!(
        mkit_rpc::map_update_ref_error(err, RefWriteCondition::Missing, "ssh"),
        mkit_core::protocol::TransportError::RefConflict
    ));
    let Some(Body::ReadRefResponse(resp)) = &frames[2].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(
        resp.object_id.as_deref(),
        Some(&winner[..]),
        "loser clobbered nothing"
    );
}

/// Ported from `serve_loop_match_conflict_reports_current_value`
/// (tests.rs:343).
#[test]
fn serve_loop_match_conflict_reports_current_value() {
    let (pipe, _) = mem();
    let (current, stale, next) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
    let main = "refs/heads/main";
    seed(&pipe, &[(main, current)], &[]);
    let (_, frames) = run(
        &pipe,
        [
            update(main, &next, Some(RefExpectation::Match), Some(&stale)),
            read_ref(main),
        ],
    );
    let err = error(&frames[0]);
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref(), Some(&current[..]));
    assert_eq!(
        err.message.as_deref(),
        Some("ref update conflict: expectation does not match current ref value")
    );
    let Some(Body::ReadRefResponse(resp)) = &frames[1].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&current[..]));
}

/// Ported from `serve_loop_match_conflict_on_absent_ref_has_empty_details`
/// (tests.rs:390): no current value, so `details` stays empty and strict
/// clients surface the message as a remote error.
#[test]
fn serve_loop_match_conflict_on_absent_ref_has_empty_details() {
    let (pipe, _) = mem();
    let ghost = "refs/heads/ghost";
    let (_, frames) = run(
        &pipe,
        [
            update(
                ghost,
                &[0x44; 32],
                Some(RefExpectation::Match),
                Some(&[0x55; 32]),
            ),
            read_ref(ghost),
        ],
    );
    let err = error(&frames[0]).clone();
    assert!(err.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(err.details.as_deref().map_or(0, <[u8]>::len), 0);
    let mapped = mkit_rpc::map_update_ref_error(err, RefWriteCondition::Match([0x55; 32]), "ssh");
    match mapped {
        mkit_core::protocol::TransportError::RemoteError(msg) => {
            assert!(msg.contains("absent"), "message should say absent: {msg}");
        }
        other => panic!("expected RemoteError, got {other:?}"),
    }
    let Some(Body::ReadRefResponse(resp)) = &frames[1].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[][..]));
}

#[test]
fn cas_conflict_body_matches_mkit_serve() {
    let Body::Error(e) = cas_conflict_body(Some([7; 32])) else {
        panic!("an Error body");
    };
    assert!(e.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
    assert_eq!(e.details.as_deref(), Some(&[7; 32][..]));
    let Body::Error(e) = cas_conflict_body(None) else {
        panic!("an Error body");
    };
    assert_eq!(
        e.message.as_deref(),
        Some("ref update conflict: expectation not met and ref is currently absent")
    );
    assert_eq!(e.details.as_deref(), Some(&[][..]));
}

// ------------------------------------------------------------------ uploads

/// Ported from `upload_drain_accepts_valid_chunks` (tests.rs:51).
#[test]
fn upload_drain_accepts_valid_chunks() {
    let (pipe, blobs) = mem();
    let (bytes, id) = valid_pack();
    let (end, frames) = run(
        &pipe,
        [
            upload_header(&id, Some(bytes.len() as u64)),
            chunk(&id, Some(0), &bytes[..5], false),
            chunk(&id, Some(5), &bytes[5..], true),
            exists(&id),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::UploadPackResponse(_))));
    let Some(Body::PackExistsResponse(resp)) = &frames[1].body else {
        panic!("expected PackExistsResponse");
    };
    assert_eq!(resp.exists, Some(true));
    assert!(blob_present(&blobs, id));
}

/// Ported from `upload_drain_rejects_malformed_streams` (tests.rs:85),
/// each case as a frame sequence: the error frame carries `mkit serve`'s
/// message, nothing is stored, and the session goes on.
#[test]
fn upload_drain_rejects_malformed_streams() {
    let (bytes, id) = valid_pack();
    let len = bytes.len() as u64;
    let wrong = b"wrong pack bytes";
    let cases: Vec<(Vec<Option<Body>>, &str)> = vec![
        (
            vec![upload_header(&id, None)],
            "UploadPack.total_bytes is required",
        ),
        (
            vec![upload_header(&[1; 7], Some(len))],
            "pack_id must be 32 bytes",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, Some(1), &bytes, true),
            ],
            "PackChunk.offset is not the expected next offset",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, None, &bytes, true),
            ],
            "PackChunk.offset is required",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&[0xAA; 32], Some(0), &bytes, true),
            ],
            "PackChunk.pack_id does not match UploadPack",
        ),
        (
            vec![
                upload_header(&id, Some(len - 1)),
                chunk(&id, Some(0), &bytes, true),
            ],
            "PackChunk data exceeds declared total_bytes",
        ),
        (
            vec![
                upload_header(&id, Some(len)),
                chunk(&id, Some(0), &bytes[..bytes.len() - 1], true),
            ],
            "PackChunk stream ended before declared total_bytes",
        ),
        (
            vec![
                upload_header(&id, Some(wrong.len() as u64)),
                chunk(&id, Some(0), wrong, true),
            ],
            "uploaded pack bytes do not match UploadPack.pack_id",
        ),
        (
            vec![upload_header(&id, Some(len)), list_refs(None)],
            "expected PackChunk after UploadPack",
        ),
        (
            vec![upload_header(&id, Some(len))],
            "pack chunk read failed",
        ),
    ];
    for (bodies, message) in cases {
        let (pipe, blobs) = mem();
        let mut bodies = bodies;
        let eof = bodies.len() == 1 && message == "pack chunk read failed";
        if !eof {
            bodies.push(exists(&id));
        }
        let (end, frames) = run(&pipe, bodies);
        assert_eq!(end, SessionEnd::Clean, "{message}");
        assert_error(&frames[0], ErrorCode::InvalidRequest, message);
        assert!(!blob_present(&blobs, id), "{message}: nothing stored");
        if !eof {
            // The session is still in frame sync.
            assert!(
                matches!(frames[1].body, Some(Body::PackExistsResponse(_))),
                "{message}"
            );
        }
    }
}

/// The `total_bytes` cap case of `upload_drain_rejects_malformed_streams`
/// (tests.rs:88). With the ssh caps the header's declared size is charged
/// to the byte budget first, so over the frame loop an oversized header
/// trips the budget, as it does in `mkit serve`. A pipeline with a smaller
/// upload cap reaches the cap's own message.
#[test]
fn declared_size_over_the_cap() {
    let (pipe, _) = mem();
    let (_, id) = valid_pack();
    let (end, frames) = run(&pipe, [upload_header(&id, Some(MAX_BYTES_PER_CONN + 1))]);
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "per-connection byte budget exceeded",
    );

    let clock = Arc::new(ManualClock::new(T0));
    let mut small = cfg(AuthMode::TransportIdentity);
    small.upload_limits.max_total_bytes = 8;
    let meta = MemoryKv::with_clock(clock.clone());
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta,
        Hooks::new(),
        small,
        clock,
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let (end, frames) = run(&pipe, [upload_header(&id, Some(9)), exists(&id)]);
    assert_eq!(end, SessionEnd::Clean);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "UploadPack.total_bytes exceeds server cap",
    );
    assert!(matches!(frames[1].body, Some(Body::PackExistsResponse(_))));
}

#[test]
fn too_many_chunks_is_rejected() {
    let (pipe, blobs) = mem();
    let n = MAX_FRAMES_PER_CONN as usize;
    let data = pack_bytes(n + 1, 3);
    let id = hash(&data);
    let mut bodies = vec![upload_header(&id, Some(data.len() as u64))];
    for i in 0..=n {
        bodies.push(chunk(&id, Some(i as u64), &data[i..=i], i == n));
    }
    let (end, frames) = run(&pipe, bodies);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(frames.len(), 1);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "too many PackChunk frames before last=true",
    );
    assert!(!blob_present(&blobs, id));
}

/// The per-upload chunk cap of SPEC-TRANSPORT §4.4 holds even when the
/// pipeline's own upload limits set none.
#[test]
fn chunk_cap_holds_with_an_uncapped_pipeline() {
    let clock = Arc::new(ManualClock::new(T0));
    let mut uncapped = cfg(AuthMode::TransportIdentity);
    uncapped.upload_limits = crate::upload::UploadLimits {
        max_total_bytes: u64::MAX,
        max_chunks: u32::MAX,
    };
    let blobs = MemoryBlobStore::default();
    let meta = MemoryKv::with_clock(clock.clone());
    let metrics = Arc::new(NoopMetrics);
    let pipe = Pipeline::new(blobs.clone(), meta, Hooks::new(), uncapped, clock, metrics).unwrap();
    let n = MAX_FRAMES_PER_CONN as usize;
    let data = pack_bytes(n + 1, 3);
    let id = hash(&data);
    let mut bodies = vec![upload_header(&id, Some(data.len() as u64))];
    for i in 0..=n {
        bodies.push(chunk(&id, Some(i as u64), &data[i..=i], i == n));
    }
    bodies.push(exists(&id));
    let (end, frames) = run(&pipe, bodies);
    assert_eq!(end, SessionEnd::Clean);
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        "too many PackChunk frames before last=true",
    );
    assert!(!blob_present(&blobs, id));
    // At the cap exactly, the same kind of pack goes through.
    let data = pack_bytes(n, 4);
    let id = hash(&data);
    let mut bodies = vec![upload_header(&id, Some(data.len() as u64))];
    for i in 0..n {
        bodies.push(chunk(&id, Some(i as u64), &data[i..=i], i + 1 == n));
    }
    let (_, frames) = run(&pipe, bodies);
    assert!(matches!(frames[0].body, Some(Body::UploadPackResponse(_))));
}

/// SPEC-REFS §3: a name over 512 bytes is refused by name, with
/// `INVALID_REQUEST`, on reads and writes; `mkit serve` used to accept it.
#[test]
fn over_long_ref_names_are_refused_by_name() {
    let (pipe, _) = mem();
    let longest = format!(
        "refs/heads/{}",
        "a".repeat(crate::refs::MAX_REF_NAME_BYTES - 11)
    );
    let over = format!("{longest}a");
    let (end, frames) = run(
        &pipe,
        [
            update(&over, &[1; 32], Some(RefExpectation::Any), None),
            read_ref(&over),
            // Field errors still come first.
            update(&over, &[1; 5], Some(RefExpectation::Any), None),
            update(&longest, &[1; 32], Some(RefExpectation::Any), None),
            read_ref(&longest),
            list_refs(Some(&over)),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert_error(&frames[0], ErrorCode::InvalidRequest, "ref name too long");
    assert_error(&frames[1], ErrorCode::InvalidRequest, "ref name too long");
    assert_error(
        &frames[2],
        ErrorCode::InvalidRequest,
        "new_id must be 32 bytes",
    );
    assert!(matches!(frames[3].body, Some(Body::UpdateRefResponse(_))));
    let Some(Body::ReadRefResponse(resp)) = &frames[4].body else {
        panic!("expected ReadRefResponse");
    };
    assert_eq!(resp.object_id.as_deref(), Some(&[1; 32][..]));
    assert_error(&frames[5], ErrorCode::Internal, "list refs failed");
}

/// R-86: a valid name outside `refs/` (`mkit serve` stored `main` as
/// `<root>/main`) is refused by name on reads and writes; a name that fails
/// the grammar keeps its old reply, and listings are unaffected.
#[test]
fn ref_names_outside_refs_are_refused_by_name() {
    let (pipe, _) = mem();
    let (end, frames) = run(
        &pipe,
        [
            update("main", &[1; 32], Some(RefExpectation::Any), None),
            read_ref("main"),
            update("packs/x", &[1; 32], Some(RefExpectation::Missing), None),
            read_ref("heads/main"),
            // Field errors still come first.
            update("main", &[1; 5], Some(RefExpectation::Any), None),
            // Grammar failures: the old replies.
            read_ref(".main"),
            update(".main", &[1; 32], Some(RefExpectation::Any), None),
            list_refs(Some("heads/")),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    let outside = crate::refs::REF_NAME_OUTSIDE_REFS;
    for f in &frames[..4] {
        assert_error(f, ErrorCode::InvalidRequest, outside);
    }
    assert_error(
        &frames[4],
        ErrorCode::InvalidRequest,
        "new_id must be 32 bytes",
    );
    assert_error(&frames[5], ErrorCode::Internal, "read ref failed");
    assert_error(&frames[6], ErrorCode::InvalidRequest, "update ref failed");
    let Some(Body::ListRefsResponse(listed)) = &frames[7].body else {
        panic!("expected ListRefsResponse, got {:?}", frames[7].body);
    };
    assert!(listed.refs.is_empty());
}

/// SPEC-REFS §4 over the ssh wire: component-boundary prefixes, as
/// `mkit serve` answers them (pinned byte for byte by `session-2`).
#[test]
fn list_refs_prefixes_match_at_component_boundaries() {
    let (pipe, _) = mem();
    let refs = [
        ("refs/heads/feat/x", [1; 32]),
        ("refs/heads/featx", [2; 32]),
        ("refs/heads/main", [3; 32]),
    ];
    seed(&pipe, &refs, &[]);
    let prefixes = [
        "refs/heads",
        "refs/heads/",
        "refs/heads/feat",
        "refs/heads/ma",
        "refs/heads/main",
        "refs//",
    ];
    let (_, frames) = run(&pipe, prefixes.map(|p| list_refs(Some(p))));
    let names: Vec<Vec<String>> = frames
        .iter()
        .map(|f| match &f.body {
            Some(Body::ListRefsResponse(r)) => {
                r.refs.iter().map(|e| e.name.clone().unwrap()).collect()
            }
            other => panic!("expected ListRefsResponse, got {other:?}"),
        })
        .collect();
    let heads = ["feat/x", "featx", "main"].map(String::from).to_vec();
    assert_eq!(names[0], heads);
    assert_eq!(names[1], heads);
    assert_eq!(names[2], ["x"]);
    assert!(names[3].is_empty());
    // A ref named exactly the prefix is not listed (SPEC-REFS §4); see
    // `GOLDEN_2` for `mkit serve`'s answer to this one.
    assert!(names[4].is_empty());
    assert_eq!(names[5], ["heads/feat/x", "heads/featx", "heads/main"]);
}

/// A storage failure answers `upload failed` only once the stream has been
/// read to its `last` chunk, so the session stays in frame sync.
#[test]
fn storage_failure_drains_then_answers_upload_failed() {
    let data = pack_bytes(3_000, 5);
    let id = hash(&data);
    let bodies = || {
        vec![
            upload_header(&id, Some(data.len() as u64)),
            chunk(&id, Some(0), &data[..1_000], false),
            chunk(&id, Some(1_000), &data[1_000..2_000], false),
            chunk(&id, Some(2_000), &data[2_000..], true),
            exists(&id),
        ]
    };
    for fault in [MemoryFault::BlobWrite(0), MemoryFault::BlobCommit] {
        let (pipe, blobs) = mem();
        let _armed = blobs.clone().with_fault(fault);
        let (end, frames) = run(&pipe, bodies());
        assert_eq!(end, SessionEnd::Clean);
        assert_eq!(frames.len(), 2, "{fault:?}");
        assert_error(&frames[0], ErrorCode::Internal, "upload failed");
        let Some(Body::PackExistsResponse(resp)) = &frames[1].body else {
            panic!("expected PackExistsResponse");
        };
        assert_eq!(resp.exists, Some(false));
    }
}

/// Ported from `serve_loop_rejects_invalid_upload_before_storage`
/// (tests.rs:184).
#[test]
fn serve_loop_rejects_invalid_upload_before_storage() {
    let (pipe, blobs) = mem();
    let bogus = [0x77; 32];
    let (end, frames) = run(
        &pipe,
        [
            upload_header(&bogus, Some(5)),
            chunk(&bogus, Some(0), b"wrong", true),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert!(!blob_present(&blobs, bogus));
    assert_error(
        &frames[0],
        ErrorCode::InvalidRequest,
        UploadError::DigestMismatch.ssh_message(),
    );
}

/// Ported from `serve_loop_rejected_upload_does_not_overwrite_existing_pack`
/// (tests.rs:226).
#[test]
fn serve_loop_rejected_upload_does_not_overwrite_existing_pack() {
    let (pipe, _) = mem();
    let (bytes, id) = valid_pack();
    seed(&pipe, &[], &[&bytes]);
    let (end, frames) = run(
        &pipe,
        [
            upload_header(&id, Some(5)),
            chunk(&id, Some(0), b"wrong", true),
            download(Some(&id)),
        ],
    );
    assert_eq!(end, SessionEnd::Clean);
    assert!(matches!(frames[0].body, Some(Body::Error(_))));
    assert_eq!(downloaded(&frames[1..], &id), bytes);
}

/// The ssh path runs without a replay ledger or quota: after uploads and
/// ref writes the metadata store holds refs and its layout version only.
#[test]
fn no_replay_or_quota_rows_are_written() {
    let (pipe, _) = mem();
    let (bytes, _) = valid_pack();
    seed(
        &pipe,
        &[("refs/heads/main", [1; 32])],
        &[&bytes, b"another"],
    );
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let (start, end) = (Key::new(vec![0u8]), Key::new(vec![0xffu8]));
    let page = block_on(pipe.meta_store().scan(&p, &start, &end, None, 100)).unwrap();
    let tags: Vec<u8> = page.entries.iter().map(|(k, _)| k.as_bytes()[0]).collect();
    assert!(!tags.is_empty());
    assert!(
        tags.iter().all(|t| matches!(t, b'r' | b'v')),
        "only ref and layout-version rows, got tags {tags:?}"
    );
}

// ---------------------------------------------------------------- downloads

/// The pack a `DownloadPack` reply carries, checking its framing: a header
/// with the length, then contiguous chunks that repeat `id`, of which only
/// the final one is `last`.
#[track_caller]
fn downloaded(frames: &[SshFrame], id: &[u8]) -> Vec<u8> {
    let Some(Body::DownloadPackHeader(h)) = &frames[0].body else {
        panic!("expected DownloadPackHeader, got {:?}", frames[0].body);
    };
    let total = h.total_bytes.unwrap();
    let mut out = Vec::new();
    for (i, f) in frames[1..].iter().enumerate() {
        let Some(Body::PackChunk(c)) = &f.body else {
            panic!("expected PackChunk, got {:?}", f.body);
        };
        assert_eq!(c.pack_id.as_deref(), Some(id));
        assert_eq!(c.offset, Some(out.len() as u64));
        out.extend_from_slice(c.data.as_deref().unwrap());
        if c.last == Some(true) {
            assert_eq!(out.len() as u64, total);
            assert_eq!(i + 2, frames.len(), "nothing after the last chunk");
            return out;
        }
    }
    panic!("no last chunk");
}

#[test]
fn download_emits_header_then_contiguous_chunks_last() {
    let (pipe, _) = mem();
    let max = crate::download::DOWNLOAD_CHUNK_MAX;
    let big = pack_bytes(2 * max + 123, 11);
    let id = hash(&big);
    seed(&pipe, &[], &[&big, b""]);
    let (end, frames) = run(&pipe, [download(Some(&id))]);
    assert_eq!(end, SessionEnd::Clean);
    assert_eq!(frames.len(), 4, "a header and three chunks");
    let chunks: Vec<(u64, usize)> = frames[1..]
        .iter()
        .map(|f| match &f.body {
            Some(Body::PackChunk(c)) => (c.offset.unwrap(), c.data.as_ref().unwrap().len()),
            _ => panic!("chunk"),
        })
        .collect();
    let max64 = max as u64;
    assert_eq!(chunks, [(0, max), (max64, max), (2 * max64, 123)]);
    assert_eq!(downloaded(&frames, &id), big);

    // The empty pack: one empty `last` chunk.
    let empty = hash(b"");
    let (_, frames) = run(&pipe, [download(Some(&empty))]);
    assert_eq!(frames.len(), 2);
    assert!(downloaded(&frames, &empty).is_empty());

    // A missing pack.
    let (_, frames) = run(&pipe, [download(Some(&[9; 32]))]);
    assert_error(&frames[0], ErrorCode::KeyNotFound, "pack not found");
}

/// A body that fails after the header is answered `pack read failed`.
#[test]
fn download_read_failure_after_header_is_internal() {
    use crate::store::{BlobBody, BlobMeta, ByteRange, StoreError};

    struct Failing(MemoryBlobStore);
    impl BlobStore for Failing {
        type Sink = <MemoryBlobStore as BlobStore>::Sink;
        async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
            self.0.begin(key, len).await
        }
        async fn get(
            &self,
            _: &BlobKey,
            _: Option<ByteRange>,
        ) -> Result<Option<BlobBody>, StoreError> {
            let piece: Result<Bytes, StoreError> = Ok(Bytes::from_static(b"abc"));
            let pieces = [
                piece,
                Err(StoreError::unavailable(std::io::Error::other("gone"))),
            ];
            let stream = futures_stream(pieces);
            Ok(Some(BlobBody::Stream { len: 10, stream }))
        }
        async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
            self.0.head(key).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            Ok(())
        }
        async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
            self.0.delete(key).await
        }
    }

    let clock = Arc::new(ManualClock::new(T0));
    let meta = MemoryKv::with_clock(clock);
    let pipe = pipeline(
        Failing(MemoryBlobStore::default()),
        meta,
        AuthMode::TransportIdentity,
    );
    let (end, frames) = run(&pipe, [download(Some(&[3; 32])), list_refs(None)]);
    assert_eq!(end, SessionEnd::Clean);
    let Some(Body::DownloadPackHeader(h)) = &frames[0].body else {
        panic!("expected DownloadPackHeader");
    };
    assert_eq!(h.total_bytes, Some(10));
    assert_error(&frames[1], ErrorCode::Internal, "pack read failed");
    assert!(matches!(frames[2].body, Some(Body::ListRefsResponse(_))));
}

/// A `'static` stream over `items`.
fn futures_stream<T: Send + Unpin + 'static>(
    items: impl IntoIterator<Item = T>,
) -> crate::rt::BoxStream<'static, T> {
    struct Iter<I>(I);
    impl<I: Iterator + Unpin> futures_core::Stream for Iter<I> {
        type Item = I::Item;
        fn poll_next(
            mut self: core::pin::Pin<&mut Self>,
            _: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Option<I::Item>> {
            core::task::Poll::Ready(self.0.next())
        }
    }
    let items: Vec<T> = items.into_iter().collect();
    Box::pin(Iter(items.into_iter()))
}

// ------------------------------------------------------------ runtime model

#[test]
fn session_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let (pipe, _) = mem();
    let mut src = script([]);
    let mut sink = VecSink::default();
    let cfg = SessionConfig::new(SERVER_ID);
    let fut = serve_session(&pipe, principal(), &mut src, &mut sink, &cfg);
    assert_send(&fut);
    assert_eq!(block_on(fut), SessionEnd::Clean);
}

/// `ReadFrames` maps `mkit-rpc`'s framing errors the way `serve_loop`
/// treated them: a truncated length prefix is a clean end of stream,
/// anything else unreadable is malformed.
#[test]
fn read_frames_maps_framing_errors() {
    let next = |bytes: Vec<u8>| block_on(ReadFrames(std::io::Cursor::new(bytes)).next_frame());
    assert!(matches!(next(Vec::new()), Err(FrameIoError::Eof)));
    assert!(matches!(next(vec![1, 0]), Err(FrameIoError::Eof)));
    let too_long = (mkit_rpc::MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
    assert!(matches!(next(too_long), Err(FrameIoError::Malformed)));
    assert!(matches!(
        next(vec![5, 0, 0, 0, 1]),
        Err(FrameIoError::Malformed)
    ));
    assert!(matches!(
        next(vec![1, 0, 0, 0, 0xff]),
        Err(FrameIoError::Malformed)
    ));

    // Over the byte stream: a garbage frame after `Hello` is answered
    // "frame parse error" and ends the session.
    let (pipe, _) = mem();
    let mut input = Vec::new();
    mkit_rpc::write_frame(&mut input, &frame(hello())).unwrap();
    input.extend_from_slice(&[1, 0, 0, 0, 0xff]);
    let mut src = ReadFrames(std::io::Cursor::new(input));
    let mut sink = VecSink::default();
    let cfg = SessionConfig::new(SERVER_ID);
    let end = block_on(serve_session(&pipe, principal(), &mut src, &mut sink, &cfg));
    assert_eq!(end, SessionEnd::ProtocolError);
    assert_error(
        &sink.frames[1],
        ErrorCode::InvalidRequest,
        "frame parse error",
    );
}

// ------------------------------------------------------------------- golden

/// The scripted session of `rust/tests/golden/ssh-serve/session-1.in.bin`,
/// and the state it runs against: refs `main`, `dev`, `tags/v1` and one
/// 1000-byte pack.
///
/// `session-1.bin` is what `mkit serve`'s `serve_loop` (mkit-cli at the
/// WP-M0-12 base, 0.4.2) answered over a `FileTransport` seeded the same
/// way. It was captured once by a throwaway mkit-cli unit test that built
/// this same input and wrote the loop's output; the input equality check
/// below pins that this builder still produces the captured script.
struct Golden {
    seeded: Vec<u8>,
    refs: [(&'static str, Hash); 3],
    input: Vec<u8>,
}

#[allow(clippy::too_many_lines)]
fn golden() -> Golden {
    let seeded = pack_bytes(1000, 7);
    let seeded_id = hash(&seeded);
    let fresh = pack_bytes(3000, 9);
    let fresh_id = hash(&fresh);
    let empty_id = hash(b"");
    let bogus = pack_bytes(40, 1);
    let bodies = vec![
        hello(),
        list_refs(Some("refs/heads/")),
        list_refs(None),
        list_refs(Some("/bad")),
        read_ref("refs/heads/main"),
        read_ref("refs/heads/absent"),
        read_ref("refs/heads/.hidden"),
        exists(&seeded_id),
        exists(&[0x99; 32]),
        exists(&[0x99; 16]),
        update(
            "refs/heads/main",
            &[0x44; 32],
            Some(RefExpectation::Match),
            Some(&[0x11; 32]),
        ),
        update(
            "refs/heads/main",
            &[0x55; 32],
            Some(RefExpectation::Match),
            Some(&[0x11; 32]),
        ),
        update(
            "refs/heads/ghost",
            &[0x55; 32],
            Some(RefExpectation::Match),
            Some(&[0x66; 32]),
        ),
        update(
            "refs/heads/dev",
            &[0x55; 32],
            Some(RefExpectation::Missing),
            None,
        ),
        update(
            "refs/heads/main",
            &[0x55; 5],
            Some(RefExpectation::Any),
            None,
        ),
        update("refs/heads/main", &[0x55; 32], None, None),
        update(
            "refs/heads/main",
            &[0x55; 32],
            Some(RefExpectation::Match),
            None,
        ),
        update(
            "refs/heads/any",
            &[0x77; 32],
            Some(RefExpectation::Any),
            Some(&[0x01; 32]),
        ),
        update(
            "refs/heads/.hidden",
            &[0x77; 32],
            Some(RefExpectation::Any),
            None,
        ),
        download(Some(&seeded_id)),
        download(Some(&[0x99; 32])),
        download(None),
        // A valid two-chunk upload.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        chunk(&fresh_id, Some(0), &fresh[..1200], false),
        chunk(&fresh_id, Some(1200), &fresh[1200..], true),
        // The empty pack: one empty `last` chunk each way.
        upload_header(&empty_id, Some(0)),
        chunk(&empty_id, Some(0), &[], true),
        download(Some(&empty_id)),
        // Header errors: nothing is read after them.
        upload_header(&fresh_id, None),
        upload_header(&[0x01; 7], Some(3)),
        // Bytes that do not hash to the declared id.
        upload_header(&[0x77; 32], Some(bogus.len() as u64)),
        chunk(&[0x77; 32], Some(0), &bogus, true),
        // An offset gap.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        chunk(&fresh_id, Some(5), &fresh, true),
        // A non-chunk frame inside an upload is consumed by the upload.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        read_ref("refs/heads/main"),
        // Stray and misplaced frames.
        chunk(&fresh_id, Some(0), &fresh[..10], false),
        hello(),
        None,
        Some(Body::HelloResponse(Box::default())),
        list_refs(Some("refs/")),
        exists(&fresh_id),
        download(Some(&fresh_id)),
        close(),
        // Never read: the session ended at Close.
        read_ref("refs/heads/main"),
    ];
    let mut input = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut input, &frame(body)).unwrap();
    }
    Golden {
        seeded,
        refs: [
            ("refs/heads/main", [0x11; 32]),
            ("refs/heads/dev", [0x22; 32]),
            ("refs/tags/v1", [0x33; 32]),
        ],
        input,
    }
}

const GOLDEN_IN: &[u8] = include_bytes!("../../../../tests/golden/ssh-serve/session-1.in.bin");
const GOLDEN_OUT: &[u8] = include_bytes!("../../../../tests/golden/ssh-serve/session-1.bin");

/// Seed `pipe` like the capture, replay the script over the blocking
/// `std::io` adapters and return the bytes written.
fn replay_golden<B: BlobStore, N: NamespaceStore>(pipe: &Pipeline<B, N>) -> Vec<u8> {
    let g = golden();
    assert_eq!(
        g.input, GOLDEN_IN,
        "the builder must produce the captured script"
    );
    seed(pipe, &g.refs, &[&g.seeded]);
    let mut src = ReadFrames(std::io::Cursor::new(g.input));
    let mut sink = WriteFrames(Vec::new());
    let cfg = SessionConfig::new(SERVER_ID);
    let end = block_on(serve_session(pipe, principal(), &mut src, &mut sink, &cfg));
    assert_eq!(end, SessionEnd::Clean, "mkit serve exited OK");
    sink.0
}

/// Frame-by-frame, for a readable failure before the byte comparison.
fn assert_same_frames(got: &[u8], want: &[u8]) {
    let decode = |bytes: &[u8]| {
        let mut r = std::io::Cursor::new(bytes);
        let mut out = Vec::new();
        while r.position() < bytes.len() as u64 {
            out.push(mkit_rpc::read_frame::<_, SshFrame>(&mut r).unwrap());
        }
        out
    };
    let (got, want) = (decode(got), decode(want));
    for (i, (g, w)) in got.iter().zip(&want).enumerate() {
        assert_eq!(g, w, "frame {i}");
    }
    assert_eq!(got.len(), want.len(), "frame count");
}

#[test]
fn golden_session_matches_mkit_serve_over_memory_stores() {
    let (pipe, _) = mem();
    let out = replay_golden(&pipe);
    assert_same_frames(&out, GOLDEN_OUT);
    assert_eq!(out, GOLDEN_OUT);
}

/// The second golden session, `session-2.in.bin`: `ListRefs` prefixes at
/// and off path-component boundaries (SPEC-REFS §4), then a download of a
/// pack over one 800 KiB chunk. The state: refs `main`, `feat/x`, `featx`,
/// `tags/v1`, one pack, and a stray non-ref file `refs/heads/README` that
/// every listing skips (the fs variant writes it; the memory stores cannot
/// hold it, and the answer is the same).
///
/// `session-2.bin` is what the `mkit serve` binary (mkit-cli at the
/// WP-M0-12 base, 0.4.2) answered over a `FileTransport` seeded the same
/// way, captured by a throwaway harness outside the repo.
///
/// One prefix is left out on purpose: a ref's exact name
/// (`refs/heads/main`). `mkit serve` answers it `INTERNAL "list refs
/// failed"`, because its directory walk hits a file; SPEC-REFS §4 says a
/// ref named exactly the prefix is skipped, so the pipeline answers an
/// empty list (`list_refs_prefixes_match_at_component_boundaries`).
struct Golden2 {
    refs: [(&'static str, Hash); 4],
    big: Vec<u8>,
    input: Vec<u8>,
}

fn golden2() -> Golden2 {
    let big = pack_bytes(800 * 1024 + 1000, 5);
    let big_id = hash(&big);
    let prefixes = [
        None,
        Some(""),
        Some("refs/heads"),
        Some("refs/heads/"),
        Some("refs/heads//"),
        Some("refs/heads/feat"),
        Some("refs/heads/feat/"),
        Some("refs/heads/ma"),
        Some("refs"),
        Some("refs/"),
        Some("refs//"),
        Some("refs/tags"),
        Some("nope/"),
    ];
    let mut bodies = vec![hello()];
    bodies.extend(prefixes.map(list_refs));
    bodies.extend([download(Some(&big_id)), exists(&big_id), close()]);
    let mut input = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut input, &frame(body)).unwrap();
    }
    Golden2 {
        refs: [
            ("refs/heads/main", [0x11; 32]),
            ("refs/heads/feat/x", [0x12; 32]),
            ("refs/heads/featx", [0x13; 32]),
            ("refs/tags/v1", [0x33; 32]),
        ],
        big,
        input,
    }
}

const GOLDEN_2_IN: &[u8] = include_bytes!("../../../../tests/golden/ssh-serve/session-2.in.bin");
const GOLDEN_2_OUT: &[u8] = include_bytes!("../../../../tests/golden/ssh-serve/session-2.bin");

/// Replay `session-2` on an already seeded `pipe`.
fn replay_golden_2<B: BlobStore, N: NamespaceStore>(pipe: &Pipeline<B, N>) -> Vec<u8> {
    let input = golden2().input;
    assert_eq!(
        input, GOLDEN_2_IN,
        "the builder must produce the captured script"
    );
    let mut src = ReadFrames(std::io::Cursor::new(input));
    let mut sink = WriteFrames(Vec::new());
    let cfg = SessionConfig::new(SERVER_ID);
    let end = block_on(serve_session(pipe, principal(), &mut src, &mut sink, &cfg));
    assert_eq!(end, SessionEnd::Clean, "mkit serve exited OK");
    sink.0
}

#[test]
fn golden_session_2_matches_mkit_serve_over_memory_stores() {
    let (pipe, _) = mem();
    let g = golden2();
    seed(&pipe, &g.refs, &[&g.big]);
    let out = replay_golden_2(&pipe);
    assert_same_frames(&out, GOLDEN_2_OUT);
    assert_eq!(out, GOLDEN_2_OUT);
}

// --------------------------------------------------------------- fs stores

#[cfg(feature = "fs")]
mod fs {
    use std::path::{Path, PathBuf};

    use mkit_core::protocol::Transport as _;
    use mkit_transport_file::FileTransport;

    use super::*;
    use crate::fs::{FsBlobStore, FsLayoutStore};

    fn fs_pipe(root: &Path) -> Pipeline<FsBlobStore, FsLayoutStore> {
        let clock = Arc::new(ManualClock::new(T0));
        let meta = FsLayoutStore::new(root, &repo()).with_clock(clock);
        pipeline(FsBlobStore::new(root), meta, AuthMode::TransportIdentity)
    }

    fn files(root: &Path) -> Vec<PathBuf> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push(path.strip_prefix(root).unwrap().to_owned());
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn golden_session_matches_mkit_serve_over_fs_stores() {
        let td = tempfile::tempdir().unwrap();
        let pipe = fs_pipe(td.path());
        let out = replay_golden(&pipe);
        assert_same_frames(&out, GOLDEN_OUT);
        assert_eq!(out, GOLDEN_OUT);
        // The files are `FileTransport`'s: the refs the session left.
        let tx = FileTransport::new(td.path());
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some([0x44; 32]));
        assert_eq!(tx.read_ref("refs/heads/any").unwrap(), Some([0x77; 32]));
    }

    #[test]
    fn golden_session_2_matches_mkit_serve_over_fs_stores() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let g = golden2();
        for (name, id) in &g.refs {
            tx.update_ref(name, RefWriteCondition::Any, id).unwrap();
        }
        tx.upload_pack(&g.big, &PackKey::new(hash(&g.big))).unwrap();
        std::fs::write(td.path().join("refs/heads/README"), b"not a ref\n").unwrap();
        let out = replay_golden_2(&fs_pipe(td.path()));
        assert_same_frames(&out, GOLDEN_2_OUT);
        assert_eq!(out, GOLDEN_2_OUT);
    }

    /// A stray non-ref file under `refs/` is skipped by every listing, in
    /// its directory or not, as `mkit serve` skips it; a read of its exact
    /// name is a storage failure (`FsLayoutStore` reads strictly, M0-08),
    /// where `mkit serve` answered it absent.
    #[test]
    fn stray_file_under_refs_is_skipped_by_listings() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        tx.update_ref("refs/heads/main", RefWriteCondition::Any, &[0x11; 32])
            .unwrap();
        std::fs::write(td.path().join("refs/heads/README"), b"not a ref\n").unwrap();
        let pipe = fs_pipe(td.path());
        let (end, frames) = run(
            &pipe,
            [
                list_refs(Some("refs/heads/")),
                list_refs(Some("refs/tags/")),
                list_refs(None),
                read_ref("refs/heads/README"),
                update(
                    "refs/heads/main",
                    &[0x12; 32],
                    Some(RefExpectation::Match),
                    Some(&[0x11; 32]),
                ),
            ],
        );
        assert_eq!(end, SessionEnd::Clean);
        let listed = |f: &SshFrame| match &f.body {
            Some(Body::ListRefsResponse(r)) => r
                .refs
                .iter()
                .map(|e| e.name.clone().unwrap())
                .collect::<Vec<_>>(),
            other => panic!("expected ListRefsResponse, got {other:?}"),
        };
        assert_eq!(listed(&frames[0]), ["main"]);
        assert!(listed(&frames[1]).is_empty());
        assert_eq!(listed(&frames[2]), ["refs/heads/main"]);
        assert_error(&frames[3], ErrorCode::Internal, "read ref failed");
        assert!(matches!(frames[4].body, Some(Body::UpdateRefResponse(_))));
    }

    /// A ref file over the 512-byte limit, written before SPEC-REFS §3
    /// capped names, is skipped by listings (with a warning) and refused
    /// by name on reads and writes; the file itself is left alone.
    #[test]
    fn over_long_legacy_ref_file_is_skipped_and_refused() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let long = format!("refs/heads/{}", vec!["a".repeat(200); 3].join("/"));
        // As a server wrote it before SPEC-REFS §3 bounded names;
        // `FileTransport` now refuses to.
        let path = long
            .split('/')
            .fold(td.path().to_path_buf(), |p, s| p.join(s));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, mkit_core::refs::encode_ref_wire(&[9; 32])).unwrap();
        tx.update_ref("refs/heads/main", RefWriteCondition::Any, &[1; 32])
            .unwrap();
        let pipe = fs_pipe(td.path());
        let (_, frames) = run(
            &pipe,
            [
                list_refs(Some("refs/heads/")),
                read_ref(&long),
                update(&long, &[8; 32], Some(RefExpectation::Match), Some(&[9; 32])),
            ],
        );
        let Some(Body::ListRefsResponse(r)) = &frames[0].body else {
            panic!("expected ListRefsResponse");
        };
        let names: Vec<_> = r.refs.iter().map(|e| e.name.clone().unwrap()).collect();
        assert_eq!(names, ["main"]);
        assert_error(&frames[1], ErrorCode::InvalidRequest, "ref name too long");
        assert_error(&frames[2], ErrorCode::InvalidRequest, "ref name too long");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            mkit_core::refs::encode_ref_wire(&[9; 32])
        );
    }

    /// Ported from `serve_loop_rejects_invalid_upload_before_storage`
    /// (tests.rs:184), over the `.mkit` layout.
    #[test]
    fn serve_loop_rejects_invalid_upload_before_storage() {
        let td = tempfile::tempdir().unwrap();
        let pipe = fs_pipe(td.path());
        let bogus = [0x77; 32];
        let (end, frames) = run(
            &pipe,
            [
                upload_header(&bogus, Some(5)),
                chunk(&bogus, Some(0), b"wrong", true),
            ],
        );
        assert_eq!(end, SessionEnd::Clean);
        assert!(matches!(frames[0].body, Some(Body::Error(_))));
        let tx = FileTransport::new(td.path());
        assert!(!tx.pack_exists(&PackKey::new(bogus)).unwrap());
        assert!(
            files(td.path()).iter().all(|p| !p.starts_with("packs")),
            "no pack or temp file left: {:?}",
            files(td.path())
        );
    }

    /// Ported from
    /// `serve_loop_rejected_upload_does_not_overwrite_existing_pack`
    /// (tests.rs:226), over the `.mkit` layout.
    #[test]
    fn serve_loop_rejected_upload_does_not_overwrite_existing_pack() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let (bytes, id) = valid_pack();
        tx.upload_pack(&bytes, &PackKey::new(id)).unwrap();
        let pipe = fs_pipe(td.path());
        let (end, _) = run(
            &pipe,
            [
                upload_header(&id, Some(5)),
                chunk(&id, Some(0), b"wrong", true),
            ],
        );
        assert_eq!(end, SessionEnd::Clean);
        assert_eq!(tx.download_pack(&PackKey::new(id)).unwrap(), bytes);
    }

    /// Ported from `serve_loop_cas_conflict_carries_current_id_in_details`
    /// (tests.rs:284), over the `.mkit` layout.
    #[test]
    fn serve_loop_cas_conflict_carries_current_id_in_details() {
        let td = tempfile::tempdir().unwrap();
        let pipe = fs_pipe(td.path());
        let (winner, loser) = ([0xA1u8; 32], [0xB2u8; 32]);
        let main = "refs/heads/main";
        let (_, frames) = run(
            &pipe,
            [
                update(main, &winner, Some(RefExpectation::Missing), None),
                update(main, &loser, Some(RefExpectation::Missing), None),
            ],
        );
        let err = error(&frames[1]).clone();
        assert_eq!(err.details.as_deref(), Some(&winner[..]));
        assert!(matches!(
            mkit_rpc::map_update_ref_error(err, RefWriteCondition::Missing, "ssh"),
            mkit_core::protocol::TransportError::RefConflict
        ));
        let tx = FileTransport::new(td.path());
        assert_eq!(tx.read_ref(main).unwrap(), Some(winner));
    }

    /// Ported from `serve_loop_match_conflict_reports_current_value`
    /// (tests.rs:343) and
    /// `serve_loop_match_conflict_on_absent_ref_has_empty_details`
    /// (tests.rs:390), over the `.mkit` layout.
    #[test]
    fn serve_loop_match_conflicts_report_current_value_or_empty() {
        let td = tempfile::tempdir().unwrap();
        let tx = FileTransport::new(td.path());
        let (current, stale, next) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        tx.update_ref("refs/heads/main", RefWriteCondition::Any, &current)
            .unwrap();
        let pipe = fs_pipe(td.path());
        let (_, frames) = run(
            &pipe,
            [
                update(
                    "refs/heads/main",
                    &next,
                    Some(RefExpectation::Match),
                    Some(&stale),
                ),
                update(
                    "refs/heads/ghost",
                    &next,
                    Some(RefExpectation::Match),
                    Some(&stale),
                ),
            ],
        );
        assert_eq!(error(&frames[0]).details.as_deref(), Some(&current[..]));
        assert_eq!(error(&frames[1]).details.as_deref(), Some(&[][..]));
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(current));
        assert_eq!(tx.read_ref("refs/heads/ghost").unwrap(), None);
    }

    /// Only `packs/` and `refs/` files: no replay or quota rows, no temp
    /// files, after uploads (good and bad) and ref writes.
    #[test]
    fn ssh_session_writes_only_packs_and_refs() {
        let td = tempfile::tempdir().unwrap();
        let pipe = fs_pipe(td.path());
        let (bytes, id) = valid_pack();
        seed(&pipe, &[("refs/heads/main", [1; 32])], &[&bytes]);
        let (_, frames) = run(
            &pipe,
            [
                upload_header(&id, Some(5)),
                chunk(&id, Some(0), b"wrong", true),
                download(Some(&id)),
            ],
        );
        assert_eq!(downloaded(&frames[1..], &id), bytes);
        let hex = mkit_core::hash::to_hex(&id);
        assert_eq!(
            files(td.path()),
            [
                // `FileTransport`'s ref lock.
                PathBuf::from(".mkit/refs/.lock"),
                PathBuf::from("packs").join(hex),
                PathBuf::from("refs/heads/main"),
            ],
        );
    }
}
