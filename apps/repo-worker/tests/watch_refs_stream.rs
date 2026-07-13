// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Host-side integration test for issue #705: drives `WatchRefs` through the
// REAL `connectrpc` `Router` + `ConnectRpcService` dispatch — the exact
// machinery `apps/repo-worker/src/worker_impl.rs::serve_connect` uses in
// production (minus the wasm/worker-specific `Request`/`Response` adapter,
// which needs the wasm32 target) — over a genuine Connect-streaming HTTP
// request/response, asserting all four `RoomEvent` kinds (commit/chat/
// reaction/presence) arrive on the wire as the new proto `oneof`, not the
// old ad hoc `WatchFrame` JSON dialect.
//
// This is deliberately host-only (no wasm32 target, no Durable Object, no
// Worker runtime): the DO <-> Connect-stream bridge itself
// (`service.rs::bridge_watch_socket`/`open_watch_socket`) is wasm32-only and
// is instead verified against a real `wrangler dev` instance — see
// apps/repo-worker/README.md "WatchRefs / streaming" for that writeup. What
// THIS test proves is the piece the README's investigation showed was the
// actual gap in earlier attempts: that a `RoomEvent` produced by a
// `ServiceStream` handler really does reach a Connect client over the wire,
// framed as the Connect streaming envelope, decodable as the schema — for
// every event kind, not just commit.

use bytes::Bytes;
use connectrpc::{
    ConnectError, ConnectRpcService, RequestContext, Response as ConnectResponse, Router,
    ServiceRequest, ServiceResult, ServiceStream,
};
use http_body_util::{BodyExt, Full};
use mkit_repo_worker::proto::mkit::repo::v1::{
    GetObjectRequest, GetObjectResponse, GetRefRequest, GetRefResponse, ListCommitsRequest,
    ListCommitsResponse, ListMessagesRequest, ListMessagesResponse, ListReactionsRequest,
    ListReactionsResponse, ListRefsRequest, ListRefsResponse, PostMessageRequest,
    PostMessageResponse, PurgeRoomRequest, PurgeRoomResponse, PutObjectRequest, PutObjectResponse,
    ReactRequest, ReactResponse, RepoService, RepoServiceExt, RoomEvent, UpdateRefRequest,
    UpdateRefResponse, WatchRefsRequest,
};
use mkit_repo_worker::room_event;
use std::sync::Arc;
use tower::ServiceExt;

/// A minimal `RepoService` test double: every RPC except `watch_refs` is
/// unreachable in this test and returns `unimplemented`. `watch_refs`
/// produces one event of EACH kind — commit, chat, reaction, presence —
/// built through the SAME `room_event::*_event` constructors the real DO
/// (`worker_impl/refstore.rs`) uses, so this test exercises the identical
/// encode path production code takes, just without the DO/WebSocket hop.
struct FakeRepoService;

fn unimplemented<T>() -> ServiceResult<T> {
    Err(ConnectError::unimplemented("not exercised by this test"))
}

// connectrpc 0.8's generated trait methods return `impl Encodable<Resp> +
// Send + use<'a, Self>`; these handlers return the concrete owned response
// types (or `ConnectError::unimplemented`), the same harmless refinement
// `worker_impl/service.rs`'s real impl uses.
#[allow(refining_impl_trait)]
impl RepoService for FakeRepoService {
    async fn put_object(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PutObjectRequest>,
    ) -> ServiceResult<PutObjectResponse> {
        unimplemented()
    }
    async fn get_object(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetObjectRequest>,
    ) -> ServiceResult<GetObjectResponse> {
        unimplemented()
    }
    async fn get_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetRefRequest>,
    ) -> ServiceResult<GetRefResponse> {
        unimplemented()
    }
    async fn update_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, UpdateRefRequest>,
    ) -> ServiceResult<UpdateRefResponse> {
        unimplemented()
    }
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        unimplemented()
    }
    async fn watch_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRefsRequest>,
    ) -> ServiceResult<ServiceStream<RoomEvent>> {
        let events: Vec<Result<RoomEvent, ConnectError>> = vec![
            Ok(room_event::commit_event(
                "refs/heads/main".to_owned(),
                &hex::encode([0xab; 32]),
                Some(&hex::encode([0x11; 32])),
            )),
            Ok(room_event::chat_event(
                &hex::encode([0xcc; 32]),
                &hex::encode([0x22; 32]),
                "hi room".to_owned(),
                1_700_000_000_000,
                7,
            )),
            Ok(room_event::reaction_event(
                hex::encode([0xab; 32]),
                "\u{1f44d}".to_owned(),
                &hex::encode([0x33; 32]),
                true,
                3,
            )),
            Ok(room_event::presence_event(
                vec![(hex::encode([0x44; 32]), 100)],
                2,
            )),
        ];
        ConnectResponse::stream_ok(futures_util::stream::iter(events))
    }
    async fn post_message(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PostMessageRequest>,
    ) -> ServiceResult<PostMessageResponse> {
        unimplemented()
    }
    async fn list_messages(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListMessagesRequest>,
    ) -> ServiceResult<ListMessagesResponse> {
        unimplemented()
    }
    async fn react(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ReactRequest>,
    ) -> ServiceResult<ReactResponse> {
        unimplemented()
    }
    async fn list_reactions(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListReactionsRequest>,
    ) -> ServiceResult<ListReactionsResponse> {
        unimplemented()
    }
    async fn list_commits(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListCommitsRequest>,
    ) -> ServiceResult<ListCommitsResponse> {
        unimplemented()
    }
    async fn purge_room(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PurgeRoomRequest>,
    ) -> ServiceResult<PurgeRoomResponse> {
        unimplemented()
    }
}

/// Frame one Connect-streaming JSON envelope: `[flags: u8][len: u32 BE][JSON body]`.
fn envelope(json: &str) -> Vec<u8> {
    let body = json.as_bytes();
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(0u8); // uncompressed data frame
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Parse every Connect envelope frame out of a raw streaming response body,
/// returning only DATA frames (skips the trailing `END_STREAM` frame, flag
/// `0x02`, which carries JSON trailers/status, not a message) as parsed JSON.
fn decode_data_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
    const END_STREAM: u8 = 0x02;
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        let flags = bytes[i];
        let len = u32::from_be_bytes(bytes[i + 1..i + 5].try_into().unwrap()) as usize;
        let start = i + 5;
        let end = start + len;
        assert!(end <= bytes.len(), "truncated envelope frame");
        if flags & END_STREAM == 0 {
            let v: serde_json::Value =
                serde_json::from_slice(&bytes[start..end]).expect("data frame is valid JSON");
            frames.push(v);
        }
        i = end;
    }
    frames
}

#[tokio::test]
async fn watch_refs_streams_all_four_room_event_kinds_over_connect() {
    let router: Router = Arc::new(FakeRepoService).register(Router::new());
    let svc = ConnectRpcService::new(router);

    let body = envelope(r#"{"room":"demo705"}"#);
    let http_req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/mkit.repo.v1.RepoService/WatchRefs")
        .header("content-type", "application/connect+json")
        .header("connect-protocol-version", "1")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let http_resp = svc
        .oneshot(http_req)
        .await
        .expect("ConnectRpcService error is Infallible");
    assert_eq!(http_resp.status(), http::StatusCode::OK);

    let body_bytes = http_resp
        .into_body()
        .collect()
        .await
        .expect("collect streaming body")
        .to_bytes();
    let frames = decode_data_frames(&body_bytes);

    assert_eq!(
        frames.len(),
        4,
        "expected exactly 4 RoomEvent data frames, got: {frames:#?}"
    );

    // Each frame is a single-key oneof object per proto3 JSON's oneof
    // mapping (`{"commit": {...}}`, NOT the old flat `{"kind":"commit",...}`
    // WatchFrame shape) — this is the actual schema-drift regression this
    // test exists to catch.
    let kinds: Vec<&str> = frames
        .iter()
        .map(|f| {
            f.as_object()
                .expect("frame is a JSON object")
                .keys()
                .next()
                .expect("oneof frame has exactly one top-level key")
                .as_str()
        })
        .collect();
    assert_eq!(kinds, vec!["commit", "chat", "reaction", "presence"]);

    // Spot-check one field per variant to confirm the payload isn't just a
    // same-shaped decoy — real fields at the expected (camelCase, proto3-
    // JSON) paths.
    assert_eq!(frames[0]["commit"]["name"], "refs/heads/main");
    assert_eq!(frames[1]["chat"]["text"], "hi room");
    assert_eq!(frames[2]["reaction"]["active"], true);
    assert_eq!(frames[3]["presence"]["viewers"], 2);
}
