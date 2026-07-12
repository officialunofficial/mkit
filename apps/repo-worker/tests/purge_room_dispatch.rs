// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Host-side integration test for issue #707: drives `PurgeRoom` through the
// REAL `connectrpc` `Router` + `ConnectRpcService` dispatch — the exact
// machinery `apps/repo-worker/src/worker_impl.rs::serve_connect` uses in
// production — over a genuine Connect unary HTTP request/response, the same
// pattern `tests/watch_refs_stream.rs` established for `WatchRefs` (see that
// file's header for why this style of test is host-only and does NOT need
// the wasm32 target, a Durable Object, or R2).
//
// What this test proves: `PurgeRoomRequest`/`PurgeRoomResponse` round-trip
// correctly through the real proto3-JSON Connect wire encoding — the request
// decodes its `room` field, and every response field (`purged`,
// `objects_deleted`, `message_bodies_deleted`, `refs_deleted`,
// `messages_deleted`, `reactions_deleted`) serializes at its documented
// camelCase JSON path. It does NOT (and, on this host target, cannot) prove
// that a real PurgeRoom call actually empties R2 or the RefStore DO's SQLite
// tables, or that the `X-Admin-Token` gate rejects an unauthenticated
// caller — `AuthInterceptor` and the RepoService impl that talks to R2/the
// DO both live in `worker_impl`, which is `#[cfg(target_arch = "wasm32")]`
// only (see `src/lib.rs`'s module doc) and needs a live Workers runtime to
// execute, not just compile. That gap is closed by the wasm32 build (compiles
// the interceptor + handler wiring) plus a manual `wrangler dev --local`
// pass — see README.md "Retention & backup/restore" for the runbook — not by
// a `cargo test` on this host target. This mirrors the exact tradeoff
// `cloudbuild/ci.yaml` documents for the rest of this crate's DO-backed RPCs.

use bytes::Bytes;
use connectrpc::{
    ConnectError, ConnectRpcService, RequestContext, Response as ConnectResponse, Router,
    ServiceRequest, ServiceResult,
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
use std::sync::Arc;
use tower::ServiceExt;

/// A minimal `RepoService` test double: every RPC except `purge_room` is
/// unreachable in this test and returns `unimplemented`. `purge_room` echoes
/// the request's `room` back inside a canned response with distinct, easily
/// asserted counts per field — this test is about the WIRE CONTRACT, not
/// actual deletion (see the file header).
struct FakeRepoService;

fn unimplemented<T>() -> ServiceResult<T> {
    Err(ConnectError::unimplemented("not exercised by this test"))
}

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
    ) -> ServiceResult<connectrpc::ServiceStream<RoomEvent>> {
        Err(ConnectError::unimplemented("not exercised by this test"))
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
        request: ServiceRequest<'_, PurgeRoomRequest>,
    ) -> ServiceResult<PurgeRoomResponse> {
        let room = request.to_owned_message().room.unwrap_or_default();
        assert_eq!(room, "demo707", "PurgeRoomRequest.room decoded off the wire");
        Ok(ConnectResponse::new(PurgeRoomResponse {
            purged: Some(true),
            objects_deleted: Some(3),
            message_bodies_deleted: Some(2),
            refs_deleted: Some(1),
            messages_deleted: Some(2),
            reactions_deleted: Some(5),
            ..Default::default()
        }))
    }
}

#[tokio::test]
async fn purge_room_round_trips_over_connect_unary() {
    let router: Router = Arc::new(FakeRepoService).register(Router::new());
    let svc = ConnectRpcService::new(router);

    let body = serde_json::to_vec(&serde_json::json!({ "room": "demo707" })).unwrap();
    let http_req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/mkit.repo.v1.RepoService/PurgeRoom")
        .header("content-type", "application/json")
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
        .expect("collect response body")
        .to_bytes();
    let resp: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("PurgeRoomResponse is valid JSON");

    // Every field at its documented camelCase proto3-JSON path — the actual
    // regression this test exists to catch (a codegen/wire-format drift on
    // the newly added message, same spirit as watch_refs_stream.rs's
    // "single-key oneof, not a decoy shape" check).
    assert_eq!(resp["purged"], true);
    assert_eq!(resp["objectsDeleted"], 3);
    assert_eq!(resp["messageBodiesDeleted"], 2);
    assert_eq!(resp["refsDeleted"], 1);
    assert_eq!(resp["messagesDeleted"], 2);
    assert_eq!(resp["reactionsDeleted"], 5);
}
