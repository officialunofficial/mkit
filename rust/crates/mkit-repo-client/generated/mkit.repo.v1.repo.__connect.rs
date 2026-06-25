///Shorthand for `OwnedView<PutObjectRequestView<'static>>`.
pub type OwnedPutObjectRequestView = ::buffa::view::OwnedView<
    __buffa::view::PutObjectRequestView<'static>,
>;
///Shorthand for `OwnedView<PutObjectResponseView<'static>>`.
pub type OwnedPutObjectResponseView = ::buffa::view::OwnedView<
    __buffa::view::PutObjectResponseView<'static>,
>;
///Shorthand for `OwnedView<GetObjectRequestView<'static>>`.
pub type OwnedGetObjectRequestView = ::buffa::view::OwnedView<
    __buffa::view::GetObjectRequestView<'static>,
>;
///Shorthand for `OwnedView<GetObjectResponseView<'static>>`.
pub type OwnedGetObjectResponseView = ::buffa::view::OwnedView<
    __buffa::view::GetObjectResponseView<'static>,
>;
///Shorthand for `OwnedView<GetRefRequestView<'static>>`.
pub type OwnedGetRefRequestView = ::buffa::view::OwnedView<
    __buffa::view::GetRefRequestView<'static>,
>;
///Shorthand for `OwnedView<GetRefResponseView<'static>>`.
pub type OwnedGetRefResponseView = ::buffa::view::OwnedView<
    __buffa::view::GetRefResponseView<'static>,
>;
///Shorthand for `OwnedView<UpdateRefRequestView<'static>>`.
pub type OwnedUpdateRefRequestView = ::buffa::view::OwnedView<
    __buffa::view::UpdateRefRequestView<'static>,
>;
///Shorthand for `OwnedView<UpdateRefResponseView<'static>>`.
pub type OwnedUpdateRefResponseView = ::buffa::view::OwnedView<
    __buffa::view::UpdateRefResponseView<'static>,
>;
///Shorthand for `OwnedView<ListRefsRequestView<'static>>`.
pub type OwnedListRefsRequestView = ::buffa::view::OwnedView<
    __buffa::view::ListRefsRequestView<'static>,
>;
///Shorthand for `OwnedView<ListRefsResponseView<'static>>`.
pub type OwnedListRefsResponseView = ::buffa::view::OwnedView<
    __buffa::view::ListRefsResponseView<'static>,
>;
///Shorthand for `OwnedView<WatchRefsRequestView<'static>>`.
pub type OwnedWatchRefsRequestView = ::buffa::view::OwnedView<
    __buffa::view::WatchRefsRequestView<'static>,
>;
///Shorthand for `OwnedView<RefEventView<'static>>`.
pub type OwnedRefEventView = ::buffa::view::OwnedView<
    __buffa::view::RefEventView<'static>,
>;
///Shorthand for `OwnedView<PostMessageRequestView<'static>>`.
pub type OwnedPostMessageRequestView = ::buffa::view::OwnedView<
    __buffa::view::PostMessageRequestView<'static>,
>;
///Shorthand for `OwnedView<PostMessageResponseView<'static>>`.
pub type OwnedPostMessageResponseView = ::buffa::view::OwnedView<
    __buffa::view::PostMessageResponseView<'static>,
>;
///Shorthand for `OwnedView<ListMessagesRequestView<'static>>`.
pub type OwnedListMessagesRequestView = ::buffa::view::OwnedView<
    __buffa::view::ListMessagesRequestView<'static>,
>;
///Shorthand for `OwnedView<ListMessagesResponseView<'static>>`.
pub type OwnedListMessagesResponseView = ::buffa::view::OwnedView<
    __buffa::view::ListMessagesResponseView<'static>,
>;
///Shorthand for `OwnedView<ReactRequestView<'static>>`.
pub type OwnedReactRequestView = ::buffa::view::OwnedView<
    __buffa::view::ReactRequestView<'static>,
>;
///Shorthand for `OwnedView<ReactResponseView<'static>>`.
pub type OwnedReactResponseView = ::buffa::view::OwnedView<
    __buffa::view::ReactResponseView<'static>,
>;
///Shorthand for `OwnedView<ListReactionsRequestView<'static>>`.
pub type OwnedListReactionsRequestView = ::buffa::view::OwnedView<
    __buffa::view::ListReactionsRequestView<'static>,
>;
///Shorthand for `OwnedView<ListReactionsResponseView<'static>>`.
pub type OwnedListReactionsResponseView = ::buffa::view::OwnedView<
    __buffa::view::ListReactionsResponseView<'static>,
>;
impl ::connectrpc::Encodable<PutObjectResponse>
for __buffa::view::PutObjectResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<PutObjectResponse>
for ::buffa::view::OwnedView<__buffa::view::PutObjectResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<GetObjectResponse>
for __buffa::view::GetObjectResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<GetObjectResponse>
for ::buffa::view::OwnedView<__buffa::view::GetObjectResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<GetRefResponse> for __buffa::view::GetRefResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<GetRefResponse>
for ::buffa::view::OwnedView<__buffa::view::GetRefResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<UpdateRefResponse>
for __buffa::view::UpdateRefResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<UpdateRefResponse>
for ::buffa::view::OwnedView<__buffa::view::UpdateRefResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ListRefsResponse>
for __buffa::view::ListRefsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ListRefsResponse>
for ::buffa::view::OwnedView<__buffa::view::ListRefsResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<RefEvent> for __buffa::view::RefEventView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<RefEvent>
for ::buffa::view::OwnedView<__buffa::view::RefEventView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<PostMessageResponse>
for __buffa::view::PostMessageResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<PostMessageResponse>
for ::buffa::view::OwnedView<__buffa::view::PostMessageResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ListMessagesResponse>
for __buffa::view::ListMessagesResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ListMessagesResponse>
for ::buffa::view::OwnedView<__buffa::view::ListMessagesResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ReactResponse> for __buffa::view::ReactResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ReactResponse>
for ::buffa::view::OwnedView<__buffa::view::ReactResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
impl ::connectrpc::Encodable<ListReactionsResponse>
for __buffa::view::ListReactionsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ListReactionsResponse>
for ::buffa::view::OwnedView<__buffa::view::ListReactionsResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
}
/// Full service name for this service.
pub const REPO_SERVICE_SERVICE_NAME: &str = "mkit.repo.v1.RepoService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `PutObject` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_PUT_OBJECT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/PutObject",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `GetObject` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_GET_OBJECT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/GetObject",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `GetRef` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_GET_REF_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/GetRef",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `UpdateRef` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_UPDATE_REF_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/UpdateRef",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ListRefs` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_LIST_REFS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/ListRefs",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `WatchRefs` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_WATCH_REFS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/WatchRefs",
        ::connectrpc::StreamType::ServerStream,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `PostMessage` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_POST_MESSAGE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/PostMessage",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ListMessages` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_LIST_MESSAGES_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/ListMessages",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `React` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_REACT_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/React",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ListReactions` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const REPO_SERVICE_LIST_REACTIONS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.repo.v1.RepoService/ListReactions",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Server trait for RepoService.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// `ServiceStream<`[`StreamMessage<Req>`](::connectrpc::StreamMessage)`>`.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.7.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait RepoService: Send + Sync + 'static {
    /// Handle the PutObject RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn put_object<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, PutObjectRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<PutObjectResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the GetObject RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn get_object<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, GetObjectRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<GetObjectResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the GetRef RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn get_ref<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, GetRefRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<GetRefResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the UpdateRef RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn update_ref<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, UpdateRefRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<UpdateRefResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the ListRefs RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn list_refs<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ListRefsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ListRefsResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the WatchRefs RPC.
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call (until the response stream is returned);
    /// message fields are read directly on it (zero-copy). Data the
    /// returned stream needs must be copied out or converted via
    /// `.to_owned_message()`.
    fn watch_refs(
        &self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, WatchRefsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            ::connectrpc::ServiceStream<
                impl ::connectrpc::Encodable<RefEvent> + Send + use<Self>,
            >,
        >,
    > + Send;
    /// Handle the PostMessage RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn post_message<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, PostMessageRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<PostMessageResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the ListMessages RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn list_messages<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ListMessagesRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ListMessagesResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the React RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn react<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ReactRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ReactResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the ListReactions RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn list_reactions<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ListReactionsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ListReactionsResponse> + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait RepoServiceExt: RepoService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: RepoService> RepoServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "PutObject",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::PutObjectRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                PutObjectRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.put_object(ctx, sreq)
                                .await?
                                .encode::<PutObjectResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_PUT_OBJECT_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "GetObject",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::GetObjectRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                GetObjectRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.get_object(ctx, sreq)
                                .await?
                                .encode::<GetObjectResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_GET_OBJECT_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "GetRef",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::GetRefRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                GetRefRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.get_ref(ctx, sreq)
                                .await?
                                .encode::<GetRefResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_GET_REF_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "UpdateRef",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::UpdateRefRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                UpdateRefRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.update_ref(ctx, sreq)
                                .await?
                                .encode::<UpdateRefResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_UPDATE_REF_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "ListRefs",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ListRefsRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ListRefsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.list_refs(ctx, sreq)
                                .await?
                                .encode::<ListRefsResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_LIST_REFS_SPEC)
            .route_view_server_stream::<
                _,
                _,
                RefEvent,
            >(
                REPO_SERVICE_SERVICE_NAME,
                "WatchRefs",
                ::connectrpc::view_streaming_handler_fn({
                    let svc = ::std::sync::Arc::clone(&self);
                    move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::WatchRefsRequestView<'static>,
                        >|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                WatchRefsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.watch_refs(ctx, sreq).await
                        }
                    }
                }),
            )
            .with_spec(REPO_SERVICE_WATCH_REFS_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "PostMessage",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::PostMessageRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                PostMessageRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.post_message(ctx, sreq)
                                .await?
                                .encode::<PostMessageResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_POST_MESSAGE_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "ListMessages",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ListMessagesRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ListMessagesRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.list_messages(ctx, sreq)
                                .await?
                                .encode::<ListMessagesResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_LIST_MESSAGES_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "React",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ReactRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ReactRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.react(ctx, sreq).await?.encode::<ReactResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_REACT_SPEC)
            .route_view(
                REPO_SERVICE_SERVICE_NAME,
                "ListReactions",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ListReactionsRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ListReactionsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.list_reactions(ctx, sreq)
                                .await?
                                .encode::<ListReactionsResponse>(format)
                        }
                    })
                },
            )
            .with_spec(REPO_SERVICE_LIST_REACTIONS_SPEC)
    }
}
/// Monomorphic dispatcher for `RepoService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = RepoServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct RepoServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: RepoService> RepoServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for RepoServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: RepoService> ::connectrpc::Dispatcher for RepoServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("mkit.repo.v1.RepoService/")?;
        match method {
            "PutObject" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_PUT_OBJECT_SPEC),
                )
            }
            "GetObject" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_GET_OBJECT_SPEC),
                )
            }
            "GetRef" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_GET_REF_SPEC),
                )
            }
            "UpdateRef" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_UPDATE_REF_SPEC),
                )
            }
            "ListRefs" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_LIST_REFS_SPEC),
                )
            }
            "WatchRefs" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::server_streaming()
                        .with_spec(REPO_SERVICE_WATCH_REFS_SPEC),
                )
            }
            "PostMessage" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_POST_MESSAGE_SPEC),
                )
            }
            "ListMessages" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_LIST_MESSAGES_SPEC),
                )
            }
            "React" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_REACT_SPEC),
                )
            }
            "ListReactions" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(REPO_SERVICE_LIST_REACTIONS_SPEC),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("mkit.repo.v1.RepoService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "PutObject" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        PutObjectRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::PutObjectRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        PutObjectRequest,
                    >::from_parts(&req, &body);
                    svc.put_object(ctx, req).await?.encode::<PutObjectResponse>(format)
                })
            }
            "GetObject" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        GetObjectRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::GetObjectRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        GetObjectRequest,
                    >::from_parts(&req, &body);
                    svc.get_object(ctx, req).await?.encode::<GetObjectResponse>(format)
                })
            }
            "GetRef" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        GetRefRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::GetRefRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        GetRefRequest,
                    >::from_parts(&req, &body);
                    svc.get_ref(ctx, req).await?.encode::<GetRefResponse>(format)
                })
            }
            "UpdateRef" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        UpdateRefRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::UpdateRefRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        UpdateRefRequest,
                    >::from_parts(&req, &body);
                    svc.update_ref(ctx, req).await?.encode::<UpdateRefResponse>(format)
                })
            }
            "ListRefs" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ListRefsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ListRefsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ListRefsRequest,
                    >::from_parts(&req, &body);
                    svc.list_refs(ctx, req).await?.encode::<ListRefsResponse>(format)
                })
            }
            "PostMessage" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        PostMessageRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::PostMessageRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        PostMessageRequest,
                    >::from_parts(&req, &body);
                    svc.post_message(ctx, req)
                        .await?
                        .encode::<PostMessageResponse>(format)
                })
            }
            "ListMessages" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ListMessagesRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ListMessagesRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ListMessagesRequest,
                    >::from_parts(&req, &body);
                    svc.list_messages(ctx, req)
                        .await?
                        .encode::<ListMessagesResponse>(format)
                })
            }
            "React" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ReactRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ReactRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ReactRequest,
                    >::from_parts(&req, &body);
                    svc.react(ctx, req).await?.encode::<ReactResponse>(format)
                })
            }
            "ListReactions" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ListReactionsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ListReactionsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ListReactionsRequest,
                    >::from_parts(&req, &body);
                    svc.list_reactions(ctx, req)
                        .await?
                        .encode::<ListReactionsResponse>(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("mkit.repo.v1.RepoService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "WatchRefs" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        WatchRefsRequest,
                    >(request, format)?;
                    let req: __buffa::view::WatchRefsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        WatchRefsRequest,
                    >::from_parts(&req, &body);
                    let resp = svc.watch_refs(ctx, req).await?;
                    Ok(
                        resp
                            .map_body(|s| ::connectrpc::dispatcher::codegen::encode_response_stream::<
                                RefEvent,
                                _,
                                _,
                            >(s, format)),
                    )
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("mkit.repo.v1.RepoService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("mkit.repo.v1.RepoService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = RepoServiceClient::new(conn, config);
/// let response = client.put_object(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = RepoServiceClient::new(http, config);
/// let response = client.put_object(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.put_object(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.put_object(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one `OwnedView` per
/// received message from `.message().await` — bind `msg.reborrow()` for field
/// access, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct RepoServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> RepoServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the PutObject RPC. Sends a request to /mkit.repo.v1.RepoService/PutObject.
    pub async fn put_object(
        &self,
        request: PutObjectRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PutObjectResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.put_object_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the PutObject RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn put_object_with_options(
        &self,
        request: PutObjectRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PutObjectResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "PutObject",
                request,
                options,
            )
            .await
    }
    /// Call the GetObject RPC. Sends a request to /mkit.repo.v1.RepoService/GetObject.
    pub async fn get_object(
        &self,
        request: GetObjectRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::GetObjectResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.get_object_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the GetObject RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn get_object_with_options(
        &self,
        request: GetObjectRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::GetObjectResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "GetObject",
                request,
                options,
            )
            .await
    }
    /// Call the GetRef RPC. Sends a request to /mkit.repo.v1.RepoService/GetRef.
    pub async fn get_ref(
        &self,
        request: GetRefRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::GetRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.get_ref_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the GetRef RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn get_ref_with_options(
        &self,
        request: GetRefRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::GetRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "GetRef",
                request,
                options,
            )
            .await
    }
    /// Call the UpdateRef RPC. Sends a request to /mkit.repo.v1.RepoService/UpdateRef.
    pub async fn update_ref(
        &self,
        request: UpdateRefRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::UpdateRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.update_ref_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the UpdateRef RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn update_ref_with_options(
        &self,
        request: UpdateRefRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::UpdateRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "UpdateRef",
                request,
                options,
            )
            .await
    }
    /// Call the ListRefs RPC. Sends a request to /mkit.repo.v1.RepoService/ListRefs.
    pub async fn list_refs(
        &self,
        request: ListRefsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListRefsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.list_refs_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ListRefs RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn list_refs_with_options(
        &self,
        request: ListRefsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListRefsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "ListRefs",
                request,
                options,
            )
            .await
    }
    /// Call the WatchRefs RPC. Sends a request to /mkit.repo.v1.RepoService/WatchRefs.
    pub async fn watch_refs(
        &self,
        request: WatchRefsRequest,
    ) -> Result<
        ::connectrpc::client::ServerStream<
            T::ResponseBody,
            __buffa::view::RefEventView<'static>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.watch_refs_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the WatchRefs RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn watch_refs_with_options(
        &self,
        request: WatchRefsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::ServerStream<
            T::ResponseBody,
            __buffa::view::RefEventView<'static>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_server_stream(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "WatchRefs",
                request,
                options,
            )
            .await
    }
    /// Call the PostMessage RPC. Sends a request to /mkit.repo.v1.RepoService/PostMessage.
    pub async fn post_message(
        &self,
        request: PostMessageRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PostMessageResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.post_message_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the PostMessage RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn post_message_with_options(
        &self,
        request: PostMessageRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PostMessageResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "PostMessage",
                request,
                options,
            )
            .await
    }
    /// Call the ListMessages RPC. Sends a request to /mkit.repo.v1.RepoService/ListMessages.
    pub async fn list_messages(
        &self,
        request: ListMessagesRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListMessagesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.list_messages_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ListMessages RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn list_messages_with_options(
        &self,
        request: ListMessagesRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListMessagesResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "ListMessages",
                request,
                options,
            )
            .await
    }
    /// Call the React RPC. Sends a request to /mkit.repo.v1.RepoService/React.
    pub async fn react(
        &self,
        request: ReactRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ReactResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.react_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the React RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn react_with_options(
        &self,
        request: ReactRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ReactResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "React",
                request,
                options,
            )
            .await
    }
    /// Call the ListReactions RPC. Sends a request to /mkit.repo.v1.RepoService/ListReactions.
    pub async fn list_reactions(
        &self,
        request: ListReactionsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListReactionsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.list_reactions_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ListReactions RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn list_reactions_with_options(
        &self,
        request: ListReactionsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ListReactionsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                REPO_SERVICE_SERVICE_NAME,
                "ListReactions",
                request,
                options,
            )
            .await
    }
}
