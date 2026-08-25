///Shorthand for `OwnedView<ListRefsRequestView<'static>>`.
pub type OwnedListRefsRequestView = ::buffa::view::OwnedView<
    __buffa::view::ListRefsRequestView<'static>,
>;
///Shorthand for `OwnedView<ListRefsResponseView<'static>>`.
pub type OwnedListRefsResponseView = ::buffa::view::OwnedView<
    __buffa::view::ListRefsResponseView<'static>,
>;
///Shorthand for `OwnedView<ReadRefRequestView<'static>>`.
pub type OwnedReadRefRequestView = ::buffa::view::OwnedView<
    __buffa::view::ReadRefRequestView<'static>,
>;
///Shorthand for `OwnedView<ReadRefResponseView<'static>>`.
pub type OwnedReadRefResponseView = ::buffa::view::OwnedView<
    __buffa::view::ReadRefResponseView<'static>,
>;
///Shorthand for `OwnedView<UpdateRefRequestView<'static>>`.
pub type OwnedUpdateRefRequestView = ::buffa::view::OwnedView<
    __buffa::view::UpdateRefRequestView<'static>,
>;
///Shorthand for `OwnedView<UpdateRefResponseView<'static>>`.
pub type OwnedUpdateRefResponseView = ::buffa::view::OwnedView<
    __buffa::view::UpdateRefResponseView<'static>,
>;
///Shorthand for `OwnedView<AdvanceRefsRequestView<'static>>`.
pub type OwnedAdvanceRefsRequestView = ::buffa::view::OwnedView<
    __buffa::view::AdvanceRefsRequestView<'static>,
>;
///Shorthand for `OwnedView<AdvanceRefsResponseView<'static>>`.
pub type OwnedAdvanceRefsResponseView = ::buffa::view::OwnedView<
    __buffa::view::AdvanceRefsResponseView<'static>,
>;
///Shorthand for `OwnedView<PackExistsRequestView<'static>>`.
pub type OwnedPackExistsRequestView = ::buffa::view::OwnedView<
    __buffa::view::PackExistsRequestView<'static>,
>;
///Shorthand for `OwnedView<PackExistsResponseView<'static>>`.
pub type OwnedPackExistsResponseView = ::buffa::view::OwnedView<
    __buffa::view::PackExistsResponseView<'static>,
>;
///Shorthand for `OwnedView<UploadPackRequestView<'static>>`.
pub type OwnedUploadPackRequestView = ::buffa::view::OwnedView<
    __buffa::view::UploadPackRequestView<'static>,
>;
///Shorthand for `OwnedView<UploadPackResponseView<'static>>`.
pub type OwnedUploadPackResponseView = ::buffa::view::OwnedView<
    __buffa::view::UploadPackResponseView<'static>,
>;
///Shorthand for `OwnedView<DownloadPackRequestView<'static>>`.
pub type OwnedDownloadPackRequestView = ::buffa::view::OwnedView<
    __buffa::view::DownloadPackRequestView<'static>,
>;
///Shorthand for `OwnedView<DownloadPackResponseView<'static>>`.
pub type OwnedDownloadPackResponseView = ::buffa::view::OwnedView<
    __buffa::view::DownloadPackResponseView<'static>,
>;
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
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<ReadRefResponse>
for __buffa::view::ReadRefResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<ReadRefResponse>
for ::buffa::view::OwnedView<__buffa::view::ReadRefResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
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
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<AdvanceRefsResponse>
for __buffa::view::AdvanceRefsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<AdvanceRefsResponse>
for ::buffa::view::OwnedView<__buffa::view::AdvanceRefsResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<PackExistsResponse>
for __buffa::view::PackExistsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<PackExistsResponse>
for ::buffa::view::OwnedView<__buffa::view::PackExistsResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<UploadPackResponse>
for __buffa::view::UploadPackResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<UploadPackResponse>
for ::buffa::view::OwnedView<__buffa::view::UploadPackResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<DownloadPackResponse>
for __buffa::view::DownloadPackResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<DownloadPackResponse>
for ::buffa::view::OwnedView<__buffa::view::DownloadPackResponseView<'static>> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
/// Full service name for this service.
pub const TRANSPORT_SERVICE_SERVICE_NAME: &str = "mkit.transport.v1.TransportService";
/// Static [`Spec`](::connectrpc::Spec) for the `ListRefs` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_LIST_REFS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/ListRefs",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `ReadRef` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_READ_REF_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/ReadRef",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `UpdateRef` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_UPDATE_REF_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/UpdateRef",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `AdvanceRefs` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_ADVANCE_REFS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/AdvanceRefs",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `PackExists` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_PACK_EXISTS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/PackExists",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `UploadPack` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_UPLOAD_PACK_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/UploadPack",
        ::connectrpc::StreamType::ClientStream,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the `DownloadPack` RPC, as seen by the server; the generated client passes it with [`origin`](::connectrpc::Spec::origin) `Client` (compare across sides with [`Spec::same_method`](::connectrpc::Spec::same_method)).
pub const TRANSPORT_SERVICE_DOWNLOAD_PACK_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/mkit.transport.v1.TransportService/DownloadPack",
        ::connectrpc::StreamType::ServerStream,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Server trait for TransportService.
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
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.9.0 and views enabled so the
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
pub trait TransportService: Send + Sync + 'static {
    /// List refs whose full name starts with `prefix`. Returned names have
    /// `prefix` stripped, per SPEC-REFS §4. An empty prefix lists every ref.
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
    /// Read a ref's current value. `exists = false` if absent.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn read_ref<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, ReadRefRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<ReadRefResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// CAS ref write. Connect code `failed_precondition` on a CAS mismatch
    /// (`MISSING` on an existing ref, or `MATCH` on a different current
    /// value); `invalid_argument` on `REF_EXPECTATION_UNSPECIFIED`. See
    /// SPEC-TRANSPORT-CONNECT §3 — the response never carries the current
    /// ref value; a client that needs to disambiguate MUST follow up with
    /// ReadRef.
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
    /// Atomically advance a branch's head ref and packmap ref together,
    /// each under its own CAS precondition. See SPEC-TRANSPORT-CONNECT §4.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn advance_refs<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, AdvanceRefsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<AdvanceRefsResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// HEAD-check a pack by digest.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn pack_exists<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, PackExistsRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<PackExistsResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Client-streaming pack upload. The first message on the stream MUST be
    /// `header`; every subsequent message MUST be `chunk`, in ascending
    /// contiguous `offset` order, ending with a `chunk.last = true` message.
    /// The server MUST reject a stream whose received byte count does not
    /// equal `header.total_bytes` or whose BLAKE3 does not equal
    /// `header.pack_id`, and MUST NOT store partial bytes on rejection. See
    /// SPEC-TRANSPORT-CONNECT §6.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// Each `requests` item is a [`StreamMessage`](::connectrpc::StreamMessage):
    /// it owns its buffer, is `Send + 'static`, and exposes zero-copy
    /// accessor methods (`item.name()`), `.view()`, and
    /// `.to_owned_message()`.
    fn upload_pack<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::InboundStream<UploadPackRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<UploadPackResponse> + Send + use<'a, Self>,
        >,
    > + Send;
    /// Server-streaming pack download. The first message on the stream MUST
    /// be `header`; every subsequent message MUST be `chunk`, ending with a
    /// `chunk.last = true` message. Connect code `not_found` (raised before
    /// any message is sent) if the digest is absent. See
    /// SPEC-TRANSPORT-CONNECT §6.
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call (until the response stream is returned);
    /// message fields are read directly on it (zero-copy). Data the
    /// returned stream needs must be copied out or converted via
    /// `.to_owned_message()`.
    fn download_pack(
        &self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<'_, DownloadPackRequest>,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            ::connectrpc::ServiceStream<
                impl ::connectrpc::Encodable<DownloadPackResponse> + Send + use<Self>,
            >,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait TransportServiceExt: TransportService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: TransportService> TransportServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                TRANSPORT_SERVICE_SERVICE_NAME,
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
            .with_spec(TRANSPORT_SERVICE_LIST_REFS_SPEC)
            .route_view(
                TRANSPORT_SERVICE_SERVICE_NAME,
                "ReadRef",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::ReadRefRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                ReadRefRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.read_ref(ctx, sreq)
                                .await?
                                .encode::<ReadRefResponse>(format)
                        }
                    })
                },
            )
            .with_spec(TRANSPORT_SERVICE_READ_REF_SPEC)
            .route_view(
                TRANSPORT_SERVICE_SERVICE_NAME,
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
            .with_spec(TRANSPORT_SERVICE_UPDATE_REF_SPEC)
            .route_view(
                TRANSPORT_SERVICE_SERVICE_NAME,
                "AdvanceRefs",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::AdvanceRefsRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                AdvanceRefsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.advance_refs(ctx, sreq)
                                .await?
                                .encode::<AdvanceRefsResponse>(format)
                        }
                    })
                },
            )
            .with_spec(TRANSPORT_SERVICE_ADVANCE_REFS_SPEC)
            .route_view(
                TRANSPORT_SERVICE_SERVICE_NAME,
                "PackExists",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::PackExistsRequestView<'static>,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                PackExistsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.pack_exists(ctx, sreq)
                                .await?
                                .encode::<PackExistsResponse>(format)
                        }
                    })
                },
            )
            .with_spec(TRANSPORT_SERVICE_PACK_EXISTS_SPEC)
            .route_view_client_stream(
                TRANSPORT_SERVICE_SERVICE_NAME,
                "UploadPack",
                ::connectrpc::view_client_streaming_handler_fn({
                    let svc = ::std::sync::Arc::clone(&self);
                    move |ctx, req, format| {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let req = ::connectrpc::dispatcher::codegen::into_stream_messages::<
                                UploadPackRequest,
                            >(req);
                            svc.upload_pack(ctx, req)
                                .await?
                                .encode::<UploadPackResponse>(format)
                        }
                    }
                }),
            )
            .with_spec(TRANSPORT_SERVICE_UPLOAD_PACK_SPEC)
            .route_view_server_stream::<
                _,
                _,
                DownloadPackResponse,
            >(
                TRANSPORT_SERVICE_SERVICE_NAME,
                "DownloadPack",
                ::connectrpc::view_streaming_handler_fn({
                    let svc = ::std::sync::Arc::clone(&self);
                    move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            __buffa::view::DownloadPackRequestView<'static>,
                        >|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                DownloadPackRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.download_pack(ctx, sreq).await
                        }
                    }
                }),
            )
            .with_spec(TRANSPORT_SERVICE_DOWNLOAD_PACK_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct TransportServiceRegisterMarker;
impl<S: TransportService> ::connectrpc::ServiceRegister<TransportServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as TransportServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `TransportService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = TransportServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct TransportServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: TransportService> TransportServiceServer<T> {
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
impl<T> Clone for TransportServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: TransportService> ::connectrpc::Dispatcher for TransportServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("mkit.transport.v1.TransportService/")?;
        match method {
            "ListRefs" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(TRANSPORT_SERVICE_LIST_REFS_SPEC),
                )
            }
            "ReadRef" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(TRANSPORT_SERVICE_READ_REF_SPEC),
                )
            }
            "UpdateRef" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(TRANSPORT_SERVICE_UPDATE_REF_SPEC),
                )
            }
            "AdvanceRefs" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(TRANSPORT_SERVICE_ADVANCE_REFS_SPEC),
                )
            }
            "PackExists" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(TRANSPORT_SERVICE_PACK_EXISTS_SPEC),
                )
            }
            "UploadPack" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::client_streaming()
                        .with_spec(TRANSPORT_SERVICE_UPLOAD_PACK_SPEC),
                )
            }
            "DownloadPack" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::server_streaming()
                        .with_spec(TRANSPORT_SERVICE_DOWNLOAD_PACK_SPEC),
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
        let Some(method) = path.strip_prefix("mkit.transport.v1.TransportService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "ListRefs" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ListRefsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ListRefsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ListRefsRequest,
                    >::from_parts(&req, &body);
                    svc.list_refs(ctx, req).await?.encode::<ListRefsResponse>(format)
                })
            }
            "ReadRef" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        ReadRefRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::ReadRefRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        ReadRefRequest,
                    >::from_parts(&req, &body);
                    svc.read_ref(ctx, req).await?.encode::<ReadRefResponse>(format)
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
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        UpdateRefRequest,
                    >::from_parts(&req, &body);
                    svc.update_ref(ctx, req).await?.encode::<UpdateRefResponse>(format)
                })
            }
            "AdvanceRefs" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        AdvanceRefsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::AdvanceRefsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        AdvanceRefsRequest,
                    >::from_parts(&req, &body);
                    svc.advance_refs(ctx, req)
                        .await?
                        .encode::<AdvanceRefsResponse>(format)
                })
            }
            "PackExists" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        PackExistsRequest,
                    >(request.encoded()?, format)?;
                    let req: __buffa::view::PackExistsRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        PackExistsRequest,
                    >::from_parts(&req, &body);
                    svc.pack_exists(ctx, req).await?.encode::<PackExistsResponse>(format)
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
        let Some(method) = path.strip_prefix("mkit.transport.v1.TransportService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "DownloadPack" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        DownloadPackRequest,
                    >(request, format)?;
                    let req: __buffa::view::DownloadPackRequestView<'_> = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        DownloadPackRequest,
                    >::from_parts(&req, &body);
                    let resp = svc.download_pack(ctx, req).await?;
                    Ok(
                        resp
                            .map_body(|s| ::connectrpc::dispatcher::codegen::encode_response_stream::<
                                DownloadPackResponse,
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
        let Some(method) = path.strip_prefix("mkit.transport.v1.TransportService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            "UploadPack" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let req_stream = ::connectrpc::dispatcher::codegen::decode_message_request_stream::<
                        UploadPackRequest,
                    >(requests, format, ctx.decode_options().clone());
                    svc.upload_pack(ctx, req_stream)
                        .await?
                        .encode::<UploadPackResponse>(format)
                })
            }
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
        let Some(method) = path.strip_prefix("mkit.transport.v1.TransportService/") else {
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
/// let client = TransportServiceClient::new(conn, config);
/// let response = client.list_refs(request).await?;
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
/// let client = TransportServiceClient::new(http, config);
/// let response = client.list_refs(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.list_refs(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.list_refs(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct TransportServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> TransportServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
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
    /// Call the ListRefs RPC. Sends a request to /mkit.transport.v1.TransportService/ListRefs.
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
                TRANSPORT_SERVICE_LIST_REFS_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the ReadRef RPC. Sends a request to /mkit.transport.v1.TransportService/ReadRef.
    pub async fn read_ref(
        &self,
        request: ReadRefRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ReadRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.read_ref_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the ReadRef RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn read_ref_with_options(
        &self,
        request: ReadRefRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::ReadRefResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                TRANSPORT_SERVICE_READ_REF_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the UpdateRef RPC. Sends a request to /mkit.transport.v1.TransportService/UpdateRef.
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
                TRANSPORT_SERVICE_UPDATE_REF_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the AdvanceRefs RPC. Sends a request to /mkit.transport.v1.TransportService/AdvanceRefs.
    pub async fn advance_refs(
        &self,
        request: AdvanceRefsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::AdvanceRefsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.advance_refs_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the AdvanceRefs RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn advance_refs_with_options(
        &self,
        request: AdvanceRefsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::AdvanceRefsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                TRANSPORT_SERVICE_ADVANCE_REFS_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the PackExists RPC. Sends a request to /mkit.transport.v1.TransportService/PackExists.
    pub async fn pack_exists(
        &self,
        request: PackExistsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PackExistsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.pack_exists_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the PackExists RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn pack_exists_with_options(
        &self,
        request: PackExistsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::PackExistsResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                TRANSPORT_SERVICE_PACK_EXISTS_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
    /// Call the UploadPack RPC. Sends a request to /mkit.transport.v1.TransportService/UploadPack.
    ///
    /// `requests` is any `Stream<Item = ...> + Send + 'static` of
    /// request messages (the `ClientRequestStream` bound); messages
    /// are sent as the stream yields them. It backs the request
    /// body, so yield owned messages or feed the call from a
    /// channel-backed stream. For a collection that is already in
    /// hand, wrap it with `::connectrpc::stream_iter(...)`.
    ///
    /// Dropping the returned future cancels the call: the request
    /// body is dropped along with it, so messages the stream had
    /// not yet yielded are never delivered. A caller that needs the
    /// request delivered must drive the call to completion rather
    /// than, say, wrapping it in a `timeout`.
    pub async fn upload_pack(
        &self,
        requests: impl ::connectrpc::client::ClientRequestStream<UploadPackRequest>,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::UploadPackResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.upload_pack_with_options(
                requests,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the UploadPack RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    ///
    /// `requests` is any `Stream<Item = ...> + Send + 'static` of
    /// request messages (the `ClientRequestStream` bound); messages
    /// are sent as the stream yields them. It backs the request
    /// body, so yield owned messages or feed the call from a
    /// channel-backed stream. For a collection that is already in
    /// hand, wrap it with `::connectrpc::stream_iter(...)`.
    ///
    /// Dropping the returned future cancels the call: the request
    /// body is dropped along with it, so messages the stream had
    /// not yet yielded are never delivered. A caller that needs the
    /// request delivered must drive the call to completion rather
    /// than, say, wrapping it in a `timeout`.
    pub async fn upload_pack_with_options(
        &self,
        requests: impl ::connectrpc::client::ClientRequestStream<UploadPackRequest>,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<__buffa::view::UploadPackResponseView<'static>>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_client_stream(
                &self.transport,
                &self.config,
                TRANSPORT_SERVICE_UPLOAD_PACK_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                requests,
                options,
            )
            .await
    }
    /// Call the DownloadPack RPC. Sends a request to /mkit.transport.v1.TransportService/DownloadPack.
    pub async fn download_pack(
        &self,
        request: DownloadPackRequest,
    ) -> Result<
        ::connectrpc::client::ServerStream<
            T::ResponseBody,
            __buffa::view::DownloadPackResponseView<'static>,
        >,
        ::connectrpc::ConnectError,
    > {
        self.download_pack_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the DownloadPack RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn download_pack_with_options(
        &self,
        request: DownloadPackRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::ServerStream<
            T::ResponseBody,
            __buffa::view::DownloadPackResponseView<'static>,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_server_stream(
                &self.transport,
                &self.config,
                TRANSPORT_SERVICE_DOWNLOAD_PACK_SPEC
                    .with_origin(::connectrpc::SpecOrigin::Client),
                request,
                options,
            )
            .await
    }
}
