//! Pipeline stage 0 as a Connect interceptor.

use core::fmt;
use std::sync::Arc;

use connectrpc::interceptor::{
    NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, Next, RequestContext, async_trait};
use futures::StreamExt as _;

use super::Shared;
use crate::auth_v2;
use crate::error::ServerError;
use crate::op::Procedure;
use crate::pipeline::{HookSet, Pipeline, RequestMeta};
use crate::principal::Principal;
use crate::store::{MultipartBlobStore, NamespaceStore};

/// Runs [`Pipeline::authenticate`] once per call, before any message
/// reaches a handler, and stores the resulting
/// [`crate::pipeline::Authenticated`] (with its test directives under
/// `test-faults`) in the request extensions. A unary call is checked
/// against its exact request bytes; a client stream against its headers
/// only; `DownloadPack`'s single request envelope is buffered, verified
/// over its reconstructed framed body (`0x00‖be32(len)‖message`, R-129)
/// and re-injected.
///
/// Calls outside `mkit.transport.v1.TransportService` (health) pass
/// through unauthenticated. For [`crate::pipeline::AuthMode::TransportIdentity`]
/// an adapter inserts the peer's [`Principal`] into the HTTP request
/// extensions; nothing a client sends can set it.
///
/// It must be the first (outermost) interceptor. An adapter that builds its
/// own chain from [`super::router`] registers it before any other, so no
/// interceptor can rewrite the message before the signature is checked. A
/// rewritten unary payload is verified over its re-encoded bytes, which
/// fails closed.
///
/// A unary body is verified as connectrpc hands it over, after any
/// `Content-Encoding` is undone. The client signs the bytes it sends
/// (SPEC-WRITE-GRANTS §9.2, SPEC-TRANSPORT-CONNECT §7.1), so a compressed
/// signed request does not verify and is rejected `unauthenticated`, as in
/// `vcs-worker`.
pub struct AuthInterceptor<B, N, H> {
    pipe: Shared<Pipeline<B, N, H>>,
}

impl<B, N, H> fmt::Debug for AuthInterceptor<B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInterceptor").finish_non_exhaustive()
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> AuthInterceptor<B, N, H> {
    /// An interceptor authenticating against `pipeline`'s auth mode.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline<B, N, H>>) -> Self {
        Self {
            pipe: Shared::new(pipeline),
        }
    }

    /// A request header as the pipeline sees it. A present-but-undecodable
    /// auth v2 header maps to `"~"`, never `None`: its presence decides
    /// signed-ness, and a value that fails to parse fails verification
    /// instead of silently turning a signed read anonymous.
    fn header(ctx: &RequestContext) -> impl Fn(&str) -> Option<String> + '_ {
        move |name: &str| {
            if name == "x-write-grant" {
                let values: Vec<_> = ctx.headers().get_all(name).iter().collect();
                if values.is_empty() {
                    return None;
                }
                return Some(
                    values
                        .iter()
                        .map(|value| value.to_str().unwrap_or("~"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            ctx.header(name).and_then(|v| {
                if name == "x-mkit-ref" {
                    core::str::from_utf8(v.as_bytes()).ok().map(str::to_owned)
                } else if auth_v2::HEADER_NAMES.contains(&name) {
                    Some(v.to_str().unwrap_or("~").to_owned())
                } else {
                    v.to_str().ok().map(str::to_owned)
                }
            })
        }
    }

    /// Authenticate the call in `ctx` and record the result in its
    /// extensions; a call outside the transport service is left alone.
    fn authenticate(
        &self,
        ctx: &mut RequestContext,
        unary_body: Option<&[u8]>,
    ) -> Result<(), ServerError> {
        let Some(procedure) = ctx.path().and_then(Procedure::from_connect_path) else {
            return Ok(());
        };
        let transport_principal = ctx.extensions().get::<Principal>().cloned();
        let authenticated = {
            let header = Self::header(ctx);
            let meta = RequestMeta {
                procedure,
                header: &header,
                unary_body,
                transport_principal,
            };
            self.pipe.get().authenticate(&meta)?
        };
        ctx.extensions_mut().insert(authenticated);
        Ok(())
    }
}

#[async_trait]
impl<B, N, H> Interceptor for AuthInterceptor<B, N, H>
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    async fn intercept_unary(
        &self,
        mut req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        // The bytes the handler will decode: the received ones unless an
        // earlier interceptor replaced the message (then re-encoded, which
        // fails the body commitment). See the type docs on compression.
        let body = req.payload.encoded()?;
        self.authenticate(&mut req.ctx, Some(&body))?;
        next.run(req).await
    }

    async fn intercept_streaming(
        &self,
        mut req: StreamRequest,
        mut inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        if req.ctx.path().and_then(Procedure::from_connect_path) != Some(Procedure::DownloadPack) {
            self.authenticate(&mut req.ctx, None)?;
            return next.run(req, inbound).await;
        }
        // `DownloadPack` is server-streaming, but its request is one
        // envelope and the `body:` commitment covers its exact wire bytes
        // `0x00‖be32(len)‖message` (R-129). The dispatcher already decoded
        // that envelope, so the frame is rebuilt from the single payload
        // (buffered, bounded) and handed on afterwards.
        let Some(item) = inbound.next().await else {
            // No request envelope: a signed call fails its body check.
            self.authenticate(&mut req.ctx, None)?;
            return next.run(req, inbound).await;
        };
        let payload = item?;
        let bytes = payload.encoded()?;
        if bytes.len() > 1024 {
            return Err(ServerError::invalid_argument("DownloadPack request too large").into());
        }
        // The envelope's compression flag is already consumed; a
        // `connect-content-encoding` (or `grpc-encoding`) header other
        // than `identity` is its proxy. An uncompressed reconstruction
        // can also never match bytes the client compressed before
        // signing, so this fails closed either way.
        let compressed_signed = {
            let header = Self::header(&req.ctx);
            auth_v2::carries_auth_headers(&header)
                && ["connect-content-encoding", "grpc-encoding"]
                    .iter()
                    .any(|name| {
                        req.ctx
                            .header(*name)
                            .is_some_and(|v| !matches!(v.to_str(), Ok("identity")))
                    })
        };
        if compressed_signed {
            return Err(ServerError::unauthenticated("compressed signed request").into());
        }
        let mut frame = Vec::with_capacity(5 + bytes.len());
        frame.push(0);
        frame.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| ServerError::invalid_argument("DownloadPack request too large"))?
                .to_be_bytes(),
        );
        frame.extend_from_slice(&bytes);
        self.authenticate(&mut req.ctx, Some(&frame))?;
        let inbound: PayloadStream =
            Box::pin(futures::stream::once(async move { Ok(payload) }).chain(inbound));
        next.run(req, inbound).await
    }
}
