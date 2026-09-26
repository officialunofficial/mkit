//! Pipeline stage 0 as a Connect interceptor.

use core::fmt;
use std::sync::Arc;

use connectrpc::interceptor::{
    NextStream, PayloadStream, StreamRequest, StreamResponse, UnaryRequest, UnaryResponse,
};
use connectrpc::{ConnectError, Interceptor, Next, RequestContext, async_trait};

use super::Shared;
use crate::error::ServerError;
use crate::op::Procedure;
use crate::pipeline::{HookSet, Pipeline, RequestMeta};
use crate::principal::Principal;
use crate::store::{BlobStore, NamespaceStore};

/// Runs [`Pipeline::authenticate`] once per call, before any message
/// reaches a handler, and stores the resulting
/// [`crate::pipeline::Authenticated`] (with its test directives under
/// `test-faults`) in the request extensions. A unary call is checked
/// against its exact request bytes; a stream against its headers only.
///
/// Calls outside `mkit.transport.v1.TransportService` (health) pass
/// through unauthenticated. For [`crate::pipeline::AuthMode::TransportIdentity`]
/// an adapter inserts the peer's [`Principal`] into the HTTP request
/// extensions; nothing a client sends can set it.
pub struct AuthInterceptor<B, N, H> {
    pipe: Shared<Pipeline<B, N, H>>,
}

impl<B, N, H> fmt::Debug for AuthInterceptor<B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInterceptor").finish_non_exhaustive()
    }
}

impl<B: BlobStore, N: NamespaceStore, H: HookSet> AuthInterceptor<B, N, H> {
    /// An interceptor authenticating against `pipeline`'s auth mode.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline<B, N, H>>) -> Self {
        Self {
            pipe: Shared::new(pipeline),
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
        let header = |name: &str| {
            ctx.header(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let meta = RequestMeta {
            procedure,
            header: &header,
            unary_body,
            transport_principal: ctx.extensions().get::<Principal>().cloned(),
        };
        let authenticated = self.pipe.get().authenticate(&meta)?;
        ctx.extensions_mut().insert(authenticated);
        Ok(())
    }
}

#[async_trait]
impl<B, N, H> Interceptor for AuthInterceptor<B, N, H>
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    async fn intercept_unary(
        &self,
        mut req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        // The request bytes as received (after any Content-Encoding is
        // undone), as `vcs-worker` verifies them.
        self.authenticate(&mut req.ctx, Some(req.payload.bytes()))?;
        next.run(req).await
    }

    async fn intercept_streaming(
        &self,
        mut req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.authenticate(&mut req.ctx, None)?;
        next.run(req, inbound).await
    }
}
