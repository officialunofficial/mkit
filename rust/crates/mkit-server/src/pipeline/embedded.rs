//! Embedded dispatch: one typed in-process entry for a procedure that has no
//! Connect route (today only `Fork`, SPEC-SERVER §9.9).
//!
//! The entry is the whole request lifecycle an embedder would otherwise
//! rebuild from storage internals, in a fixed order:
//!
//! 1. authenticate as the procedure (auth v2 over the exact body bytes). This
//!    reads no storage, so an unauthenticated or mis-signed request is
//!    refused before anything below runs;
//! 2. parse the body;
//! 3. [`EmbeddedGate::deployment`], the embedder's deployment check;
//! 4. ask the pipeline whether the request replays a *completed* procedure
//!    ([`EmbeddedProcedure::completed`]); a storage failure or inconsistent
//!    evidence is an error, never a bypass;
//! 5. [`EmbeddedGate::policy`], skipped only when step 4 proved a completed
//!    replay with consistent evidence;
//! 6. the procedure itself, whose result always comes from the pipeline.
//!
//! An embedder that signs with `mkit-client` can build the request headers
//! for a procedure with no Connect route using `Client::sign_envelope`; this
//! crate does not depend on it.
//!
//! The error is the pipeline's own [`ServerError`], so status, headers
//! (`Retry-After`) and details are those of the transport path.

use super::{Authenticated, HookSet, Pipeline, RequestMeta, ResponseMeta};
use crate::error::ServerError;
use crate::fork::{ForkRequest, ForkResult};
use crate::op::Procedure;
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::{MultipartBlobStore, NamespaceStore};

/// A procedure with an embedded entry. Implemented by a marker type per
/// procedure; see [`Fork`].
pub trait EmbeddedProcedure {
    /// The decoded request.
    type Request: MaybeSend + MaybeSync;
    /// The typed success value.
    type Output;
    /// The procedure the request is authenticated for.
    const PROCEDURE: Procedure;

    /// Decode the exact signed body bytes.
    ///
    /// # Errors
    /// `invalid_argument` for anything but the canonical encoding.
    fn parse(body: &[u8]) -> Result<Self::Request, ServerError>;

    /// Whether `request` replays a completed run of the procedure with
    /// consistent evidence.
    ///
    /// `true` skips the embedder's policy, so an implementation must answer
    /// from verified, fail-closed evidence (an error, never `true`, when the
    /// evidence cannot be read or disagrees).
    fn completed<'a, B, N, H>(
        pipeline: &'a Pipeline<B, N, H>,
        a: &'a Authenticated,
        request: &'a Self::Request,
    ) -> BoxFuture<'a, Result<bool, ServerError>>
    where
        B: MultipartBlobStore,
        N: NamespaceStore,
        H: HookSet;

    /// Run the procedure.
    fn run<'a, B, N, H>(
        pipeline: &'a Pipeline<B, N, H>,
        a: &'a Authenticated,
        request: Self::Request,
    ) -> BoxFuture<'a, Result<(Self::Output, ResponseMeta), ServerError>>
    where
        B: MultipartBlobStore,
        N: NamespaceStore,
        H: HookSet;
}

/// [`EmbeddedProcedure`] for `ForkRepo`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fork;

impl EmbeddedProcedure for Fork {
    type Request = ForkRequest;
    type Output = ForkResult;
    const PROCEDURE: Procedure = Procedure::Fork;

    fn parse(body: &[u8]) -> Result<ForkRequest, ServerError> {
        ForkRequest::parse(body)
    }

    fn completed<'a, B, N, H>(
        pipeline: &'a Pipeline<B, N, H>,
        a: &'a Authenticated,
        request: &'a ForkRequest,
    ) -> BoxFuture<'a, Result<bool, ServerError>>
    where
        B: MultipartBlobStore,
        N: NamespaceStore,
        H: HookSet,
    {
        Box::pin(async move { Ok(pipeline.completed_fork(a, request).await?.is_some()) })
    }

    fn run<'a, B, N, H>(
        pipeline: &'a Pipeline<B, N, H>,
        a: &'a Authenticated,
        request: ForkRequest,
    ) -> BoxFuture<'a, Result<(ForkResult, ResponseMeta), ServerError>>
    where
        B: MultipartBlobStore,
        N: NamespaceStore,
        H: HookSet,
    {
        Box::pin(pipeline.fork_repo_with_meta(a, request))
    }
}

/// The embedder's two checks around an embedded dispatch. Both default to
/// allowing.
pub trait EmbeddedGate<R>: MaybeSend + MaybeSync {
    /// The deployment check, run after authentication and before any
    /// pipeline storage read (for example a stored-layout compatibility
    /// guard). An error refuses the request.
    fn deployment(&self) -> BoxFuture<'_, Result<(), ServerError>> {
        Box::pin(async { Ok(()) })
    }

    /// The pre-dispatch policy, run after authentication and before the
    /// procedure. It is skipped only for a request the pipeline proved to
    /// replay a completed run with consistent evidence. An error refuses the
    /// request and is returned unchanged.
    fn policy<'a>(
        &'a self,
        _a: &'a Authenticated,
        _request: &'a R,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        Box::pin(async { Ok(()) })
    }
}

/// A gate that allows everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGate;

impl<R> EmbeddedGate<R> for NoGate {}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Dispatch procedure `P` for an embedder, in the order of the module
    /// docs. `header` looks a request header up by its lowercase name;
    /// `body` is the exact canonical body the request signed.
    ///
    /// # Errors
    /// `unauthenticated` for missing or invalid credentials,
    /// `invalid_argument` for a body that is not canonical, whatever the
    /// gate refuses, `unavailable` when completed-replay evidence cannot be
    /// read or is inconsistent, and the procedure's own errors.
    pub async fn dispatch_embedded<P, G>(
        &self,
        header: &dyn Fn(&str) -> Option<String>,
        body: &[u8],
        gate: &G,
    ) -> Result<(P::Output, ResponseMeta), ServerError>
    where
        P: EmbeddedProcedure,
        G: EmbeddedGate<P::Request>,
    {
        let a = self.authenticate(&RequestMeta {
            procedure: P::PROCEDURE,
            header,
            header_values: None,
            unary_body: Some(body),
            transport_principal: None,
        })?;
        let request = P::parse(body)?;
        gate.deployment().await?;
        if !P::completed(self, &a, &request).await? {
            gate.policy(&a, &request).await?;
        }
        P::run(self, &a, request).await
    }

    /// [`Self::dispatch_embedded`] for `ForkRepo`: the typed result and the
    /// success-only admission headers.
    ///
    /// # Errors
    /// Those of [`Self::dispatch_embedded`] and [`Self::fork_repo`].
    pub async fn dispatch_fork<G: EmbeddedGate<ForkRequest>>(
        &self,
        header: &dyn Fn(&str) -> Option<String>,
        body: &[u8],
        gate: &G,
    ) -> Result<(ForkResult, ResponseMeta), ServerError> {
        self.dispatch_embedded::<Fork, G>(header, body, gate).await
    }
}
