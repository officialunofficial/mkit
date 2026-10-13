//! Embedded dispatch on a Worker: a typed in-process entry for a procedure
//! with no Connect route (today `Fork`, SPEC-SERVER §9.9), so an embedder
//! neither re-implements the Worker's deployment guards nor reads the
//! coordinator's storage to recognise a completed replay.
//!
//! [`EmbeddedDispatch`] runs, in order: authentication (no storage read), the
//! same [`DeploymentGuard`] the fetch path runs followed by the embedder's own
//! deployment check, the pipeline's own completed replay check, the
//! embedder's optional pre-dispatch policy (skipped only for a completed
//! replay with consistent evidence) and the procedure. See
//! [`mkit_server::pipeline::EmbeddedGate`] for the contract of the two
//! embedder checks and `Pipeline::dispatch_embedded` for the order.
//!
//! A refusal is the pipeline's [`ServerError`]: the same code, status,
//! `Retry-After` header and admission details as the transport path. A guard
//! refusal is `unavailable` with the guard's public text, as on fetch.

use mkit_server::fork::{ForkRequest, ForkResult};
use mkit_server::pipeline::{
    EmbeddedFork, EmbeddedGate, EmbeddedProcedure, HookSet, Pipeline, ResponseMeta,
};
use mkit_server::{BoxFuture, MultipartBlobStore, NamespaceStore, ServerError};

use crate::sharding_guard::DeploymentGuard;

/// A pipeline with the store its deployment guard reads. Build it from the
/// embedder's own pipeline and the namespace store that pipeline runs on.
pub struct EmbeddedDispatch<B, N, H> {
    pipeline: Pipeline<B, N, H>,
    store: N,
    guard: DeploymentGuard,
}

impl<B, N, H> core::fmt::Debug for EmbeddedDispatch<B, N, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmbeddedDispatch")
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

/// The deployment guard followed by the embedder's own gate.
struct WorkerGate<'a, S, G> {
    guard: &'a DeploymentGuard,
    store: &'a S,
    inner: &'a G,
}

impl<R, S, G> EmbeddedGate<R> for WorkerGate<'_, S, G>
where
    R: mkit_server::MaybeSend + mkit_server::MaybeSync,
    S: NamespaceStore,
    G: EmbeddedGate<R>,
{
    fn deployment(&self) -> BoxFuture<'_, Result<(), ServerError>> {
        Box::pin(async move {
            self.guard
                .check(self.store)
                .await
                .map_err(|error| ServerError::unavailable(error.public_message()))?;
            self.inner.deployment().await
        })
    }

    fn policy<'a>(
        &'a self,
        a: &'a mkit_server::pipeline::Authenticated,
        request: &'a R,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        self.inner.policy(a, request)
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> EmbeddedDispatch<B, N, H> {
    /// `store` must be the namespace store `pipeline` runs on (or a handle to
    /// the same deployment), `guard` the deployment's [`DeploymentGuard`].
    #[must_use]
    pub fn new(pipeline: Pipeline<B, N, H>, store: N, guard: DeploymentGuard) -> Self {
        Self {
            pipeline,
            store,
            guard,
        }
    }

    /// The wrapped pipeline, for the calls that need no guard.
    #[must_use]
    pub fn pipeline(&self) -> &Pipeline<B, N, H> {
        &self.pipeline
    }

    /// Dispatch procedure `P`. `header` looks a request header up by its
    /// lowercase name; `body` is the exact canonical body that was signed;
    /// `gate` carries the embedder's pre-dispatch policy.
    ///
    /// # Errors
    /// Those of `Pipeline::dispatch_embedded`, plus `unavailable` with the
    /// guard's public text when the stored layout is incompatible.
    pub async fn dispatch<P, G>(
        &self,
        header: &dyn Fn(&str) -> Option<String>,
        body: &[u8],
        gate: &G,
    ) -> Result<(P::Output, ResponseMeta), ServerError>
    where
        P: EmbeddedProcedure,
        G: EmbeddedGate<P::Request>,
    {
        let gate = WorkerGate {
            guard: &self.guard,
            store: &self.store,
            inner: gate,
        };
        self.pipeline
            .dispatch_embedded::<P, _>(header, body, &gate)
            .await
    }

    /// [`Self::dispatch`] for `ForkRepo`.
    ///
    /// # Errors
    /// Those of [`Self::dispatch`] and `Pipeline::fork_repo`.
    pub async fn dispatch_fork<G: EmbeddedGate<ForkRequest>>(
        &self,
        header: &dyn Fn(&str) -> Option<String>,
        body: &[u8],
        gate: &G,
    ) -> Result<(ForkResult, ResponseMeta), ServerError> {
        self.dispatch::<EmbeddedFork, G>(header, body, gate).await
    }
}
