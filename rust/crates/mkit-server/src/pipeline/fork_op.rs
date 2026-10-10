//! `Pipeline::fork_repo` (SPEC-SERVER §9.9): the request stages of a fork,
//! before and around the durable job in [`crate::fork`].
//!
//! Stage order: shape and signed body, stage-0 replay, source read
//! authorization (every refusal is the uniform `source not found`), the
//! source snapshot, destination write authorization with the source facts
//! (the Authority hook decides the visibility rule), admission, the
//! job-lifetime reservation, then the job. Quota is charged once, atomically
//! with the job row, so an exhausted window refuses the fork before any work.

use mkit_core::hash::hash;

use super::{
    Allowance, Authenticated, HookSet, Pipeline, ResponseMeta, Sharding, admission, check_ref_name,
    internal, meta_error, repo_is_private, stored_mismatch,
};
use crate::budget::SliceBudget;
use crate::error::{Code, ServerError};
use crate::fork::{
    self, ChargeV1, FenceV1, ForkEnv, ForkError, ForkLimits, ForkRequest, ForkResult, JOB_TTL_MS,
    ReplayV1, SLICE_CALLS, SettleV1, StartOutcome,
};
use crate::op::{Commitment, OpKind, Operation};
use crate::pipeline::hooks::{Admission, AdmissionInput, ForkAdmission};
use crate::replay::{ReplayDecision, StoredResult, classify};
use crate::repo::{Addressing, RepoId};
use crate::store::codec::{self, AbortReason, StoredProcedure};
use crate::store::{MultipartBlobStore, NamespaceStore, keys};

/// Unavailable while the job runs; the client retries the same request.
fn in_progress() -> ServerError {
    ServerError::unavailable("fork in progress")
        .with_http_status(503)
        .with_header("Retry-After", "1")
}

fn visibility_of(private: bool) -> mkit_attest::grant::Visibility {
    if private {
        mkit_attest::grant::Visibility::Private
    } else {
        mkit_attest::grant::Visibility::Public
    }
}

/// What the source's coordinator held at the one read of the fork.
struct SourceFacts {
    visibility: Option<mkit_attest::grant::Visibility>,
    revision: u64,
    stored_bytes: u64,
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Fork the published tip of `request.source_ref` of the source into the
    /// authenticated repository, which must not exist yet. The result is the
    /// lineage anchor; while the durable job is still running the answer is
    /// `unavailable` with a `Retry-After` hint and the same request is
    /// retried (a new nonce resumes the same job).
    ///
    /// `a` must come from [`Self::authenticate`] with `Procedure::Fork` and
    /// [`ForkRequest::canonical_body`] as the unary body.
    ///
    /// # Errors
    /// `failed_precondition` when the deployment cannot fork (it needs
    /// multi-repository addressing, leased sharding, indexed mode and auth
    /// v2), `"source tip changed"`, or `"destination not empty"`;
    /// `unauthenticated` when the signed body is not `request`;
    /// `permission_denied` for a grant, an unwritable destination or a denial
    /// by the hooks; `not_found "source not found"` for every other
    /// source-side refusal (an unreadable or absent source, anything not
    /// published, verified, sealed or clear); `resource_exhausted` for an
    /// exhausted quota window or `"fork too large"`; `unavailable` while the
    /// job runs, for lag, or for a failed backend call.
    pub async fn fork_repo(
        &self,
        a: &Authenticated,
        request: ForkRequest,
    ) -> Result<ForkResult, ServerError> {
        self.fork_repo_with_meta(a, request)
            .await
            .map(|(result, _)| result)
    }

    /// [`Self::fork_repo`], also returning the success-only admission
    /// headers (empty unless this very request finished the job).
    ///
    /// # Errors
    /// Those of [`Self::fork_repo`].
    pub async fn fork_repo_with_meta(
        &self,
        a: &Authenticated,
        request: ForkRequest,
    ) -> Result<(ForkResult, ResponseMeta), ServerError> {
        self.observe(a, self.fork_stages(a, request)).await
    }

    fn require_fork_deployment(&self) -> Result<(), ServerError> {
        if matches!(self.cfg.addressing, Addressing::Multi(_))
            && self.cfg.sharding == Sharding::D34
            && self.cfg.indexed.is_some()
        {
            Ok(())
        } else {
            Err(ServerError::failed_precondition(
                "fork is not supported by this deployment",
            ))
        }
    }

    fn fork_env(&self) -> ForkEnv<'_, N> {
        ForkEnv {
            store: &self.meta,
            shards: self.shards.as_ref(),
            clock: self.clock.as_ref(),
            takedown_denial: self.cfg.takedown_denial,
            extract_min_bytes: self.cfg.indexed.map(|indexed| indexed.extract_min_bytes),
            limits: ForkLimits::default(),
        }
    }

    #[allow(clippy::too_many_lines)] // One request lifecycle: the stages share their locals.
    async fn fork_stages(
        &self,
        a: &Authenticated,
        request: ForkRequest,
    ) -> Result<(ForkResult, ResponseMeta), ServerError> {
        self.require_fork_deployment()?;
        if a.write_grant.is_some() {
            return Err(ServerError::permission_denied(
                "a grant never authorizes ForkRepo",
            ));
        }
        let auth = a
            .auth
            .as_ref()
            .ok_or_else(|| ServerError::unauthenticated("fork requires auth v2 authorization"))?;
        if auth.commitment != Commitment::Body(hash(&request.canonical_body())) {
            return Err(ServerError::unauthenticated(
                "request differs from the signed body",
            ));
        }
        let dest = a.repo().repo.clone();
        if request.source == dest {
            return Err(ServerError::invalid_argument(
                "a fork needs a source other than its destination",
            ));
        }
        check_ref_name(&request.source_ref)?;
        if !request.source_ref.starts_with("refs/heads/") {
            return Err(ServerError::invalid_argument("a fork names a branch"));
        }
        let uniform = || ForkError::NotFound.error();
        self.cfg
            .namespace_mode
            .namespace(request.source.namespace.as_str())
            .map_err(|_| uniform())?;
        let p = self.shards.coordinator(&dest.namespace);

        // Stage 0: a finished fork replays its stored result.
        let replay_key = keys::replay(&auth.replay_scope);
        let rows = self
            .meta
            .get_many(&p, &[replay_key, keys::fork_job(&dest.name)])
            .await
            .map_err(meta_error)?;
        let [record, job] = rows.try_into().map_err(|_| internal("fork replay read"))?;
        // A destination the job registered is that job's: the start decides
        // whether this request is the same fork.
        let job = job
            .as_ref()
            .map(fork::decode_job)
            .transpose()
            .map_err(meta_error)?;
        let record = record
            .as_ref()
            .map(codec::decode_replay_record)
            .transpose()
            .map_err(meta_error)?;
        match classify(record.as_ref(), &auth.fingerprint) {
            ReplayDecision::New => {}
            ReplayDecision::Return(StoredResult::Fork) => {
                let result = job
                    .and_then(|job| job.result)
                    .ok_or_else(|| internal("fork replay without a result"))?;
                return Ok((result, ResponseMeta::default()));
            }
            ReplayDecision::Return(other) => return Err(stored_mismatch(&other)),
            ReplayDecision::FingerprintMismatch => {
                return Err(ServerError::invalid_argument(
                    "nonce reused for a different operation",
                ));
            }
            ReplayDecision::Resume | ReplayDecision::RetryLater => {
                return Err(ServerError::aborted_retryable(
                    "operation already in flight; retry",
                ));
            }
        }

        // Source read authorization: the caller must be able to read what it
        // forks, and every refusal looks the same.
        let mut read = Operation::new(
            request.source.clone(),
            a.principal.clone(),
            a.auth.clone(),
            OpKind::ReadRef {
                name: request.source_ref.clone(),
            },
        );
        read.business_now_ms = Some(a.business_now_ms);
        match self.authorize_read_with_meta(&read, &self.meta, None).await {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.code(),
                    Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                ) =>
            {
                return Err(uniform());
            }
            Err(error) => return Err(error),
        }
        let source = self.fork_source_facts(&request.source).await?;

        // Destination write authorization, with the source facts for the hook.
        let mut op = self.identify(
            a,
            OpKind::ForkRepo {
                source: request.source.clone(),
                source_ref: request.source_ref.clone(),
                expected_tip: request.expected_tip,
                source_visibility: source.visibility,
                source_visibility_revision: source.revision,
                dest_visibility: request.dest_visibility,
            },
        )?;
        op.creation = self.creation_facts(&op, None).await?;
        Box::pin(self.ensure_authority_activation(&dest.namespace)).await?;
        let (authz, _) = self.authorize(&op).await?;
        op.authz = authz;
        let env = self.fork_env();
        let spec = request.spec_for(dest.clone());
        if let Some(job) = job {
            // The destination is a job's: the same fork joins it (nothing is
            // admitted, charged or reserved twice), any other is refused.
            if job.binding != fork::binding(&spec) {
                return Err(ForkError::NotEmpty.error());
            }
            let report = fork::step(&env, &dest, &SliceBudget::new(SLICE_CALLS))
                .await
                .map_err(|error| error.error())?;
            return Self::fork_answer(report.job, ResponseMeta::default());
        }
        if !op.creation.repo {
            return Err(ForkError::NotEmpty.error());
        }

        // What admission charges for: the bytes of the pack set the tip pins
        // (exact, and the source is refused here before anything is admitted
        // or reserved), or, when the plan does not fit one slice, the source's
        // counted bytes, an upper bound that can trail by the relay lag.
        let inherited = match fork::plan_bytes(&env, &spec).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => source.stored_bytes,
            Err(error) => return Err(error.error()),
        };

        // Admission, then the reservation that lives as long as the job.
        if !self.hooks.admission().is_default() {
            self.check_outbox_backpressure(&p, None).await?;
        }
        let credentials = admission::validate_credentials(&a.credential_capture)?;
        let mut input = AdmissionInput::new(&op);
        input.credential_headers = &credentials;
        input.declared_bytes = inherited;
        input.new_to_repo_bytes = Some(inherited);
        input.fork = Some(ForkAdmission::new(&request.source, inherited));
        let allowance = self.admit(input).await?;
        let pending = match allowance.reservation.as_deref() {
            Some(rid) => Some(
                self.record_pending_for(a, &p, rid, StoredProcedure::Fork, JOB_TTL_MS)
                    .await?,
            ),
            None => None,
        };
        let settle = SettleV1 {
            rid: pending.as_ref().map(|g| g.rid.clone()).unwrap_or_default(),
            pending: pending
                .as_ref()
                .map(|g| g.value.as_bytes().to_vec())
                .unwrap_or_default(),
            repository: a.repo().identity.clone(),
            replay: Some(ReplayV1 {
                scope: auth.replay_scope,
                fingerprint: auth.fingerprint,
                expires_at_ms: auth.expires_at_ms,
            }),
            charges: allowance.charges.iter().map(ChargeV1::of).collect(),
            // As for an upload, the default admission also counts the fork
            // against the namespace's aggregate cap.
            namespace_cap: (matches!(self.cfg.addressing, Addressing::Multi(_))
                && self.hooks.admission().is_default())
            .then(|| allowance.charges.first().map(ChargeV1::of))
            .flatten(),
            declared_bytes: inherited,
        };
        let fence = FenceV1 {
            authority_generation: op.authz.authority_generation,
            grant_epoch: None,
            create_namespace: op.creation.namespace,
        };
        // The source's facts were read before two hook round trips: a change
        // since refuses the fork, so the hook's decision still stands for the
        // visibility the job starts under.
        let recheck = match self.fork_source_facts(&request.source).await {
            Ok(now) if now.visibility == source.visibility && now.revision == source.revision => {
                Ok(())
            }
            Ok(_) => Err(ServerError::unavailable("source changed; retry")),
            Err(error) => Err(error),
        };
        if let Err(error) = recheck {
            self.abort_fork_reservation(&p, pending.as_ref(), &error)
                .await;
            return Err(error);
        }
        let started = match fork::start_with(&env, &spec, Some(settle), Some(fence)).await {
            Ok(started) => started,
            Err(error) => {
                self.abort_fork_reservation(&p, pending.as_ref(), &error.error())
                    .await;
                return Err(error.error());
            }
        };
        let ours = matches!(started, StartOutcome::Started(_));
        if !ours && let Some(pending) = &pending {
            // The job exists already: this request's reservation and charges
            // were never used.
            self.resolve_pending(&p, pending, AbortReason::ReplayRace, String::new())
                .await;
        }
        let report = fork::step(&env, &dest, &SliceBudget::new(SLICE_CALLS))
            .await
            .map_err(|error| error.error())?;
        let meta = if ours {
            response_meta(allowance)
        } else {
            ResponseMeta::default()
        };
        Self::fork_answer(report.job, meta)
    }

    /// What a request answers about the job it advanced.
    fn fork_answer(
        job: fork::ForkJobV1,
        meta: ResponseMeta,
    ) -> Result<(ForkResult, ResponseMeta), ServerError> {
        match (job.result, job.failure) {
            (Some(result), _) => Ok((result, meta)),
            (None, Some(failure)) => Err(failure.error()),
            (None, None) => Err(in_progress()),
        }
    }

    /// The source's visibility, revision and counted bytes, read together.
    async fn fork_source_facts(&self, source: &RepoId) -> Result<SourceFacts, ServerError> {
        let uniform = || ForkError::NotFound.error();
        let p = self.shards.coordinator(&source.namespace);
        let rows = self
            .meta
            .get_many(
                &p,
                &[
                    keys::repo_record(&source.name),
                    keys::repo_visibility(&source.name),
                    keys::repo_visibility_revision(&source.name),
                    keys::repo_storage(&source.name),
                ],
            )
            .await
            .map_err(meta_error)?;
        let [record, visibility, revision, storage]: [Option<crate::Value>; 4] =
            rows.try_into().map_err(|_| internal("fork source read"))?;
        if record.is_none() {
            return Err(uniform());
        }
        let stored = visibility
            .as_ref()
            .map(codec::decode_repo_visibility)
            .transpose()
            .map_err(meta_error)?;
        Ok(SourceFacts {
            visibility: self.visibility_applies().then(|| {
                visibility_of(repo_is_private(
                    stored.as_ref(),
                    self.cfg.default_repo_visibility,
                ))
            }),
            revision: revision
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0),
            stored_bytes: storage
                .as_ref()
                .map(codec::decode_repo_storage)
                .transpose()
                .map_err(meta_error)?
                .map_or(0, |state| state.stored_bytes),
        })
    }

    /// Release the reservation of a request that did not start a job.
    async fn abort_fork_reservation(
        &self,
        p: &crate::store::Partition,
        pending: Option<&super::reservation::PendingGuard>,
        error: &ServerError,
    ) {
        if let Some(pending) = pending {
            let (reason, detail) = super::reservation::abort_reason(error);
            self.resolve_pending(p, pending, reason, detail).await;
        }
    }
}

fn response_meta(allowance: Allowance) -> ResponseMeta {
    if allowance.response_headers.is_empty() && allowance.external_ref.is_none() {
        return ResponseMeta::default();
    }
    let mut headers = allowance.response_headers;
    if !headers.is_empty() {
        headers.push(("Cache-Control".into(), "private".into()));
    }
    ResponseMeta {
        headers,
        external_ref: allowance.external_ref,
    }
}
