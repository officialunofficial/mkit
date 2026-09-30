//! `Pipeline::serve_http_object`: the SPEC-HTTP-OBJECTS §3 precedence over
//! this pipeline's stores. It lives here because it needs the pipeline's
//! private stage functions; everything reusable is in `http_objects`.
//!
//! Stage 2, inert in Stage 1 (R-154, R-169): reachable only when a
//! deployment sets `PipelineConfig::http_objects` programmatically.

use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::ObjectType;

use tracing::Instrument as _;

use super::{
    HookSet, MultipartBlobStore, NamespaceStore, OpKind, Operation, Pipeline, Principal, Procedure,
    ms,
};
use crate::http_objects::range::{self, Selection};
use crate::http_objects::reach::{self, Reach};
use crate::http_objects::resolve::{self, Budget, Env};
use crate::http_objects::seams::{AdmitDecision, AdmitRequest, TakedownVerdict};
use crate::http_objects::{
    Fail, HttpBody, HttpObjectRequest, HttpObjectResponse, HttpSeams, METRIC_HTTP_REACH_CAPPED,
    ParsedUrl, Target, route,
};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::store::read;
use crate::{Code, ServerError};

const ALLOW: &str = "GET, HEAD, OPTIONS";
/// The ref namespace of packmaps: never a published tip.
const PACKMAP_PREFIX: &str = "refs/mkit/packmap/";

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet> Pipeline<B, N, H> {
    /// Whether this pipeline can mount HTTP object routes. Opaque pipelines cannot.
    #[must_use]
    pub fn http_objects_enabled(&self) -> bool {
        self.cfg.indexed.is_some() && self.cfg.http_objects.is_some()
    }

    /// Public-key publication configuration; never exposes seeds.
    #[must_use]
    pub fn url_token_config(&self) -> Option<&crate::url_token::UrlTokenConfig> {
        self.cfg.url_tokens.as_ref()
    }

    /// Replace the inert seams of an HTTP-objects pipeline: admission
    /// (WP-4.13), proofs (WP-4.14b), tokens (WP-4.15), takedown (WP-5.9a) or
    /// a maintained reachable set (WP-5.3a). A pipeline built without
    /// `PipelineConfig::http_objects` is unchanged.
    #[must_use]
    pub fn with_http_seams(mut self, edit: impl FnOnce(HttpSeams) -> HttpSeams) -> Self {
        self.http_seams = self.http_seams.take().map(edit);
        self
    }

    /// Serve one HTTP object request (GET, HEAD or OPTIONS) and never fail:
    /// every error is mapped to its §3 response. The principal is always
    /// `anonymous`, whatever credentials the request carries (§7); the
    /// raw path, query and any token are never logged.
    pub async fn serve_http_object(&self, req: &HttpObjectRequest<'_>) -> HttpObjectResponse {
        self.serve_http_with_runtime(req, None, None).await
    }

    /// Adapter-provided retained settlement runtime for this request.
    pub async fn serve_http_object_with_runtime(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: crate::http_objects::HttpReadRuntime,
    ) -> HttpObjectResponse {
        self.serve_http_with_runtime(req, Some(runtime), None).await
    }

    /// Adapter-provided proof builder and retained settlement runtime.
    pub async fn serve_http_object_with_proofs(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: crate::http_objects::HttpReadRuntime,
        proofs: std::sync::Arc<dyn crate::http_objects::ProofServer>,
    ) -> HttpObjectResponse {
        self.serve_http_with_runtime(req, Some(runtime), Some(proofs))
            .await
    }

    async fn serve_http_with_runtime(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: Option<crate::http_objects::HttpReadRuntime>,
        proofs: Option<std::sync::Arc<dyn crate::http_objects::ProofServer>>,
    ) -> HttpObjectResponse {
        let mut response = self.serve_http_inner(req, runtime, proofs).await;
        if req.method == "HEAD" {
            // Content-Length already describes the GET body.
            response.body = HttpBody::Empty;
        }
        response
    }

    async fn serve_http_inner(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: Option<crate::http_objects::HttpReadRuntime>,
        proofs: Option<std::sync::Arc<dyn crate::http_objects::ProofServer>>,
    ) -> HttpObjectResponse {
        let (Some(_), Some(seams)) = (&self.cfg.http_objects, &self.http_seams) else {
            return HttpObjectResponse::not_found();
        };
        let mut seams = seams.clone();
        if let Some(proofs) = proofs {
            seams.proofs = proofs;
        }
        if let Some(runtime) = runtime {
            seams.read_runtime = Some(runtime);
        }
        match req.method {
            "OPTIONS" => return HttpObjectResponse::new(204).with_header("Allow", ALLOW),
            "GET" | "HEAD" => {}
            _ => return HttpObjectResponse::error(405).with_header("Allow", ALLOW),
        }
        let Ok(parsed) = route::parse_request(req) else {
            return HttpObjectResponse::error(400);
        };
        // Precheck before any repository lookup; public repositories
        // discard both successes and failures without consulting claims.
        let token = parsed
            .query
            .token
            .as_ref()
            .map(|token| seams.tokens.precheck(token, self.clock.now_ms()));
        let Some(repo) = repo_id(&parsed) else {
            return HttpObjectResponse::not_found();
        };
        let ref_path = matches!(parsed.target, Target::Ref { .. });
        let procedure = if ref_path {
            Procedure::HttpGetRefPath
        } else {
            Procedure::HttpGetObject
        };
        let identity = parsed
            .repository
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let mut outcome = self.outcome_for(procedure, "anonymous", &identity);
        let served = async {
            self.serve_repository(req, &seams, &parsed, &repo, token)
                .await
        }
        .instrument(outcome.span.clone())
        .await;
        match served {
            Ok(response) => {
                let code = match response.status {
                    ..400 => None,
                    402 | 403 | 451 => Some(Code::PermissionDenied),
                    416 => Some(Code::OutOfRange),
                    404 => Some(Code::NotFound),
                    _ => Some(Code::Unknown),
                };
                match code {
                    None => outcome.record(Ok(())),
                    Some(code) => outcome.record(Err(&ServerError::new(code, "http"))),
                }
                response
            }
            Err(fail) => {
                outcome.record(Err(&ServerError::new(fail.code(), "http")));
                fail.into_response()
            }
        }
    }

    #[allow(clippy::too_many_lines)] // One function per §3 step group reads best in order.
    async fn serve_repository(
        &self,
        req: &HttpObjectRequest<'_>,
        seams: &HttpSeams,
        parsed: &ParsedUrl,
        repo: &RepoId,
        token: Option<Result<crate::url_token::Prechecked, crate::url_token::TokenRejected>>,
    ) -> Result<HttpObjectResponse, Fail> {
        let head = req.method == "HEAD";
        let (Some(cfg), Some(indexed)) = (&self.cfg.http_objects, &self.cfg.indexed) else {
            return Err(Fail::Unavailable);
        };
        // §3 step 6: the Authorizer runs for every read, as `anonymous`.
        let ref_name = match &parsed.target {
            Target::Ref { name, .. } => Some(name.clone()),
            Target::Object(_) => None,
        };
        let op = Operation::new(
            repo.clone(),
            Principal::Anonymous,
            None,
            OpKind::HttpGet { ref_name },
        );
        let expiry = self
            .authorize_http_read(&op, &parsed.target, seams, token)
            .await?;

        let view = crate::store::view::ViewStore {
            store: &self.meta,
            repo,
            writer: false,
            policy: self.publication_policy.as_deref(),
        };
        let env = Env {
            blobs: &self.blobs,
            meta: &view,
            shards: self.shards.as_ref(),
            repo,
            indexed,
            cfg,
            metrics: self.metrics.as_ref(),
        };
        let mut budget = Budget(cfg.http_decode_budget);
        let now = ms(self.clock.now_ms());

        // §3 step 7: resolve in the published view.
        let (leaf_id, commit, located) = match &parsed.target {
            Target::Ref { name, path } => {
                let shard = self.shards.ref_shard(repo, name);
                let tip = read::read_ref(&view, &shard, &repo.name, name)
                    .await
                    .map_err(|error| {
                        tracing::warn!(detail = %error, "ref read failed");
                        Fail::Unavailable
                    })?
                    .ok_or(Fail::NotFound)?;
                let resolved = resolve::resolve_ref(&env, tip, path, &mut budget).await?;
                let located = resolve::locate(&env, resolved.leaf).await?;
                // A ref path is reachable by construction: warm the cache.
                for id in [&resolved.commit, &resolved.leaf] {
                    seams.reachability.record(repo, id, now);
                }
                (resolved.leaf, Some(resolved.commit), located)
            }
            Target::Object(id) => {
                let located = resolve::locate(&env, *id).await?;
                if !seams
                    .reachability
                    .known_reachable(repo, id, now)
                    .await
                    .map_err(|error| Fail::from_server_error(&error))?
                {
                    self.prove_reachable(&env, seams, id, &mut budget).await?;
                    seams.reachability.record(repo, id, now);
                }
                (*id, None, located)
            }
        };

        // Keep the leaf verdict until proof context has passed step 7.
        // An invalid context must not learn this leaf's tombstone at step 8.
        let takedown = seams
            .takedown
            .check(repo, &leaf_id)
            .await
            .map_err(|error| Fail::from_server_error(&error))?;
        if matches!(takedown, TakedownVerdict::NotFound) {
            return Err(Fail::NotFound);
        }

        // Proof context validation precedes validators and payment. Explicit
        // contexts must themselves be published-reachable, even if the leaf is.
        let context = if parsed.query.proof {
            let (proof_commit, path) = match &parsed.target {
                Target::Ref { path, .. } => (commit.ok_or(Fail::NotFound)?, path.as_slice()),
                Target::Object(_) => (
                    parsed.query.commit.ok_or(Fail::NotFound)?,
                    parsed.query.path.as_deref().ok_or(Fail::NotFound)?,
                ),
            };
            if !ref_path_target(&parsed.target) {
                self.prove_reachable(&env, seams, &proof_commit, &mut budget)
                    .await?;
            }
            Some(
                crate::http_objects::proof::context(
                    &env,
                    seams.takedown.as_ref(),
                    proof_commit,
                    path,
                    leaf_id,
                    &mut budget,
                )
                .await?,
            )
        } else {
            None
        };
        // §3 step 8: a reachable leaf in a valid proof context may return 451.
        if let TakedownVerdict::Respond(response) = takedown {
            return Ok(response);
        }
        let metadata = if let Some(context) = &context {
            Some(context.metadata(&env, &mut budget).await?)
        } else {
            None
        };
        let ref_path = matches!(parsed.target, Target::Ref { .. });
        let mut inline = Budget(cfg.max_inline_object_bytes);
        // Proofs use canonical manifests, including when no extracted file
        // representation is available. Ordinary reads retain their holder gate.
        let leaf = if context.is_none() {
            Some(resolve::open_leaf(&env, leaf_id, located, &mut inline).await?)
        } else {
            None
        };
        // Required canonical chunks are authorization dependencies too.
        // Prepare their metadata before validators, but defer selector/cap
        // errors so a matching validator still precedes a 416 (§3 step 9).
        let proof = if let (Some(context), Some(metadata)) = (&context, &metadata) {
            match context
                .select(&env, seams.takedown.as_ref(), metadata, parsed.query.range)
                .await
            {
                Ok(proof) => Some(Ok(proof)),
                Err(Fail::ProofRange) => Some(Err(Fail::ProofRange)),
                Err(other) => return Err(other),
            }
        } else {
            None
        };
        let etag = context.as_ref().map_or_else(
            || format!("\"{}\"", to_hex(&leaf_id)),
            |c| c.etag(parsed.query.range),
        );
        let ty = metadata
            .as_ref()
            .map(|c| c.ty)
            .or_else(|| leaf.as_ref().map(|l| l.ty))
            .ok_or(Fail::Unavailable)?;
        let metadata_commit = context.as_ref().map(|c| c.commit).or(commit);
        let values = |name: &str| (req.headers)(name);
        let mut success = Vec::with_capacity(8);
        success.push(("ETag", etag.clone()));
        success.push(("X-Mkit-Object", to_hex(&leaf_id)));
        success.push(("X-Mkit-Object-Type", ty.name().to_owned()));
        if let Some(commit) = &metadata_commit {
            success.push(("X-Mkit-Commit", to_hex(commit)));
        }

        // A configured Admission makes every success private, a 304
        // included, without calling it for the 304 (§5.3).
        let private_policy = cfg.admit_reads || seams.admission.is_configured();

        // §3 step 9: a matching validator, before Range and Admission.
        if range::if_none_match(&values("if-none-match"), &etag) {
            let mut response = HttpObjectResponse::new(304).with_header(
                "Cache-Control",
                super::http_tokens::cache(ref_path, private_policy, expiry, self.clock.now_ms()),
            );
            response.headers.extend(success);
            return Ok(response);
        }

        // §3 step 10: representation selection and caps, before Admission.
        let proof = proof.transpose()?;
        if proof.is_some() && !seams.proofs.is_supported() {
            return Err(Fail::ProofRange);
        }
        let window = if let Some(leaf) = &leaf {
            let single = |name: &str| {
                let mut all = values(name);
                (all.len() == 1).then(|| all.remove(0))
            };
            let if_range = match values("if-range").len() {
                0 => None,
                1 => single("if-range"),
                _ => Some(String::new()),
            };
            match range::select(
                single("range").as_deref(),
                if_range.as_deref(),
                &etag,
                leaf.len,
            ) {
                Selection::Full => None,
                Selection::Partial { start, end } => Some((start, end)),
                Selection::Unsatisfiable => {
                    return Ok(HttpObjectResponse::error(416)
                        .with_header("Content-Range", format!("bytes */{}", leaf.len)));
                }
            }
        } else {
            None
        };
        let selected_len = proof
            .as_ref()
            .map(|p| p.encoded_len)
            .or_else(|| {
                leaf.as_ref()
                    .map(|l| window.map_or(l.len, |(a, b)| b - a + 1))
            })
            .ok_or(Fail::Unavailable)?;

        // §3 step 11: read Admission, when configured.
        let first = |name: &str| (req.headers)(name).into_iter().next();
        let credentials = {
            let meta = super::RequestMeta {
                procedure: op.procedure(),
                header: &first,
                header_values: Some(req.headers),
                unary_body: None,
                transport_principal: None,
            };
            if private_policy {
                super::admission::validate_credentials(
                    &super::admission::capture_http_credentials(
                        &meta,
                        &self.cfg.admission_credential_headers,
                        req.header_names,
                    )
                    .map_err(|e| Fail::from_server_error(&e))?,
                )
                .map_err(|e| Fail::from_server_error(&e))?
            } else {
                Vec::new()
            }
        };
        let request = AdmitRequest {
            repo,
            procedure: op.procedure(),
            head,
            ref_path,
            declared_bytes: selected_len,
            credential_headers: &credentials,
        };
        let (admitted, mut finalizer) = if cfg.admit_reads {
            match self.admit_http_read(seams, &op, &request, leaf_id).await {
                Ok(result) => result,
                Err(error) if error.http_status() == Some(402) => {
                    return Ok(super::http_admission::challenge_response(&error, head));
                }
                Err(error) => return Err(Fail::from_server_error(&error)),
            }
        } else {
            match seams
                .admission
                .admit(&request)
                .await
                .map_err(|e| Fail::from_server_error(&e))?
            {
                AdmitDecision::Allow(admitted) => (admitted, None),
                AdmitDecision::Respond(response) => return Ok(response),
            }
        };

        // §8: public ref redirects retain the original repository prefix.
        // All earlier checks, including validators and Range, have already run.
        if cfg.redirect_public_refs
            && ref_path
            && proof.is_none()
            && expiry.is_none()
            && !private_policy
        {
            let prefix = req
                .raw_path
                .split_once("/-/")
                .map_or("", |(prefix, _)| prefix);
            return Ok(HttpObjectResponse::new(302)
                .with_header(
                    "Location",
                    format!("{prefix}/-/objects/{}", to_hex(&leaf_id)),
                )
                .with_header("Cache-Control", "no-cache")
                .with_header("Content-Length", "0"));
        }

        // §3 step 12: 200 or 206.
        let mut hook = admitted.on_end;
        let body = if head || selected_len == 0 {
            if let Some(hook) = hook.take() {
                hook(0, Ok(()));
            }
            if let Some(finalizer) = finalizer.take() {
                finalizer.complete(true).await;
            }
            HttpBody::Empty
        } else {
            let opened = if let Some(proof) = &proof {
                let mut source = crate::http_objects::proof::RepositorySource {
                    env: Env {
                        blobs: &self.blobs,
                        meta: &view,
                        shards: self.shards.as_ref(),
                        repo,
                        indexed,
                        cfg,
                        metrics: self.metrics.as_ref(),
                    },
                    budget: Budget(cfg.http_decode_budget),
                    gate: seams.takedown.as_ref(),
                };
                match seams.proofs.build(proof, &mut source).await {
                    Ok(bytes) if bytes.len() as u64 == selected_len => {
                        Ok(crate::http_objects::body_with_hook(
                            HttpBody::Bytes(bytes.into()),
                            hook.take(),
                        ))
                    }
                    _ => Err(resolve::Miss::Unavailable),
                }
            } else if let Some(leaf) = &leaf {
                resolve::open_body(&self.blobs, leaf, window, &mut hook).await
            } else {
                Err(resolve::Miss::Unavailable)
            };
            match opened {
                Ok(body) => body,
                Err(miss) => {
                    if let Some(hook) = hook.take() {
                        hook(0, Err(&ServerError::unavailable("object unavailable")));
                    }
                    if let Some(finalizer) = finalizer.take() {
                        finalizer.complete(false).await;
                    }
                    return Err(miss.into());
                }
            }
        };
        let mut response = HttpObjectResponse::new(if window.is_some() { 206 } else { 200 })
            .with_header(
                "Accept-Ranges",
                if proof.is_some() { "none" } else { "bytes" },
            )
            .with_header(
                "Cache-Control",
                super::http_tokens::cache(
                    ref_path,
                    admitted.private || private_policy,
                    expiry,
                    self.clock.now_ms(),
                ),
            )
            .with_header("Content-Length", selected_len.to_string())
            .with_header(
                "Content-Type",
                match &proof {
                    Some(p) if p.span => "application/vnd.mkit.disclosure-span",
                    Some(_) => "application/vnd.mkit.disclosure",
                    None => match ty {
                        ObjectType::Blob | ObjectType::ChunkedBlob => "application/octet-stream",
                        _ => "application/vnd.mkit.object",
                    },
                },
            );
        if let (Some((start, end)), Some(leaf)) = (window, &leaf) {
            response =
                response.with_header("Content-Range", format!("bytes {start}-{end}/{}", leaf.len));
        }
        response.headers.extend(success);
        response.headers.extend(admitted.headers);
        response.body = match finalizer {
            Some(f) => f.wrap(body),
            None => body,
        };
        Ok(response)
    }

    /// Prove `id` reachable from a published ref, or fail the request.
    async fn prove_reachable(
        &self,
        env: &Env<'_, B, impl NamespaceStore>,
        seams: &HttpSeams,
        id: &Hash,
        budget: &mut Budget,
    ) -> Result<(), Fail> {
        let (tips, truncated) = self
            .published_tips(env.repo, env.cfg.max_walk_objects)
            .await?;
        let reached = if truncated {
            Reach::Capped
        } else {
            reach::walk(env, seams.takedown.as_ref(), &tips, *id, budget).await?
        };
        match reached {
            Reach::Reachable => Ok(()),
            Reach::Unreachable => Err(Fail::NotFound),
            Reach::Capped => {
                tracing::warn!("reachability walk hit a cap");
                self.metrics.incr(METRIC_HTTP_REACH_CAPPED, &[], 1);
                Err(Fail::NotFound)
            }
        }
    }

    /// The published ref values and whether enumeration hit its row or page
    /// budget. Packmaps are excluded from tips but charged to the scan budget.
    /// Refs are read through the published facade, even when a live advance
    /// is verified but still awaits clearance.
    async fn published_tips(&self, repo: &RepoId, cap: usize) -> Result<(Vec<Hash>, bool), Fail> {
        let view = crate::store::view::ViewStore {
            store: &self.meta,
            repo,
            writer: false,
            policy: self.publication_policy.as_deref(),
        };
        let scan = crate::refs::list_scan_prefix("refs/");
        let partitions = self.shards.ref_index_partitions(repo);
        let (mut tips, mut last) = (Vec::new(), None::<String>);
        let mut rows_left = cap;
        let mut pages_left = cap.div_ceil(self.cfg.list_page_limit as usize);
        loop {
            // Reserve every shard's maximum prefetch, including rows discarded
            // by the merge or excluded below. This conservatively bounds actual
            // backend rows even when the emitted page is small.
            let limit = self
                .cfg
                .list_page_limit
                .min(u32::try_from(rows_left / partitions.len()).unwrap_or(u32::MAX));
            if limit == 0 || pages_left == 0 {
                return Ok((tips, true));
            }
            rows_left -= limit as usize * partitions.len();
            pages_left -= 1;
            let page = if partitions.len() == 1 {
                let bucket = super::list::RefBucket {
                    store: &view,
                    partition: &partitions[0],
                };
                super::list::page(
                    &[bucket],
                    repo,
                    &scan,
                    last.as_deref(),
                    limit,
                    super::list::MAX_RESPONSE_BYTES,
                )
                .await
            } else {
                let buckets: Vec<_> = partitions
                    .iter()
                    .map(|partition| super::list::IndexBucket {
                        store: &view,
                        partition,
                    })
                    .collect();
                super::list::page(
                    &buckets,
                    repo,
                    &scan,
                    last.as_deref(),
                    limit,
                    super::list::MAX_RESPONSE_BYTES,
                )
                .await
            }
            .map_err(|error| {
                tracing::warn!(detail = %error, "ref listing scan failed");
                Fail::Unavailable
            })?;
            for entry in page.refs {
                if entry.name.starts_with(PACKMAP_PREFIX)
                    || !crate::refs::is_served_ref_name(&entry.name)
                {
                    continue;
                }
                tips.push(entry.id);
            }
            let Some(next) = page.next else {
                return Ok((tips, false));
            };
            last = Some(super::list::decode_token(repo, &scan, &next).ok_or(Fail::Unavailable)?);
        }
    }
}

fn ref_path_target(target: &Target) -> bool {
    matches!(target, Target::Ref { .. })
}

/// The storage identity of a parsed repository prefix.
fn repo_id(parsed: &ParsedUrl) -> Option<RepoId> {
    let identity = parsed.repository.as_ref()?;
    Some(RepoId {
        namespace: NamespaceKey::from_namespace(identity.namespace()?),
        name: RepoName::new(identity.name()).ok()?,
    })
}
