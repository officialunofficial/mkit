//! `Pipeline::serve_http_object`: the SPEC-HTTP-OBJECTS §3 precedence over
//! this pipeline's stores. It lives here because it needs the pipeline's
//! private stage functions; everything reusable is in `http_objects`.
//!
//! Reachable only when a deployment opts into indexed HTTP serving through
//! `PipelineConfig::http_objects`; native embedders and the Paid Workers launch
//! configure this through their adapters.

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
use crate::repo::{RepoId, RepoName};
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

    /// Replace the inert seams of an HTTP-objects pipeline: tokens,
    /// takedown or a maintained reachable set. A pipeline built without
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
        self.serve_http_with_runtime(req, None).await
    }

    /// Adapter-provided retained settlement runtime for this request.
    pub async fn serve_http_object_with_runtime(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: crate::http_objects::HttpReadRuntime,
    ) -> HttpObjectResponse {
        self.serve_http_with_runtime(req, Some(runtime)).await
    }

    async fn serve_http_with_runtime(
        &self,
        req: &HttpObjectRequest<'_>,
        runtime: Option<crate::http_objects::HttpReadRuntime>,
    ) -> HttpObjectResponse {
        let mut response = self.serve_http_inner(req, runtime).await;
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
    ) -> HttpObjectResponse {
        let (Some(_), Some(seams)) = (&self.cfg.http_objects, &self.http_seams) else {
            return HttpObjectResponse::not_found();
        };
        let mut seams = seams.clone();
        if let Some(runtime) = runtime {
            seams.read_runtime = Some(runtime);
        }
        match req.method {
            "OPTIONS" => return HttpObjectResponse::new(204).with_header("Allow", ALLOW),
            "GET" | "HEAD" => {}
            _ => return HttpObjectResponse::error(405).with_header("Allow", ALLOW),
        }
        let Ok(parsed) = route::parse_request(req, self.cfg.namespace_mode) else {
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

        let denial_budget = crate::indexed::budget::SliceBudget::new(crate::limits::REQUEST_CALLS);
        let proof_meta = crate::indexed::budget::Budgeted::new(&self.meta, &denial_budget);
        let proof_blobs = crate::indexed::budget::Budgeted::new(&self.blobs, &denial_budget);
        let view = crate::store::view::ViewStore {
            store: &proof_meta,
            repo,
            writer: false,
            policy: self.publication_policy.as_deref(),
        };
        let env = Env {
            no_reads: &std::collections::BTreeSet::new(),
            blobs: &proof_blobs,
            meta: &view,
            shards: self.shards.as_ref(),
            repo,
            indexed,
            cfg,
            metrics: self.metrics.as_ref(),
            caps: crate::indexed::resolve::Caps::Legacy,
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
                if self.cfg.takedown_denial
                    || !seams
                        .reachability
                        .known_reachable(repo, id, now)
                        .await
                        .map_err(|error| Fail::from_server_error(&error))?
                {
                    match self.prove_reachable(&env, seams, id, &mut budget).await {
                        // A spent proof allowance reads as an unknown id.
                        Err(Fail::Unavailable) if denial_budget.remaining() == 0 => {
                            return Err(Fail::NotFound);
                        }
                        other => other?,
                    }
                    seams.reachability.record(repo, id, now);
                }
                (*id, None, located)
            }
        };

        for id in [&leaf_id, &located.pack] {
            crate::takedown::denial::require_clear(&proof_meta, id)
                .await
                .map_err(|e| {
                    if e.public_message() == "object blocked" {
                        Fail::NotFound
                    } else {
                        Fail::Unavailable
                    }
                })?;
        }
        if self.cfg.takedown_denial {
            crate::takedown::denial::require_object_clear(
                &self.meta,
                self.shards.as_ref(),
                repo,
                &leaf_id,
                indexed,
                &denial_budget,
            )
            .await
            .map_err(|e| {
                if e.public_message() == "object blocked" {
                    Fail::NotFound
                } else {
                    Fail::Unavailable
                }
            })?;
        }
        let takedown = seams
            .takedown
            .check(repo, &leaf_id)
            .await
            .map_err(|error| Fail::from_server_error(&error))?;
        if matches!(takedown, TakedownVerdict::NotFound) {
            return Err(Fail::NotFound);
        }

        // §3 step 8: a reachable leaf may return 451.
        if let TakedownVerdict::Respond(response) = takedown {
            return Ok(response);
        }
        // Unsupported proof profile: access checks precede the uniform 416,
        // but proof preparation, validators, admission and body setup do not run.
        if parsed.query.proof {
            return Err(Fail::UnsupportedProof);
        }
        let ref_path = matches!(parsed.target, Target::Ref { .. });
        let mut inline = Budget(cfg.max_inline_object_bytes);
        let leaf = resolve::open_leaf(&env, leaf_id, located, &mut inline).await?;
        let etag = format!("\"{}\"", to_hex(&leaf_id));
        let ty = leaf.ty;
        let values = |name: &str| (req.headers)(name);
        let mut success = Vec::with_capacity(8);
        success.push(("ETag", etag.clone()));
        success.push(("X-Mkit-Object", to_hex(&leaf_id)));
        success.push(("X-Mkit-Object-Type", ty.name().to_owned()));
        if let Some(commit) = &commit {
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
        let window = {
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
        };
        let selected_len = window.map_or(leaf.len, |(a, b)| b - a + 1);

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
            #[cfg(test)]
            head,
            #[cfg(test)]
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
                #[cfg(test)]
                AdmitDecision::Respond(response) => return Ok(response),
            }
        };

        // §8: public ref redirects retain the original repository prefix.
        // All earlier checks, including validators and Range, have already run.
        if cfg.redirect_public_refs && ref_path && expiry.is_none() && !private_policy {
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
            let opened = resolve::open_body(&proof_blobs, &leaf, window, &mut hook).await;
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
        let filename = match (&parsed.target, ty) {
            (Target::Ref { path, .. }, ObjectType::Blob | ObjectType::ChunkedBlob) => {
                path.last().map(Vec::as_slice)
            }
            _ => None,
        };
        let file_headers = filename.map(crate::http_objects::content_headers::media_type);
        let mut response = HttpObjectResponse::new(if window.is_some() { 206 } else { 200 })
            .with_header("Accept-Ranges", "bytes")
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
                match ty {
                    ObjectType::Blob | ObjectType::ChunkedBlob => {
                        file_headers.map_or("application/octet-stream", |(media, _)| media)
                    }
                    _ => "application/vnd.mkit.object",
                },
            );
        if let Some((start, end)) = window {
            response =
                response.with_header("Content-Range", format!("bytes {start}-{end}/{}", leaf.len));
        }
        if let (Some(name), Some((_, kind))) = (filename, file_headers) {
            response = response.with_header(
                "Content-Disposition",
                crate::http_objects::content_headers::disposition(name, kind),
            );
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
        env: &Env<'_, impl crate::BlobStore, impl NamespaceStore>,
        seams: &HttpSeams,
        id: &Hash,
        budget: &mut Budget,
    ) -> Result<(), Fail> {
        let (tips, truncated) = self
            .reader_tips(env.meta, env.repo, env.cfg.max_walk_objects, false)
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

    /// Enumerate view-selected refs with bounded rows/pages; packmaps only spend budget.
    pub(super) async fn reader_tips(
        &self,
        store: &impl NamespaceStore,
        repo: &RepoId,
        cap: usize,
        writer: bool,
    ) -> Result<(Vec<Hash>, bool), Fail> {
        let view = crate::store::view::ViewStore {
            store,
            repo,
            writer,
            policy: self.publication_policy.as_deref(),
        };
        let scan = crate::refs::list_scan_prefix("refs/");
        let partitions = self.shards.ref_index_partitions(repo);
        let (mut tips, mut last) = (Vec::new(), None::<String>);
        let mut rows_left = cap;
        let page_limit = self
            .cfg
            .list_page_limit
            .min(u32::try_from(crate::store::read_io::ROWS).unwrap_or(u32::MAX));
        let mut pages_left = cap.div_ceil(page_limit as usize);
        loop {
            // Reserve every shard's maximum prefetch, including rows discarded
            // by the merge or excluded below. This conservatively bounds actual
            // backend rows even when the emitted page is small.
            let limit =
                page_limit.min(u32::try_from(rows_left / partitions.len()).unwrap_or(u32::MAX));
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
                // The shards are independent scans: one wave, not one round each.
                super::list::page_in_waves(
                    &view,
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

/// The storage identity of a parsed repository prefix.
fn repo_id(parsed: &ParsedUrl) -> Option<RepoId> {
    let identity = parsed.repository.as_ref()?;
    Some(RepoId {
        namespace: identity.namespace()?.key(),
        name: RepoName::new(identity.name()).ok()?,
    })
}
