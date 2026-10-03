//! HTTP-only private-read authorization: rr/rv, binding, then stored epoch.
use super::{AuthMode, Authorizer, HookSet, Pipeline, meta_error};
use crate::http_objects::{Fail, HttpSeams, Target, cache_control};
use crate::op::CallerView;
use crate::policy::read as read_policy;
use crate::store::{MultipartBlobStore, NamespaceStore, codec, keys};
use crate::url_token::{Binding, Prechecked, TokenRejected, UrlTarget};
use crate::{Code, Operation};

/// Token targets are decoded UTF-8 paths joined once, never URL text or
/// proof selectors. Root paths retain the empty final target field.
pub(crate) fn target(target: &Target) -> Option<UrlTarget> {
    match target {
        Target::Object(id) => Some(UrlTarget::Object(*id)),
        Target::Ref { name, path } => {
            let parts: Option<Vec<_>> = path
                .iter()
                .map(|part| core::str::from_utf8(part).ok())
                .collect();
            UrlTarget::path(name, parts?.join("/")).ok()
        }
    }
}

/// Private responses must bypass shared-cache lookup and insertion in
/// adapters (WP-4.16), including when a token is on an immutable id URL.
pub(super) fn cache(ref_path: bool, admitted: bool, expiry: Option<i64>, now: i64) -> String {
    if let Some(expiry) = expiry {
        if ref_path {
            "private, no-cache".into()
        } else {
            format!(
                "private, max-age={}, immutable",
                expiry.saturating_sub(now).max(0) / 1000
            )
        }
    } else {
        cache_control(ref_path, admitted).into()
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn authorize_http_read(
        &self,
        op: &Operation,
        requested: &Target,
        seams: &HttpSeams,
        prechecked: Option<Result<Prechecked, TokenRejected>>,
    ) -> Result<Option<i64>, Fail> {
        self.authorize_http_read_with_meta(op, requested, seams, prechecked, &self.meta)
            .await
    }
    pub(super) async fn authorize_http_read_with_meta<S: NamespaceStore>(
        &self,
        op: &Operation,
        requested: &Target,
        seams: &HttpSeams,
        prechecked: Option<Result<Prechecked, TokenRejected>>,
        meta: &S,
    ) -> Result<Option<i64>, Fail> {
        let partition = self.shards.coordinator(&op.repo.namespace);
        let mut changed_ms = 0;
        let private = if self.visibility_gates_reads() {
            // Deliberately do not use read_repo_state: e must not be read
            // until every stateless token binding check has passed.
            let values = meta
                .get_many(
                    &partition,
                    &[
                        keys::repo_record(&op.repo.name),
                        keys::repo_visibility(&op.repo.name),
                    ],
                )
                .await
                .map_err(|_| Fail::Unavailable)?;
            let record = values
                .first()
                .and_then(Option::as_ref)
                .ok_or(Fail::NotFound)?;
            codec::decode_repo_record(record).map_err(|_| Fail::Unavailable)?;
            let visibility = values
                .get(1)
                .and_then(Option::as_ref)
                .map(codec::decode_repo_visibility)
                .transpose()
                .map_err(|_| Fail::Unavailable)?;
            changed_ms = visibility
                .as_ref()
                .map_or(0, codec::RepoVisibilityV1::visibility_changed_ms);
            super::repo_is_private(visibility.as_ref(), self.cfg.default_repo_visibility)
        } else {
            false
        };
        let expiry = if private {
            let prechecked = prechecked.and_then(Result::ok).ok_or(Fail::NotFound)?;
            let requested = target(requested).ok_or(Fail::NotFound)?;
            let AuthMode::AuthV2(auth) = &self.cfg.auth else {
                return Err(Fail::NotFound);
            };
            let repository = format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str());
            let bound = prechecked
                .check_binding(
                    &Binding {
                        audience: auth.audience(),
                        repository: &repository,
                        target: &requested,
                    },
                    self.clock.now_ms(),
                    seams.tokens.ttl_ms(),
                )
                .map_err(|_| Fail::NotFound)?;
            // A visibility change revokes earlier tokens; no extra read.
            bound
                .check_visibility_change(changed_ms)
                .map_err(|_| Fail::NotFound)?;
            let value = meta
                .get(&partition, &keys::grant_epoch())
                .await
                .map_err(|_| Fail::Unavailable)?;
            let epoch = value
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)
                .map_err(|_| Fail::Unavailable)?
                .unwrap_or(0);
            bound.check_epoch(epoch).map_err(|_| Fail::NotFound)?;
            Some(bound.expiry_ms())
        } else {
            None
        };

        // HTTP always calls Authorizer, under either role, retaining an
        // anonymous principal and published view even when it allows a token.
        self.hooks.authorizer().authorize(op).await.map_err(|e| {
            if private
                && matches!(
                    e.code(),
                    Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                )
            {
                Fail::NotFound
            } else {
                Fail::from_server_error(&e)
            }
        })?;
        let caller = read_policy::Caller {
            http_token_authorized: expiry.is_some(),
            signed: false,
            owner: false,
            grant: None,
            hook: read_policy::HookEval::Allow { writer_view: false },
            authority: false,
        };
        match read_policy::decide(op.procedure(), private, caller) {
            read_policy::ReadDecision::Allow(CallerView::Anonymous) => Ok(expiry),
            _ => Err(Fail::NotFound),
        }
    }
}
