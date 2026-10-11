//! Same-repository branch creation from one authoritative published pair.

use super::{Authenticated, HookSet, Pipeline, ResponseMeta, check_ref_name, stored_mismatch};
use crate::error::{Code, ServerError};
use crate::op::{OpKind, Operation, PublishedRefSource, RefUpdate};
use crate::replay::StoredResult;
use crate::store::{MultipartBlobStore, NamespaceStore};
use mkit_core::hash::Hash;
use mkit_core::protocol::{AdvanceOutcome, RefWriteCondition};

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Create `destination_ref` and its packmap from `source_ref`'s published
    /// pair in the authenticated repository. Both destination refs must be absent.
    /// The source is reauthorized and its publication row compared before each
    /// apply. A subsequent source move is concurrent: success copies the captured
    /// pair exactly. Configured publication checks still apply to the destination.
    ///
    /// # Errors
    /// `not_found "source not found"` for an absent or unreadable source;
    /// `failed_precondition "source tip changed"` on an expected-tip mismatch;
    /// `unavailable` when the source publication row changes during the operation;
    /// otherwise the errors of [`Self::advance_refs`]. Requires atomic metadata.
    pub async fn advance_refs_from_published(
        &self,
        a: &Authenticated,
        source_ref: String,
        destination_ref: String,
        expected_tip: Option<Hash>,
    ) -> Result<AdvanceOutcome, ServerError> {
        self.advance_refs_from_published_with_meta(a, source_ref, destination_ref, expected_tip)
            .await
            .map(|(outcome, _)| outcome)
    }

    /// [`Self::advance_refs_from_published`], returning success-only admission headers.
    ///
    /// # Errors
    /// Those of [`Self::advance_refs_from_published`].
    pub async fn advance_refs_from_published_with_meta(
        &self,
        a: &Authenticated,
        source_ref: String,
        destination_ref: String,
        expected_tip: Option<Hash>,
    ) -> Result<(AdvanceOutcome, ResponseMeta), ServerError> {
        self.observe(a, async {
            check_ref_name(&destination_ref)?;
            let packmap = mkit_attest::grant::head_packmap(&destination_ref)
                .ok_or_else(|| ServerError::invalid_argument("destination must be a branch"))?;
            check_ref_name(&packmap)?;
            if !self.meta.capabilities().atomic_multi_key {
                return Err(ServerError::failed_precondition(
                    "published branch creation requires atomic metadata",
                ));
            }
            let update = |name| RefUpdate {
                name,
                condition: RefWriteCondition::Missing,
                new: None, // Filled from the source only after stage-0 replay.
            };
            match self
                .write_inner(
                    a,
                    OpKind::AdvanceRefs {
                        head: update(destination_ref),
                        packmap: update(packmap),
                        tickets: vec![],
                    },
                    None,
                    Some((&source_ref, expected_tip)),
                )
                .await?
            {
                (StoredResult::AdvanceRefs(outcome), meta) => Ok((outcome, meta)),
                (other, _) => Err(stored_mismatch(&other)),
            }
        })
        .await
    }

    pub(super) async fn capture_published_source<S: NamespaceStore>(
        &self,
        op: &Operation,
        source_ref: &str,
        expected_tip: Option<Hash>,
        meta: &S,
    ) -> Result<PublishedRefSource, ServerError> {
        // Bound hook input before constructing the read operation.
        if !source_ref.starts_with("refs/heads/") || !crate::refs::validate_ref_name(source_ref) {
            return Err(crate::fork::ForkError::NotFound.error());
        }
        let mut read = op.clone();
        read.kind = OpKind::ReadRef {
            name: source_ref.to_owned(),
        };
        read.authz = crate::op::AuthzFacts::default();
        read.published_source = None;
        self.authorize_read_with_meta(&read, meta, None)
            .await
            .map_err(|error| match error.code() {
                Code::NotFound | Code::PermissionDenied | Code::Unauthenticated => {
                    crate::fork::ForkError::NotFound.error()
                }
                _ => error,
            })?;
        let observed =
            crate::fork::read_published(meta, self.shards.as_ref(), &op.repo, source_ref)
                .await
                .map_err(|error| error.error())?;
        if expected_tip.is_some_and(|expected| observed.value.head != Some(expected)) {
            return Err(ServerError::failed_precondition("source tip changed"));
        }
        Ok(PublishedRefSource {
            ref_name: source_ref.to_owned(),
            pair: observed.value.clone(),
            generation: observed.generation,
            publication_sequence: observed.published,
            observed,
            expected_tip,
        })
    }

    pub(super) async fn fence_published_source<S: NamespaceStore>(
        &self,
        op: &Operation,
        a: &Authenticated,
        meta: &S,
    ) -> Result<(), ServerError> {
        if let Some(source) = &op.published_source {
            let mut fresh = op.clone();
            fresh.business_now_ms = Some(self.clock.now_ms().saturating_add(a.business_skew_ms));
            let current = self
                .capture_published_source(&fresh, &source.ref_name, source.expected_tip, meta)
                .await?;
            if current.observed != source.observed {
                return Err(ServerError::unavailable(
                    "source publication changed; retry",
                ));
            }
        }
        Ok(())
    }
}
