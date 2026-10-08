//! Cross-request structural evidence with fresh authority and a strict ref fence.
use super::{
    AtomicBool, BTreeSet, Budget, Budgeted, Code, Hash, HistoryCommit, HistoryMode, HistoryOptions,
    HookSet, MultipartBlobStore, NamespaceStore, Node, OBJECT_READER_CALLS, Object, ObjectReader,
    ObjectType, ReaderSession, ReaderView, Role, ServerError, SliceBudget, exhausted, failure, ms,
    reserve_output, settle, validate_history,
};
use crate::Redacted;
use crate::history_token::{ClaimState, Claims, WitnessNode};
use crate::pipeline::read_proofs::WitnessError;
use crate::store::{
    Batch, BatchOutcome, Precondition, Value, codec, keys, publication::Publication,
};

mod issue;
mod timestamp;
pub use issue::HistoryContinuationState;

/// Retryable selected-ref continuation; credential text is redacted in Debug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryContinuation {
    /// Opaque authenticated structural evidence, passed to the next page.
    pub token: Redacted,
    /// Original absolute expiry, never extended by successors.
    pub expires_at_ms: u64,
}
/// Which order a continued page walks.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContinuedHistoryOrder {
    /// First-parent paging; the token carries one linear provenance chain.
    #[default]
    FirstParent,
    /// All-parents paging in the timestamp-discovery order of
    /// `mkit_core::history_order::TimestampDiscovery`; the token carries the
    /// sealed reducer snapshot verbatim. Page 1 is the embedder's own loop —
    /// this order requires an issued continuation.
    TimestampDiscovery,
}
/// Options for [`ObjectReader::walk_history_page_with_options_in`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContinuedHistoryOptions {
    /// The continuation order; a token whose order byte differs is refused.
    pub order: ContinuedHistoryOrder,
}
/// A page of commits in the requested order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuedHistoryPage {
    /// Canonical commits in the requested order.
    pub commits: Vec<HistoryCommit>,
    /// Absent at the end of accessible history.
    pub next: Option<HistoryContinuation>,
}

// Imported evidence never escapes this operation, including cancellation.
struct HistoryProofScope<'a> {
    session: &'a mut ReaderSession,
    saved: crate::pipeline::read_proofs::ReadProofs,
}
impl<'a> HistoryProofScope<'a> {
    fn new(session: &'a mut ReaderSession) -> Self {
        let isolated = session.proofs.isolated();
        let saved = std::mem::replace(&mut session.proofs, isolated);
        Self { session, saved }
    }
}
impl Drop for HistoryProofScope<'_> {
    fn drop(&mut self) {
        self.saved.inherit_deadline(&self.session.proofs);
        std::mem::swap(&mut self.session.proofs, &mut self.saved);
    }
}

pub(crate) struct Anchor {
    pub(crate) tip: Hash,
    pub(crate) publication: Publication,
    pub(crate) raw: Vec<Option<Value>>,
}
fn absent() -> ServerError {
    ServerError::not_found("object reader unavailable")
}
fn guard(key: crate::store::Key, value: Option<&Value>) -> Precondition {
    match value {
        Some(v) => Precondition::Equals(key, v.clone()),
        None => Precondition::Absent(key),
    }
}
fn digest_parts(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Hash {
    let mut h = blake3::Hasher::new();
    for part in parts {
        let bytes = part.as_ref();
        h.update(&(bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    *h.finalize().as_bytes()
}

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    /// Page a selected ref's first-parent history, without re-walking the
    /// cursor's ancestry on continued requests. Pass `None` for the first page.
    /// Each request uses a new reader/session and fresh credentials. MACs carry
    /// structural evidence only; live authority, membership, dependencies and
    /// denial are checked for every served object. Anchor equality includes
    /// the never-reset publication stamp. Replays within the same scope and
    /// fixed expiry rerun live checks and can retry a lost response.
    /// All-parent paging uses [`Self::walk_history_page_with_options_in`] with
    /// [`ContinuedHistoryOrder::TimestampDiscovery`].
    /// # Errors
    /// Invalid ref/limits or disabled configuration. Invalid, revoked, expired,
    /// inaccessible continuations return uniform `Ok(None)` in
    /// either view. Backend faults remain `Unavailable`, owner budget exhaustion
    /// remains typed, and no spent allowance is refunded on failure.
    pub async fn walk_history_page_in(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        continuation: Option<&str>,
        limit: usize,
    ) -> Result<Option<ContinuedHistoryPage>, ServerError> {
        self.walk_history_page_with_options_in(
            session,
            reference,
            continuation,
            limit,
            ContinuedHistoryOptions::default(),
        )
        .await
    }

    /// Page a selected ref's history in `options.order`. First-parent page 1
    /// passes `None` and mints a continuation; timestamp-discovery order needs
    /// an issued token — its page 1 is the embedder's own
    /// [`TimestampDiscovery`](mkit_core::history_order::TimestampDiscovery)
    /// loop over `read_canonical_in`, then
    /// [`Self::issue_history_continuation_in`]. A token minted for one order
    /// refused by the other. Every object is re-validated live.
    /// # Errors
    /// Invalid ref/limits/order or disabled configuration. Invalid, revoked,
    /// expired, inaccessible continuations return uniform `Ok(None)` in either
    /// view. A bounded history-state cap reports a typed
    /// [`HistoryStateLimit`](crate::HistoryStateLimit); backend faults remain
    /// `Unavailable` and no spent allowance is refunded on failure.
    pub async fn walk_history_page_with_options_in(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        continuation: Option<&str>,
        limit: usize,
        options: ContinuedHistoryOptions,
    ) -> Result<Option<ContinuedHistoryPage>, ServerError> {
        self.check_selected(reference)?;
        let defaults = HistoryOptions {
            mode: HistoryMode::FirstParent,
            ..HistoryOptions::default()
        };
        validate_history(reference, defaults)?;
        if limit == 0 || limit > defaults.max_nodes {
            return Err(ServerError::invalid_argument("invalid history page size"));
        }
        if options.order == ContinuedHistoryOrder::TimestampDiscovery && continuation.is_none() {
            return Err(ServerError::invalid_argument(
                "timestamp continuations resume an issued token",
            ));
        }
        let config = self
            .pipe
            .cfg
            .history_tokens
            .as_ref()
            .ok_or_else(|| ServerError::unimplemented("history tokens not configured"))?;
        if let Ok(mkit_core::repo_identity::Namespace::Ed25519(key)) =
            mkit_core::repo_identity::Namespace::parse(self.repo.namespace.as_str())
            && config.check_public_roles(&[key]).is_err()
        {
            return Ok(None);
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let capped = AtomicBool::new(false);
        let scope = HistoryProofScope::new(session);
        let mut token_expiry = None;
        let result = self
            .continued_page(
                scope.session,
                reference,
                continuation,
                limit,
                options.order,
                config,
                &calls,
                &admission,
                &capped,
                &mut token_expiry,
            )
            .await;
        let result = settle(result, &capped);
        let result = match result {
            // Exhaustion after the token's expiry is absence; a typed history
            // state cap is never folded into absence.
            Err(e)
                if e.code() == Code::ResourceExhausted
                    && e.history_state_limit().is_none()
                    && token_expiry
                        .is_some_and(|expiry| ms(self.pipe.clock.now_ms()) >= expiry) =>
            {
                Err(absent())
            }
            other => other,
        };
        match result {
            Err(e)
                if matches!(
                    e.code(),
                    Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                ) =>
            {
                Ok(None)
            }
            other => self.discovery_result(other),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One ordered authentication/read/commit boundary.
    async fn continued_page(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        token: Option<&str>,
        limit: usize,
        order: ContinuedHistoryOrder,
        config: &crate::history_token::HistoryTokenConfig,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        capped: &AtomicBool,
        token_expiry: &mut Option<u64>,
    ) -> Result<Option<ContinuedHistoryPage>, ServerError> {
        let claims = if let Some(token) = token {
            // Reserve parsing bytes before binary/base64 allocations. MAC and
            // stateless bindings precede repository/security state reads.
            let (_, mut charge, _, _) = session.split_with_proofs(self.cfg.http_decode_budget);
            let len = u64::try_from(token.len()).map_err(|_| exhausted())?;
            if charge.budget.0 < len {
                return Err(exhausted());
            }
            charge.budget.0 -= len;
            let claims = config.verify(token).map_err(|()| absent())?;
            let matching = matches!(
                (&claims.state, order),
                (ClaimState::FirstParent, ContinuedHistoryOrder::FirstParent)
                    | (
                        ClaimState::TimestampDiscovery(_),
                        ContinuedHistoryOrder::TimestampDiscovery
                    )
            );
            if !matching
                || claims.namespace != self.repo.namespace.as_str()
                || claims.repository != self.repo.name.as_str()
                || claims.reference != reference
                || claims.writer != matches!(self.view, ReaderView::Owner(_))
                || claims.issued > ms(self.pipe.clock.now_ms())
                || ms(self.pipe.clock.now_ms()) >= claims.expires
            {
                return Err(absent());
            }
            *token_expiry = Some(claims.expires);
            Some(claims)
        } else {
            None
        };
        let now = ms(self.pipe.clock.now_ms());
        session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        let authority = self.authorize(calls).await?;
        let (credential, credential_expiry) = self.history_credential(authority.as_ref())?;
        if claims.as_ref().is_some_and(|c| c.credential != credential) {
            return Err(absent());
        }
        session
            .proofs
            .bind(&self.identity, authority, now, self.cfg)?;
        let anchor = {
            let meta = Budgeted::new(&self.pipe.meta, calls)
                .with_session(&session.io.calls)
                .flagging(capped)
                .with_io(admission);
            self.continuation_anchor(&meta, reference).await?
        };
        let security = {
            let meta = Budgeted::new(&self.pipe.meta, calls)
                .with_session(&session.io.calls)
                .flagging(capped)
                .with_io(admission);
            self.history_security(&meta, claims.is_none()).await?
        };
        if let Some(c) = &claims {
            if c.anchor != anchor.tip
                || c.publication != anchor.publication
                || c.security != security
                || c.witness.first().map(|node| node.id) != Some(anchor.tip)
                || c.witness
                    .iter()
                    .filter_map(|node| node.predecessor)
                    .any(|predecessor| {
                        self.seams
                            .takedown
                            .stops_descent(&self.repo, &c.witness[usize::from(predecessor)].id)
                    })
            {
                return Err(absent());
            }
            session
                .proofs
                .restore_witness(&c.witness, c.expires)
                .map_err(|_| absent())?;
        }
        let mut decode = Budget(self.cfg.http_decode_budget);
        let carried = claims.as_ref().map(|c| (c.issued, c.expires));
        let (nodes, successor) = if let Some(c) = claims {
            match c.state {
                ClaimState::FirstParent => {
                    let cursor = c.witness.last().ok_or_else(absent)?.id;
                    let (nodes, complete) = self
                        .resume_linear(session, cursor, limit, None, calls, admission, &mut decode)
                        .await?;
                    let next = self.linear_next(session, &nodes, complete)?;
                    (nodes, next)
                }
                ClaimState::TimestampDiscovery(walk) => {
                    self.resume_timestamp(session, walk, limit, calls, admission, &mut decode)
                        .await?
                }
            }
        } else {
            session.proofs.capture_selected(Some(anchor.tip));
            let mut tip = anchor.tip;
            let mut role = Role::Tip;
            let mut tags = BTreeSet::new();
            let first = loop {
                let node = self
                    .proved_node(session, tip, role, calls, admission, &mut decode)
                    .await?
                    .ok_or_else(absent)?;
                if let Object::Tag(tag) = &node.object {
                    if tags.len() >= HistoryOptions::default().max_tags || !tags.insert(tip) {
                        return Err(exhausted());
                    }
                    if !matches!(
                        tag.target_type,
                        ObjectType::Tag | ObjectType::Commit | ObjectType::Remix
                    ) || !self.link_node(session, &node, tag.target)?
                    {
                        return Err(absent());
                    }
                    tip = tag.target;
                    role = Role::Exact(tag.target_type);
                } else {
                    break node;
                }
            };
            let (nodes, complete) = self
                .resume_linear(
                    session,
                    tip,
                    limit,
                    Some(first),
                    calls,
                    admission,
                    &mut decode,
                )
                .await?;
            let next = self.linear_next(session, &nodes, complete)?;
            (nodes, next)
        };
        let now = ms(self.pipe.clock.now_ms());
        let expires = carried.map_or_else(
            || {
                now.saturating_add(config.ttl_ms())
                    .min(session.proofs.expiry())
                    .min(credential_expiry)
            },
            |(_, expires)| expires,
        );
        if now >= expires || !session.proofs.current(now) {
            return Err(absent());
        }
        let next = if let Some((state, witness)) = successor {
            let issued = carried.map_or(now, |(issued, _)| issued);
            let new = Claims {
                realm: config.realm().into(),
                namespace: self.repo.namespace.as_str().into(),
                repository: self.repo.name.as_str().into(),
                reference: reference.into(),
                writer: matches!(self.view, ReaderView::Owner(_)),
                credential,
                anchor: anchor.tip,
                publication: anchor.publication.clone(),
                security,
                issued,
                expires,
                state,
                witness,
            };
            let token = config
                .mint(&new)
                .map_err(ServerError::history_state_limit_exceeded)?;
            Some(HistoryContinuation {
                token: Redacted::new(token),
                expires_at_ms: expires,
            })
        } else {
            None
        };
        let bytes = nodes
            .iter()
            .try_fold(
                next.as_ref().map_or(0, |n| n.token.expose().len() as u64),
                |total, n| total.checked_add(n.bytes.len() as u64),
            )
            .ok_or_else(exhausted)?;
        reserve_output(session, bytes)?;
        // Validate a coherent anchor without allocating or consuming paging
        // state. Batched reads alone need not be atomic.
        let meta = Budgeted::new(&self.pipe.meta, calls)
            .with_session(&session.io.calls)
            .flagging(capped)
            .with_io(admission);
        self.closing_fence(
            &meta,
            reference,
            &anchor.raw,
            &anchor.publication,
            anchor.tip,
            security,
            expires,
        )
        .await?;
        // Live serving validation is the last asynchronous phase. A later ref
        // change invalidates both the original token and its successor.
        self.final_nodes(session, &nodes, calls, admission).await?;
        if ms(self.pipe.clock.now_ms()) >= expires {
            return Err(absent());
        }
        let emitted: BTreeSet<Hash> = nodes.iter().map(|node| node.id).collect();
        if session
            .proofs
            .ancestors(&emitted)
            .iter()
            .any(|id| self.seams.takedown.stops_descent(&self.repo, id))
        {
            return Err(absent());
        }
        Ok(Some(ContinuedHistoryPage {
            commits: nodes
                .into_iter()
                .map(|n| HistoryCommit {
                    id: n.id,
                    canonical: n.bytes.to_vec(),
                })
                .collect(),
            next,
        }))
    }

    /// The minted successor state of a non-final first-parent page: the cursor
    /// is the last served commit's first parent and its provenance chain is
    /// the token's witness.
    fn linear_next(
        &self,
        session: &mut ReaderSession,
        nodes: &[Node],
        complete: bool,
    ) -> Result<Option<(ClaimState, Vec<WitnessNode>)>, ServerError> {
        if complete {
            return Ok(None);
        }
        let node = nodes.last().ok_or_else(absent)?;
        let parent = *node.parents().and_then(|p| p.first()).ok_or_else(absent)?;
        if !self.link_node(session, node, parent)? {
            return Ok(None);
        }
        match session.proofs.history_witness(&[parent], false) {
            Ok(witness) => Ok(Some((ClaimState::FirstParent, witness))),
            Err(WitnessError::Limit) => Err(ServerError::history_state_limit_exceeded(
                crate::HistoryStateLimit::Provenance,
            )),
            Err(WitnessError::Unproven) => Err(absent()),
        }
    }

    /// The write-free ref guard and closing reads shared by issuance and
    /// redemption: the fence rejects any ref/publication/security change
    /// observed since `raw`/`publication`/`tip` were read, and any lapse into
    /// `expires`.
    #[allow(clippy::too_many_arguments)] // One ordered write-free validation cut.
    async fn closing_fence(
        &self,
        meta: &impl NamespaceStore,
        reference: &str,
        raw: &[Option<Value>],
        publication: &Publication,
        tip: Hash,
        security: Hash,
        expires: u64,
    ) -> Result<(), ServerError> {
        let batch = Batch::new()
            .require(Precondition::NotAfter(expires.saturating_sub(1)))
            .require(guard(
                keys::publication(&self.repo.name, reference),
                raw.first().and_then(Option::as_ref),
            ))
            .require(guard(
                keys::ref_key(&self.repo.name, reference),
                raw.get(1).and_then(Option::as_ref),
            ));
        if meta
            .apply(&self.pipe.shards.ref_shard(&self.repo, reference), batch)
            .await
            .map_err(failure)?
            != BatchOutcome::Committed
        {
            return Err(absent());
        }
        // The write-free guard is the ref validation cut. Closing reads
        // reject subsequently observed boundary changes before serving.
        if self.history_security(meta, false).await? != security {
            return Err(absent());
        }
        let final_anchor = self.continuation_anchor(meta, reference).await?;
        if final_anchor.raw != raw
            || final_anchor.publication != *publication
            || final_anchor.tip != tip
            || ms(self.pipe.clock.now_ms()) >= expires
        {
            return Err(absent());
        }
        Ok(())
    }

    pub(crate) async fn continuation_anchor(
        &self,
        meta: &impl NamespaceStore,
        reference: &str,
    ) -> Result<Anchor, ServerError> {
        let values = meta
            .get_many(
                &self.pipe.shards.ref_shard(&self.repo, reference),
                &[
                    keys::publication(&self.repo.name, reference),
                    keys::ref_key(&self.repo.name, reference),
                ],
            )
            .await
            .map_err(failure)?;
        if values.len() != 2 {
            return Err(failure(()));
        }
        let publication = Publication::decode(values[0].as_ref()).map_err(failure)?;
        // A missing ledger cannot authenticate a continuation's ABA fence.
        if values[0].is_none() || publication.sequence == 0 {
            return Err(absent());
        }
        let tip = if matches!(self.view, ReaderView::Owner(_)) {
            values[1]
                .as_ref()
                .map(codec::decode_ref_id)
                .transpose()
                .map_err(failure)?
        } else {
            publication.value.head
        };
        Ok(Anchor {
            tip: tip.ok_or_else(absent)?,
            publication,
            raw: values,
        })
    }
    pub(crate) async fn history_security(
        &self,
        meta: &impl NamespaceStore,
        activate: bool,
    ) -> Result<Hash, ServerError> {
        let mut values = meta
            .get_many(
                &self.pipe.shards.coordinator(&self.repo.namespace),
                &[
                    keys::repo_record(&self.repo.name),
                    keys::repo_visibility(&self.repo.name),
                    keys::grant_epoch(),
                    keys::authority_generation(),
                    keys::repo_visibility_revision(&self.repo.name),
                ],
            )
            .await
            .map_err(failure)?;
        if values.len() != 5 {
            return Err(failure(()));
        }
        codec::decode_repo_record(values[0].as_ref().ok_or_else(absent)?).map_err(failure)?;
        values[1]
            .as_ref()
            .map(codec::decode_repo_visibility)
            .transpose()
            .map_err(failure)?;
        values[2]
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(failure)?;
        values[3]
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(failure)?;
        values[4]
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(failure)?;
        if activate && values[4].is_none() {
            let key = keys::repo_visibility_revision(&self.repo.name);
            let value = codec::encode_u64(0);
            let batch = Batch::new()
                .require(Precondition::Absent(key.clone()))
                .put(key, value.clone());
            if meta
                .apply(&self.pipe.shards.coordinator(&self.repo.namespace), batch)
                .await
                .map_err(failure)?
                != BatchOutcome::Committed
            {
                return Err(absent());
            }
            values[4] = Some(value);
        }
        let mut parts = values
            .iter()
            .map(|v| match v {
                None => vec![0],
                Some(value) => [b"\x01".as_slice(), value.as_bytes()].concat(),
            })
            .collect::<Vec<_>>();
        parts.push(vec![u8::from(
            self.pipe.cfg.default_repo_visibility == crate::pipeline::RepoVisibility::Private,
        )]);
        Ok(digest_parts(parts))
    }
    pub(crate) fn history_credential(
        &self,
        authority: Option<&crate::pipeline::Authenticated>,
    ) -> Result<(Hash, u64), ServerError> {
        let mut expiry = u64::MAX;
        let mut parts = vec![b"anonymous".to_vec()];
        let crate::pipeline::AuthMode::AuthV2(auth) = &self.pipe.cfg.auth else {
            return Err(absent());
        };
        parts.push(auth.audience().as_bytes().to_vec());
        if let Some(a) = authority {
            parts[0] = a.principal.kind().as_bytes().to_vec();
            parts.push(a.principal.ed25519().ok_or_else(absent)?.to_vec());
            self.pipe
                .cfg
                .history_tokens
                .as_ref()
                .ok_or_else(absent)?
                .check_public_roles(&[*a.principal.ed25519().ok_or_else(absent)?])
                .map_err(|_| absent())?;
            let auth = a.auth.as_ref().ok_or_else(absent)?;
            expiry = ms(auth.expires_at_ms);
            if let Some(grant) = &a.write_grant {
                parts.push(grant.expose().as_bytes().to_vec());
                let cfg = self.pipe.cfg.grants.as_ref().ok_or_else(absent)?;
                let grant = mkit_attest::grant::verify_grant_owner(cfg.verifier(), grant.expose())
                    .map_err(|_| absent())?;
                expiry = expiry.min(ms(grant.statement().expiry_ms));
            }
            parts.push(a.credential_scope_digest().to_vec());
        }
        Ok((digest_parts(parts), expiry))
    }
    #[allow(clippy::too_many_arguments)] // Optional already loaded selected tip avoids duplicate serving I/O.
    async fn resume_linear(
        &self,
        session: &mut ReaderSession,
        cursor: Hash,
        limit: usize,
        mut first: Option<Node>,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        decode: &mut Budget,
    ) -> Result<(Vec<Node>, bool), ServerError> {
        let mut output = Vec::new();
        let mut current = cursor;
        let mut complete = false;
        while output.len() < limit {
            let node = if let Some(node) = first.take() {
                node
            } else {
                self.proved_node(session, current, Role::Commit, calls, admission, decode)
                    .await?
                    .ok_or_else(absent)?
            };
            let parent = node.parents().and_then(|p| p.first()).copied();
            let next = parent.filter(|_| !self.seams.takedown.stops_descent(&self.repo, &node.id));
            if let Some(next) = next {
                if session.proofs.contains(&next) {
                    return Err(absent());
                }
                self.link_node(session, &node, next)?;
                current = next;
            } else {
                complete = true;
            }
            output.push(node);
            if complete {
                break;
            }
        }
        Ok((output, complete))
    }
}
