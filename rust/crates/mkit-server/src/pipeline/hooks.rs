//! The PRD §5.4 extension points as traits, with the defaults M0 ships.
//!
//! The stage surface is settled now. M0 runs stages 0 to 6; the receipt
//! (7) and outcome (8) hooks exist but the pipeline does not call them
//! until M3/M5. `HookSet` grows by associated type when a later work
//! package adds a stage (`ContentInspector`, `LeasePolicy`).

use core::future::Future;
use std::sync::Arc;

use mkit_core::protocol::PackKey;

use crate::error::{Redacted, ServerError};
use crate::op::{AuthzFacts, Operation};
use crate::quota::{QuotaCharge, QuotaLimits, QuotaScope};
use crate::rt::{MaybeSend, MaybeSync};
use crate::store::BlobKey;

/// Stage 2: may the principal do this? Runs before any quota or replay
/// record is allocated; an error is returned as is. In Multi addressing,
/// `op.authz` already carries built-in owner/grant facts (SPEC-SERVER §6.2),
/// which are preserved for admission. Single addressing uses returned facts.
/// M2 adds grants and their epoch preconditions.
pub trait Authorizer: MaybeSend + MaybeSync {
    /// Whether this is the open default, unsuitable as an authority source.
    fn is_open(&self) -> bool {
        false
    }

    /// Allow `op` with the facts established, or return the error to
    /// answer with.
    fn authorize(
        &self,
        op: &Operation,
    ) -> impl Future<Output = Result<AuthzFacts, ServerError>> + MaybeSend;
}

/// Stage 3 input: the full PRD §5.4 field set, present from M0
/// (reconciliation R-10). M0 fills `op`, `declared_bytes`, `pack_id`,
/// `idempotency_key` (the auth v2 nonce) and `write_quota`;
/// Creation fields are the pre-admission observation from `op.creation`;
/// racing first writes may both observe creation. `new_to_repo_bytes` stays
/// `None` until membership, and the grant comes from `op.authz` (M2). Bytes new to
/// the store are deliberately absent: they would be a pricing oracle.
#[derive(Clone)]
#[non_exhaustive]
pub struct AdmissionInput<'a> {
    /// The operation, with its verified principal.
    pub op: &'a Operation,
    /// Bytes the request declares: 0 for ref writes.
    pub declared_bytes: u64,
    /// The pack an upload names.
    pub pack_id: Option<PackKey>,
    /// Whether the namespace was absent before admission; racing writes may both see true.
    pub creates_namespace: bool,
    /// Whether the repository was absent before admission; racing writes may both see true.
    pub creates_repo: bool,
    /// Bytes new to the repository, known only from membership (M1).
    pub new_to_repo_bytes: Option<u64>,
    /// The idempotency key: the auth v2 nonce of a signed write.
    pub idempotency_key: Option<&'a str>,
    /// The deployment's default write quota (`PipelineConfig::write_quota`),
    /// which [`DefaultAdmission`] charges.
    pub write_quota: Option<QuotaLimits>,
    /// Canonical server audience, when auth v2 supplies one.
    pub audience: Option<&'a str>,
    /// Selected payment credentials; values never appear in debug output.
    pub credential_headers: &'a [CredentialHeader],
}

impl core::fmt::Debug for AdmissionInput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmissionInput")
            .field("op", &self.op)
            .field("declared_bytes", &self.declared_bytes)
            .field("pack_id", &self.pack_id)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

/// One selected credential header, with a value hidden from diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialHeader {
    /// Header name.
    pub name: String,
    /// Secret header value.
    pub value: Redacted,
}

impl core::fmt::Debug for CredentialHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialHeader")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<'a> AdmissionInput<'a> {
    /// An input for `op` with every optional field unset.
    #[must_use]
    pub fn new(op: &'a Operation) -> Self {
        Self {
            op,
            declared_bytes: 0,
            pack_id: None,
            creates_namespace: op.creation.namespace,
            creates_repo: op.creation.repo,
            new_to_repo_bytes: None,
            idempotency_key: op.auth.as_ref().map(|auth| auth.nonce.as_str()),
            write_quota: None,
            audience: None,
            credential_headers: &[],
        }
    }
}

/// One admission challenge (SPEC-TRANSPORT-CONNECT §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Lowercase authentication scheme, e.g. `mpp`.
    pub scheme: String,
    /// The challenge parameters.
    pub value: String,
}

/// What stage 3 decided. A challenge or a denial allocates nothing, and no
/// code path stores either as a replay result.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AdmissionDecision {
    /// Proceed, applying `charges` in the write's batch. Build it with
    /// [`AdmissionDecision::allow`].
    #[non_exhaustive]
    Allow {
        /// Quota charges the batch applies atomically with the write.
        charges: Vec<QuotaCharge>,
        /// The reservation id outcomes are keyed by (M3).
        reservation: Option<String>,
        /// Success-only payment receipt headers.
        response_headers: Vec<(String, String)>,
        /// Hook-owned external reference, carried for later receipt storage.
        external_ref: Option<String>,
    },
    /// Ask for credentials on a unary operation.
    #[non_exhaustive]
    Challenge {
        /// The challenges offered.
        challenges: Vec<Challenge>,
        /// Human-readable description.
        description: String,
        /// Challenge pass-through headers.
        response_headers: Vec<(String, String)>,
    },
    /// Refuse with this error.
    Deny(ServerError),
}

impl AdmissionDecision {
    /// `Allow` with `charges` and no reservation.
    #[must_use]
    pub fn allow(charges: Vec<QuotaCharge>) -> Self {
        Self::Allow {
            charges,
            reservation: None,
            response_headers: Vec::new(),
            external_ref: None,
        }
    }

    /// Set the reservation of an `Allow`; other decisions are unchanged.
    #[must_use]
    pub fn with_reservation(mut self, id: impl Into<String>) -> Self {
        if let Self::Allow { reservation, .. } = &mut self {
            *reservation = Some(id.into());
        }
        self
    }

    /// Attach a validated later pass-through response header.
    #[must_use]
    pub fn with_response_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match &mut self {
            Self::Allow {
                response_headers, ..
            }
            | Self::Challenge {
                response_headers, ..
            } => {
                response_headers.push((name.into(), value.into()));
            }
            Self::Deny(_) => {}
        }
        self
    }

    /// Set the hook's external reference on an Allow.
    #[must_use]
    pub fn with_external_ref(mut self, reference: impl Into<String>) -> Self {
        if let Self::Allow { external_ref, .. } = &mut self {
            *external_ref = Some(reference.into());
        }
        self
    }

    /// Build an admission challenge.
    #[must_use]
    pub fn challenge(challenges: Vec<Challenge>, description: impl Into<String>) -> Self {
        Self::Challenge {
            challenges,
            description: description.into(),
            response_headers: Vec::new(),
        }
    }

    /// Build an explicit denial.
    #[must_use]
    pub fn deny(message: impl Into<String>) -> Self {
        Self::Deny(ServerError::permission_denied(message.into()))
    }
}

/// Stage 3: admission, e.g. an abuse quota or a payment.
pub trait Admission: MaybeSend + MaybeSync {
    /// Whether this is the default quota-only admission (D27).
    fn is_default(&self) -> bool {
        false
    }

    /// Decide whether a new write may proceed.
    fn admit(
        &self,
        input: &AdmissionInput<'_>,
    ) -> impl Future<Output = Result<AdmissionDecision, ServerError>> + MaybeSend;
}

/// Stage 5: checks before `apply`. `pack` is set for uploads (M0-05b).
pub trait PreReceive: MaybeSend + MaybeSync {
    /// Accept `op`, or return the error to answer with.
    fn check(
        &self,
        op: &Operation,
        pack: Option<&BlobKey>,
    ) -> impl Future<Output = Result<(), ServerError>> + MaybeSend;
}

/// Stage 7: signs a storage receipt for a committed write (M3).
pub trait ReceiptSigner: MaybeSend + MaybeSync {
    /// The receipt for `op`, if any.
    fn sign(&self, op: &Operation) -> impl Future<Output = Option<Vec<u8>>> + MaybeSend;
}

use super::durable_outcome::{DeliveryError, Outcome};

/// Stage 8 receives outcomes at least once. A duplicate may arrive even
/// after `Ok`; different reservations can arrive in any order. The sink must
/// deduplicate by `reservation_id`.
pub trait OutcomeSink: MaybeSend + MaybeSync {
    /// Deliver one terminal outcome. Every error leaves it queued for retry.
    fn deliver(
        &self,
        outcome: &Outcome,
    ) -> impl Future<Output = Result<(), DeliveryError>> + MaybeSend;

    /// Deliver a batch sequentially by default; each result is independent.
    fn deliver_batch(
        &self,
        outcomes: &[Outcome],
    ) -> impl Future<Output = Vec<Result<(), DeliveryError>>> + MaybeSend {
        async move {
            let mut results = Vec::with_capacity(outcomes.len());
            for outcome in outcomes {
                results.push(self.deliver(outcome).await);
            }
            results
        }
    }
}

impl<T: OutcomeSink> OutcomeSink for Arc<T> {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        T::deliver(self, outcome).await
    }
}

/// The hooks the pipeline runs, one associated type per stage.
pub trait HookSet: MaybeSend + MaybeSync {
    /// Stage 2.
    type Az: Authorizer;
    /// Stage 3.
    type Ad: Admission;
    /// Stage 5.
    type Pr: PreReceive;
    /// Stage 7.
    type Rs: ReceiptSigner;
    /// Stage 8.
    type Os: OutcomeSink;

    /// The authorizer.
    fn authorizer(&self) -> &Self::Az;
    /// The admission step.
    fn admission(&self) -> &Self::Ad;
    /// The pre-receive checks.
    fn pre_receive(&self) -> &Self::Pr;
    /// The receipt signer.
    fn receipts(&self) -> &Self::Rs;
    /// The outcome sink.
    fn outcomes(&self) -> &Self::Os;
}

/// A [`HookSet`] from one value per stage; `Hooks::default()` is M0's.
#[derive(Debug, Clone, Default)]
pub struct Hooks<
    Az = OpenAuthorizer,
    Ad = DefaultAdmission,
    Pr = NoPreReceive,
    Rs = NoReceipts,
    Os = NoOutcomes,
> {
    /// Stage 2.
    pub authorizer: Az,
    /// Stage 3.
    pub admission: Ad,
    /// Stage 5.
    pub pre_receive: Pr,
    /// Stage 7.
    pub receipts: Rs,
    /// Stage 8.
    pub outcomes: Os,
}

impl Hooks {
    /// M0's hooks: open authorization and the default admission quota.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<Az, Ad, Pr, Rs, Os> HookSet for Hooks<Az, Ad, Pr, Rs, Os>
where
    Az: Authorizer,
    Ad: Admission,
    Pr: PreReceive,
    Rs: ReceiptSigner,
    Os: OutcomeSink,
{
    type Az = Az;
    type Ad = Ad;
    type Pr = Pr;
    type Rs = Rs;
    type Os = Os;

    fn authorizer(&self) -> &Az {
        &self.authorizer
    }
    fn admission(&self) -> &Ad {
        &self.admission
    }
    fn pre_receive(&self) -> &Pr {
        &self.pre_receive
    }
    fn receipts(&self) -> &Rs {
        &self.receipts
    }
    fn outcomes(&self) -> &Os {
        &self.outcomes
    }
}

/// Allows everything: single-repository deployments (`write_policy =
/// open`), where authentication is the only gate.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAuthorizer;

impl Authorizer for OpenAuthorizer {
    fn is_open(&self) -> bool {
        true
    }

    async fn authorize(&self, _op: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts::default())
    }
}

/// Today's abuse quota: a signed write charges one operation and its
/// declared bytes to its signer's counter in its namespace, under
/// `input.write_quota`. Unsigned writes and deployments without a quota
/// are allowed with no charge. WP-1.26 adds the per-namespace charge.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultAdmission;

impl Admission for DefaultAdmission {
    fn is_default(&self) -> bool {
        true
    }

    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let charges = match (input.write_quota, &input.op.auth) {
            (Some(limits), Some(auth)) if input.op.procedure().is_write() => vec![QuotaCharge {
                scope: QuotaScope::for_signer(&input.op.repo.namespace, &auth.signer),
                bytes: input.declared_bytes,
                limits,
            }],
            _ => Vec::new(),
        };
        Ok(AdmissionDecision::allow(charges))
    }
}

/// No pre-receive checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPreReceive;

impl PreReceive for NoPreReceive {
    async fn check(&self, _op: &Operation, _pack: Option<&BlobKey>) -> Result<(), ServerError> {
        Ok(())
    }
}

/// No receipts.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReceipts;

impl ReceiptSigner for NoReceipts {
    async fn sign(&self, _op: &Operation) -> Option<Vec<u8>> {
        None
    }
}

/// Acknowledges outcomes without external delivery.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOutcomes;

impl OutcomeSink for NoOutcomes {
    async fn deliver(&self, _row: &Outcome) -> Result<(), DeliveryError> {
        Ok(())
    }
}
