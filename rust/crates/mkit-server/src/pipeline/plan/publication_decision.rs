//! Typed publication decision and checked physical projection.
use crate::{
    error::ServerError,
    store::{
        StoreError, Value,
        publication::{Advance, Publication},
    },
};
use mkit_primitives::{
    decision::{
        Guarded, Observed, PublicationFact, RequiredGuard, WriteDecision,
        ref_write::{RefPublication, check_guard_completeness, decide_ref_publication},
    },
    evidence::{RepositoryId, Revision},
};

fn fact(state: &Publication) -> PublicationFact {
    // Opaque host observation handle; no portable numeric revision encoding.
    let generation = if state.generation == 0 {
        [0; 32]
    } else {
        mkit_core::hash::hash(crate::store::codec::encode_u64(state.generation).as_bytes())
    };
    PublicationFact::new(
        Revision(generation),
        state.sequence,
        state.published,
        state.boundary,
        state.value.head,
        state.value.packmap,
    )
}

pub(super) fn decide(
    repository: RepositoryId,
    prior: Option<&Value>,
    advance: &Advance,
    deleted: bool,
) -> Result<Guarded<WriteDecision>, ServerError> {
    let current = Publication::decode(prior).map_err(crate::pipeline::meta_error)?;
    let observed = prior.map_or(Observed::Absent(Revision([0; 32])), |raw| {
        Observed::Present {
            value: fact(&current),
            revision: Revision(mkit_core::hash::hash(raw.as_bytes())),
        }
    });
    let request = RefPublication {
        repository,
        head: advance.value.head,
        packmap: advance.value.packmap,
        deleted,
        publishable: advance.state.publishable(),
        max_unpublished: crate::store::publication::MAX_UNPUBLISHED_ADVANCES,
    };
    let sealed = decide_ref_publication(&request, &observed).map_err(|failure| {
        crate::pipeline::meta_error(StoreError::Corrupt(failure.code.as_str().into()))
    })?;
    if matches!(sealed.decision(), WriteDecision::Retry(_)) {
        return Err(crate::pipeline::meta_error(StoreError::unavailable(
            "publication backlog full",
        )));
    }
    Ok(sealed)
}

/// Validate the complete physical projection before any caller can commit it.
/// The existing append encoder retains advance obligations, membership relays,
/// and timer representation. Its publication result must equal the pure effect.
pub(super) fn check_projection(
    sealed: &Guarded<WriteDecision>,
    prior: Option<&Value>,
    conditions: &[crate::store::Precondition],
    publication_key: &crate::store::Key,
    lowered: &Publication,
) -> Result<(), ServerError> {
    let WriteDecision::Apply(effects) = sealed.decision() else {
        return Err(super::internal("unsupported publication decision"));
    };
    if effects.publication.len() != 1 || effects.publication[0].next != fact(lowered) {
        return Err(super::internal(
            "publication projection differs from decision",
        ));
    }
    let expected = crate::store::outbox::guard(publication_key.clone(), prior);
    if !conditions.contains(&expected) {
        return Err(super::internal("publication guard omitted"));
    }
    let discharged: Vec<_> = sealed.required_guards().iter().filter(|guard|
        matches!(guard, RequiredGuard::Publication { repository, .. } if *repository == sealed.repository())
    ).cloned().collect();
    check_guard_completeness(sealed, &discharged).map_err(|e| super::internal(e.code.as_str()))
}
