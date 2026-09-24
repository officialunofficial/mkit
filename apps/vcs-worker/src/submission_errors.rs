// SPDX-License-Identifier: MIT OR Apache-2.0
//! Exact core-error to hosted-refusal classification, shared with native tests.

use mkit_core::{
    pack::RawPackError,
    partial::{InspectError, PartialError, SnapshotWalkError, StagedUpdateError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValidationFailure {
    Resource,
    Invalid,
    Unavailable,
}

pub(crate) fn staged(error: &StagedUpdateError) -> ValidationFailure {
    match error {
        StagedUpdateError::Budget
        | StagedUpdateError::Pack(RawPackError::Limit(_))
        | StagedUpdateError::Inspect(InspectError::Limit(_))
        | StagedUpdateError::Partial(
            PartialError::WitnessTooLarge
            | PartialError::WorkspaceTooLarge
            | PartialError::ValidationBudgetExceeded
            | PartialError::RecipientBudgetExceeded
            | PartialError::SubmissionTooLarge,
        ) => ValidationFailure::Resource,
        StagedUpdateError::Inconsistent | StagedUpdateError::Partial(PartialError::Source(_)) => {
            ValidationFailure::Unavailable
        }
        _ => ValidationFailure::Invalid,
    }
}

pub(crate) fn walk(error: SnapshotWalkError, candidate: bool) -> ValidationFailure {
    match error {
        SnapshotWalkError::BudgetExceeded => ValidationFailure::Resource,
        SnapshotWalkError::InconsistentAccounting => ValidationFailure::Unavailable,
        _ if candidate => ValidationFailure::Invalid,
        _ => ValidationFailure::Unavailable,
    }
}

pub(crate) fn inspect(error: &InspectError, candidate: bool) -> ValidationFailure {
    match error {
        InspectError::Limit(_) => ValidationFailure::Resource,
        _ if candidate => ValidationFailure::Invalid,
        _ => ValidationFailure::Unavailable,
    }
}

pub(crate) fn partial(error: &PartialError) -> ValidationFailure {
    match error {
        PartialError::WitnessTooLarge
        | PartialError::WorkspaceTooLarge
        | PartialError::ValidationBudgetExceeded
        | PartialError::RecipientBudgetExceeded
        | PartialError::SubmissionTooLarge => ValidationFailure::Resource,
        PartialError::Source(_) => ValidationFailure::Unavailable,
        _ => ValidationFailure::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_budget_variants_are_resource_not_invalid() {
        assert_eq!(
            staged(&StagedUpdateError::Budget),
            ValidationFailure::Resource
        );
        assert_eq!(
            staged(&StagedUpdateError::Pack(RawPackError::Limit("pack"))),
            ValidationFailure::Resource
        );
        assert_eq!(
            staged(&StagedUpdateError::Inspect(InspectError::Limit("object"))),
            ValidationFailure::Resource
        );
        assert_eq!(
            staged(&StagedUpdateError::Partial(
                PartialError::SubmissionTooLarge
            )),
            ValidationFailure::Resource
        );
        assert_eq!(
            walk(SnapshotWalkError::BudgetExceeded, true),
            ValidationFailure::Resource
        );
        assert_eq!(
            walk(SnapshotWalkError::BudgetExceeded, false),
            ValidationFailure::Resource
        );
        assert_eq!(
            inspect(&InspectError::Limit("tree"), true),
            ValidationFailure::Resource
        );
        assert_eq!(
            partial(&PartialError::WitnessTooLarge),
            ValidationFailure::Resource
        );
    }

    #[test]
    fn malformed_candidate_and_inconsistent_ledger_are_distinct() {
        assert_eq!(
            staged(&StagedUpdateError::Invalid),
            ValidationFailure::Invalid
        );
        assert_eq!(
            staged(&StagedUpdateError::Inconsistent),
            ValidationFailure::Unavailable
        );
        assert_eq!(
            walk(SnapshotWalkError::WrongId, true),
            ValidationFailure::Invalid
        );
        assert_eq!(
            walk(SnapshotWalkError::WrongId, false),
            ValidationFailure::Unavailable
        );
        assert_eq!(
            walk(SnapshotWalkError::InconsistentAccounting, true),
            ValidationFailure::Unavailable
        );
        assert_eq!(
            inspect(&InspectError::Corrupt, true),
            ValidationFailure::Invalid
        );
        assert_eq!(
            inspect(&InspectError::Corrupt, false),
            ValidationFailure::Unavailable
        );
    }
}
