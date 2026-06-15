use axum::http::StatusCode;
use cairn_database::MembershipMutationOutcome;

use super::super::api_response::ApiError;

pub(in crate::http::admin_groups) fn group_membership_mutation_error(
    outcome: MembershipMutationOutcome,
) -> Option<ApiError> {
    match outcome {
        MembershipMutationOutcome::Applied => None,
        MembershipMutationOutcome::NotFound => Some(ApiError::status(
            StatusCode::NOT_FOUND,
            "group or user not found",
        )),
        MembershipMutationOutcome::WouldRemoveLastOwner => Some(ApiError::status(
            StatusCode::CONFLICT,
            "administrators group must keep at least one owner",
        )),
    }
}

pub(in crate::http::admin_groups) fn group_membership_deletion_error(
    outcome: MembershipMutationOutcome,
) -> Option<ApiError> {
    match outcome {
        MembershipMutationOutcome::Applied => None,
        MembershipMutationOutcome::NotFound => Some(ApiError::status(
            StatusCode::NOT_FOUND,
            "membership not found",
        )),
        MembershipMutationOutcome::WouldRemoveLastOwner => Some(ApiError::status(
            StatusCode::CONFLICT,
            "administrators group must keep at least one owner",
        )),
    }
}
