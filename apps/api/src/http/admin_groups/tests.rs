use axum::http::StatusCode;
use cairn_database::MembershipMutationOutcome;

use super::super::api_response::ApiError;
use super::errors::{group_membership_deletion_error, group_membership_mutation_error};

#[test]
fn group_membership_mutation_errors_preserve_status_and_detail() {
    assert!(group_membership_mutation_error(MembershipMutationOutcome::Applied).is_none());

    let not_found =
        group_membership_mutation_error(MembershipMutationOutcome::NotFound).expect("error");
    assert!(matches!(
        not_found,
        ApiError::Status {
            status: StatusCode::NOT_FOUND,
            ref message,
            ..
        } if message == "group or user not found"
    ));

    let protected =
        group_membership_mutation_error(MembershipMutationOutcome::WouldRemoveLastOwner)
            .expect("error");
    assert!(matches!(
        protected,
        ApiError::Status {
            status: StatusCode::CONFLICT,
            ref message,
            ..
        } if message == "administrators group must keep at least one owner"
    ));
}

#[test]
fn group_membership_deletion_errors_preserve_status_and_detail() {
    assert!(group_membership_deletion_error(MembershipMutationOutcome::Applied).is_none());

    let not_found =
        group_membership_deletion_error(MembershipMutationOutcome::NotFound).expect("error");
    assert!(matches!(
        not_found,
        ApiError::Status {
            status: StatusCode::NOT_FOUND,
            ref message,
            ..
        } if message == "membership not found"
    ));

    let protected =
        group_membership_deletion_error(MembershipMutationOutcome::WouldRemoveLastOwner)
            .expect("error");
    assert!(matches!(
        protected,
        ApiError::Status {
            status: StatusCode::CONFLICT,
            ref message,
            ..
        } if message == "administrators group must keep at least one owner"
    ));
}
