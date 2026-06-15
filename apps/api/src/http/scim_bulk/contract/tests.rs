use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::http::{scim_operations::ScimOperationResult, scim_protocol::SCIM_ERROR_SCHEMA};

#[test]
fn scim_bulk_path_accepts_only_bounded_relative_resource_paths() {
    let user_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();

    assert_eq!(scim_bulk_path("/Users").unwrap(), ScimBulkPath::Users);
    assert_eq!(
        scim_bulk_path(&format!("Users/{user_id}")).unwrap(),
        ScimBulkPath::User(user_id)
    );
    assert_eq!(
        scim_bulk_path(&format!("/scim/v2/Groups/{group_id}")).unwrap(),
        ScimBulkPath::Group(group_id)
    );
    assert_eq!(scim_bulk_path("v2/Groups").unwrap(), ScimBulkPath::Groups);

    let absolute = scim_bulk_path("https://id.example.com/scim/v2/Users")
        .expect_err("absolute URLs are not accepted");
    assert_eq!(absolute.scim_type, Some("invalidPath"));

    let query =
        scim_bulk_path("/Users?count=1").expect_err("query strings are not accepted in Bulk");
    assert_eq!(query.scim_type, Some("invalidPath"));

    let malformed =
        scim_bulk_path("/Users/not-a-uuid").expect_err("resource paths require UUID ids");
    assert_eq!(malformed.scim_type, Some("invalidPath"));
}

#[test]
fn scim_bulk_validation_bounds_fail_on_errors_and_bulk_ids() {
    assert_eq!(scim_bulk_fail_on_errors(None).unwrap(), None);
    assert_eq!(scim_bulk_fail_on_errors(Some(1)).unwrap(), Some(1));

    let invalid_fail_on_errors =
        scim_bulk_fail_on_errors(Some(0)).expect_err("zero is not a valid threshold");
    assert_eq!(invalid_fail_on_errors.scim_type, Some("invalidValue"));

    let operations = vec![
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some(" user-one ".to_owned()),
            path: "/Users".to_owned(),
            data: None,
        },
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some("user-one".to_owned()),
            path: "/Users".to_owned(),
            data: None,
        },
    ];
    let duplicate =
        validate_scim_bulk_ids(&operations).expect_err("trimmed bulkIds must be unique");
    assert_eq!(duplicate.scim_type, Some("invalidValue"));
}

#[test]
fn scim_bulk_response_entries_use_standard_status_and_error_shape() {
    let success = scim_bulk_success_response(
        "POST",
        Some("user-one".to_owned()),
        ScimOperationResult::json(
            StatusCode::CREATED,
            json!({ "id": "user-id" }),
            Some("http://localhost:8080/scim/v2/Users/user-id".to_owned()),
        ),
    );
    assert_eq!(success["method"], json!("POST"));
    assert_eq!(success["bulkId"], json!("user-one"));
    assert_eq!(success["status"], json!("201"));
    assert_eq!(
        success["location"],
        json!("http://localhost:8080/scim/v2/Users/user-id")
    );
    assert_eq!(success["response"]["id"], json!("user-id"));

    let error = crate::http::scim_protocol::ScimError::invalid_path("unsupported SCIM Bulk path");
    let failure = scim_bulk_error_response("PATCH", None, &error);
    assert_eq!(failure["method"], json!("PATCH"));
    assert_eq!(failure["status"], json!("400"));
    assert_eq!(failure["response"]["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(failure["response"]["scimType"], json!("invalidPath"));
}
