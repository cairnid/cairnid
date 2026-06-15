use super::{
    contract::{
        ScimBulkOperationRequest, scim_bulk_data, scim_bulk_error_response,
        scim_bulk_job_operations,
    },
    references::{
        scim_bulk_dependencies_are_ready, scim_bulk_reference_dependencies,
        scim_resolve_bulk_path_references, scim_resolve_bulk_value_references,
    },
};
use crate::http::{
    scim_input::{ScimGroupRequest, scim_group_input},
    scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_PATCH_OP_SCHEMA, SCIM_USER_SCHEMA, ScimError},
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[test]
fn scim_bulk_resolves_prior_bulk_id_references_in_paths_and_data() {
    let user_id = Uuid::new_v4();
    let mut references = HashMap::new();
    references.insert("user-one".to_owned(), user_id);

    let operation = ScimBulkOperationRequest {
        method: "POST".to_owned(),
        bulk_id: Some("group-one".to_owned()),
        path: "/Groups".to_owned(),
        data: Some(json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Engineering",
            "members": [{
                "value": "bulkId:user-one",
                "type": "User"
            }]
        })),
    };

    let request =
        scim_bulk_data::<ScimGroupRequest>(&operation, "Group", &references).expect("group");
    let input = scim_group_input(request).expect("group input");
    assert_eq!(input.member_user_ids, vec![user_id]);

    let resolved_path = scim_resolve_bulk_path_references("/Users/bulkId:user-one", &references)
        .expect("resolved path");
    assert_eq!(resolved_path, format!("/Users/{user_id}"));

    let error = scim_resolve_bulk_value_references(&json!("bulkId:future-user"), &references)
        .expect_err("unresolved references fail during operation execution");
    assert_eq!(error.scim_type, Some("invalidValue"));
}

#[test]
fn scim_bulk_dependency_readiness_supports_forward_references() {
    let operations = vec![
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some("group-one".to_owned()),
            path: "/Groups".to_owned(),
            data: Some(json!({
                "schemas": [SCIM_GROUP_SCHEMA],
                "displayName": "Engineering",
                "members": [{
                    "value": "bulkId:user-one",
                    "type": "User"
                }]
            })),
        },
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some("user-one".to_owned()),
            path: "/Users".to_owned(),
            data: Some(json!({
                "schemas": [SCIM_USER_SCHEMA],
                "userName": "ada@example.com"
            })),
        },
        ScimBulkOperationRequest {
            method: "PATCH".to_owned(),
            bulk_id: None,
            path: "/Users/bulkId:user-one".to_owned(),
            data: Some(json!({
                "schemas": [SCIM_PATCH_OP_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "displayName",
                    "value": "Ada Lovelace"
                }]
            })),
        },
    ];
    let operations = scim_bulk_job_operations(operations).expect("valid job operations");
    let creatable_bulk_ids = operations
        .iter()
        .filter(|operation| operation.operation.method.eq_ignore_ascii_case("POST"))
        .filter_map(|operation| operation.bulk_id.as_ref().cloned())
        .collect::<HashSet<_>>();
    let dependencies = operations
        .iter()
        .map(|operation| scim_bulk_reference_dependencies(&operation.operation))
        .collect::<Result<Vec<_>, _>>()
        .expect("valid dependencies");
    let mut references = HashMap::new();
    let failed_bulk_ids = HashSet::new();

    assert!(!scim_bulk_dependencies_are_ready(
        &dependencies[0],
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));
    assert!(scim_bulk_dependencies_are_ready(
        &dependencies[1],
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));
    assert!(!scim_bulk_dependencies_are_ready(
        &dependencies[2],
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));

    let user_id = Uuid::new_v4();
    references.insert("user-one".to_owned(), user_id);
    assert!(scim_bulk_dependencies_are_ready(
        &dependencies[0],
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));
    assert!(scim_bulk_dependencies_are_ready(
        &dependencies[2],
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));
    assert_eq!(
        scim_resolve_bulk_path_references("/Users/bulkId:user-one", &references)
            .expect("resolved path"),
        format!("/Users/{user_id}")
    );
}

#[test]
fn scim_bulk_dependency_readiness_fails_closed_for_unresolvable_references() {
    let unknown_operation = ScimBulkOperationRequest {
        method: "PATCH".to_owned(),
        bulk_id: None,
        path: "/Groups/bulkId:missing-group".to_owned(),
        data: None,
    };
    let unknown_dependencies =
        scim_bulk_reference_dependencies(&unknown_operation).expect("dependencies");
    let references = HashMap::new();
    let creatable_bulk_ids = HashSet::new();
    let failed_bulk_ids = HashSet::new();

    assert!(scim_bulk_dependencies_are_ready(
        &unknown_dependencies,
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));
    let unknown_error = scim_resolve_bulk_path_references(&unknown_operation.path, &references)
        .expect_err("unknown bulkId should fail during execution");
    assert_eq!(unknown_error.scim_type, Some("invalidValue"));

    let mut creatable_bulk_ids = HashSet::new();
    creatable_bulk_ids.insert("failed-user".to_owned());
    let mut failed_bulk_ids = HashSet::new();
    failed_bulk_ids.insert("failed-user".to_owned());
    let failed_operation = ScimBulkOperationRequest {
        method: "PATCH".to_owned(),
        bulk_id: None,
        path: "/Users/bulkId:failed-user".to_owned(),
        data: None,
    };
    let failed_dependencies =
        scim_bulk_reference_dependencies(&failed_operation).expect("dependencies");
    assert!(scim_bulk_dependencies_are_ready(
        &failed_dependencies,
        &references,
        &creatable_bulk_ids,
        &failed_bulk_ids
    ));

    let circular_operations = vec![
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some("group-a".to_owned()),
            path: "/Groups".to_owned(),
            data: Some(json!({
                "schemas": [SCIM_GROUP_SCHEMA],
                "displayName": "Group A",
                "members": [{ "value": "bulkId:group-b", "type": "Group" }]
            })),
        },
        ScimBulkOperationRequest {
            method: "POST".to_owned(),
            bulk_id: Some("group-b".to_owned()),
            path: "/Groups".to_owned(),
            data: Some(json!({
                "schemas": [SCIM_GROUP_SCHEMA],
                "displayName": "Group B",
                "members": [{ "value": "bulkId:group-a", "type": "Group" }]
            })),
        },
    ];
    let circular_operations =
        scim_bulk_job_operations(circular_operations).expect("valid job operations");
    let circular_creatable = circular_operations
        .iter()
        .filter_map(|operation| operation.bulk_id.as_ref().cloned())
        .collect::<HashSet<_>>();
    let circular_dependencies = circular_operations
        .iter()
        .map(|operation| scim_bulk_reference_dependencies(&operation.operation))
        .collect::<Result<Vec<_>, _>>()
        .expect("valid dependencies");
    let failed_bulk_ids = HashSet::new();

    assert!(!scim_bulk_dependencies_are_ready(
        &circular_dependencies[0],
        &references,
        &circular_creatable,
        &failed_bulk_ids
    ));
    assert!(!scim_bulk_dependencies_are_ready(
        &circular_dependencies[1],
        &references,
        &circular_creatable,
        &failed_bulk_ids
    ));

    let conflict = ScimError::conflict("SCIM Bulk bulkId references could not be resolved");
    let response = scim_bulk_error_response("POST", Some("group-a".to_owned()), &conflict);
    assert_eq!(response["status"], json!("409"));
    assert_eq!(
        response["response"]["detail"],
        json!("SCIM Bulk bulkId references could not be resolved")
    );
}
