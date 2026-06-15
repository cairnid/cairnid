use axum::http::HeaderMap;
use std::collections::HashMap;
use uuid::Uuid;

use super::super::{
    AppState,
    scim_input::{ScimGroupRequest, ScimPatchRequest, ScimUserRequest},
    scim_operations::{
        ScimOperationResult, scim_create_group_operation, scim_create_user_operation,
        scim_delete_group_operation, scim_delete_user_operation, scim_patch_group_operation,
        scim_patch_user_operation, scim_replace_group_operation, scim_replace_user_operation,
    },
    scim_protocol::ScimError,
};
use super::{
    contract::{
        ScimBulkMethod, ScimBulkOperationRequest, ScimBulkPath, scim_bulk_data,
        scim_bulk_expect_no_data, scim_bulk_path, scim_required_bulk_id,
    },
    references::scim_resolve_bulk_path_references,
};

pub(in crate::http::scim_bulk) async fn scim_execute_bulk_operation(
    state: &AppState,
    headers: &HeaderMap,
    operation: &ScimBulkOperationRequest,
    bulk_references: &HashMap<String, Uuid>,
) -> Result<ScimOperationResult, ScimError> {
    let method = ScimBulkMethod::parse(&operation.method)?;
    let resolved_path = scim_resolve_bulk_path_references(&operation.path, bulk_references)?;
    let path = scim_bulk_path(&resolved_path)?;

    match (method, path) {
        (ScimBulkMethod::Post, ScimBulkPath::Users) => {
            let _bulk_id = scim_required_bulk_id(operation.bulk_id.as_deref())?;
            let payload = scim_bulk_data::<ScimUserRequest>(operation, "User", bulk_references)?;
            scim_create_user_operation(state, headers, payload).await
        }
        (ScimBulkMethod::Put, ScimBulkPath::User(user_id)) => {
            let payload = scim_bulk_data::<ScimUserRequest>(operation, "User", bulk_references)?;
            scim_replace_user_operation(state, headers, user_id, payload).await
        }
        (ScimBulkMethod::Patch, ScimBulkPath::User(user_id)) => {
            let payload =
                scim_bulk_data::<ScimPatchRequest>(operation, "PatchOp", bulk_references)?;
            scim_patch_user_operation(state, headers, user_id, payload).await
        }
        (ScimBulkMethod::Delete, ScimBulkPath::User(user_id)) => {
            scim_bulk_expect_no_data(operation)?;
            scim_delete_user_operation(state, headers, user_id).await
        }
        (ScimBulkMethod::Post, ScimBulkPath::Groups) => {
            let _bulk_id = scim_required_bulk_id(operation.bulk_id.as_deref())?;
            let payload = scim_bulk_data::<ScimGroupRequest>(operation, "Group", bulk_references)?;
            scim_create_group_operation(state, headers, payload).await
        }
        (ScimBulkMethod::Put, ScimBulkPath::Group(group_id)) => {
            let payload = scim_bulk_data::<ScimGroupRequest>(operation, "Group", bulk_references)?;
            scim_replace_group_operation(state, headers, group_id, payload).await
        }
        (ScimBulkMethod::Patch, ScimBulkPath::Group(group_id)) => {
            let payload =
                scim_bulk_data::<ScimPatchRequest>(operation, "PatchOp", bulk_references)?;
            scim_patch_group_operation(state, headers, group_id, payload).await
        }
        (ScimBulkMethod::Delete, ScimBulkPath::Group(group_id)) => {
            scim_bulk_expect_no_data(operation)?;
            scim_delete_group_operation(state, headers, group_id).await
        }
        _ => Err(ScimError::invalid_value(
            "unsupported SCIM Bulk operation for path and method",
        )),
    }
}
