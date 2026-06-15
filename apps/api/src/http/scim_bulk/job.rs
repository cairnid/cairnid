use axum::http::HeaderMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::{
    contract::{ScimBulkJobOperation, scim_bulk_error_response, scim_bulk_success_response},
    operations::scim_execute_bulk_operation,
    references::{
        scim_bulk_dependencies_are_ready, scim_bulk_reference_dependencies,
        scim_bulk_result_resource_id,
    },
};
use crate::http::{AppState, scim_protocol::ScimError};

pub(super) async fn execute_scim_bulk_job(
    state: &AppState,
    headers: &HeaderMap,
    operations: Vec<ScimBulkJobOperation>,
    fail_on_errors: Option<usize>,
) -> Result<Vec<Value>, ScimError> {
    let creatable_bulk_ids = operations
        .iter()
        .filter(|operation| operation.operation.method.eq_ignore_ascii_case("POST"))
        .filter_map(|operation| operation.bulk_id.as_ref().cloned())
        .collect::<HashSet<_>>();
    let dependencies = operations
        .iter()
        .map(|operation| scim_bulk_reference_dependencies(&operation.operation))
        .collect::<Result<Vec<_>, _>>()?;

    let mut error_count = 0_usize;
    let mut bulk_references = HashMap::new();
    let mut failed_bulk_ids = HashSet::new();
    let mut pending = (0..operations.len()).collect::<HashSet<_>>();
    let mut responses = std::iter::repeat_with(|| None)
        .take(operations.len())
        .collect::<Vec<Option<Value>>>();

    while !pending.is_empty() && fail_on_errors.is_none_or(|limit| error_count < limit) {
        let ready_indices = operations
            .iter()
            .enumerate()
            .filter_map(|(index, _operation)| {
                (pending.contains(&index)
                    && scim_bulk_dependencies_are_ready(
                        &dependencies[index],
                        &bulk_references,
                        &creatable_bulk_ids,
                        &failed_bulk_ids,
                    ))
                .then_some(index)
            })
            .collect::<Vec<_>>();

        if ready_indices.is_empty() {
            record_unresolved_operations(
                &operations,
                &mut pending,
                &mut failed_bulk_ids,
                &mut responses,
                fail_on_errors,
                error_count,
            );
            break;
        }

        for index in ready_indices {
            pending.remove(&index);
            let operation = &operations[index];
            let response = match scim_execute_bulk_operation(
                state,
                headers,
                &operation.operation,
                &bulk_references,
            )
            .await
            {
                Ok(result) => {
                    if operation.operation.method.eq_ignore_ascii_case("POST")
                        && let Some(bulk_id) = operation.bulk_id.as_deref()
                        && let Some(resource_id) = scim_bulk_result_resource_id(&result)
                    {
                        bulk_references.insert(bulk_id.to_owned(), resource_id);
                    }
                    scim_bulk_success_response(&operation.method, operation.bulk_id.clone(), result)
                }
                Err(error) => {
                    if operation.operation.method.eq_ignore_ascii_case("POST")
                        && let Some(bulk_id) = operation.bulk_id.as_ref()
                    {
                        failed_bulk_ids.insert(bulk_id.clone());
                    }
                    error_count += 1;
                    scim_bulk_error_response(&operation.method, operation.bulk_id.clone(), &error)
                }
            };
            responses[index] = Some(response);

            if fail_on_errors.is_some_and(|limit| error_count >= limit) {
                break;
            }
        }
    }

    Ok(responses.into_iter().flatten().collect())
}

fn record_unresolved_operations(
    operations: &[ScimBulkJobOperation],
    pending: &mut HashSet<usize>,
    failed_bulk_ids: &mut HashSet<String>,
    responses: &mut [Option<Value>],
    fail_on_errors: Option<usize>,
    mut error_count: usize,
) {
    let unresolved_error = ScimError::conflict("SCIM Bulk bulkId references could not be resolved");
    let unresolved = pending.iter().copied().collect::<Vec<_>>();
    for index in unresolved {
        let operation = &operations[index];
        pending.remove(&index);
        if operation.operation.method.eq_ignore_ascii_case("POST")
            && let Some(bulk_id) = operation.bulk_id.as_ref()
        {
            failed_bulk_ids.insert(bulk_id.clone());
        }
        responses[index] = Some(scim_bulk_error_response(
            &operation.method,
            operation.bulk_id.clone(),
            &unresolved_error,
        ));
        error_count += 1;
        if fail_on_errors.is_some_and(|limit| error_count >= limit) {
            break;
        }
    }
}
