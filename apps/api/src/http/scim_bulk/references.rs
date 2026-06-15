use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::super::{
    scim_input::optional_scim_str, scim_operations::ScimOperationResult, scim_protocol::ScimError,
};
use super::contract::ScimBulkOperationRequest;

pub(super) fn scim_bulk_reference_dependencies(
    operation: &ScimBulkOperationRequest,
) -> Result<HashSet<String>, ScimError> {
    let mut references = HashSet::new();
    scim_collect_bulk_path_references(&operation.path, &mut references)?;
    if let Some(data) = operation.data.as_ref() {
        scim_collect_bulk_value_references(data, &mut references)?;
    }
    Ok(references)
}

fn scim_collect_bulk_path_references(
    path: &str,
    references: &mut HashSet<String>,
) -> Result<(), ScimError> {
    for segment in path.split('/') {
        if let Some(reference) = segment.strip_prefix("bulkId:") {
            references.insert(scim_bulk_reference_name(reference)?);
        }
    }
    Ok(())
}

fn scim_collect_bulk_value_references(
    value: &Value,
    references: &mut HashSet<String>,
) -> Result<(), ScimError> {
    match value {
        Value::String(value) => {
            if let Some(reference) = value.strip_prefix("bulkId:") {
                references.insert(scim_bulk_reference_name(reference)?);
            }
        }
        Value::Array(values) => {
            for value in values {
                scim_collect_bulk_value_references(value, references)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                scim_collect_bulk_value_references(value, references)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

pub(super) fn scim_bulk_dependencies_are_ready(
    dependencies: &HashSet<String>,
    bulk_references: &HashMap<String, Uuid>,
    creatable_bulk_ids: &HashSet<String>,
    failed_bulk_ids: &HashSet<String>,
) -> bool {
    dependencies.iter().all(|reference| {
        bulk_references.contains_key(reference)
            || failed_bulk_ids.contains(reference)
            || !creatable_bulk_ids.contains(reference)
    })
}

pub(super) fn scim_resolve_bulk_path_references(
    path: &str,
    bulk_references: &HashMap<String, Uuid>,
) -> Result<String, ScimError> {
    let mut resolved = Vec::new();
    for segment in path.split('/') {
        if let Some(reference) = segment.strip_prefix("bulkId:") {
            let resource_id = scim_bulk_reference_id(reference, bulk_references)?;
            resolved.push(resource_id.to_string());
        } else {
            resolved.push(segment.to_owned());
        }
    }
    Ok(resolved.join("/"))
}

pub(super) fn scim_resolve_bulk_value_references(
    value: &Value,
    bulk_references: &HashMap<String, Uuid>,
) -> Result<Value, ScimError> {
    match value {
        Value::String(value) => {
            if let Some(reference) = value.strip_prefix("bulkId:") {
                Ok(json!(
                    scim_bulk_reference_id(reference, bulk_references)?.to_string()
                ))
            } else {
                Ok(Value::String(value.clone()))
            }
        }
        Value::Array(values) => values
            .iter()
            .map(|value| scim_resolve_bulk_value_references(value, bulk_references))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut resolved = serde_json::Map::new();
            for (key, value) in values {
                resolved.insert(
                    key.clone(),
                    scim_resolve_bulk_value_references(value, bulk_references)?,
                );
            }
            Ok(Value::Object(resolved))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
    }
}

fn scim_bulk_reference_id(
    reference: &str,
    bulk_references: &HashMap<String, Uuid>,
) -> Result<Uuid, ScimError> {
    let reference = scim_bulk_reference_name(reference)?;
    bulk_references.get(&reference).copied().ok_or_else(|| {
        ScimError::invalid_value(
            "SCIM Bulk bulkId reference must point to a successful POST operation",
        )
    })
}

fn scim_bulk_reference_name(reference: &str) -> Result<String, ScimError> {
    optional_scim_str("bulkId reference", Some(reference), 80)?
        .ok_or_else(|| ScimError::invalid_value("SCIM Bulk bulkId reference cannot be empty"))
}

pub(super) fn scim_bulk_result_resource_id(result: &ScimOperationResult) -> Option<Uuid> {
    result
        .body
        .as_ref()
        .and_then(|body| body.get("id"))
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}
