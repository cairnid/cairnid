use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::types::{ScimBulkJobOperation, ScimBulkOperationRequest};
use crate::http::{
    scim_bulk::references::scim_resolve_bulk_value_references,
    scim_input::optional_scim_str,
    scim_protocol::{SCIM_BULK_MAX_OPERATIONS, ScimError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http::scim_bulk) enum ScimBulkMethod {
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http::scim_bulk) enum ScimBulkPath {
    Users,
    User(Uuid),
    Groups,
    Group(Uuid),
}

impl ScimBulkMethod {
    pub(in crate::http::scim_bulk) fn parse(value: &str) -> Result<Self, ScimError> {
        if value.eq_ignore_ascii_case("POST") {
            Ok(Self::Post)
        } else if value.eq_ignore_ascii_case("PUT") {
            Ok(Self::Put)
        } else if value.eq_ignore_ascii_case("PATCH") {
            Ok(Self::Patch)
        } else if value.eq_ignore_ascii_case("DELETE") {
            Ok(Self::Delete)
        } else {
            Err(ScimError::invalid_value("unsupported SCIM Bulk method"))
        }
    }
}

pub(in crate::http::scim_bulk) fn scim_bulk_path(
    raw_path: &str,
) -> Result<ScimBulkPath, ScimError> {
    let path = raw_path.trim();
    if path.is_empty() {
        return Err(ScimError::invalid_path("SCIM Bulk path cannot be empty"));
    }
    if path.contains("://") || path.contains('?') || path.contains('#') {
        return Err(ScimError::invalid_path(
            "SCIM Bulk path must be relative to the SCIM service root",
        ));
    }

    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("scim/v2/").unwrap_or(path);
    let path = path.strip_prefix("v2/").unwrap_or(path);
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(ScimError::invalid_path("invalid SCIM Bulk path"));
    }

    match segments.as_slice() {
        ["Users"] => Ok(ScimBulkPath::Users),
        ["Users", user_id] => Uuid::parse_str(user_id)
            .map(ScimBulkPath::User)
            .map_err(|_| ScimError::invalid_path("SCIM Bulk user path must include a UUID")),
        ["Groups"] => Ok(ScimBulkPath::Groups),
        ["Groups", group_id] => Uuid::parse_str(group_id)
            .map(ScimBulkPath::Group)
            .map_err(|_| ScimError::invalid_path("SCIM Bulk group path must include a UUID")),
        _ => Err(ScimError::invalid_path("unsupported SCIM Bulk path")),
    }
}

pub(in crate::http::scim_bulk) fn scim_bulk_fail_on_errors(
    value: Option<usize>,
) -> Result<Option<usize>, ScimError> {
    match value {
        None => Ok(None),
        Some(limit @ 1..=SCIM_BULK_MAX_OPERATIONS) => Ok(Some(limit)),
        Some(_) => Err(ScimError::invalid_value("failOnErrors out of range")),
    }
}

pub(in crate::http::scim_bulk) fn scim_bulk_job_operations(
    operations: Vec<ScimBulkOperationRequest>,
) -> Result<Vec<ScimBulkJobOperation>, ScimError> {
    operations
        .into_iter()
        .map(|operation| {
            let method = scim_bulk_response_method(&operation.method);
            let bulk_id = scim_bulk_id(operation.bulk_id.as_deref())?;
            Ok(ScimBulkJobOperation {
                method,
                bulk_id,
                operation,
            })
        })
        .collect()
}

pub(in crate::http::scim_bulk) fn validate_scim_bulk_ids(
    operations: &[ScimBulkOperationRequest],
) -> Result<(), ScimError> {
    let mut seen = HashSet::new();
    for operation in operations {
        let Some(bulk_id) = scim_bulk_id(operation.bulk_id.as_deref())? else {
            continue;
        };
        if !seen.insert(bulk_id) {
            return Err(ScimError::invalid_value(
                "duplicate SCIM Bulk bulkId values are not allowed",
            ));
        }
    }
    Ok(())
}

pub(in crate::http::scim_bulk) fn scim_required_bulk_id(
    value: Option<&str>,
) -> Result<String, ScimError> {
    scim_bulk_id(value)?
        .ok_or_else(|| ScimError::invalid_value("SCIM Bulk POST operations must include bulkId"))
}

fn scim_bulk_id(value: Option<&str>) -> Result<Option<String>, ScimError> {
    optional_scim_str("bulkId", value, 80)
}

fn scim_bulk_response_method(value: &str) -> String {
    let method = value.trim();
    if method.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        method.to_ascii_uppercase()
    }
}

pub(in crate::http::scim_bulk) fn scim_bulk_data<T>(
    operation: &ScimBulkOperationRequest,
    resource_name: &'static str,
    bulk_references: &HashMap<String, Uuid>,
) -> Result<T, ScimError>
where
    T: DeserializeOwned,
{
    let data = operation.data.as_ref().ok_or_else(|| {
        ScimError::invalid_value("SCIM Bulk operation data is required for this method")
    })?;
    let data = scim_resolve_bulk_value_references(data, bulk_references)?;

    serde_json::from_value(data)
        .map_err(|_| ScimError::invalid_value(format!("invalid SCIM Bulk {resource_name} data")))
}

pub(in crate::http::scim_bulk) fn scim_bulk_expect_no_data(
    operation: &ScimBulkOperationRequest,
) -> Result<(), ScimError> {
    if operation.data.is_some() {
        return Err(ScimError::invalid_value(
            "SCIM Bulk DELETE operations must not include data",
        ));
    }
    Ok(())
}
