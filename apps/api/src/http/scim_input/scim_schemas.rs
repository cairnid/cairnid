use serde_json::Value;

use super::super::scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA, ScimError};

pub(super) fn validate_scim_user_request_schemas(schemas: &[String]) -> Result<(), ScimError> {
    validate_optional_request_schemas(schemas, SCIM_USER_SCHEMA, "unsupported SCIM user schema")
}

pub(super) fn validate_scim_group_request_schemas(schemas: &[String]) -> Result<(), ScimError> {
    validate_optional_request_schemas(schemas, SCIM_GROUP_SCHEMA, "unsupported SCIM group schema")
}

pub(super) fn validate_scim_user_schemas_patch_value(value: &Value) -> Result<(), ScimError> {
    validate_required_schema_patch_value(
        value,
        SCIM_USER_SCHEMA,
        "schemas must include the core User schema",
    )
}

pub(super) fn validate_scim_group_schemas_patch_value(value: &Value) -> Result<(), ScimError> {
    validate_required_schema_patch_value(
        value,
        SCIM_GROUP_SCHEMA,
        "schemas must include the core Group schema",
    )
}

fn validate_optional_request_schemas(
    schemas: &[String],
    required_schema: &str,
    error_message: &'static str,
) -> Result<(), ScimError> {
    if schemas.is_empty() || schemas.iter().any(|schema| schema == required_schema) {
        Ok(())
    } else {
        Err(ScimError::invalid_value(error_message))
    }
}

fn validate_required_schema_patch_value(
    value: &Value,
    required_schema: &str,
    error_message: &'static str,
) -> Result<(), ScimError> {
    let contains_schema = if let Some(value) = value.as_str() {
        value == required_schema
    } else {
        let schemas = serde_json::from_value::<Vec<String>>(value.clone())
            .map_err(|_| ScimError::invalid_value("schemas must be a string array"))?;
        schemas.iter().any(|schema| schema == required_schema)
    };
    if contains_schema {
        Ok(())
    } else {
        Err(ScimError::invalid_value(error_message))
    }
}
