use serde_json::Value;

use super::super::scim_protocol::ScimError;

pub(super) fn scim_required_string_value(
    field: &'static str,
    value: &Value,
    max_len: usize,
) -> Result<String, ScimError> {
    let Some(value) = value.as_str() else {
        return Err(ScimError::invalid_value(format!(
            "{field} must be a string"
        )));
    };
    optional_scim_string(field, Some(value.to_owned()), max_len)?
        .ok_or_else(|| ScimError::invalid_value(format!("{field} cannot be empty")))
}

pub(super) fn scim_optional_string_value(
    field: &'static str,
    value: &Value,
    max_len: usize,
) -> Result<Option<String>, ScimError> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(ScimError::invalid_value(format!(
            "{field} must be a string or null"
        )));
    };
    optional_scim_string(field, Some(value.to_owned()), max_len)
}

pub(super) fn scim_bool_value(field: &'static str, value: &Value) -> Result<bool, ScimError> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        if value.eq_ignore_ascii_case("true") {
            return Ok(true);
        }
        if value.eq_ignore_ascii_case("false") {
            return Ok(false);
        }
    }
    Err(ScimError::invalid_value(format!("{field} must be boolean")))
}

pub(super) fn optional_scim_string(
    field: &'static str,
    value: Option<String>,
    max_len: usize,
) -> Result<Option<String>, ScimError> {
    optional_scim_str(field, value.as_deref(), max_len)
}

pub(in crate::http) fn optional_scim_str(
    field: &'static str,
    value: Option<&str>,
    max_len: usize,
) -> Result<Option<String>, ScimError> {
    value
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            if trimmed.chars().count() > max_len {
                return Err(ScimError::invalid_value(format!(
                    "{field} exceeds maximum length"
                )));
            }
            Ok(Some(trimmed.to_owned()))
        })
        .transpose()
        .map(Option::flatten)
}
