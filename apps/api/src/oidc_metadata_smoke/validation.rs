use serde_json::Value;

use super::types::OidcMetadataSmokeError;

pub(super) fn require_object(
    value: &Value,
    label: &'static str,
) -> Result<(), OidcMetadataSmokeError> {
    if value.is_object() {
        Ok(())
    } else if label == "jwks" || label == "jwks.keys[]" {
        Err(OidcMetadataSmokeError::InvalidJwks(format!(
            "{label} must be an object"
        )))
    } else {
        Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
            "{label} must be an object"
        )))
    }
}

pub(super) fn require_endpoint(
    discovery: &Value,
    issuer: &str,
    field: &'static str,
    path: &'static str,
) -> Result<(), OidcMetadataSmokeError> {
    let expected = format!("{issuer}{path}");
    require_string_field(discovery, field, &expected)
}

pub(super) fn require_string_field(
    discovery: &Value,
    field: &'static str,
    expected: &str,
) -> Result<(), OidcMetadataSmokeError> {
    match discovery.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
            "{field} must be {expected}, got {actual}"
        ))),
        None => Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
            "{field} must be {expected}"
        ))),
    }
}

pub(super) fn require_bool_field(
    discovery: &Value,
    field: &'static str,
    expected: bool,
) -> Result<(), OidcMetadataSmokeError> {
    match discovery.get(field).and_then(Value::as_bool) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
            "{field} must be {expected}, got {actual}"
        ))),
        None => Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
            "{field} must be {expected}"
        ))),
    }
}

pub(super) fn require_string_array_contains_all(
    discovery: &Value,
    field: &'static str,
    required: &[&'static str],
) -> Result<(), OidcMetadataSmokeError> {
    let values = string_array_field(discovery, field)?;
    for required_value in required {
        if !values.contains(required_value) {
            return Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
                "{field} must include {required_value}"
            )));
        }
    }
    Ok(())
}

pub(super) fn require_string_array_excludes_all(
    discovery: &Value,
    field: &'static str,
    disallowed: &[&'static str],
) -> Result<(), OidcMetadataSmokeError> {
    let values = string_array_field(discovery, field)?;
    for disallowed_value in disallowed {
        if values.contains(disallowed_value) {
            return Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
                "{field} must not include {disallowed_value}"
            )));
        }
    }
    Ok(())
}

pub(super) fn require_string_array_only(
    discovery: &Value,
    field: &'static str,
    allowed: &[&'static str],
) -> Result<(), OidcMetadataSmokeError> {
    let values = string_array_field(discovery, field)?;
    for required_value in allowed {
        if !values.contains(required_value) {
            return Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
                "{field} must include {required_value}"
            )));
        }
    }
    for value in values {
        if !allowed.contains(&value) {
            return Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
                "{field} must not include {value}"
            )));
        }
    }
    Ok(())
}

fn string_array_field<'a>(
    discovery: &'a Value,
    field: &'static str,
) -> Result<Vec<&'a str>, OidcMetadataSmokeError> {
    let values = discovery
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OidcMetadataSmokeError::InvalidDiscovery(format!("{field} must be an array"))
        })?;
    let mut strings = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match value.as_str() {
            Some(value) => strings.push(value),
            None => {
                return Err(OidcMetadataSmokeError::InvalidDiscovery(format!(
                    "{field}[{index}] must be a string"
                )));
            }
        }
    }
    Ok(strings)
}
