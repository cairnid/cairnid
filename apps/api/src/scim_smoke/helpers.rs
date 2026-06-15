use reqwest::Url;
use serde_json::Value;
use std::collections::HashSet;
use uuid::Uuid;

use super::ScimSmokeError;

pub(super) fn scim_smoke_base_url(value: &str) -> Result<Url, ScimSmokeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ScimSmokeError::InvalidInput(
            "SCIM smoke base URL cannot be empty".to_owned(),
        ));
    }
    let mut url = Url::parse(trimmed).map_err(|error| {
        ScimSmokeError::InvalidInput(format!("invalid SCIM smoke URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScimSmokeError::InvalidInput(
            "SCIM smoke base URL must use http or https".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ScimSmokeError::InvalidInput(
            "SCIM smoke base URL must not include credentials".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ScimSmokeError::InvalidInput(
            "SCIM smoke base URL must not include query or fragment".to_owned(),
        ));
    }
    let normalized_path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&normalized_path);
    Ok(url)
}

pub(super) fn scim_resource_url(base_url: &Url, path: &str) -> Result<Url, ScimSmokeError> {
    let path = path.trim_start_matches('/');
    base_url
        .join(&format!("scim/v2/{path}"))
        .map_err(|error| ScimSmokeError::InvalidInput(format!("invalid SCIM path: {error}")))
}

pub(super) fn non_empty_secret(
    name: &'static str,
    value: String,
) -> Result<String, ScimSmokeError> {
    if value.trim().is_empty() {
        Err(ScimSmokeError::InvalidInput(format!(
            "{name} cannot be empty"
        )))
    } else {
        Ok(value)
    }
}

pub(super) fn truncate_error_body(value: String) -> String {
    value.chars().take(1024).collect()
}

pub(super) fn resource_id(resource: &Value) -> Result<Uuid, ScimSmokeError> {
    let value = resource
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ScimSmokeError::Assertion("SCIM resource is missing id".to_owned()))?;
    Uuid::parse_str(value)
        .map_err(|_| ScimSmokeError::Assertion("SCIM resource id is not a UUID".to_owned()))
}

pub(super) fn expect_bool(
    resource: &Value,
    pointer: &'static str,
    expected: bool,
) -> Result<(), ScimSmokeError> {
    match resource.pointer(pointer).and_then(Value::as_bool) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ScimSmokeError::Assertion(format!(
            "{pointer} was {actual}, expected {expected}"
        ))),
        None => Err(ScimSmokeError::Assertion(format!(
            "{pointer} is missing or not boolean"
        ))),
    }
}

pub(super) fn expect_str(
    resource: &Value,
    pointer: &'static str,
    expected: &str,
) -> Result<(), ScimSmokeError> {
    match resource.pointer(pointer).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ScimSmokeError::Assertion(format!(
            "{pointer} was {actual}, expected {expected}"
        ))),
        None => Err(ScimSmokeError::Assertion(format!(
            "{pointer} is missing or not a string"
        ))),
    }
}

pub(super) fn expect_missing(
    resource: &Value,
    pointer: &'static str,
) -> Result<(), ScimSmokeError> {
    if resource.pointer(pointer).is_none() {
        Ok(())
    } else {
        Err(ScimSmokeError::Assertion(format!(
            "{pointer} should be absent"
        )))
    }
}

pub(super) fn expect_list_response_id(
    response: &Value,
    expected_id: &str,
) -> Result<(), ScimSmokeError> {
    let resources = response
        .get("Resources")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimSmokeError::Assertion("ListResponse missing Resources".to_owned()))?;
    if resources
        .iter()
        .any(|resource| resource.get("id").and_then(Value::as_str) == Some(expected_id))
    {
        Ok(())
    } else {
        Err(ScimSmokeError::Assertion(format!(
            "ListResponse did not include resource id {expected_id}"
        )))
    }
}

pub(super) fn expect_member_set(
    resource: &Value,
    expected_user_ids: &[Uuid],
) -> Result<(), ScimSmokeError> {
    let members = resource
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimSmokeError::Assertion("Group resource missing members".to_owned()))?;
    let actual = members
        .iter()
        .map(|member| {
            member
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| ScimSmokeError::Assertion("Group member missing value".to_owned()))
                .and_then(|value| {
                    Uuid::parse_str(value).map_err(|_| {
                        ScimSmokeError::Assertion("Group member value is not a UUID".to_owned())
                    })
                })
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let expected = expected_user_ids.iter().copied().collect::<HashSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(ScimSmokeError::Assertion(format!(
            "Group member set was {actual:?}, expected {expected:?}"
        )))
    }
}

pub(super) fn expect_bulk_operation<'a>(
    response: &'a Value,
    index: usize,
    expected_status: &str,
) -> Result<&'a Value, ScimSmokeError> {
    let operations = response
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimSmokeError::Assertion("BulkResponse missing Operations".to_owned()))?;
    let operation = operations.get(index).ok_or_else(|| {
        ScimSmokeError::Assertion(format!("BulkResponse missing operation {index}"))
    })?;
    match operation.get("status").and_then(Value::as_str) {
        Some(actual) if actual == expected_status => Ok(operation),
        Some(actual) => Err(ScimSmokeError::Assertion(format!(
            "Bulk operation {index} returned status {actual}, expected {expected_status}"
        ))),
        None => Err(ScimSmokeError::Assertion(format!(
            "Bulk operation {index} missing string status"
        ))),
    }
}

pub(super) fn expect_bulk_response(operation: &Value) -> Result<&Value, ScimSmokeError> {
    operation
        .get("response")
        .ok_or_else(|| ScimSmokeError::Assertion("Bulk operation missing response body".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::super::SCIM_BULK_RESPONSE_SCHEMA;
    use super::*;
    use serde_json::json;

    #[test]
    fn scim_smoke_base_url_normalizes_origin_or_path_prefix() {
        let origin = scim_smoke_base_url("https://id.example.com").expect("valid origin");
        assert_eq!(origin.as_str(), "https://id.example.com/");
        assert_eq!(
            scim_resource_url(&origin, "Users")
                .expect("valid SCIM URL")
                .as_str(),
            "https://id.example.com/scim/v2/Users"
        );

        let prefixed =
            scim_smoke_base_url("https://id.example.com/identity/").expect("valid prefix");
        assert_eq!(
            scim_resource_url(&prefixed, "/Groups")
                .expect("valid SCIM URL")
                .as_str(),
            "https://id.example.com/identity/scim/v2/Groups"
        );
    }

    #[test]
    fn scim_smoke_base_url_rejects_unsafe_components() {
        for value in [
            "",
            "ftp://id.example.com",
            "https://user:pass@id.example.com",
            "https://id.example.com?token=value",
            "https://id.example.com#fragment",
        ] {
            assert!(matches!(
                scim_smoke_base_url(value),
                Err(ScimSmokeError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn scim_smoke_response_helpers_validate_expected_resources() {
        let user_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let user = json!({
            "id": user_id.to_string(),
            "active": false
        });
        assert_eq!(resource_id(&user).expect("uuid id"), user_id);
        assert!(expect_bool(&user, "/active", false).is_ok());

        let list = json!({
            "Resources": [
                { "id": user_id.to_string() },
                { "id": "Group" }
            ]
        });
        assert!(expect_list_response_id(&list, &user_id.to_string()).is_ok());
        assert!(expect_list_response_id(&list, "Group").is_ok());

        let group = json!({
            "id": group_id.to_string(),
            "members": [{ "value": user_id.to_string(), "type": "User" }]
        });
        assert!(expect_member_set(&group, &[user_id]).is_ok());
        assert!(expect_missing(&group, "/members/0/display").is_ok());

        let bulk = json!({
            "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "user-one",
                    "status": "201",
                    "response": { "id": user_id.to_string() }
                },
                {
                    "method": "DELETE",
                    "status": "204"
                }
            ]
        });
        let operation = expect_bulk_operation(&bulk, 0, "201").expect("bulk operation");
        assert_eq!(
            resource_id(expect_bulk_response(operation).expect("bulk body")).expect("uuid id"),
            user_id
        );
        assert!(expect_bulk_operation(&bulk, 1, "204").is_ok());
    }
}
