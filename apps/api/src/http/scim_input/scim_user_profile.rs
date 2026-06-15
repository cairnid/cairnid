use serde::Deserialize;
use serde_json::Value;

use super::super::scim_protocol::ScimError;
use super::scim_values::{optional_scim_string, scim_bool_value, scim_required_string_value};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimNameRequest {
    #[serde(default)]
    pub(super) formatted: Option<String>,
    #[serde(default)]
    pub(super) given_name: Option<String>,
    #[serde(default)]
    pub(super) family_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ScimEmailRequest {
    pub(super) value: String,
    #[serde(rename = "type", default)]
    pub(super) email_type: Option<String>,
    #[serde(default)]
    pub(super) primary: Option<bool>,
}

impl ScimEmailRequest {
    fn is_primary(&self) -> bool {
        self.primary.unwrap_or(false)
    }
}

pub(super) fn scim_email_from_patch_value(value: &Value) -> Result<String, ScimError> {
    if let Some(value) = value.as_str() {
        return Ok(cairn_domain::normalize_email(value.to_owned())?);
    }
    if value.is_object() {
        let email = serde_json::from_value::<ScimEmailRequest>(value.clone())
            .map_err(|_| ScimError::invalid_value("emails must contain value fields"))?;
        let selected_email = cairn_domain::normalize_email(email.value.clone())?;
        validate_scim_email_values(&selected_email, std::slice::from_ref(&email))?;
        return Ok(selected_email);
    }

    let emails = serde_json::from_value::<Vec<ScimEmailRequest>>(value.clone())
        .map_err(|_| ScimError::invalid_value("emails must be a string, object, or array"))?;
    if emails.is_empty() {
        return Err(ScimError::invalid_value("emails cannot be empty"));
    }
    let selected = emails
        .iter()
        .find(|email| email.is_primary())
        .unwrap_or(&emails[0]);
    let selected_email = cairn_domain::normalize_email(selected.value.clone())?;
    validate_scim_email_values(&selected_email, &emails)?;
    Ok(selected_email)
}

pub(super) fn validate_scim_email_type_patch_value(value: &Value) -> Result<(), ScimError> {
    let email_type = scim_required_string_value("emails.type", value, 32)?;
    if email_type.eq_ignore_ascii_case("work") {
        Ok(())
    } else {
        Err(ScimError::invalid_value(
            "emails.type must be work for Cairn Identity users",
        ))
    }
}

pub(super) fn validate_scim_email_primary_patch_value(value: &Value) -> Result<(), ScimError> {
    if scim_bool_value("emails.primary", value)? {
        Ok(())
    } else {
        Err(ScimError::invalid_value(
            "emails.primary must remain true for Cairn Identity users",
        ))
    }
}

pub(super) fn validate_scim_email_values(
    user_name: &str,
    emails: &[ScimEmailRequest],
) -> Result<(), ScimError> {
    for email in emails {
        let normalized = cairn_domain::normalize_email(email.value.clone())?;
        if normalized != user_name {
            return Err(ScimError::invalid_value(
                "emails.value must match userName for Cairn Identity users",
            ));
        }
        if let Some(email_type) = email.email_type.as_deref() {
            let email_type = email_type.trim();
            if email_type.is_empty()
                || email_type.chars().count() > 32
                || !email_type.eq_ignore_ascii_case("work")
            {
                return Err(ScimError::invalid_value(
                    "emails.type must be work for Cairn Identity users",
                ));
            }
        }
    }
    let primary_count = emails.iter().filter(|email| email.is_primary()).count();
    if primary_count > 1 {
        return Err(ScimError::invalid_value(
            "only one primary email can be supplied",
        ));
    }
    Ok(())
}

pub(super) fn scim_display_name(
    user_name: &str,
    display_name: Option<String>,
    name: Option<ScimNameRequest>,
) -> Result<String, ScimError> {
    if let Some(display_name) = optional_scim_string("displayName", display_name, 160)? {
        return Ok(display_name);
    }
    if let Some(name) = name {
        if let Some(formatted) = optional_scim_string("name.formatted", name.formatted, 160)? {
            return Ok(formatted);
        }
        let mut parts = Vec::new();
        if let Some(given_name) = optional_scim_string("name.givenName", name.given_name, 80)? {
            parts.push(given_name);
        }
        if let Some(family_name) = optional_scim_string("name.familyName", name.family_name, 80)? {
            parts.push(family_name);
        }
        if !parts.is_empty() {
            return Ok(parts.join(" "));
        }
    }
    Ok(user_name.to_owned())
}
