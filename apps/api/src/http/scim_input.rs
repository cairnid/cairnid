use cairn_domain::{UserId, UserStatus};
use serde::Deserialize;
use uuid::Uuid;

mod scim_group_members;
mod scim_group_patch;
mod scim_patch_path;
mod scim_patch_request;
mod scim_schemas;
mod scim_user_patch;
mod scim_user_profile;
mod scim_values;

use self::scim_group_members::{ScimGroupMemberRequest, scim_group_member_user_ids};
use self::scim_schemas::{validate_scim_group_request_schemas, validate_scim_user_request_schemas};
use self::scim_user_profile::{
    ScimEmailRequest, ScimNameRequest, scim_display_name, validate_scim_email_values,
};
use self::scim_values::optional_scim_string;
use super::scim_protocol::ScimError;

pub(super) use self::scim_group_patch::scim_patch_group_input;
pub(super) use self::scim_patch_request::ScimPatchRequest;
pub(super) use self::scim_user_patch::scim_patch_user_input;
pub(super) use self::scim_values::optional_scim_str;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimUserRequest {
    #[serde(default)]
    schemas: Vec<String>,
    user_name: String,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    name: Option<ScimNameRequest>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    emails: Vec<ScimEmailRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimGroupRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    members: Vec<ScimGroupMemberRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScimUserInput {
    pub(super) email: String,
    pub(super) external_id: Option<String>,
    pub(super) email_verified: bool,
    pub(super) display_name: String,
    pub(super) status: UserStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScimGroupInput {
    pub(super) display_name: String,
    pub(super) external_id: Option<String>,
    pub(super) member_user_ids: Vec<UserId>,
}

pub(super) fn scim_user_input(payload: ScimUserRequest) -> Result<ScimUserInput, ScimError> {
    validate_scim_user_request_schemas(&payload.schemas)?;

    let email = cairn_domain::normalize_email(payload.user_name)?;
    validate_scim_email_values(&email, &payload.emails)?;
    let display_name = scim_display_name(&email, payload.display_name, payload.name)?;
    let external_id = optional_scim_string("externalId", payload.external_id, 256)?;
    Ok(ScimUserInput {
        email,
        external_id,
        email_verified: false,
        display_name,
        status: if payload.active.unwrap_or(true) {
            UserStatus::Active
        } else {
            UserStatus::Suspended
        },
    })
}

pub(super) fn scim_group_input(payload: ScimGroupRequest) -> Result<ScimGroupInput, ScimError> {
    validate_scim_group_request_schemas(&payload.schemas)?;

    let display_name = optional_scim_string("displayName", payload.display_name, 160)?
        .ok_or_else(|| ScimError::invalid_value("displayName is required"))?;
    let external_id = optional_scim_string("externalId", payload.external_id, 256)?;
    let member_user_ids = scim_group_member_user_ids(payload.members)?;
    Ok(ScimGroupInput {
        display_name,
        external_id,
        member_user_ids,
    })
}

pub(super) fn scim_group_slug(
    group_id: Uuid,
    external_id: Option<&str>,
    display_name: &str,
) -> Result<String, ScimError> {
    let seed = external_id.unwrap_or(display_name);
    let mut base = String::new();
    for character in seed.chars() {
        if character.is_ascii_alphanumeric() {
            base.push(character.to_ascii_lowercase());
        } else if !base.ends_with('-') {
            base.push('-');
        }
    }
    let base = base.trim_matches('-');
    let base = if base.is_empty() {
        group_id.to_string()
    } else {
        base.to_owned()
    };
    let mut slug = format!("scim-{base}");
    if slug.len() > 80 {
        slug.truncate(80);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    Ok(cairn_domain::checked_string("slug", slug, 80)?)
}

#[cfg(test)]
mod tests;
