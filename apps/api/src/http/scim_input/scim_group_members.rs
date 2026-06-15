use cairn_domain::UserId;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use uuid::Uuid;

use super::super::scim_protocol::{SCIM_GROUP_MAX_MEMBERS, ScimError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimGroupMemberRequest {
    pub(super) value: Uuid,
    #[serde(rename = "$ref", default)]
    pub(super) reference: Option<String>,
    #[serde(rename = "type", default)]
    pub(super) member_type: Option<String>,
    #[serde(default)]
    pub(super) display: Option<String>,
}

pub(super) fn scim_group_member_user_ids(
    members: Vec<ScimGroupMemberRequest>,
) -> Result<Vec<UserId>, ScimError> {
    let user_ids = members
        .into_iter()
        .map(scim_group_member_user_id_from_request)
        .collect::<Result<Vec<_>, _>>()?;
    unique_scim_group_member_user_ids(user_ids)
}

pub(super) fn scim_group_member_user_ids_from_patch_value(
    value: &Value,
) -> Result<Vec<UserId>, ScimError> {
    if let Some(values) = value.as_array() {
        let user_ids = values
            .iter()
            .map(scim_group_member_user_id_from_patch_value)
            .collect::<Result<Vec<_>, _>>()?;
        return unique_scim_group_member_user_ids(user_ids);
    }

    unique_scim_group_member_user_ids(vec![scim_group_member_user_id_from_patch_value(value)?])
}

pub(super) fn scim_group_single_member_user_id_from_patch_value(
    value: &Value,
    value_only: bool,
) -> Result<UserId, ScimError> {
    if value_only {
        scim_group_member_value_user_id_from_patch_value(value)
    } else {
        scim_group_member_user_id_from_patch_value(value)
    }
}

pub(super) fn scim_group_member_value_user_ids_from_patch_value(
    value: &Value,
) -> Result<Vec<UserId>, ScimError> {
    if let Some(values) = value.as_array() {
        let user_ids = values
            .iter()
            .map(scim_group_member_value_user_id_from_patch_value)
            .collect::<Result<Vec<_>, _>>()?;
        return unique_scim_group_member_user_ids(user_ids);
    }

    unique_scim_group_member_user_ids(vec![scim_group_member_value_user_id_from_patch_value(
        value,
    )?])
}

fn scim_group_member_value_user_id_from_patch_value(value: &Value) -> Result<UserId, ScimError> {
    let Some(value) = value.as_str() else {
        return Err(ScimError::invalid_value(
            "members.value must be a UUID string",
        ));
    };
    Uuid::parse_str(value).map_err(|_| ScimError::invalid_value("members.value must be a UUID"))
}

fn scim_group_member_user_id_from_patch_value(value: &Value) -> Result<UserId, ScimError> {
    if let Some(value) = value.as_str() {
        return Uuid::parse_str(value)
            .map_err(|_| ScimError::invalid_value("members.value must be a UUID"));
    }

    let member = serde_json::from_value::<ScimGroupMemberRequest>(value.clone())
        .map_err(|_| ScimError::invalid_value("members must contain value fields"))?;
    scim_group_member_user_id_from_request(member)
}

fn scim_group_member_user_id_from_request(
    member: ScimGroupMemberRequest,
) -> Result<UserId, ScimError> {
    let ScimGroupMemberRequest {
        value,
        reference,
        member_type,
        display,
    } = member;
    let _reference = reference;
    let _display = display;

    if let Some(member_type) = member_type
        && !member_type.eq_ignore_ascii_case("User")
    {
        return Err(ScimError::invalid_value(
            "SCIM group members only support User resources",
        ));
    }

    Ok(value)
}

fn unique_scim_group_member_user_ids(user_ids: Vec<UserId>) -> Result<Vec<UserId>, ScimError> {
    if user_ids.len() > SCIM_GROUP_MAX_MEMBERS {
        return Err(ScimError::invalid_value("too many group members"));
    }

    let mut seen = HashSet::with_capacity(user_ids.len());
    let mut unique_user_ids = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        if !seen.insert(user_id) {
            return Err(ScimError::invalid_value(
                "duplicate members.value entries are not allowed",
            ));
        }
        unique_user_ids.push(user_id);
    }
    Ok(unique_user_ids)
}
