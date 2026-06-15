use axum::http::StatusCode;
use cairn_database::ScimGroupMember;
use cairn_domain::{Group, UserId};
use serde_json::Value;
use std::collections::HashSet;

use super::super::scim_protocol::{SCIM_GROUP_MAX_MEMBERS, ScimError};
use super::ScimGroupInput;
use super::scim_group_members::{
    scim_group_member_user_ids_from_patch_value, scim_group_member_value_user_ids_from_patch_value,
    scim_group_single_member_user_id_from_patch_value,
};
use super::scim_patch_path::{ScimGroupPatchPath, scim_group_patch_path};
use super::scim_patch_request::{ScimPatchOp, ScimPatchOperation, ScimPatchRequest};
use super::scim_schemas::validate_scim_group_schemas_patch_value;
use super::scim_values::{
    optional_scim_string, scim_optional_string_value, scim_required_string_value,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScimGroupPatchState {
    display_name: String,
    external_id: Option<String>,
    member_user_ids: Vec<UserId>,
}

pub(in crate::http) fn scim_patch_group_input(
    current_group: &Group,
    current_members: &[ScimGroupMember],
    payload: ScimPatchRequest,
) -> Result<ScimGroupInput, ScimError> {
    let mut state = ScimGroupPatchState::from_group(current_group, current_members);
    for operation in payload.into_validated_operations()? {
        apply_scim_group_patch_operation(&mut state, operation)?;
    }
    state.into_input()
}

impl ScimGroupPatchState {
    fn from_group(group: &Group, members: &[ScimGroupMember]) -> Self {
        Self {
            display_name: group.display_name.clone(),
            external_id: group.scim_external_id.clone(),
            member_user_ids: members.iter().map(|member| member.user_id).collect(),
        }
    }

    fn into_input(self) -> Result<ScimGroupInput, ScimError> {
        if self.member_user_ids.len() > SCIM_GROUP_MAX_MEMBERS {
            return Err(ScimError::invalid_value("too many group members"));
        }

        Ok(ScimGroupInput {
            display_name: optional_scim_string("displayName", Some(self.display_name), 160)?
                .ok_or_else(|| ScimError::invalid_value("displayName is required"))?,
            external_id: self.external_id,
            member_user_ids: self.member_user_ids,
        })
    }

    fn add_member_user_ids(&mut self, user_ids: Vec<UserId>) -> Result<(), ScimError> {
        let mut existing = self.member_user_ids.iter().copied().collect::<HashSet<_>>();
        for user_id in user_ids {
            if existing.insert(user_id) {
                self.member_user_ids.push(user_id);
            }
        }
        if self.member_user_ids.len() > SCIM_GROUP_MAX_MEMBERS {
            return Err(ScimError::invalid_value("too many group members"));
        }
        Ok(())
    }

    fn replace_member_user_ids(&mut self, user_ids: Vec<UserId>) {
        self.member_user_ids = user_ids;
    }

    fn add_filtered_member_user_id(
        &mut self,
        filtered_user_id: UserId,
        value: &Value,
        value_only: bool,
    ) -> Result<(), ScimError> {
        let user_id = scim_group_single_member_user_id_from_patch_value(value, value_only)?;
        if user_id != filtered_user_id {
            return Err(ScimError::invalid_value(
                "filtered members PATCH value must match the path filter",
            ));
        }
        self.add_member_user_ids(vec![user_id])
    }

    fn replace_filtered_member_user_id(
        &mut self,
        filtered_user_id: UserId,
        value: &Value,
        value_only: bool,
    ) -> Result<(), ScimError> {
        let replacement_user_id =
            scim_group_single_member_user_id_from_patch_value(value, value_only)?;
        let target_index = self
            .member_user_ids
            .iter()
            .position(|existing| existing == &filtered_user_id)
            .ok_or_else(|| {
                ScimError::no_target("SCIM PATCH member filter did not match a stored member")
            })?;

        if replacement_user_id == filtered_user_id {
            return Ok(());
        }

        if self.member_user_ids.contains(&replacement_user_id) {
            self.member_user_ids.remove(target_index);
        } else {
            self.member_user_ids[target_index] = replacement_user_id;
        }
        Ok(())
    }

    fn remove_member_user_id(&mut self, user_id: UserId) {
        self.member_user_ids.retain(|existing| existing != &user_id);
    }
}

fn apply_scim_group_patch_operation(
    state: &mut ScimGroupPatchState,
    operation: ScimPatchOperation,
) -> Result<(), ScimError> {
    let op = ScimPatchOp::parse(&operation.op)?;
    match op {
        ScimPatchOp::Add | ScimPatchOp::Replace => {
            let value = operation
                .value
                .as_ref()
                .ok_or_else(|| ScimError::invalid_value("SCIM PATCH value is required"))?;
            if let Some(path) = operation.path.as_deref() {
                apply_scim_group_patch_path_value(state, scim_group_patch_path(path)?, value, op)
            } else {
                apply_scim_group_patch_resource_value(state, value, op)
            }
        }
        ScimPatchOp::Remove => {
            let path = operation
                .path
                .as_deref()
                .ok_or_else(|| ScimError::invalid_path("SCIM PATCH remove requires path"))?;
            remove_scim_group_patch_path(state, scim_group_patch_path(path)?)
        }
    }
}

fn apply_scim_group_patch_resource_value(
    state: &mut ScimGroupPatchState,
    value: &Value,
    op: ScimPatchOp,
) -> Result<(), ScimError> {
    let object = value
        .as_object()
        .ok_or_else(|| ScimError::invalid_value("SCIM PATCH resource value must be an object"))?;
    if object.is_empty() {
        return Err(ScimError::invalid_value(
            "SCIM PATCH resource value cannot be empty",
        ));
    }

    for (attribute, value) in object {
        apply_scim_group_patch_path_value(state, scim_group_patch_path(attribute)?, value, op)?;
    }
    Ok(())
}

fn apply_scim_group_patch_path_value(
    state: &mut ScimGroupPatchState,
    path: ScimGroupPatchPath,
    value: &Value,
    op: ScimPatchOp,
) -> Result<(), ScimError> {
    match path {
        ScimGroupPatchPath::DisplayName => {
            state.display_name = scim_required_string_value("displayName", value, 160)?;
        }
        ScimGroupPatchPath::ExternalId => {
            state.external_id = scim_optional_string_value("externalId", value, 256)?;
        }
        ScimGroupPatchPath::Members {
            value: None,
            value_only,
        } => {
            let member_user_ids = if value_only {
                scim_group_member_value_user_ids_from_patch_value(value)?
            } else {
                scim_group_member_user_ids_from_patch_value(value)?
            };
            match op {
                ScimPatchOp::Add => state.add_member_user_ids(member_user_ids)?,
                ScimPatchOp::Replace => state.replace_member_user_ids(member_user_ids),
                ScimPatchOp::Remove => unreachable!("remove is handled separately"),
            }
        }
        ScimGroupPatchPath::Members {
            value: Some(user_id),
            value_only,
        } => match op {
            ScimPatchOp::Add => {
                state.add_filtered_member_user_id(user_id, value, value_only)?;
            }
            ScimPatchOp::Replace => {
                state.replace_filtered_member_user_id(user_id, value, value_only)?;
            }
            ScimPatchOp::Remove => unreachable!("remove is handled separately"),
        },
        ScimGroupPatchPath::Schemas => {
            validate_scim_group_schemas_patch_value(value)?;
        }
    }
    Ok(())
}

fn remove_scim_group_patch_path(
    state: &mut ScimGroupPatchState,
    path: ScimGroupPatchPath,
) -> Result<(), ScimError> {
    match path {
        ScimGroupPatchPath::ExternalId => {
            state.external_id = None;
            Ok(())
        }
        ScimGroupPatchPath::Members { value: None, .. } => {
            state.member_user_ids.clear();
            Ok(())
        }
        ScimGroupPatchPath::Members {
            value: Some(user_id),
            ..
        } => {
            state.remove_member_user_id(user_id);
            Ok(())
        }
        ScimGroupPatchPath::Schemas => Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "schemas cannot be removed from Cairn Identity groups",
        )),
        ScimGroupPatchPath::DisplayName => Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "displayName cannot be removed from Cairn Identity groups",
        )),
    }
}
