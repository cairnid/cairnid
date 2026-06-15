use axum::http::StatusCode;
use cairn_domain::{User, UserStatus};
use serde_json::Value;

use super::super::scim_protocol::ScimError;
use super::ScimUserInput;
use super::scim_patch_path::{ScimEmailPatchAttribute, ScimPatchPath, scim_patch_path};
use super::scim_patch_request::{ScimPatchOp, ScimPatchOperation, ScimPatchRequest};
use super::scim_schemas::validate_scim_user_schemas_patch_value;
use super::scim_user_profile::{
    ScimNameRequest, scim_display_name, scim_email_from_patch_value,
    validate_scim_email_primary_patch_value, validate_scim_email_type_patch_value,
};
use super::scim_values::{
    optional_scim_string, scim_bool_value, scim_optional_string_value, scim_required_string_value,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScimPatchState {
    email: String,
    external_id: Option<String>,
    email_verified: bool,
    display_name: String,
    status: UserStatus,
    patch_given_name: Option<String>,
    patch_family_name: Option<String>,
}

pub(in crate::http) fn scim_patch_user_input(
    current_user: &User,
    payload: ScimPatchRequest,
) -> Result<ScimUserInput, ScimError> {
    let mut state = ScimPatchState::from_user(current_user);
    for operation in payload.into_validated_operations()? {
        apply_scim_patch_operation(&mut state, operation)?;
    }
    state.into_input()
}

impl ScimPatchState {
    fn from_user(user: &User) -> Self {
        Self {
            email: user.email.clone(),
            external_id: user.scim_external_id.clone(),
            email_verified: user.email_verified,
            display_name: user.display_name.clone(),
            status: user.status,
            patch_given_name: None,
            patch_family_name: None,
        }
    }

    fn into_input(self) -> Result<ScimUserInput, ScimError> {
        Ok(ScimUserInput {
            email: self.email,
            external_id: self.external_id,
            email_verified: self.email_verified,
            display_name: optional_scim_string("displayName", Some(self.display_name), 160)?
                .ok_or_else(|| ScimError::invalid_value("displayName cannot be empty"))?,
            status: self.status,
        })
    }

    fn set_user_name(&mut self, email: String) {
        if self.email != email {
            self.email = email;
            self.email_verified = false;
        }
    }

    fn set_email_from_emails(&mut self, email: String) {
        self.set_user_name(email);
    }

    fn set_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
        self.patch_given_name = None;
        self.patch_family_name = None;
    }

    fn set_given_name(&mut self, given_name: String) -> Result<(), ScimError> {
        self.patch_given_name = Some(given_name);
        self.rebuild_display_name_from_patch_parts()
    }

    fn set_family_name(&mut self, family_name: String) -> Result<(), ScimError> {
        self.patch_family_name = Some(family_name);
        self.rebuild_display_name_from_patch_parts()
    }

    fn rebuild_display_name_from_patch_parts(&mut self) -> Result<(), ScimError> {
        let mut parts = Vec::new();
        if let Some(given_name) = &self.patch_given_name {
            parts.push(given_name.as_str());
        }
        if let Some(family_name) = &self.patch_family_name {
            parts.push(family_name.as_str());
        }
        let display_name = optional_scim_string("displayName", Some(parts.join(" ")), 160)?
            .ok_or_else(|| ScimError::invalid_value("displayName cannot be empty"))?;
        self.display_name = display_name;
        Ok(())
    }
}

fn apply_scim_patch_operation(
    state: &mut ScimPatchState,
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
                let path = scim_patch_path(path)?;
                apply_scim_patch_path_value(state, path, value)
            } else {
                apply_scim_patch_resource_value(state, value)
            }
        }
        ScimPatchOp::Remove => {
            let path = operation
                .path
                .as_deref()
                .ok_or_else(|| ScimError::invalid_path("SCIM PATCH remove requires path"))?;
            remove_scim_patch_path(state, scim_patch_path(path)?)
        }
    }
}

fn apply_scim_patch_resource_value(
    state: &mut ScimPatchState,
    value: &Value,
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
        let path = scim_patch_path(attribute)?;
        apply_scim_patch_path_value(state, path, value)?;
    }
    Ok(())
}

fn apply_scim_patch_path_value(
    state: &mut ScimPatchState,
    path: ScimPatchPath,
    value: &Value,
) -> Result<(), ScimError> {
    match path {
        ScimPatchPath::UserName => {
            state.set_user_name(cairn_domain::normalize_email(scim_required_string_value(
                "userName", value, 320,
            )?)?);
        }
        ScimPatchPath::ExternalId => {
            state.external_id = scim_optional_string_value("externalId", value, 256)?;
        }
        ScimPatchPath::DisplayName => {
            state.set_display_name(scim_required_string_value("displayName", value, 160)?);
        }
        ScimPatchPath::Active => {
            state.status = if scim_bool_value("active", value)? {
                UserStatus::Active
            } else {
                UserStatus::Suspended
            };
        }
        ScimPatchPath::Name => {
            let name = serde_json::from_value::<ScimNameRequest>(value.clone())
                .map_err(|_| ScimError::invalid_value("name must be a SCIM name object"))?;
            let display_name = scim_display_name(&state.email, None, Some(name))?;
            state.set_display_name(display_name);
        }
        ScimPatchPath::NameFormatted => {
            state.set_display_name(scim_required_string_value("name.formatted", value, 160)?);
        }
        ScimPatchPath::NameGivenName => {
            state.set_given_name(scim_required_string_value("name.givenName", value, 80)?)?;
        }
        ScimPatchPath::NameFamilyName => {
            state.set_family_name(scim_required_string_value("name.familyName", value, 80)?)?;
        }
        ScimPatchPath::Emails { filter, attribute } => {
            if let Some(filter) = filter
                && !filter.matches_email(&state.email)
            {
                return Err(ScimError::no_target(
                    "SCIM PATCH email filter did not match a stored email",
                ));
            }
            match attribute {
                ScimEmailPatchAttribute::Resource => {
                    state.set_email_from_emails(scim_email_from_patch_value(value)?);
                }
                ScimEmailPatchAttribute::Value => {
                    state.set_email_from_emails(cairn_domain::normalize_email(
                        scim_required_string_value("emails.value", value, 320)?,
                    )?);
                }
                ScimEmailPatchAttribute::Type => {
                    validate_scim_email_type_patch_value(value)?;
                }
                ScimEmailPatchAttribute::Primary => {
                    validate_scim_email_primary_patch_value(value)?;
                }
            }
        }
        ScimPatchPath::Schemas => {
            validate_scim_user_schemas_patch_value(value)?;
        }
    }
    Ok(())
}

fn remove_scim_patch_path(
    state: &mut ScimPatchState,
    path: ScimPatchPath,
) -> Result<(), ScimError> {
    match path {
        ScimPatchPath::ExternalId => {
            state.external_id = None;
            Ok(())
        }
        ScimPatchPath::Emails { filter, .. } => {
            if let Some(filter) = filter
                && !filter.matches_email(&state.email)
            {
                return Err(ScimError::no_target(
                    "SCIM PATCH email filter did not match a stored email",
                ));
            }
            Err(ScimError::mutability(
                StatusCode::BAD_REQUEST,
                "emails cannot be removed from Cairn Identity users",
            ))
        }
        ScimPatchPath::Schemas => Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "schemas cannot be removed from Cairn Identity users",
        )),
        ScimPatchPath::UserName
        | ScimPatchPath::DisplayName
        | ScimPatchPath::Active
        | ScimPatchPath::Name
        | ScimPatchPath::NameFormatted
        | ScimPatchPath::NameGivenName
        | ScimPatchPath::NameFamilyName => Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "required Cairn Identity user attributes cannot be removed through SCIM PATCH",
        )),
    }
}
