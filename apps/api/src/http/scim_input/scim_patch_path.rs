use axum::http::StatusCode;
use cairn_domain::UserId;
use uuid::Uuid;

use super::super::{
    scim_projection::{strip_scim_group_schema_prefix, strip_scim_user_schema_prefix},
    scim_protocol::ScimError,
    scim_query::{scim_eq_condition, scim_filter_string},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScimPatchPath {
    UserName,
    ExternalId,
    DisplayName,
    Active,
    Name,
    NameFormatted,
    NameGivenName,
    NameFamilyName,
    Emails {
        filter: Option<ScimEmailFilter>,
        attribute: ScimEmailPatchAttribute,
    },
    Schemas,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScimEmailPatchAttribute {
    Resource,
    Value,
    Type,
    Primary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScimGroupPatchPath {
    DisplayName,
    ExternalId,
    Members {
        value: Option<UserId>,
        value_only: bool,
    },
    Schemas,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScimEmailFilter {
    TypeWork,
    PrimaryTrue,
    Value(String),
}

impl ScimEmailFilter {
    pub(super) fn matches_email(&self, email: &str) -> bool {
        match self {
            Self::TypeWork | Self::PrimaryTrue => true,
            Self::Value(value) => value == email,
        }
    }
}

pub(super) fn scim_patch_path(raw_path: &str) -> Result<ScimPatchPath, ScimError> {
    let path = strip_scim_user_schema_prefix(raw_path.trim());
    if path.is_empty() {
        return Err(ScimError::invalid_path("SCIM PATCH path cannot be empty"));
    }

    let lower = path.to_ascii_lowercase();
    match lower.as_str() {
        "username" => Ok(ScimPatchPath::UserName),
        "externalid" => Ok(ScimPatchPath::ExternalId),
        "displayname" => Ok(ScimPatchPath::DisplayName),
        "active" => Ok(ScimPatchPath::Active),
        "name" => Ok(ScimPatchPath::Name),
        "name.formatted" => Ok(ScimPatchPath::NameFormatted),
        "name.givenname" => Ok(ScimPatchPath::NameGivenName),
        "name.familyname" => Ok(ScimPatchPath::NameFamilyName),
        "emails" => Ok(ScimPatchPath::Emails {
            filter: None,
            attribute: ScimEmailPatchAttribute::Resource,
        }),
        "emails.value" => Ok(ScimPatchPath::Emails {
            filter: None,
            attribute: ScimEmailPatchAttribute::Value,
        }),
        "emails.type" => Ok(ScimPatchPath::Emails {
            filter: None,
            attribute: ScimEmailPatchAttribute::Type,
        }),
        "emails.primary" => Ok(ScimPatchPath::Emails {
            filter: None,
            attribute: ScimEmailPatchAttribute::Primary,
        }),
        "schemas" => Ok(ScimPatchPath::Schemas),
        "id" | "meta" | "meta.created" | "meta.lastmodified" | "meta.location" => {
            Err(ScimError::mutability(
                StatusCode::BAD_REQUEST,
                "read-only SCIM user attributes cannot be modified",
            ))
        }
        _ if lower.starts_with("emails[") => scim_patch_email_path(path),
        _ => Err(ScimError::invalid_path("unsupported SCIM PATCH path")),
    }
}

pub(super) fn scim_group_patch_path(raw_path: &str) -> Result<ScimGroupPatchPath, ScimError> {
    let path = strip_scim_group_schema_prefix(raw_path.trim());
    if path.is_empty() {
        return Err(ScimError::invalid_path("SCIM PATCH path cannot be empty"));
    }

    let lower = path.to_ascii_lowercase();
    match lower.as_str() {
        "displayname" => Ok(ScimGroupPatchPath::DisplayName),
        "externalid" => Ok(ScimGroupPatchPath::ExternalId),
        "members" => Ok(ScimGroupPatchPath::Members {
            value: None,
            value_only: false,
        }),
        "members.value" => Ok(ScimGroupPatchPath::Members {
            value: None,
            value_only: true,
        }),
        "members.$ref" | "members.display" | "members.type" => Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "generated SCIM group member attributes cannot be modified",
        )),
        "schemas" => Ok(ScimGroupPatchPath::Schemas),
        "id" | "meta" | "meta.created" | "meta.lastmodified" | "meta.location" => {
            Err(ScimError::mutability(
                StatusCode::BAD_REQUEST,
                "read-only SCIM group attributes cannot be modified",
            ))
        }
        _ if lower.starts_with("members[") => scim_group_patch_member_path(path),
        _ => Err(ScimError::invalid_path("unsupported SCIM PATCH path")),
    }
}

fn scim_group_patch_member_path(path: &str) -> Result<ScimGroupPatchPath, ScimError> {
    let open = path
        .find('[')
        .ok_or_else(|| ScimError::invalid_path("invalid SCIM member path"))?;
    if !path[..open].eq_ignore_ascii_case("members") {
        return Err(ScimError::invalid_path("invalid SCIM member path"));
    }
    let close = path[open + 1..]
        .find(']')
        .map(|offset| open + 1 + offset)
        .ok_or_else(|| ScimError::invalid_path("unterminated SCIM member filter path"))?;
    let suffix = path[close + 1..].trim();
    let value_only = if suffix.is_empty() {
        false
    } else if suffix.eq_ignore_ascii_case(".value") {
        true
    } else if suffix.eq_ignore_ascii_case(".$ref")
        || suffix.eq_ignore_ascii_case(".display")
        || suffix.eq_ignore_ascii_case(".type")
    {
        return Err(ScimError::mutability(
            StatusCode::BAD_REQUEST,
            "generated SCIM group member attributes cannot be modified",
        ));
    } else {
        return Err(ScimError::invalid_path(
            "unsupported SCIM member filter sub-attribute",
        ));
    };

    let (attribute, raw_value) = scim_eq_condition(&path[open + 1..close])?;
    if !attribute.eq_ignore_ascii_case("value") {
        return Err(ScimError::invalid_filter(
            "SCIM group member filters only support value",
        ));
    }
    let value = scim_filter_string(raw_value)?;
    let user_id = Uuid::parse_str(&value)
        .map_err(|_| ScimError::invalid_filter("SCIM group member value must be a UUID"))?;
    Ok(ScimGroupPatchPath::Members {
        value: Some(user_id),
        value_only,
    })
}

fn scim_patch_email_path(path: &str) -> Result<ScimPatchPath, ScimError> {
    let open = path
        .find('[')
        .ok_or_else(|| ScimError::invalid_path("invalid SCIM email path"))?;
    if !path[..open].eq_ignore_ascii_case("emails") {
        return Err(ScimError::invalid_path("invalid SCIM email path"));
    }
    let close = path[open + 1..]
        .find(']')
        .map(|offset| open + 1 + offset)
        .ok_or_else(|| ScimError::invalid_path("unterminated SCIM email filter path"))?;
    let filter = scim_email_filter(&path[open + 1..close])?;
    let suffix = path[close + 1..].trim();
    let attribute = if suffix.is_empty() {
        ScimEmailPatchAttribute::Resource
    } else if suffix.eq_ignore_ascii_case(".value") {
        ScimEmailPatchAttribute::Value
    } else if suffix.eq_ignore_ascii_case(".type") {
        ScimEmailPatchAttribute::Type
    } else if suffix.eq_ignore_ascii_case(".primary") {
        ScimEmailPatchAttribute::Primary
    } else {
        return Err(ScimError::invalid_path(
            "unsupported SCIM email filter sub-attribute",
        ));
    };
    Ok(ScimPatchPath::Emails {
        filter: Some(filter),
        attribute,
    })
}

fn scim_email_filter(value: &str) -> Result<ScimEmailFilter, ScimError> {
    let (attribute, raw_value) = scim_eq_condition(value)?;
    match attribute.to_ascii_lowercase().as_str() {
        "type" => {
            let value = scim_filter_string(raw_value)?;
            if value.eq_ignore_ascii_case("work") {
                Ok(ScimEmailFilter::TypeWork)
            } else {
                Err(ScimError::no_target(
                    "SCIM PATCH email type filter did not match a stored email",
                ))
            }
        }
        "primary" => match raw_value.trim() {
            "true" => Ok(ScimEmailFilter::PrimaryTrue),
            "false" => Err(ScimError::no_target(
                "SCIM PATCH email primary filter did not match a stored email",
            )),
            _ => Err(ScimError::invalid_filter(
                "SCIM PATCH email primary filter must be boolean",
            )),
        },
        "value" => Ok(ScimEmailFilter::Value(cairn_domain::normalize_email(
            scim_filter_string(raw_value)?,
        )?)),
        _ => Err(ScimError::invalid_filter(
            "unsupported SCIM PATCH email filter attribute",
        )),
    }
}
