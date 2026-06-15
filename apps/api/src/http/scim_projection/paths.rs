use serde::Deserialize;
use std::collections::HashSet;

use super::super::scim_protocol::{
    SCIM_GROUP_SCHEMA, SCIM_PROJECTION_MAX_ATTRIBUTES, SCIM_USER_SCHEMA, ScimError,
};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(in crate::http) enum ScimSearchAttributes {
    List(Vec<String>),
    CommaSeparated(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) enum ScimResourceKind {
    User,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::http) struct ScimProjectionPath {
    pub(super) top: &'static str,
    pub(super) sub: Option<&'static str>,
}

impl ScimProjectionPath {
    pub(in crate::http) const fn top(top: &'static str) -> Self {
        Self { top, sub: None }
    }

    pub(in crate::http) const fn sub(top: &'static str, sub: &'static str) -> Self {
        Self {
            top,
            sub: Some(sub),
        }
    }

    pub(super) fn is_always_returned(&self) -> bool {
        matches!(self.top, "schemas" | "id")
    }
}

impl ScimSearchAttributes {
    pub(super) fn projection_paths(
        self,
        kind: ScimResourceKind,
    ) -> Result<Vec<ScimProjectionPath>, ScimError> {
        match self {
            Self::List(values) => scim_projection_paths_from_values(kind, values),
            Self::CommaSeparated(value) => scim_projection_paths(kind, &value),
        }
    }
}

pub(in crate::http) fn scim_projection_paths(
    kind: ScimResourceKind,
    value: &str,
) -> Result<Vec<ScimProjectionPath>, ScimError> {
    scim_projection_paths_from_values(kind, value.split(','))
}

fn scim_projection_paths_from_values<I, S>(
    kind: ScimResourceKind,
    values: I,
) -> Result<Vec<ScimProjectionPath>, ScimError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for raw_value in values {
        for raw_path in raw_value.as_ref().split(',') {
            let path = scim_projection_path(kind, raw_path)?;
            if seen.insert(path.clone()) {
                paths.push(path);
            }
            if paths.len() > SCIM_PROJECTION_MAX_ATTRIBUTES {
                return Err(ScimError::invalid_value(
                    "too many SCIM projection attributes",
                ));
            }
        }
    }
    if paths.is_empty() {
        return Err(ScimError::invalid_value(
            "SCIM projection attributes cannot be empty",
        ));
    }
    Ok(paths)
}

pub(in crate::http) fn strip_scim_user_schema_prefix(path: &str) -> &str {
    let Some(prefix) = path.get(..SCIM_USER_SCHEMA.len()) else {
        return path;
    };
    if prefix.eq_ignore_ascii_case(SCIM_USER_SCHEMA)
        && path
            .get(SCIM_USER_SCHEMA.len()..SCIM_USER_SCHEMA.len() + 1)
            .is_some_and(|separator| separator == ":")
    {
        &path[SCIM_USER_SCHEMA.len() + 1..]
    } else {
        path
    }
}

pub(in crate::http) fn strip_scim_group_schema_prefix(path: &str) -> &str {
    let Some(prefix) = path.get(..SCIM_GROUP_SCHEMA.len()) else {
        return path;
    };
    if prefix.eq_ignore_ascii_case(SCIM_GROUP_SCHEMA)
        && path
            .get(SCIM_GROUP_SCHEMA.len()..SCIM_GROUP_SCHEMA.len() + 1)
            .is_some_and(|separator| separator == ":")
    {
        &path[SCIM_GROUP_SCHEMA.len() + 1..]
    } else {
        path
    }
}

fn scim_projection_path(
    kind: ScimResourceKind,
    raw_path: &str,
) -> Result<ScimProjectionPath, ScimError> {
    let path = match kind {
        ScimResourceKind::User => strip_scim_user_schema_prefix(raw_path.trim()),
        ScimResourceKind::Group => strip_scim_group_schema_prefix(raw_path.trim()),
    };
    if path.is_empty() {
        return Err(ScimError::invalid_value(
            "SCIM projection attribute cannot be empty",
        ));
    }
    if path.contains('[') || path.contains(']') {
        return Err(ScimError::invalid_value(
            "filtered SCIM projection attributes are not supported",
        ));
    }

    let parts = path.split('.').collect::<Vec<_>>();
    if parts.len() > 2 || parts.iter().any(|part| part.trim().is_empty()) {
        return Err(ScimError::invalid_value(
            "unsupported SCIM projection attribute",
        ));
    }

    let top = parts[0].trim().to_ascii_lowercase();
    let sub = parts.get(1).map(|part| part.trim().to_ascii_lowercase());
    match kind {
        ScimResourceKind::User => scim_user_projection_path(&top, sub.as_deref()),
        ScimResourceKind::Group => scim_group_projection_path(&top, sub.as_deref()),
    }
}

fn scim_user_projection_path(
    top: &str,
    sub: Option<&str>,
) -> Result<ScimProjectionPath, ScimError> {
    match (top, sub) {
        ("schemas", None) => Ok(ScimProjectionPath::top("schemas")),
        ("id", None) => Ok(ScimProjectionPath::top("id")),
        ("externalid", None) => Ok(ScimProjectionPath::top("externalId")),
        ("username", None) => Ok(ScimProjectionPath::top("userName")),
        ("displayname", None) => Ok(ScimProjectionPath::top("displayName")),
        ("active", None) => Ok(ScimProjectionPath::top("active")),
        ("name", None) => Ok(ScimProjectionPath::top("name")),
        ("name", Some("formatted")) => Ok(ScimProjectionPath::sub("name", "formatted")),
        ("name", Some("givenname")) => Ok(ScimProjectionPath::sub("name", "givenName")),
        ("name", Some("familyname")) => Ok(ScimProjectionPath::sub("name", "familyName")),
        ("emails", None) => Ok(ScimProjectionPath::top("emails")),
        ("emails", Some("value")) => Ok(ScimProjectionPath::sub("emails", "value")),
        ("emails", Some("type")) => Ok(ScimProjectionPath::sub("emails", "type")),
        ("emails", Some("primary")) => Ok(ScimProjectionPath::sub("emails", "primary")),
        ("meta", None) => Ok(ScimProjectionPath::top("meta")),
        ("meta", Some("resourcetype")) => Ok(ScimProjectionPath::sub("meta", "resourceType")),
        ("meta", Some("created")) => Ok(ScimProjectionPath::sub("meta", "created")),
        ("meta", Some("lastmodified")) => Ok(ScimProjectionPath::sub("meta", "lastModified")),
        ("meta", Some("location")) => Ok(ScimProjectionPath::sub("meta", "location")),
        _ => Err(ScimError::invalid_value(
            "unsupported SCIM user projection attribute",
        )),
    }
}

fn scim_group_projection_path(
    top: &str,
    sub: Option<&str>,
) -> Result<ScimProjectionPath, ScimError> {
    match (top, sub) {
        ("schemas", None) => Ok(ScimProjectionPath::top("schemas")),
        ("id", None) => Ok(ScimProjectionPath::top("id")),
        ("externalid", None) => Ok(ScimProjectionPath::top("externalId")),
        ("displayname", None) => Ok(ScimProjectionPath::top("displayName")),
        ("members", None) => Ok(ScimProjectionPath::top("members")),
        ("members", Some("value")) => Ok(ScimProjectionPath::sub("members", "value")),
        ("members", Some("$ref")) => Ok(ScimProjectionPath::sub("members", "$ref")),
        ("members", Some("display")) => Ok(ScimProjectionPath::sub("members", "display")),
        ("members", Some("type")) => Ok(ScimProjectionPath::sub("members", "type")),
        ("meta", None) => Ok(ScimProjectionPath::top("meta")),
        ("meta", Some("resourcetype")) => Ok(ScimProjectionPath::sub("meta", "resourceType")),
        ("meta", Some("created")) => Ok(ScimProjectionPath::sub("meta", "created")),
        ("meta", Some("lastmodified")) => Ok(ScimProjectionPath::sub("meta", "lastModified")),
        ("meta", Some("location")) => Ok(ScimProjectionPath::sub("meta", "location")),
        _ => Err(ScimError::invalid_value(
            "unsupported SCIM group projection attribute",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_paths_accept_schema_qualified_attributes_and_reject_filters() {
        let group_paths = scim_projection_paths(
            ScimResourceKind::Group,
            &format!("{SCIM_GROUP_SCHEMA}:members.$ref,displayName"),
        )
        .expect("group projection paths");

        assert_eq!(
            group_paths,
            vec![
                ScimProjectionPath::sub("members", "$ref"),
                ScimProjectionPath::top("displayName")
            ]
        );

        let filtered = scim_projection_paths(ScimResourceKind::User, "emails[value eq \"x\"]")
            .expect_err("filtered projection paths are not accepted");
        assert_eq!(filtered.scim_type, Some("invalidValue"));
    }
}
