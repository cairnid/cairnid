use super::{
    paths::{ScimProjectionPath, ScimResourceKind, ScimSearchAttributes, scim_projection_paths},
    types::ScimProjection,
};
use crate::http::{
    scim_protocol::{SCIM_QUERY_MAX_BYTES, ScimError},
    urlencoded::parse_url_encoded_pairs,
};

pub(in crate::http) fn scim_search_projection_paths(
    kind: ScimResourceKind,
    attributes: Option<ScimSearchAttributes>,
) -> Result<Option<Vec<ScimProjectionPath>>, ScimError> {
    attributes
        .map(|attributes| attributes.projection_paths(kind))
        .transpose()
}

pub(in crate::http) fn scim_resource_projection_query(
    raw_query: Option<&str>,
    kind: ScimResourceKind,
    context: &'static str,
) -> Result<ScimProjection, ScimError> {
    let query = raw_query.unwrap_or_default();
    if query.len() > SCIM_QUERY_MAX_BYTES {
        return Err(ScimError::invalid_value(format!("{context} too large")));
    }

    let pairs = parse_url_encoded_pairs(query)
        .map_err(|_| ScimError::invalid_value(format!("invalid {context}")))?;
    let mut attributes = None;
    let mut excluded_attributes = None;
    for (name, value) in pairs {
        match name.as_str() {
            "attributes" if attributes.is_some() => {
                return Err(ScimError::invalid_value("duplicate attributes parameter"));
            }
            "excludedAttributes" if excluded_attributes.is_some() => {
                return Err(ScimError::invalid_value(
                    "duplicate excludedAttributes parameter",
                ));
            }
            "attributes" => attributes = Some(scim_projection_paths(kind, &value)?),
            "excludedAttributes" => {
                excluded_attributes = Some(scim_projection_paths(kind, &value)?);
            }
            _ => return Err(ScimError::invalid_value("unsupported SCIM query parameter")),
        }
    }

    scim_projection_from_query(attributes, excluded_attributes)
}

pub(in crate::http) fn scim_projection_from_query(
    attributes: Option<Vec<ScimProjectionPath>>,
    excluded_attributes: Option<Vec<ScimProjectionPath>>,
) -> Result<ScimProjection, ScimError> {
    match (attributes, excluded_attributes) {
        (Some(_), Some(_)) => Err(ScimError::invalid_value(
            "attributes and excludedAttributes are mutually exclusive",
        )),
        (Some(attributes), None) => Ok(ScimProjection::Include(attributes)),
        (None, Some(excluded_attributes)) => Ok(ScimProjection::Exclude(excluded_attributes)),
        (None, None) => Ok(ScimProjection::Default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::scim_protocol::SCIM_GROUP_SCHEMA;

    #[test]
    fn projection_query_rejects_conflicts_and_accepts_schema_qualified_attributes() {
        let projection = scim_resource_projection_query(
            Some(&format!(
                "attributes={SCIM_GROUP_SCHEMA}%3Amembers.%24ref,displayName"
            )),
            ScimResourceKind::Group,
            "SCIM group query",
        )
        .expect("valid projection query");

        assert_eq!(
            projection,
            ScimProjection::Include(vec![
                ScimProjectionPath::sub("members", "$ref"),
                ScimProjectionPath::top("displayName")
            ])
        );

        let conflict = scim_resource_projection_query(
            Some("attributes=displayName&excludedAttributes=members"),
            ScimResourceKind::Group,
            "SCIM group query",
        )
        .expect_err("projection modes conflict");
        assert_eq!(conflict.scim_type, Some("invalidValue"));

        let filtered = scim_projection_paths(ScimResourceKind::User, "emails[value eq \"x\"]")
            .expect_err("filtered projection paths are not accepted");
        assert_eq!(filtered.scim_type, Some("invalidValue"));
    }
}
