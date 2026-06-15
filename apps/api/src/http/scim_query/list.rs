use super::super::{
    scim_projection::{ScimResourceKind, scim_projection_from_query, scim_projection_paths},
    scim_protocol::{
        SCIM_DEFAULT_COUNT, SCIM_MAX_COUNT, SCIM_MAX_START_INDEX, SCIM_QUERY_MAX_BYTES, ScimError,
    },
    urlencoded::parse_url_encoded_pairs,
};
use super::{
    filter::{scim_group_filter, scim_user_filter},
    types::{ScimGroupListQuery, ScimUserListQuery},
};

pub(in crate::http) fn scim_user_list_query(
    raw_query: Option<&str>,
) -> Result<ScimUserListQuery, ScimError> {
    let query = raw_query.unwrap_or_default();
    if query.len() > SCIM_QUERY_MAX_BYTES {
        return Err(ScimError::invalid_value("SCIM query too large"));
    }

    let pairs = parse_url_encoded_pairs(query)
        .map_err(|_| ScimError::invalid_value("invalid SCIM query"))?;
    let mut start_index = None;
    let mut count = None;
    let mut filter = None;
    let mut attributes = None;
    let mut excluded_attributes = None;

    for (name, value) in pairs {
        match name.as_str() {
            "startIndex" if start_index.is_some() => {
                return Err(ScimError::invalid_value("duplicate startIndex parameter"));
            }
            "count" if count.is_some() => {
                return Err(ScimError::invalid_value("duplicate count parameter"));
            }
            "filter" if filter.is_some() => {
                return Err(ScimError::invalid_value("duplicate filter parameter"));
            }
            "attributes" if attributes.is_some() => {
                return Err(ScimError::invalid_value("duplicate attributes parameter"));
            }
            "excludedAttributes" if excluded_attributes.is_some() => {
                return Err(ScimError::invalid_value(
                    "duplicate excludedAttributes parameter",
                ));
            }
            "startIndex" => start_index = Some(scim_list_start_index(&value)?),
            "count" => count = Some(scim_list_count(&value)?),
            "filter" => filter = Some(scim_user_filter(&value)?),
            "attributes" => {
                attributes = Some(scim_projection_paths(ScimResourceKind::User, &value)?);
            }
            "excludedAttributes" => {
                excluded_attributes = Some(scim_projection_paths(ScimResourceKind::User, &value)?);
            }
            _ => return Err(ScimError::invalid_value("unsupported SCIM query parameter")),
        }
    }

    Ok(ScimUserListQuery {
        start_index: start_index.unwrap_or(1),
        count: count.unwrap_or(SCIM_DEFAULT_COUNT),
        filter: filter.unwrap_or_default(),
        projection: scim_projection_from_query(attributes, excluded_attributes)?,
    })
}

pub(in crate::http) fn scim_group_list_query(
    raw_query: Option<&str>,
) -> Result<ScimGroupListQuery, ScimError> {
    let query = raw_query.unwrap_or_default();
    if query.len() > SCIM_QUERY_MAX_BYTES {
        return Err(ScimError::invalid_value("SCIM query too large"));
    }

    let pairs = parse_url_encoded_pairs(query)
        .map_err(|_| ScimError::invalid_value("invalid SCIM query"))?;
    let mut start_index = None;
    let mut count = None;
    let mut filter = None;
    let mut attributes = None;
    let mut excluded_attributes = None;

    for (name, value) in pairs {
        match name.as_str() {
            "startIndex" if start_index.is_some() => {
                return Err(ScimError::invalid_value("duplicate startIndex parameter"));
            }
            "count" if count.is_some() => {
                return Err(ScimError::invalid_value("duplicate count parameter"));
            }
            "filter" if filter.is_some() => {
                return Err(ScimError::invalid_value("duplicate filter parameter"));
            }
            "attributes" if attributes.is_some() => {
                return Err(ScimError::invalid_value("duplicate attributes parameter"));
            }
            "excludedAttributes" if excluded_attributes.is_some() => {
                return Err(ScimError::invalid_value(
                    "duplicate excludedAttributes parameter",
                ));
            }
            "startIndex" => start_index = Some(scim_list_start_index(&value)?),
            "count" => count = Some(scim_list_count(&value)?),
            "filter" => filter = Some(scim_group_filter(&value)?),
            "attributes" => {
                attributes = Some(scim_projection_paths(ScimResourceKind::Group, &value)?);
            }
            "excludedAttributes" => {
                excluded_attributes = Some(scim_projection_paths(ScimResourceKind::Group, &value)?);
            }
            _ => return Err(ScimError::invalid_value("unsupported SCIM query parameter")),
        }
    }

    Ok(ScimGroupListQuery {
        start_index: start_index.unwrap_or(1),
        count: count.unwrap_or(SCIM_DEFAULT_COUNT),
        filter: filter.unwrap_or_default(),
        projection: scim_projection_from_query(attributes, excluded_attributes)?,
    })
}

fn scim_list_start_index(value: &str) -> Result<i64, ScimError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| ScimError::invalid_value("invalid startIndex"))?;
    if !(1..=SCIM_MAX_START_INDEX).contains(&parsed) {
        return Err(ScimError::invalid_value("startIndex out of range"));
    }
    Ok(parsed)
}

fn scim_list_count(value: &str) -> Result<i64, ScimError> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| ScimError::invalid_value("invalid count"))?;
    if !(0..=SCIM_MAX_COUNT).contains(&parsed) {
        return Err(ScimError::invalid_value("count out of range"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::scim_projection::{
        ScimProjection, ScimProjectionPath, scim_resource_projection_query,
    };
    use crate::http::scim_protocol::SCIM_GROUP_SCHEMA;

    #[test]
    fn user_list_query_accepts_bounded_exact_filters() {
        let query = scim_user_list_query(Some(
            "startIndex=2&count=10&attributes=userName%2Cemails.value&filter=userName%20eq%20%22User%40Example.COM%22%20and%20active%20eq%20true%20and%20externalId%20eq%20%22hr-123%22",
        ))
        .expect("valid SCIM query");

        assert_eq!(query.start_index, 2);
        assert_eq!(query.count, 10);
        assert_eq!(
            query.filter.user_name_eq.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(query.filter.external_id_eq.as_deref(), Some("hr-123"));
        assert_eq!(query.filter.active_eq, Some(true));
        assert_eq!(
            query.projection,
            ScimProjection::Include(vec![
                ScimProjectionPath::top("userName"),
                ScimProjectionPath::sub("emails", "value")
            ])
        );

        let duplicate = scim_user_list_query(Some(
            "filter=userName%20eq%20%22a%40example.com%22%20and%20userName%20eq%20%22b%40example.com%22",
        ))
        .expect_err("duplicate userName filter should fail");
        assert_eq!(duplicate.scim_type, Some("invalidFilter"));

        let unsupported = scim_user_list_query(Some("filter=title%20eq%20%22Admin%22"))
            .expect_err("unsupported filter should fail");
        assert_eq!(unsupported.scim_type, Some("invalidFilter"));

        let mutually_exclusive =
            scim_user_list_query(Some("attributes=userName&excludedAttributes=emails"))
                .expect_err("projection parameters are mutually exclusive");
        assert_eq!(mutually_exclusive.scim_type, Some("invalidValue"));

        let unsupported_projection = scim_user_list_query(Some("attributes=title"))
            .expect_err("unsupported projection should fail");
        assert_eq!(unsupported_projection.scim_type, Some("invalidValue"));
    }

    #[test]
    fn group_list_query_rejects_duplicates_and_resource_filter_parameters() {
        let query = scim_group_list_query(Some(
            "startIndex=3&count=20&excludedAttributes=members.display%2Cmeta&filter=displayName%20eq%20%22Engineering%22%20and%20externalId%20eq%20%22group-123%22",
        ))
        .expect("valid SCIM group query");

        assert_eq!(query.start_index, 3);
        assert_eq!(query.count, 20);
        assert_eq!(query.filter.display_name_eq.as_deref(), Some("Engineering"));
        assert_eq!(query.filter.external_id_eq.as_deref(), Some("group-123"));
        assert_eq!(
            query.projection,
            ScimProjection::Exclude(vec![
                ScimProjectionPath::sub("members", "display"),
                ScimProjectionPath::top("meta")
            ])
        );

        let duplicate = scim_group_list_query(Some(
            "filter=displayName%20eq%20%22A%22%20and%20displayName%20eq%20%22B%22",
        ))
        .expect_err("duplicate displayName filter should fail");
        assert_eq!(duplicate.scim_type, Some("invalidFilter"));

        let unsupported =
            scim_group_list_query(Some("filter=userName%20eq%20%22a%40example.com%22"))
                .expect_err("unsupported filter should fail");
        assert_eq!(unsupported.scim_type, Some("invalidFilter"));

        let resource_filter = scim_resource_projection_query(
            Some("filter=displayName%20eq%20%22Engineering%22"),
            ScimResourceKind::Group,
            "SCIM group query",
        )
        .expect_err("single-resource projection query should reject filter");
        assert_eq!(resource_filter.scim_type, Some("invalidValue"));

        let resource_projection = scim_resource_projection_query(
            Some(&format!("attributes={SCIM_GROUP_SCHEMA}%3Amembers.%24ref")),
            ScimResourceKind::Group,
            "SCIM group query",
        )
        .expect("schema-qualified projection path");
        assert_eq!(
            resource_projection,
            ScimProjection::Include(vec![ScimProjectionPath::sub("members", "$ref")])
        );
    }
}
