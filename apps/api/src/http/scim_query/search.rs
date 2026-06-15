use super::super::{
    scim_projection::{ScimResourceKind, scim_projection_from_query, scim_search_projection_paths},
    scim_protocol::{
        SCIM_DEFAULT_COUNT, SCIM_MAX_COUNT, SCIM_MAX_START_INDEX, SCIM_SEARCH_REQUEST_SCHEMA,
        ScimError,
    },
};
use super::{
    filter::{scim_group_filter, scim_user_filter},
    types::{ScimGroupListQuery, ScimSearchRequest, ScimUserListQuery},
};

pub(in crate::http) fn reject_scim_search_query(raw_query: Option<&str>) -> Result<(), ScimError> {
    match raw_query {
        Some(query) if !query.is_empty() => Err(ScimError::invalid_value(
            "SCIM SearchRequest query parameters are not supported",
        )),
        _ => Ok(()),
    }
}

pub(in crate::http) fn scim_user_search_query(
    payload: ScimSearchRequest,
) -> Result<ScimUserListQuery, ScimError> {
    validate_scim_search_request_common(&payload)?;
    Ok(ScimUserListQuery {
        start_index: scim_search_start_index(payload.start_index)?,
        count: scim_search_count(payload.count)?,
        filter: payload
            .filter
            .as_deref()
            .map(scim_user_filter)
            .transpose()?
            .unwrap_or_default(),
        projection: scim_projection_from_query(
            scim_search_projection_paths(ScimResourceKind::User, payload.attributes)?,
            scim_search_projection_paths(ScimResourceKind::User, payload.excluded_attributes)?,
        )?,
    })
}

pub(in crate::http) fn scim_group_search_query(
    payload: ScimSearchRequest,
) -> Result<ScimGroupListQuery, ScimError> {
    validate_scim_search_request_common(&payload)?;
    Ok(ScimGroupListQuery {
        start_index: scim_search_start_index(payload.start_index)?,
        count: scim_search_count(payload.count)?,
        filter: payload
            .filter
            .as_deref()
            .map(scim_group_filter)
            .transpose()?
            .unwrap_or_default(),
        projection: scim_projection_from_query(
            scim_search_projection_paths(ScimResourceKind::Group, payload.attributes)?,
            scim_search_projection_paths(ScimResourceKind::Group, payload.excluded_attributes)?,
        )?,
    })
}

fn validate_scim_search_request_common(payload: &ScimSearchRequest) -> Result<(), ScimError> {
    if payload.schemas.len() != 1 || payload.schemas[0] != SCIM_SEARCH_REQUEST_SCHEMA {
        return Err(ScimError::invalid_value(
            "SCIM SearchRequest schema is required",
        ));
    }
    if payload.sort_by.is_some() || payload.sort_order.is_some() {
        return Err(ScimError::invalid_value(
            "SCIM SearchRequest sorting is not supported",
        ));
    }
    Ok(())
}

fn scim_search_start_index(start_index: Option<i64>) -> Result<i64, ScimError> {
    let start_index = start_index.unwrap_or(1);
    if !(1..=SCIM_MAX_START_INDEX).contains(&start_index) {
        return Err(ScimError::invalid_value("startIndex out of range"));
    }
    Ok(start_index)
}

fn scim_search_count(count: Option<i64>) -> Result<i64, ScimError> {
    let count = count.unwrap_or(SCIM_DEFAULT_COUNT);
    if !(0..=SCIM_MAX_COUNT).contains(&count) {
        return Err(ScimError::invalid_value("count out of range"));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::scim_projection::{ScimProjection, ScimProjectionPath};
    use crate::http::scim_protocol::SCIM_USER_SCHEMA;
    use serde_json::json;

    #[test]
    fn search_request_rejects_sort_and_conflicting_projection_modes() {
        let user_payload: ScimSearchRequest = serde_json::from_value(json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "filter": "userName eq \"User@Example.COM\" and active eq true",
            "startIndex": 2,
            "count": 10,
            "attributes": ["userName", "emails.value"]
        }))
        .expect("valid SearchRequest JSON");
        let user_query = scim_user_search_query(user_payload).expect("valid user SearchRequest");

        assert_eq!(user_query.start_index, 2);
        assert_eq!(user_query.count, 10);
        assert_eq!(
            user_query.filter.user_name_eq.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(user_query.filter.active_eq, Some(true));
        assert_eq!(
            user_query.projection,
            ScimProjection::Include(vec![
                ScimProjectionPath::top("userName"),
                ScimProjectionPath::sub("emails", "value")
            ])
        );

        let group_payload: ScimSearchRequest = serde_json::from_value(json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "filter": "displayName eq \"Engineering\"",
            "excludedAttributes": "members.display,meta"
        }))
        .expect("valid SearchRequest JSON");
        let group_query =
            scim_group_search_query(group_payload).expect("valid group SearchRequest");

        assert_eq!(group_query.start_index, 1);
        assert_eq!(group_query.count, SCIM_DEFAULT_COUNT);
        assert_eq!(
            group_query.filter.display_name_eq.as_deref(),
            Some("Engineering")
        );
        assert_eq!(
            group_query.projection,
            ScimProjection::Exclude(vec![
                ScimProjectionPath::sub("members", "display"),
                ScimProjectionPath::top("meta")
            ])
        );

        let missing_schema: ScimSearchRequest = serde_json::from_value(json!({
            "schemas": [SCIM_USER_SCHEMA],
            "filter": "displayName eq \"Engineering\""
        }))
        .expect("syntactically valid JSON");
        let missing_schema_error =
            scim_group_search_query(missing_schema).expect_err("SearchRequest schema is required");
        assert_eq!(missing_schema_error.scim_type, Some("invalidValue"));

        let sorted: ScimSearchRequest = serde_json::from_value(json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "sortBy": "displayName"
        }))
        .expect("syntactically valid JSON");
        let sorted_error = scim_group_search_query(sorted).expect_err("sort is unsupported");
        assert_eq!(sorted_error.scim_type, Some("invalidValue"));

        let mutually_exclusive: ScimSearchRequest = serde_json::from_value(json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "attributes": ["displayName"],
            "excludedAttributes": ["members"]
        }))
        .expect("syntactically valid JSON");
        let mutually_exclusive_error = scim_group_search_query(mutually_exclusive)
            .expect_err("projection parameters conflict");
        assert_eq!(mutually_exclusive_error.scim_type, Some("invalidValue"));

        let query_error = reject_scim_search_query(Some("count=1"))
            .expect_err("SearchRequest query parameters are not supported");
        assert_eq!(query_error.scim_type, Some("invalidValue"));
    }
}
