use cairn_database::ConsentGrantListFilter;

use super::super::super::{
    ADMIN_LIST_QUERY_MAX_BYTES, ApiError, urlencoded::parse_url_encoded_pairs,
};
use super::super::pagination::{AdminListQuery, decode_admin_list_cursor};

pub(super) struct ConsentGrantListParts {
    pub(super) page: AdminListQuery,
    pub(super) filter: ConsentGrantListFilter,
}

pub(super) struct ConsentGrantQueryLabels {
    pub(super) too_large: &'static str,
    pub(super) invalid_query: &'static str,
    pub(super) duplicate_parameter: &'static str,
    pub(super) invalid_limit: &'static str,
    pub(super) limit_out_of_range: &'static str,
    pub(super) unsupported_parameter: &'static str,
    pub(super) invalid_status: &'static str,
}

pub(super) fn parse_consent_grant_list_parts(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
    labels: ConsentGrantQueryLabels,
) -> Result<ConsentGrantListParts, ApiError> {
    debug_assert!(default_limit > 0);
    debug_assert!(default_limit <= max_limit);

    let query = raw_query.unwrap_or_default();
    if query.len() > ADMIN_LIST_QUERY_MAX_BYTES {
        return Err(ApiError::bad_request(labels.too_large));
    }

    let pairs =
        parse_url_encoded_pairs(query).map_err(|_| ApiError::bad_request(labels.invalid_query))?;
    let mut limit = None;
    let mut cursor = None;
    let mut revoked = None;
    let mut status_seen = false;

    for (name, value) in pairs {
        match name.as_str() {
            "limit" if limit.is_some() => {
                return Err(ApiError::bad_request(labels.duplicate_parameter));
            }
            "cursor" if cursor.is_some() => {
                return Err(ApiError::bad_request(labels.duplicate_parameter));
            }
            "status" if status_seen => {
                return Err(ApiError::bad_request(labels.duplicate_parameter));
            }
            "limit" => {
                let parsed = value
                    .parse::<i64>()
                    .map_err(|_| ApiError::bad_request(labels.invalid_limit))?;
                if parsed < 1 || parsed > max_limit {
                    return Err(ApiError::bad_request(labels.limit_out_of_range));
                }
                limit = Some(parsed);
            }
            "cursor" => {
                cursor = Some(decode_admin_list_cursor(&value)?);
            }
            "status" => {
                status_seen = true;
                revoked = consent_grant_status_filter(&value, labels.invalid_status)?;
            }
            _ => return Err(ApiError::bad_request(labels.unsupported_parameter)),
        }
    }

    Ok(ConsentGrantListParts {
        page: AdminListQuery {
            limit: limit.unwrap_or(default_limit),
            cursor,
        },
        filter: ConsentGrantListFilter { revoked },
    })
}

fn consent_grant_status_filter(
    value: &str,
    invalid_status_message: &'static str,
) -> Result<Option<bool>, ApiError> {
    match value.trim() {
        "all" => Ok(None),
        "active" => Ok(Some(false)),
        "revoked" => Ok(Some(true)),
        _ => Err(ApiError::bad_request(invalid_status_message)),
    }
}
