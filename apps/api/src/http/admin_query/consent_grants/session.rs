use super::{
    SessionConsentGrantListQuery,
    common::{ConsentGrantQueryLabels, parse_consent_grant_list_parts},
};
use crate::http::ApiError;

pub(in crate::http) fn session_consent_grant_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<SessionConsentGrantListQuery, ApiError> {
    let parts = parse_consent_grant_list_parts(
        raw_query,
        default_limit,
        max_limit,
        ConsentGrantQueryLabels {
            too_large: "session consent list query too large",
            invalid_query: "invalid session consent list query",
            duplicate_parameter: "duplicate session consent list parameter",
            invalid_limit: "invalid session consent list limit",
            limit_out_of_range: "session consent list limit out of range",
            unsupported_parameter: "unsupported session consent list parameter",
            invalid_status: "invalid session consent status filter",
        },
    )?;

    Ok(SessionConsentGrantListQuery {
        page: parts.page,
        filter: parts.filter,
    })
}
