use super::{
    AdminConsentGrantListQuery,
    common::{ConsentGrantQueryLabels, parse_consent_grant_list_parts},
};
use crate::http::ApiError;

pub(in crate::http) fn admin_consent_grant_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<AdminConsentGrantListQuery, ApiError> {
    let parts = parse_consent_grant_list_parts(
        raw_query,
        default_limit,
        max_limit,
        ConsentGrantQueryLabels {
            too_large: "admin list query too large",
            invalid_query: "invalid admin list query",
            duplicate_parameter: "duplicate admin list parameter",
            invalid_limit: "invalid admin list limit",
            limit_out_of_range: "admin list limit out of range",
            unsupported_parameter: "unsupported admin list parameter",
            invalid_status: "invalid admin consent status filter",
        },
    )?;

    Ok(AdminConsentGrantListQuery {
        page: parts.page,
        filter: parts.filter,
    })
}
