use cairn_database::OidcClientListFilter;

use super::super::{
    super::{ADMIN_LIST_QUERY_MAX_BYTES, ApiError, urlencoded::parse_url_encoded_pairs},
    pagination::{AdminListQuery, decode_admin_list_cursor},
};
use super::{
    filters::{
        admin_oidc_client_grant_type_filter, admin_oidc_client_scope_filter,
        admin_oidc_client_status_filter, admin_oidc_client_type_filter,
    },
    types::AdminOidcClientListQuery,
};

pub(in crate::http) fn admin_oidc_client_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<AdminOidcClientListQuery, ApiError> {
    debug_assert!(default_limit > 0);
    debug_assert!(default_limit <= max_limit);

    let query = raw_query.unwrap_or_default();
    if query.len() > ADMIN_LIST_QUERY_MAX_BYTES {
        return Err(ApiError::bad_request("admin list query too large"));
    }

    let pairs = parse_url_encoded_pairs(query)
        .map_err(|_| ApiError::bad_request("invalid admin list query"))?;
    let mut limit = None;
    let mut cursor = None;
    let mut search_prefix = None;
    let mut public_client = None;
    let mut status = None;
    let mut grant_type = None;
    let mut scope = None;
    let mut search_seen = false;
    let mut scope_seen = false;

    for (name, value) in pairs {
        match name.as_str() {
            "limit" if limit.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "cursor" if cursor.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "q" if search_seen => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "client_type" if public_client.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "status" if status.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "grant_type" if grant_type.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "scope" if scope_seen => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "limit" => {
                let parsed = value
                    .parse::<i64>()
                    .map_err(|_| ApiError::bad_request("invalid admin list limit"))?;
                if parsed < 1 || parsed > max_limit {
                    return Err(ApiError::bad_request("admin list limit out of range"));
                }
                limit = Some(parsed);
            }
            "cursor" => {
                cursor = Some(decode_admin_list_cursor(&value)?);
            }
            "q" => {
                search_seen = true;
                let trimmed = value.trim();
                if trimmed.len() > 128 {
                    return Err(ApiError::bad_request(
                        "admin OIDC client search query too large",
                    ));
                }
                if !trimmed.is_empty() {
                    search_prefix = Some(trimmed.to_owned());
                }
            }
            "client_type" => {
                public_client = Some(admin_oidc_client_type_filter(&value)?);
            }
            "status" => {
                status = Some(admin_oidc_client_status_filter(&value)?);
            }
            "grant_type" => {
                grant_type = Some(admin_oidc_client_grant_type_filter(&value)?);
            }
            "scope" => {
                scope_seen = true;
                scope = admin_oidc_client_scope_filter(&value)?;
            }
            _ => return Err(ApiError::bad_request("unsupported admin list parameter")),
        }
    }

    Ok(AdminOidcClientListQuery {
        page: AdminListQuery {
            limit: limit.unwrap_or(default_limit),
            cursor,
        },
        filter: OidcClientListFilter {
            search_prefix,
            public_client,
            status,
            grant_type,
            scope,
        },
    })
}
