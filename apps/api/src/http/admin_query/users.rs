#[cfg(test)]
use axum::http::StatusCode;
use cairn_database::UserListFilter;
use cairn_domain::UserStatus;

use super::super::{ADMIN_LIST_QUERY_MAX_BYTES, ApiError, urlencoded::parse_url_encoded_pairs};
#[cfg(test)]
use super::pagination::encode_admin_list_cursor;
use super::pagination::{AdminListQuery, decode_admin_list_cursor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct AdminUserListQuery {
    pub(in crate::http) page: AdminListQuery,
    pub(in crate::http) filter: UserListFilter,
}

pub(in crate::http) fn admin_user_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<AdminUserListQuery, ApiError> {
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
    let mut status = None;
    let mut search_seen = false;
    let mut status_seen = false;

    for (name, value) in pairs {
        match name.as_str() {
            "limit" if limit.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "cursor" if cursor.is_some() => {
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
                if search_seen {
                    return Err(ApiError::bad_request("duplicate admin list parameter"));
                }
                search_seen = true;
                let trimmed = value.trim();
                if trimmed.len() > 128 {
                    return Err(ApiError::bad_request("admin user search query too large"));
                }
                if !trimmed.is_empty() {
                    search_prefix = Some(trimmed.to_owned());
                }
            }
            "status" => {
                if status_seen {
                    return Err(ApiError::bad_request("duplicate admin list parameter"));
                }
                status_seen = true;
                status = Some(admin_user_status_filter(&value)?);
            }
            _ => return Err(ApiError::bad_request("unsupported admin list parameter")),
        }
    }

    Ok(AdminUserListQuery {
        page: AdminListQuery {
            limit: limit.unwrap_or(default_limit),
            cursor,
        },
        filter: UserListFilter {
            search_prefix,
            status,
        },
    })
}

fn admin_user_status_filter(value: &str) -> Result<UserStatus, ApiError> {
    match value {
        "active" => Ok(UserStatus::Active),
        "suspended" => Ok(UserStatus::Suspended),
        "locked" => Ok(UserStatus::Locked),
        _ => Err(ApiError::bad_request("invalid admin user status filter")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_database::ListCursor;
    use time::OffsetDateTime;
    use uuid::Uuid;

    const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
    const ADMIN_LIST_MAX_LIMIT: i64 = 250;

    #[test]
    fn admin_user_list_query_parser_accepts_bounded_filters() {
        let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
        let encoded_cursor = encode_admin_list_cursor(cursor);
        assert_eq!(
            admin_user_list_query(
                Some(&format!(
                    "q=Admin%20User&status=suspended&limit=25&cursor={encoded_cursor}"
                )),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("filtered user query"),
            AdminUserListQuery {
                page: AdminListQuery {
                    limit: 25,
                    cursor: Some(cursor),
                },
                filter: UserListFilter {
                    search_prefix: Some("Admin User".to_owned()),
                    status: Some(UserStatus::Suspended),
                },
            }
        );

        assert_eq!(
            admin_user_list_query(
                Some("q=%20%20"),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("blank search is ignored")
            .filter,
            UserListFilter::default()
        );

        let long_query = format!("q={}", "a".repeat(129));
        for (query, expected) in [
            ("q=a&q=b", "duplicate admin list parameter"),
            (
                "status=active&status=locked",
                "duplicate admin list parameter",
            ),
            ("status=disabled", "invalid admin user status filter"),
            (long_query.as_str(), "admin user search query too large"),
        ] {
            let error =
                admin_user_list_query(Some(query), ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT)
                    .expect_err("invalid user list query must fail");
            assert_api_bad_request_message(error, expected);
        }
    }

    fn assert_api_bad_request_message(error: ApiError, expected_message: &str) {
        assert!(matches!(
            error,
            ApiError::Status {
                status: StatusCode::BAD_REQUEST,
                ref message,
                ..
            } if message == expected_message
        ));
    }
}
