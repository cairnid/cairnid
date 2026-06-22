#[cfg(test)]
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_database::ListCursor;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{ADMIN_LIST_QUERY_MAX_BYTES, ApiError, urlencoded::parse_url_encoded_pairs};

#[derive(Debug, Serialize)]
pub(in crate::http) struct ListPage<T> {
    pub(in crate::http) items: Vec<T>,
    pub(in crate::http) next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) struct AdminListQuery {
    pub(in crate::http) limit: i64,
    pub(in crate::http) cursor: Option<ListCursor>,
}

pub(in crate::http) struct ListQueryLabels {
    pub(in crate::http) too_large: &'static str,
    pub(in crate::http) invalid_query: &'static str,
    pub(in crate::http) duplicate_parameter: &'static str,
    pub(in crate::http) invalid_limit: &'static str,
    pub(in crate::http) limit_out_of_range: &'static str,
    pub(in crate::http) invalid_cursor: &'static str,
    pub(in crate::http) unsupported_parameter: &'static str,
}

impl AdminListQuery {
    pub(in crate::http) fn fetch_limit(self) -> i64 {
        self.limit + 1
    }
}

pub(in crate::http) fn admin_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<AdminListQuery, ApiError> {
    list_query(
        raw_query,
        default_limit,
        max_limit,
        ListQueryLabels {
            too_large: "admin list query too large",
            invalid_query: "invalid admin list query",
            duplicate_parameter: "duplicate admin list parameter",
            invalid_limit: "invalid admin list limit",
            limit_out_of_range: "admin list limit out of range",
            invalid_cursor: "invalid admin list cursor",
            unsupported_parameter: "unsupported admin list parameter",
        },
    )
}

pub(in crate::http) fn list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
    labels: ListQueryLabels,
) -> Result<AdminListQuery, ApiError> {
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
    for (name, value) in pairs {
        match name.as_str() {
            "limit" if limit.is_some() => {
                return Err(ApiError::bad_request(labels.duplicate_parameter));
            }
            "cursor" if cursor.is_some() => {
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
                cursor = Some(decode_list_cursor(&value, labels.invalid_cursor)?);
            }
            _ => return Err(ApiError::bad_request(labels.unsupported_parameter)),
        }
    }

    Ok(AdminListQuery {
        limit: limit.unwrap_or(default_limit),
        cursor,
    })
}

pub(in crate::http) fn list_page<T>(
    mut rows: Vec<T>,
    limit: i64,
    cursor_for_item: impl Fn(&T) -> ListCursor,
) -> ListPage<T> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = if has_more {
        rows.last()
            .map(cursor_for_item)
            .map(encode_admin_list_cursor)
    } else {
        None
    };

    ListPage {
        items: rows,
        next_cursor,
    }
}

pub(in crate::http::admin_query) fn encode_admin_list_cursor(cursor: ListCursor) -> String {
    let payload = format!(
        "{}.{}",
        cursor.created_at.unix_timestamp_nanos(),
        cursor.tie_breaker_id
    );
    URL_SAFE_NO_PAD.encode(payload.as_bytes())
}

pub(in crate::http::admin_query) fn decode_admin_list_cursor(
    value: &str,
) -> Result<ListCursor, ApiError> {
    decode_list_cursor(value, "invalid admin list cursor")
}

fn decode_list_cursor(
    value: &str,
    invalid_cursor_message: &'static str,
) -> Result<ListCursor, ApiError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return Err(ApiError::bad_request(invalid_cursor_message));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request(invalid_cursor_message))?;
    let decoded =
        std::str::from_utf8(&decoded).map_err(|_| ApiError::bad_request(invalid_cursor_message))?;
    let (created_at, tie_breaker_id) = decoded
        .split_once('.')
        .ok_or_else(|| ApiError::bad_request(invalid_cursor_message))?;
    let created_at = created_at
        .parse::<i128>()
        .ok()
        .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
        .ok_or_else(|| ApiError::bad_request(invalid_cursor_message))?;
    let tie_breaker_id = Uuid::parse_str(tie_breaker_id)
        .map_err(|_| ApiError::bad_request(invalid_cursor_message))?;

    Ok(ListCursor::new(created_at, tie_breaker_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
    const ADMIN_LIST_MAX_LIMIT: i64 = 250;

    #[test]
    fn admin_list_limit_parser_enforces_strict_bounded_contract() {
        assert_eq!(
            admin_list_query(None, ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT)
                .expect("default list limit"),
            AdminListQuery {
                limit: ADMIN_LIST_DEFAULT_LIMIT,
                cursor: None
            }
        );
        assert_eq!(
            admin_list_query(
                Some("limit=1"),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("minimum list limit"),
            AdminListQuery {
                limit: 1,
                cursor: None
            }
        );
        assert_eq!(
            admin_list_query(
                Some("limit=250"),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("maximum list limit"),
            AdminListQuery {
                limit: ADMIN_LIST_MAX_LIMIT,
                cursor: None
            }
        );

        let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
        let encoded_cursor = encode_admin_list_cursor(cursor);
        assert_eq!(
            admin_list_query(
                Some(&format!("cursor={encoded_cursor}&limit=10")),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("cursor query"),
            AdminListQuery {
                limit: 10,
                cursor: Some(cursor)
            }
        );

        for (query, expected) in [
            ("limit=0", "admin list limit out of range"),
            ("limit=251", "admin list limit out of range"),
            ("limit=ten", "invalid admin list limit"),
            ("limit=", "invalid admin list limit"),
            ("limit=10&limit=20", "duplicate admin list parameter"),
            ("cursor=", "invalid admin list cursor"),
            ("cursor=*", "invalid admin list cursor"),
            ("offset=10", "unsupported admin list parameter"),
            ("limit=%", "invalid admin list query"),
        ] {
            let error =
                admin_list_query(Some(query), ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT)
                    .expect_err("invalid query must fail");
            assert_api_bad_request_message(error, expected);
        }
        let duplicate_cursor_query = format!("cursor={encoded_cursor}&cursor={encoded_cursor}");
        let error = admin_list_query(
            Some(&duplicate_cursor_query),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT,
        )
        .expect_err("duplicate cursor must fail");
        assert_api_bad_request_message(error, "duplicate admin list parameter");

        let query = "a".repeat(ADMIN_LIST_QUERY_MAX_BYTES + 1);
        let error = admin_list_query(Some(&query), ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT)
            .expect_err("oversized query must fail");
        assert_api_bad_request_message(error, "admin list query too large");
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
