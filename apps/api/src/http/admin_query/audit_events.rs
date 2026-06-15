#[cfg(test)]
use axum::http::StatusCode;
use cairn_database::AuditEventListFilter;
use cairn_domain::AuditActorKind;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use super::super::{ADMIN_LIST_QUERY_MAX_BYTES, ApiError, urlencoded::parse_url_encoded_pairs};
#[cfg(test)]
use super::pagination::encode_admin_list_cursor;
use super::pagination::{AdminListQuery, decode_admin_list_cursor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct AdminAuditEventListQuery {
    pub(in crate::http) page: AdminListQuery,
    pub(in crate::http) filter: AuditEventListFilter,
}

pub(in crate::http) fn admin_audit_event_list_query(
    raw_query: Option<&str>,
    default_limit: i64,
    max_limit: i64,
) -> Result<AdminAuditEventListQuery, ApiError> {
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
    let mut action_prefix = None;
    let mut target_prefix = None;
    let mut actor_kind = None;
    let mut actor_id = None;
    let mut created_from = None;
    let mut created_to = None;
    let mut action_seen = false;
    let mut target_seen = false;

    for (name, value) in pairs {
        match name.as_str() {
            "limit" if limit.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "cursor" if cursor.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "action" if action_seen => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "target" if target_seen => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "actor_kind" if actor_kind.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "actor_id" if actor_id.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "from" if created_from.is_some() => {
                return Err(ApiError::bad_request("duplicate admin list parameter"));
            }
            "to" if created_to.is_some() => {
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
            "action" => {
                action_seen = true;
                action_prefix =
                    admin_audit_prefix_filter(&value, "admin audit action filter too large")?;
            }
            "target" => {
                target_seen = true;
                target_prefix =
                    admin_audit_prefix_filter(&value, "admin audit target filter too large")?;
            }
            "actor_kind" => {
                actor_kind = Some(admin_audit_actor_kind_filter(&value)?);
            }
            "actor_id" => {
                actor_id = Some(admin_audit_actor_id_filter(&value)?);
            }
            "from" => {
                created_from = Some(admin_audit_timestamp_filter(&value)?);
            }
            "to" => {
                created_to = Some(admin_audit_timestamp_filter(&value)?);
            }
            _ => return Err(ApiError::bad_request("unsupported admin list parameter")),
        }
    }

    if let (Some(from), Some(to)) = (created_from, created_to)
        && from >= to
    {
        return Err(ApiError::bad_request("admin audit time range invalid"));
    }

    Ok(AdminAuditEventListQuery {
        page: AdminListQuery {
            limit: limit.unwrap_or(default_limit),
            cursor,
        },
        filter: AuditEventListFilter {
            action_prefix,
            target_prefix,
            actor_kind,
            actor_id,
            created_from,
            created_to,
        },
    })
}

fn admin_audit_prefix_filter(
    value: &str,
    too_large_message: &'static str,
) -> Result<Option<String>, ApiError> {
    let trimmed = value.trim();
    if trimmed.len() > 128 {
        return Err(ApiError::bad_request(too_large_message));
    }

    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

fn admin_audit_actor_kind_filter(value: &str) -> Result<AuditActorKind, ApiError> {
    match value {
        "user" => Ok(AuditActorKind::User),
        "client" => Ok(AuditActorKind::Client),
        "system" => Ok(AuditActorKind::System),
        _ => Err(ApiError::bad_request(
            "invalid admin audit actor kind filter",
        )),
    }
}

fn admin_audit_actor_id_filter(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value.trim())
        .map_err(|_| ApiError::bad_request("invalid admin audit actor_id filter"))
}

fn admin_audit_timestamp_filter(value: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| ApiError::bad_request("invalid admin audit timestamp filter"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_database::ListCursor;

    const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
    const ADMIN_LIST_MAX_LIMIT: i64 = 250;

    #[test]
    fn admin_audit_event_list_query_parser_accepts_bounded_filters() {
        let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
        let encoded_cursor = encode_admin_list_cursor(cursor);
        let actor_id = Uuid::new_v4();
        let created_from =
            OffsetDateTime::parse("2026-06-07T00:00:00Z", &Rfc3339).expect("timestamp parses");
        let created_to =
            OffsetDateTime::parse("2026-06-08T00:00:00Z", &Rfc3339).expect("timestamp parses");
        let query = format!(
            "action=Admin.User&target={actor_id}&actor_kind=user&actor_id={actor_id}&from=2026-06-07T00%3A00%3A00Z&to=2026-06-08T00%3A00%3A00Z&limit=25&cursor={encoded_cursor}"
        );

        assert_eq!(
            admin_audit_event_list_query(
                Some(&query),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("filtered audit query"),
            AdminAuditEventListQuery {
                page: AdminListQuery {
                    limit: 25,
                    cursor: Some(cursor),
                },
                filter: AuditEventListFilter {
                    action_prefix: Some("Admin.User".to_owned()),
                    target_prefix: Some(actor_id.to_string()),
                    actor_kind: Some(AuditActorKind::User),
                    actor_id: Some(actor_id),
                    created_from: Some(created_from),
                    created_to: Some(created_to),
                },
            }
        );

        assert_eq!(
            admin_audit_event_list_query(
                Some("action=%20%20&target=%20"),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT
            )
            .expect("blank prefixes are ignored")
            .filter,
            AuditEventListFilter::default()
        );

        let long_action_query = format!("action={}", "a".repeat(129));
        let invalid_time_range = "from=2026-06-08T00%3A00%3A00Z&to=2026-06-07T00%3A00%3A00Z";
        for (query, expected) in [
            ("action=a&action=b", "duplicate admin list parameter"),
            ("action=&action=b", "duplicate admin list parameter"),
            ("actor_kind=robot", "invalid admin audit actor kind filter"),
            ("actor_id=not-a-uuid", "invalid admin audit actor_id filter"),
            ("from=not-a-time", "invalid admin audit timestamp filter"),
            (invalid_time_range, "admin audit time range invalid"),
            (
                long_action_query.as_str(),
                "admin audit action filter too large",
            ),
        ] {
            let error = admin_audit_event_list_query(
                Some(query),
                ADMIN_LIST_DEFAULT_LIMIT,
                ADMIN_LIST_MAX_LIMIT,
            )
            .expect_err("invalid audit list query must fail");
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
