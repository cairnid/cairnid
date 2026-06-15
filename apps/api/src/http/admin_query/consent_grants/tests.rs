use axum::http::StatusCode;
use cairn_database::{ConsentGrantListFilter, ListCursor};
use time::OffsetDateTime;
use uuid::Uuid;

use super::*;
use crate::http::admin_query::pagination::encode_admin_list_cursor;
use crate::http::api_response::ApiError;

const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
const ADMIN_LIST_MAX_LIMIT: i64 = 250;

#[test]
fn admin_consent_grant_list_query_parser_accepts_status_filter() {
    let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
    let encoded_cursor = encode_admin_list_cursor(cursor);
    assert_eq!(
        admin_consent_grant_list_query(
            Some(&format!("status=revoked&limit=25&cursor={encoded_cursor}")),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("filtered consent grant query"),
        AdminConsentGrantListQuery {
            page: AdminListQuery {
                limit: 25,
                cursor: Some(cursor),
            },
            filter: ConsentGrantListFilter {
                revoked: Some(true),
            },
        }
    );

    assert_eq!(
        admin_consent_grant_list_query(
            Some("status=all"),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("all status is accepted")
        .filter,
        ConsentGrantListFilter::default()
    );
    assert_eq!(
        admin_consent_grant_list_query(
            Some("status=active"),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("active status is accepted")
        .filter,
        ConsentGrantListFilter {
            revoked: Some(false),
        }
    );

    for (query, expected) in [
        (
            "status=active&status=revoked",
            "duplicate admin list parameter",
        ),
        ("status=", "invalid admin consent status filter"),
        ("status=pending", "invalid admin consent status filter"),
        ("scope=openid", "unsupported admin list parameter"),
    ] {
        let error = admin_consent_grant_list_query(
            Some(query),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT,
        )
        .expect_err("invalid consent grant list query must fail");
        assert_api_bad_request_message(error, expected);
    }
}

#[test]
fn session_consent_grant_list_query_parser_accepts_status_filter() {
    let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
    let encoded_cursor = encode_admin_list_cursor(cursor);
    assert_eq!(
        session_consent_grant_list_query(
            Some(&format!("status=revoked&limit=25&cursor={encoded_cursor}")),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("filtered session consent grant query"),
        SessionConsentGrantListQuery {
            page: AdminListQuery {
                limit: 25,
                cursor: Some(cursor),
            },
            filter: ConsentGrantListFilter {
                revoked: Some(true),
            },
        }
    );

    assert_eq!(
        session_consent_grant_list_query(
            Some("status=all"),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("all status is accepted")
        .filter,
        ConsentGrantListFilter::default()
    );
    assert_eq!(
        session_consent_grant_list_query(
            Some("status=active"),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("active status is accepted")
        .filter,
        ConsentGrantListFilter {
            revoked: Some(false),
        }
    );

    for (query, expected) in [
        (
            "status=active&status=revoked",
            "duplicate session consent list parameter",
        ),
        ("status=", "invalid session consent status filter"),
        ("status=pending", "invalid session consent status filter"),
        ("scope=openid", "unsupported session consent list parameter"),
    ] {
        let error = session_consent_grant_list_query(
            Some(query),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT,
        )
        .expect_err("invalid session consent grant list query must fail");
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
