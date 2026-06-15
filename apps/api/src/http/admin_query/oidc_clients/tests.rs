use axum::http::StatusCode;
use cairn_database::{ListCursor, OidcClientListFilter};
use cairn_domain::{OidcClientStatus, OidcGrantType};
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::super::ApiError;
use super::super::pagination::{AdminListQuery, encode_admin_list_cursor};
use super::admin_oidc_client_list_query;
use super::types::AdminOidcClientListQuery;

const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
const ADMIN_LIST_MAX_LIMIT: i64 = 250;

#[test]
fn admin_oidc_client_list_query_parser_accepts_bounded_filters() {
    let cursor = ListCursor::new(OffsetDateTime::now_utc(), Uuid::new_v4());
    let encoded_cursor = encode_admin_list_cursor(cursor);
    assert_eq!(
        admin_oidc_client_list_query(
            Some(&format!(
                "q=Admin%20Client&client_type=confidential&status=disabled&grant_type=client_credentials&scope=email&limit=25&cursor={encoded_cursor}"
            )),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("filtered OIDC client query"),
        AdminOidcClientListQuery {
            page: AdminListQuery {
                limit: 25,
                cursor: Some(cursor),
            },
            filter: OidcClientListFilter {
                search_prefix: Some("Admin Client".to_owned()),
                public_client: Some(false),
                status: Some(OidcClientStatus::Disabled),
                grant_type: Some(OidcGrantType::ClientCredentials),
                scope: Some("email".to_owned()),
            },
        }
    );

    assert_eq!(
        admin_oidc_client_list_query(
            Some("q=%20%20&scope=%20"),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT
        )
        .expect("blank filters are ignored")
        .filter,
        OidcClientListFilter::default()
    );

    let long_query = format!("q={}", "a".repeat(129));
    let long_scope = format!("scope={}", "a".repeat(129));
    for (query, expected) in [
        ("q=a&q=b", "duplicate admin list parameter"),
        (
            "client_type=public&client_type=confidential",
            "duplicate admin list parameter",
        ),
        (
            "grant_type=authorization_code&grant_type=refresh_token",
            "duplicate admin list parameter",
        ),
        (
            "status=active&status=disabled",
            "duplicate admin list parameter",
        ),
        ("scope=&scope=email", "duplicate admin list parameter"),
        (
            "client_type=private",
            "invalid admin OIDC client type filter",
        ),
        (
            "status=suspended",
            "invalid admin OIDC client status filter",
        ),
        (
            "grant_type=password",
            "invalid admin OIDC client grant_type filter",
        ),
        (
            "scope=bad%20scope",
            "invalid admin OIDC client scope filter",
        ),
        (
            long_query.as_str(),
            "admin OIDC client search query too large",
        ),
        (
            long_scope.as_str(),
            "admin OIDC client scope filter too large",
        ),
    ] {
        let error = admin_oidc_client_list_query(
            Some(query),
            ADMIN_LIST_DEFAULT_LIMIT,
            ADMIN_LIST_MAX_LIMIT,
        )
        .expect_err("invalid OIDC client list query must fail");
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
