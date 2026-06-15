use super::super::api_response::ApiError;
use super::super::oauth_http::{
    BearerTokenError, bearer_challenge_param_value, bearer_challenge_response,
    bearer_challenge_value, bearer_token_error_response, introspection_request_from_oauth_form,
    is_bearer_challenge_param_character, revocation_request_from_oauth_form,
};
use super::super::urlencoded::percent_encode_minimal;
use super::super::{AppState, OAUTH_FORM_BODY_MAX_BYTES, OAUTH_QUERY_MAX_BYTES, build_router};
use super::{api_test_database, response_json, test_access_token, test_config, test_oidc_client};
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
};
use cairn_database::Database;
use cairn_domain::User;
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn bearer_challenge_responses_use_rfc6750_headers_and_no_store() {
    let missing = bearer_challenge_response(StatusCode::UNAUTHORIZED, None, None, None);
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\""
    );
    assert_eq!(
        missing.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let insufficient_scope = bearer_challenge_response(
        StatusCode::FORBIDDEN,
        Some("insufficient_scope"),
        Some("userinfo requires a user access token"),
        Some("openid"),
    );
    assert_eq!(
        insufficient_scope
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer realm=\"cairn\", error=\"insufficient_scope\", error_description=\"userinfo requires a user access token\", scope=\"openid\""
    );
    assert_eq!(
        insufficient_scope.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );
}

#[test]
fn bearer_challenge_params_are_rfc6750_visible_ascii() {
    let challenge = bearer_challenge_value(
        Some("invalid\n\"token\""),
        Some("bad\n\"quoted\" caf\u{00e9} \\ value"),
        Some("openid\n\"admin\" caf\u{00e9} \\ write"),
    );

    assert_eq!(
        challenge,
        "Bearer realm=\"cairn\", error=\"invalid  token \", error_description=\"bad  quoted  caf    value\", scope=\"openid  admin  caf    write\""
    );
    assert!(
        bearer_challenge_param_value("bad\n\"quoted\" caf\u{00e9} \\ value")
            .chars()
            .all(is_bearer_challenge_param_character)
    );
}

#[test]
fn unsupported_bearer_auth_scheme_uses_bare_challenge() {
    let response = bearer_token_error_response(BearerTokenError::UnsupportedScheme);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn userinfo_route_supports_post_bearer_challenges() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/userinfo")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn userinfo_route_rejects_invalid_post_body_bearer_token() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/userinfo")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("access_token=bad,token"))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\", error=\"invalid_request\", error_description=\"invalid bearer token request\""
    );
}

#[tokio::test]
async fn userinfo_route_rejects_malformed_or_oversized_post_form_before_database() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    for body in [
        "%".to_owned(),
        format!("access_token={}", "a".repeat((2 * 1024 * 1024) + 1)),
    ] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/userinfo")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer realm=\"cairn\", error=\"invalid_request\", error_description=\"invalid bearer token request\""
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}

#[tokio::test]
async fn userinfo_route_rejects_uri_query_bearer_tokens() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo?access_token=query-token")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\", error=\"invalid_request\", error_description=\"invalid bearer token request\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn userinfo_route_rejects_malformed_query_encoding() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo?other=%")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\", error=\"invalid_request\", error_description=\"invalid bearer token request\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn userinfo_route_rejects_oversized_query() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let uri = format!(
        "/oauth2/userinfo?other={}",
        "a".repeat(OAUTH_QUERY_MAX_BYTES + 1)
    );
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\", error=\"invalid_request\", error_description=\"invalid bearer token request\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn userinfo_route_requires_openid_scope_on_user_access_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-userinfo-openid-{}", Uuid::new_v4()),
        "API UserInfo OpenID",
    )?;
    database.create_organization(&organization).await?;

    let user = User::new(
        organization.id,
        format!("userinfo-openid-{}@example.com", Uuid::new_v4()),
        "UserInfo OpenID User",
    )?;
    database.create_user(&user, None).await?;

    let mut client = test_oidc_client(organization.id);
    client.client_id = format!("userinfo-openid-client-{}", Uuid::new_v4());
    client.allowed_scopes = vec!["openid".to_owned(), "profile".to_owned()];
    database.create_oidc_client(&client).await?;

    let raw_access_token = format!("userinfo-profile-only-{}", Uuid::new_v4());
    let mut access_token = test_access_token(
        organization.id,
        user.id,
        client.id,
        &raw_access_token,
        None,
        now,
    );
    access_token.scopes = vec!["profile".to_owned()];
    database.insert_access_token(&access_token).await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {raw_access_token}"))
                .body(axum::body::Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer realm=\"cairn\", error=\"insufficient_scope\", error_description=\"userinfo requires openid scope\", scope=\"openid\""
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    Ok(())
}

#[tokio::test]
async fn oauth_form_endpoints_require_form_content_type() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    for (path, body) in [
        ("/oauth2/token", "grant_type=authorization_code"),
        ("/oauth2/introspect", "token=opaque-token"),
        ("/oauth2/revoke", "token=opaque-token"),
    ] {
        for content_type in [None, Some("application/json")] {
            let mut request = Request::builder().method(Method::POST).uri(path);
            if let Some(content_type) = content_type {
                request = request.header(header::CONTENT_TYPE, content_type);
            }
            let response = build_router(state.clone())
                .oneshot(
                    request
                        .body(axum::body::Body::from(body))
                        .expect("valid request"),
                )
                .await
                .expect("router response");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body bytes");
            let payload: serde_json::Value =
                serde_json::from_slice(&body).expect("OAuth error JSON");
            assert_eq!(payload["error"], "invalid_request");
            assert_eq!(
                payload["error_description"],
                "content type must be application/x-www-form-urlencoded"
            );
        }
    }
}

#[tokio::test]
async fn oauth_form_endpoints_return_oauth_errors_for_extractor_rejections() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    for path in ["/oauth2/token", "/oauth2/introspect", "/oauth2/revoke"] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(
                        header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
                    .body(axum::body::Body::from("%"))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("OAuth error JSON");
        assert_eq!(payload["error"], "invalid_request");
        assert_eq!(payload["error_description"], "invalid form request");
    }
}

#[tokio::test]
async fn oauth_form_endpoints_reject_oversized_bodies() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let body = "a".repeat(OAUTH_FORM_BODY_MAX_BYTES + 1);

    for path in ["/oauth2/token", "/oauth2/introspect", "/oauth2/revoke"] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(body.clone()))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

        let payload = response_json(response).await.expect("OAuth error JSON");
        assert_eq!(payload["error"], "invalid_request");
        assert_eq!(payload["error_description"], "form body too large");
    }
}

#[tokio::test]
async fn oauth_form_endpoints_reject_bodies_above_axum_default_with_oauth_errors() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let body = "a".repeat((2 * 1024 * 1024) + 1);

    for path in ["/oauth2/token", "/oauth2/introspect", "/oauth2/revoke"] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(body.clone()))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

        let payload = response_json(response).await.expect("OAuth error JSON");
        assert_eq!(payload["error"], "invalid_request");
        assert_eq!(payload["error_description"], "form body too large");
    }
}

#[tokio::test]
async fn oauth_form_endpoints_reject_duplicate_parameters() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    for (path, body) in [
        (
            "/oauth2/token",
            "grant_type=client_credentials&grant_type=refresh_token&client_id=client",
        ),
        ("/oauth2/introspect", "token=one&token=two&client_id=client"),
        ("/oauth2/revoke", "token=one&token=two&client_id=client"),
    ] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

        let payload = response_json(response).await.expect("OAuth error JSON");
        assert_eq!(payload["error"], "invalid_request");
        assert_eq!(payload["error_description"], "duplicate form parameter");
    }
}

#[test]
fn oauth_form_endpoint_parsers_reject_blank_required_tokens() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    for error in [
        introspection_request_from_oauth_form(&headers, b"token=+++&client_id=client")
            .expect_err("blank introspection token should fail"),
        revocation_request_from_oauth_form(&headers, b"token=+++&client_id=client")
            .expect_err("blank revocation token should fail"),
    ] {
        assert!(matches!(
            error,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing token")
        ));
    }
}

#[tokio::test]
async fn revoke_endpoint_revokes_client_bound_access_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-oauth-revoke-{}", Uuid::new_v4()),
        "API OAuth Revoke",
    )?;
    database.create_organization(&organization).await?;

    let user = User::new(
        organization.id,
        format!("oauth-revoke-user-{}@example.com", Uuid::new_v4()),
        "OAuth Revoke User",
    )?;
    database.create_user(&user, None).await?;

    let mut client = test_oidc_client(organization.id);
    client.client_id = format!("oauth-revoke-client-{}", Uuid::new_v4());
    database.create_oidc_client(&client).await?;

    let raw_access_token = format!("oauth-revoke-access-{}", Uuid::new_v4());
    let access_token = test_access_token(
        organization.id,
        user.id,
        client.id,
        &raw_access_token,
        None,
        now,
    );
    database.insert_access_token(&access_token).await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={}&token={raw_access_token}&token_type_hint=access_token",
                    percent_encode_minimal(&client.client_id)
                )))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    assert!(body.is_empty());

    let revoked_access_token = database
        .get_access_token(&access_token.token_hash)
        .await?
        .expect("access token exists");
    assert!(revoked_access_token.revoked_at.is_some());

    Ok(())
}

#[tokio::test]
async fn token_endpoint_rejects_blank_grant_type_as_invalid_request() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "grant_type=+++&client_id=public-client",
                ))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

    let payload = response_json(response).await.expect("OAuth error JSON");
    assert_eq!(payload["error"], "invalid_request");
    assert_eq!(payload["error_description"], "missing grant_type");
}

#[tokio::test]
async fn token_endpoint_distinguishes_malformed_and_unsupported_grant_type() {
    use tower::ServiceExt as _;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };

    let malformed_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "grant_type=authorization_code+&client_id=public-client",
                ))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(malformed_response.status(), StatusCode::BAD_REQUEST);
    let payload = response_json(malformed_response)
        .await
        .expect("OAuth error JSON");
    assert_eq!(payload["error"], "invalid_request");
    assert_eq!(payload["error_description"], "invalid grant_type");

    let unsupported_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "grant_type=password&client_id=public-client",
                ))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(unsupported_response.status(), StatusCode::BAD_REQUEST);
    let payload = response_json(unsupported_response)
        .await
        .expect("OAuth error JSON");
    assert_eq!(payload["error"], "unsupported_grant_type");
    assert!(payload.get("error_description").is_none());
}
