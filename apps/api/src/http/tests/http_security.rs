use super::super::api_response::ApiError;
use super::super::content_type::request_has_json_content_type;
use super::super::cookies::CSRF_HEADER;
use super::super::oauth_http::{
    oauth_empty_response, oauth_json_response, oauth_redirect_response,
};
use super::super::security::{
    api_response_requires_no_store, http_trace_labels, http_trace_path,
    security_response_header_pairs, unsafe_api_request_path, validate_api_browser_origin,
};
use super::super::{API_JSON_BODY_MAX_BYTES, AppState, build_router};
use super::{response_json, test_config};
use axum::{
    Json,
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
};
use cairn_database::Database;
use cairn_oidc::OAuthErrorBody;
use serde_json::json;
use uuid::Uuid;

#[test]
fn security_headers_are_strict_for_api_responses() {
    let config = test_config(cairn_domain::Environment::Development);
    let headers = security_response_header_pairs(&config)
        .into_iter()
        .collect::<HeaderMap>();

    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("cross-origin-opener-policy").unwrap(),
        "same-origin"
    );
    assert!(!headers.contains_key("strict-transport-security"));
}

#[test]
fn http_trace_path_excludes_query_parameters() {
    let request = Request::builder()
        .uri("/oauth2/authorize?client_id=client&login_hint=user%40example.com&code=secret")
        .body(axum::body::Body::empty())
        .expect("valid request");

    assert_eq!(http_trace_path(&request), "/oauth2/authorize");
}

#[test]
fn http_trace_labels_exclude_token_bearing_request_data() {
    let cases = [
        (
            Method::GET,
            "/oauth2/authorize?client_id=client&login_hint=person%40example.com&code=query-secret&state=state-secret",
            "/oauth2/authorize",
            "",
        ),
        (
            Method::POST,
            "/oauth2/token?code=query-code-secret&refresh_token=query-refresh-secret",
            "/oauth2/token",
            "grant_type=authorization_code&code=body-code-secret&code_verifier=body-verifier-secret",
        ),
        (
            Method::POST,
            "/oauth2/introspect?token=query-access-secret",
            "/oauth2/introspect",
            "token=body-access-secret&client_secret=body-client-secret",
        ),
        (
            Method::GET,
            "/scim/v2/Users?filter=userName%20eq%20%22person%40example.com%22",
            "/scim/v2/Users",
            "",
        ),
        (
            Method::POST,
            "/api/v1/session/password/change?current_password=query-password-secret",
            "/api/v1/session/password/change",
            r#"{"current_password":"body-password-secret","new_password":"body-new-password-secret"}"#,
        ),
    ];

    for (method, uri, expected_path, body) in cases {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer header-bearer-secret")
            .header(
                header::COOKIE,
                "cairn_session=session-cookie-secret; cairn_csrf=csrf-cookie-secret",
            )
            .header(CSRF_HEADER, "csrf-header-secret")
            .body(axum::body::Body::from(body))
            .expect("valid request");

        let labels = http_trace_labels(&request);
        let snapshot = format!("method={} path={}", labels.method, labels.path);

        assert_eq!(labels.path, expected_path);
        for secret in [
            "query-secret",
            "state-secret",
            "person%40example.com",
            "query-code-secret",
            "query-refresh-secret",
            "body-code-secret",
            "body-verifier-secret",
            "query-access-secret",
            "body-access-secret",
            "body-client-secret",
            "header-bearer-secret",
            "session-cookie-secret",
            "csrf-cookie-secret",
            "csrf-header-secret",
            "query-password-secret",
            "body-password-secret",
            "body-new-password-secret",
        ] {
            assert!(
                !snapshot.contains(secret),
                "trace labels leaked {secret}: {snapshot}"
            );
        }
    }
}

#[test]
fn production_security_headers_include_hsts() {
    let config = test_config(cairn_domain::Environment::Production);
    let headers = security_response_header_pairs(&config)
        .into_iter()
        .collect::<HeaderMap>();

    assert_eq!(
        headers.get("strict-transport-security").unwrap(),
        "max-age=63072000; includeSubDomains"
    );
}

#[test]
fn api_v1_paths_require_no_store_cache_headers() {
    assert!(api_response_requires_no_store("/api/v1/session/csrf"));
    assert!(api_response_requires_no_store("/api/v1/users"));
    assert!(api_response_requires_no_store("/scim/v2/Users"));
    assert!(!api_response_requires_no_store("/.well-known/jwks.json"));
    assert!(!api_response_requires_no_store("/healthz"));
}

#[test]
fn unsafe_api_browser_origin_must_match_public_web_origin() {
    let config = test_config(cairn_domain::Environment::Development);
    let mut headers = HeaderMap::new();

    assert!(validate_api_browser_origin(&config, &Method::GET, "/api/v1/users", &headers).is_ok());
    assert!(validate_api_browser_origin(&config, &Method::POST, "/oauth2/token", &headers).is_ok());
    assert!(validate_api_browser_origin(&config, &Method::POST, "/api/v1/users", &headers).is_ok());

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://localhost:5173"),
    );
    assert!(validate_api_browser_origin(&config, &Method::POST, "/api/v1/users", &headers).is_ok());

    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    assert!(
        validate_api_browser_origin(&config, &Method::POST, "/api/v1/users", &headers).is_err()
    );

    headers.clear();
    headers.insert(
        header::REFERER,
        HeaderValue::from_static("http://localhost:5173/admin/users"),
    );
    assert!(
        validate_api_browser_origin(&config, &Method::DELETE, "/api/v1/users", &headers).is_ok()
    );

    headers.insert(
        header::REFERER,
        HeaderValue::from_static("https://evil.example/admin/users"),
    );
    assert!(
        validate_api_browser_origin(&config, &Method::DELETE, "/api/v1/users", &headers).is_err()
    );
}

#[test]
fn api_json_content_type_accepts_json_media_types() {
    let mut headers = HeaderMap::new();
    assert!(!request_has_json_content_type(&headers));

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    assert!(request_has_json_content_type(&headers));

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/merge-patch+json"),
    );
    assert!(request_has_json_content_type(&headers));

    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/json"));
    assert!(!request_has_json_content_type(&headers));
}

#[tokio::test]
async fn api_json_mutations_reject_invalid_bodies_before_handlers() {
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

    for (content_type, body, expected_error) in [
        (
            None,
            "{}".to_owned(),
            "content type must be application/json",
        ),
        (
            Some("application/json"),
            "{".to_owned(),
            "invalid JSON body",
        ),
        (
            Some("application/json"),
            "a".repeat(API_JSON_BODY_MAX_BYTES + 1),
            "JSON body too large",
        ),
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/session/login");
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
        assert_eq!(
            response_json(response).await.expect("json body"),
            json!({ "error": expected_error })
        );
    }
}

#[test]
fn oauth_responses_disable_http_caching() {
    let json_response = oauth_json_response(StatusCode::OK, Json(json!({ "active": true })));
    assert_eq!(json_response.status(), StatusCode::OK);
    assert_eq!(
        json_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        json_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );

    let empty_response = oauth_empty_response(StatusCode::OK);
    assert_eq!(
        empty_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        empty_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );

    let error_response = ApiError::oauth(
        StatusCode::BAD_REQUEST,
        OAuthErrorBody::invalid_request("invalid request"),
    )
    .into_response();
    assert!(
        !error_response
            .headers()
            .contains_key(header::WWW_AUTHENTICATE)
    );
    assert_eq!(
        error_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        error_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );

    let redirect_response = oauth_redirect_response("https://client.example/callback?code=abc");
    assert!(redirect_response.status().is_redirection());
    assert_eq!(
        redirect_response.headers().get(header::LOCATION).unwrap(),
        "https://client.example/callback?code=abc"
    );
    assert_eq!(
        redirect_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        redirect_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );
}

#[tokio::test]
async fn api_v1_cross_origin_mutation_classes_are_rejected_before_handlers() {
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

    struct MutationRoute {
        name: &'static str,
        method: Method,
        path: String,
    }

    let user_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();
    let client_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    let routes = vec![
        MutationRoute {
            name: "bootstrap",
            method: Method::POST,
            path: "/api/v1/bootstrap".to_owned(),
        },
        MutationRoute {
            name: "consent",
            method: Method::POST,
            path: "/api/v1/consent".to_owned(),
        },
        MutationRoute {
            name: "invitation create",
            method: Method::POST,
            path: "/api/v1/invitations".to_owned(),
        },
        MutationRoute {
            name: "invitation accept",
            method: Method::POST,
            path: "/api/v1/invitations/accept".to_owned(),
        },
        MutationRoute {
            name: "email verification request",
            method: Method::POST,
            path: "/api/v1/session/email-verification/request".to_owned(),
        },
        MutationRoute {
            name: "email verification confirm",
            method: Method::POST,
            path: "/api/v1/session/email-verification/confirm".to_owned(),
        },
        MutationRoute {
            name: "login",
            method: Method::POST,
            path: "/api/v1/session/login".to_owned(),
        },
        MutationRoute {
            name: "reauthenticate",
            method: Method::POST,
            path: "/api/v1/session/reauthenticate".to_owned(),
        },
        MutationRoute {
            name: "password change",
            method: Method::POST,
            path: "/api/v1/session/password/change".to_owned(),
        },
        MutationRoute {
            name: "logout",
            method: Method::POST,
            path: "/api/v1/session/logout".to_owned(),
        },
        MutationRoute {
            name: "current-user browser session revoke",
            method: Method::DELETE,
            path: format!("/api/v1/session/browser-sessions/{session_id}"),
        },
        MutationRoute {
            name: "current-user consent revoke",
            method: Method::DELETE,
            path: format!("/api/v1/session/consent-grants/{grant_id}"),
        },
        MutationRoute {
            name: "MFA credential revoke",
            method: Method::DELETE,
            path: format!("/api/v1/session/mfa/credentials/{credential_id}"),
        },
        MutationRoute {
            name: "recovery-code regeneration",
            method: Method::POST,
            path: "/api/v1/session/mfa/recovery-codes/regenerate".to_owned(),
        },
        MutationRoute {
            name: "TOTP enrollment start",
            method: Method::POST,
            path: "/api/v1/session/mfa/totp/start".to_owned(),
        },
        MutationRoute {
            name: "TOTP enrollment confirm",
            method: Method::POST,
            path: "/api/v1/session/mfa/totp/confirm".to_owned(),
        },
        MutationRoute {
            name: "WebAuthn enrollment start",
            method: Method::POST,
            path: "/api/v1/session/mfa/webauthn/start".to_owned(),
        },
        MutationRoute {
            name: "WebAuthn enrollment finish",
            method: Method::POST,
            path: "/api/v1/session/mfa/webauthn/finish".to_owned(),
        },
        MutationRoute {
            name: "password recovery request",
            method: Method::POST,
            path: "/api/v1/session/password-recovery/request".to_owned(),
        },
        MutationRoute {
            name: "password recovery complete",
            method: Method::POST,
            path: "/api/v1/session/password-recovery/complete".to_owned(),
        },
        MutationRoute {
            name: "admin user create",
            method: Method::POST,
            path: "/api/v1/users".to_owned(),
        },
        MutationRoute {
            name: "admin user status",
            method: Method::PUT,
            path: format!("/api/v1/users/{user_id}/status"),
        },
        MutationRoute {
            name: "admin user email verification",
            method: Method::POST,
            path: format!("/api/v1/users/{user_id}/email-verification/request"),
        },
        MutationRoute {
            name: "admin user password recovery",
            method: Method::POST,
            path: format!("/api/v1/users/{user_id}/password-recovery/request"),
        },
        MutationRoute {
            name: "admin user browser session revoke",
            method: Method::DELETE,
            path: format!("/api/v1/users/{user_id}/browser-sessions/{session_id}"),
        },
        MutationRoute {
            name: "admin group create",
            method: Method::POST,
            path: "/api/v1/groups".to_owned(),
        },
        MutationRoute {
            name: "admin group membership upsert",
            method: Method::PUT,
            path: format!("/api/v1/groups/{group_id}/memberships/{user_id}"),
        },
        MutationRoute {
            name: "admin group membership delete",
            method: Method::DELETE,
            path: format!("/api/v1/groups/{group_id}/memberships/{user_id}"),
        },
        MutationRoute {
            name: "admin consent policy template create",
            method: Method::POST,
            path: "/api/v1/oidc/consent-policy-templates".to_owned(),
        },
        MutationRoute {
            name: "admin OIDC client create",
            method: Method::POST,
            path: "/api/v1/oidc/clients".to_owned(),
        },
        MutationRoute {
            name: "admin OIDC client secret rotation",
            method: Method::POST,
            path: format!("/api/v1/oidc/clients/{client_id}/secret/rotate"),
        },
        MutationRoute {
            name: "admin OIDC client status",
            method: Method::PUT,
            path: format!("/api/v1/oidc/clients/{client_id}/status"),
        },
        MutationRoute {
            name: "admin OIDC consent revoke",
            method: Method::DELETE,
            path: format!("/api/v1/oidc/clients/{client_id}/consent-grants/{grant_id}"),
        },
    ];
    let app = build_router(state);

    for route in routes {
        assert!(
            unsafe_api_request_path(&route.method, route.path.as_str()),
            "{} must be covered by the browser-origin policy",
            route.name
        );

        for (browser_header, browser_header_value) in [
            (header::ORIGIN, "https://evil.example"),
            (header::REFERER, "https://evil.example/admin"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(route.method.clone())
                        .uri(route.path.as_str())
                        .header(browser_header.clone(), browser_header_value)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from("{}"))
                        .expect("valid request"),
                )
                .await
                .expect("router response");

            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{} with {browser_header}",
                route.name
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store",
                "{} with {browser_header}",
                route.name
            );
            assert_eq!(
                response.headers().get(header::PRAGMA).unwrap(),
                "no-cache",
                "{} with {browser_header}",
                route.name
            );
            assert_eq!(
                response.headers().get("x-content-type-options").unwrap(),
                "nosniff",
                "{} with {browser_header}",
                route.name
            );

            let payload = response_json(response).await.expect("error response JSON");
            assert_eq!(
                payload["error"], "invalid request origin",
                "{} with {browser_header}",
                route.name
            );
        }
    }
}

#[tokio::test]
async fn api_v1_responses_disable_http_caching() {
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
                .uri("/api/v1/session/csrf")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .is_some_and(|cookie| cookie
                .to_str()
                .is_ok_and(|value| value.starts_with("cairn_csrf=")))
    );
}
