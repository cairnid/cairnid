use super::super::cookies::CSRF_HEADER;
use super::super::{AppState, OAUTH_FORM_BODY_MAX_BYTES, OAUTH_QUERY_MAX_BYTES, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_config,
    test_mfa_session, test_oidc_client, test_session,
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_database::Database;
use cairn_domain::{
    AuthSession, ConsentGrant, ConsentGrantMode, ConsentPolicyTemplate, Group, Membership,
    MembershipRole, OidcClient, OidcClientStatus, Organization, RedirectUri, User,
};
use cairn_oidc::{IdTokenIssueRequest, SigningMaterial, issue_id_token};
use openssl::{pkey::PKey, rsa::Rsa};
use serde_json::{Value, json};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

const OIDC_PUBLIC_FLOW_CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const OIDC_PUBLIC_FLOW_CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[tokio::test]
async fn authorization_route_rejects_ambiguous_client_duplicates_before_database() {
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
                    .uri("/oauth2/authorize?response_type=code&client_id=public-client&client_id=other-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                    .body(axum::body::Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "duplicate authorization request parameter" })
    );
}

#[tokio::test]
async fn authorization_route_rejects_malformed_query_encoding_before_database() {
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
                    .uri("/oauth2/authorize?client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&state=%")
                    .body(axum::body::Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "invalid authorization request" })
    );
}

#[tokio::test]
async fn authorization_route_rejects_oversized_query_before_database() {
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
        "/oauth2/authorize?state={}",
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
        response_json(response).await.expect("json body"),
        json!({ "error": "authorization request too large" })
    );
}

#[tokio::test]
async fn authorization_post_rejects_malformed_or_oversized_form_before_database() {
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

    for (body, expected_error) in [
        ("%".to_owned(), "invalid authorization request"),
        (
            format!("state={}", "a".repeat(OAUTH_FORM_BODY_MAX_BYTES + 1)),
            "authorization request too large",
        ),
        (
            format!("state={}", "a".repeat((2 * 1024 * 1024) + 1)),
            "authorization request too large",
        ),
        (
            "client_id=public-client&client_id=other-client".to_owned(),
            "duplicate authorization request parameter",
        ),
    ] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/authorize")
                    .header(
                        header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
                    .body(axum::body::Body::from(body))
                    .expect("valid request"),
            )
            .await
            .expect("router response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await.expect("json body"),
            json!({ "error": expected_error })
        );
    }
}

#[tokio::test]
async fn authorization_post_rejects_missing_form_content_type_before_database() {
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
                .uri("/oauth2/authorize")
                .body(axum::body::Body::from("client_id=public-client"))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "content type must be application/x-www-form-urlencoded" })
    );
}

#[tokio::test]
async fn logout_route_rejects_malformed_query_encoding_before_database() {
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
                .uri("/oauth2/logout?id_token_hint=%")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "invalid logout request" })
    );
}

#[tokio::test]
async fn logout_route_rejects_oversized_query_before_database() {
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
        "/oauth2/logout?id_token_hint={}",
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
        response_json(response).await.expect("json body"),
        json!({ "error": "logout request too large" })
    );
}

#[tokio::test]
async fn logout_route_rejects_duplicate_registered_parameters_before_database() {
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
                .uri("/oauth2/logout?id_token_hint=one&id_token_hint=two")
                .body(axum::body::Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "duplicate logout request parameter" })
    );
}

#[tokio::test]
async fn logout_post_rejects_malformed_or_oversized_form_before_database() {
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

    for (body, expected_error) in [
        ("%".to_owned(), "invalid logout request"),
        (
            format!(
                "id_token_hint={}",
                "a".repeat(OAUTH_FORM_BODY_MAX_BYTES + 1)
            ),
            "logout request too large",
        ),
        (
            format!("id_token_hint={}", "a".repeat((2 * 1024 * 1024) + 1)),
            "logout request too large",
        ),
        (
            "id_token_hint=one&id_token_hint=two".to_owned(),
            "duplicate logout request parameter",
        ),
    ] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/logout")
                    .header(
                        header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    )
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
        assert_eq!(
            response_json(response).await.expect("json body"),
            json!({ "error": expected_error })
        );
    }
}

#[tokio::test]
async fn logout_post_rejects_missing_form_content_type_before_database() {
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
                .uri("/oauth2/logout")
                .body(axum::body::Body::from("id_token_hint=value"))
                .expect("valid request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await.expect("json body"),
        json!({ "error": "content type must be application/x-www-form-urlencoded" })
    );
}

#[tokio::test]
async fn logout_without_redirect_logs_out_locally_for_no_params_state_and_post()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-logout-local-{}", Uuid::new_v4()),
        "API Logout Local",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("logout-local-{}@example.com", Uuid::new_v4()),
        "Logout Local User",
    )?;
    database.create_user(&user, None).await?;
    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);

    for (method, uri, body) in [
        (Method::GET, "/oauth2/logout", ""),
        (Method::GET, "/oauth2/logout?state=do-not-echo", ""),
        (Method::POST, "/oauth2/logout", "state=do-not-echo"),
    ] {
        let session = test_session(organization.id, user.id, now);
        database.create_auth_session(&session).await?;
        let mut request = Request::builder().method(method.clone()).uri(uri).header(
            header::COOKIE,
            session_cookie(session.id, Some(TEST_CSRF_TOKEN)),
        );
        if method == Method::POST {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }

        let response = router
            .clone()
            .oneshot(request.body(axum::body::Body::from(body.to_owned()))?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_clears_session_cookies(&response);
        assert_eq!(response_json(response).await?, json!({ "status": "ok" }));
        assert_session_revoked(&database, session.id, true).await?;
    }

    Ok(())
}

#[tokio::test]
async fn logout_with_valid_hint_and_registered_redirect_returns_exact_location()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let fixture = create_logout_fixture(&database, "api-logout-redirect").await?;
    let state = AppState {
        database,
        organization_id: fixture.organization.id,
        config: test_config_with_signing(fixture.signing.clone()),
    };
    let router = build_router(state);
    let redirect_uri = "http%3A%2F%2Flocalhost%3A3000%2Fsigned-out";

    for (state_query, expected_location) in [
        ("", "http://localhost:3000/signed-out"),
        (
            "&state=state%20value",
            "http://localhost:3000/signed-out?state=state%20value",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/oauth2/logout?id_token_hint={}&post_logout_redirect_uri={redirect_uri}{state_query}",
                        fixture.id_token
                    ))
                    .body(axum::body::Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            expected_location
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    }

    Ok(())
}

#[tokio::test]
async fn logout_with_valid_hint_without_redirect_logs_out_locally()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let fixture = create_logout_fixture(&database, "api-logout-hint-local").await?;
    let state = AppState {
        database: database.clone(),
        organization_id: fixture.organization.id,
        config: test_config_with_signing(fixture.signing.clone()),
    };

    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/oauth2/logout?id_token_hint={}", fixture.id_token))
                .header(
                    header::COOKIE,
                    session_cookie(fixture.session.id, Some(TEST_CSRF_TOKEN)),
                )
                .body(axum::body::Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_clears_session_cookies(&response);
    assert_eq!(response_json(response).await?, json!({ "status": "ok" }));
    assert_session_revoked(&database, fixture.session.id, true).await?;

    Ok(())
}

#[tokio::test]
async fn logout_redirect_requires_valid_hint_without_revoking_session()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let fixture = create_logout_fixture(&database, "api-logout-hint-required").await?;
    let state = AppState {
        database: database.clone(),
        organization_id: fixture.organization.id,
        config: test_config_with_signing(fixture.signing.clone()),
    };
    let router = build_router(state);
    let redirect_uri = "http%3A%2F%2Flocalhost%3A3000%2Fsigned-out";

    for uri in [
        format!("/oauth2/logout?post_logout_redirect_uri={redirect_uri}"),
        format!(
            "/oauth2/logout?id_token_hint={}x&post_logout_redirect_uri={redirect_uri}",
            fixture.id_token
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header(
                        header::COOKIE,
                        session_cookie(fixture.session.id, Some(TEST_CSRF_TOKEN)),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_session_revoked(&database, fixture.session.id, false).await?;
    }

    Ok(())
}

#[tokio::test]
async fn logout_redirect_requires_exact_registered_post_logout_redirect_uri()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let fixture = create_logout_fixture(&database, "api-logout-redirect-exact").await?;
    let state = AppState {
        database: database.clone(),
        organization_id: fixture.organization.id,
        config: test_config_with_signing(fixture.signing.clone()),
    };
    let router = build_router(state);

    for redirect_uri in [
        "http%3A%2F%2Flocalhost%3A3000%2Fother-signed-out",
        "http%3A%2F%2Flocalhost%3A3000%2Fsigned-out%3Fadded%3D1",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/oauth2/logout?id_token_hint={}&post_logout_redirect_uri={redirect_uri}",
                        fixture.id_token
                    ))
                    .header(
                        header::COOKIE,
                        session_cookie(fixture.session.id, Some(TEST_CSRF_TOKEN)),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_session_revoked(&database, fixture.session.id, false).await?;
    }

    Ok(())
}

#[tokio::test]
async fn logout_redirect_rejects_client_id_mismatch_and_disabled_client_without_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let fixture = create_logout_fixture(&database, "api-logout-client-binding").await?;
    let mut other_client = test_oidc_client(fixture.organization.id);
    other_client.client_id = format!("logout-other-client-{}", Uuid::new_v4());
    other_client.post_logout_redirect_uris =
        vec![RedirectUri::parse("http://localhost:3000/signed-out")?];
    database.create_oidc_client(&other_client).await?;
    let mut disabled_client = test_oidc_client(fixture.organization.id);
    disabled_client.client_id = format!("logout-disabled-client-{}", Uuid::new_v4());
    disabled_client.status = OidcClientStatus::Disabled;
    disabled_client.post_logout_redirect_uris =
        vec![RedirectUri::parse("http://localhost:3000/signed-out")?];
    database.create_oidc_client(&disabled_client).await?;
    let disabled_token = logout_id_token(
        &disabled_client,
        &fixture.user,
        &fixture.session,
        &fixture.signing,
    )?;
    let state = AppState {
        database: database.clone(),
        organization_id: fixture.organization.id,
        config: test_config_with_signing(fixture.signing.clone()),
    };
    let router = build_router(state);
    let redirect_uri = "http%3A%2F%2Flocalhost%3A3000%2Fsigned-out";

    for uri in [
        format!(
            "/oauth2/logout?id_token_hint={}&client_id={}&post_logout_redirect_uri={redirect_uri}",
            fixture.id_token, other_client.client_id
        ),
        format!(
            "/oauth2/logout?id_token_hint={disabled_token}&post_logout_redirect_uri={redirect_uri}"
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header(
                        header::COOKIE,
                        session_cookie(fixture.session.id, Some(TEST_CSRF_TOKEN)),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_session_revoked(&database, fixture.session.id, false).await?;
    }

    Ok(())
}

#[tokio::test]
async fn authorization_route_redirects_invalid_max_age_after_client_validation()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-invalid-max-age-{}", Uuid::new_v4()),
        "API Invalid Max Age",
    )?;
    database.create_organization(&organization).await?;
    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/oauth2/authorize?response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&max_age=soon&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                    .body(axum::body::Body::empty())?,
            )
            .await?;

    assert!(response.status().is_redirection());
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://localhost:3000/callback?error=invalid_request&iss=http%3A%2F%2Flocalhost%3A8080&error_description=invalid%20max_age&state=state-value"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

    Ok(())
}

#[tokio::test]
async fn authorization_route_redirects_unsupported_request_object_parameters()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-request-object-errors-{}", Uuid::new_v4()),
        "API Request Object Errors",
    )?;
    database.create_organization(&organization).await?;
    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let base_query = "response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

    for (extra, expected_error) in [
        ("request=eyJhbGciOiJub25lIn0", "request_not_supported"),
        (
            "request_uri=https%3A%2F%2Fclient.example.com%2Frequest.jwt",
            "request_uri_not_supported",
        ),
    ] {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/oauth2/authorize?{base_query}&{extra}"))
                    .body(axum::body::Body::empty())?,
            )
            .await?;

        assert!(response.status().is_redirection());
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("redirect location")
            .to_str()?;
        let callback = Url::parse(location)?;
        assert_eq!(
            callback
                .query_pairs()
                .find_map(|(name, value)| (name == "error").then(|| value.into_owned())),
            Some(expected_error.to_owned())
        );
        assert_eq!(
            callback
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then(|| value.into_owned())),
            Some("state-value".to_owned())
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    }

    Ok(())
}

#[tokio::test]
async fn authorization_route_maps_missing_response_type_to_invalid_request()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-missing-response-type-{}", Uuid::new_v4()),
        "API Missing Response Type",
    )?;
    database.create_organization(&organization).await?;
    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/oauth2/authorize?client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                    .body(axum::body::Body::empty())?,
            )
            .await?;

    assert!(response.status().is_redirection());
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://localhost:3000/callback?error=invalid_request&iss=http%3A%2F%2Flocalhost%3A8080&error_description=missing%20response_type&state=state-value"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

    Ok(())
}

#[tokio::test]
async fn authorization_route_enforces_requested_acr_values_for_existing_sessions()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-acr-values-{}", Uuid::new_v4()),
        "API ACR Values",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("acr-values-user-{}@example.com", Uuid::new_v4()),
        "ACR Values User",
    )?;
    database.create_user(&user, None).await?;
    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/oauth2/authorize?response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&prompt=none&acr_values=urn%3Acairn%3Aacr%3Apassword%2Btotp&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
                    .header(header::COOKIE, session_cookie(session.id, None))
                    .body(axum::body::Body::empty())?,
            )
            .await?;

    assert!(response.status().is_redirection());
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://localhost:3000/callback?error=login_required&iss=http%3A%2F%2Flocalhost%3A8080&error_description=requested%20acr_values%20require%20reauthentication&state=state-value"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

    Ok(())
}

#[tokio::test]
async fn authorization_post_uses_form_body_for_existing_session_flow()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-authorize-post-{}", Uuid::new_v4()),
        "API Authorize Post",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("authorize-post-user-{}@example.com", Uuid::new_v4()),
        "Authorize Post User",
    )?;
    database.create_user(&user, None).await?;
    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    database
        .create_consent_grant(&ConsentGrant {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            user_id: user.id,
            client_id: client.id,
            scopes: vec!["openid".to_owned()],
            created_at: now,
            revoked_at: None,
        })
        .await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let authorize_body = "response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::from(authorize_body))?,
        )
        .await?;

    assert!(response.status().is_redirection());
    let callback_location = response
        .headers()
        .get(header::LOCATION)
        .expect("callback redirect location")
        .to_str()?;
    let callback = Url::parse(callback_location)?;
    assert_eq!(
        callback.origin().ascii_serialization(),
        "http://localhost:3000"
    );
    assert_eq!(callback.path(), "/callback");
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "code" && !value.trim().is_empty() })
    );
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "state" && value == "state-value" })
    );
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "iss" && value == "http://localhost:8080" })
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");

    Ok(())
}

#[tokio::test]
async fn oidc_public_flow_authorization_code_pkce_public_client_gate()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-oidc-public-flow-{}", Uuid::new_v4()),
        "API OIDC Public Flow",
    )?;
    database.create_organization(&organization).await?;

    let mut user = User::new(
        organization.id,
        format!("oidc-public-flow-user-{}@example.com", Uuid::new_v4()),
        "OIDC Public Flow User",
    )?;
    user.email_verified = true;
    database.create_user(&user, None).await?;

    let group = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: "engineering".to_owned(),
        scim_external_id: None,
        display_name: "Engineering".to_owned(),
        created_at: now,
    };
    database.create_group(&group).await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: user.id,
            group_id: group.id,
            role: MembershipRole::Member,
            created_at: now,
        })
        .await?;

    let client_id = format!("oidc-public-flow-client-{}", Uuid::new_v4());
    let wrong_client_id = format!("oidc-public-flow-wrong-client-{}", Uuid::new_v4());
    let mut client = test_oidc_client(organization.id);
    client.client_id = client_id.clone();
    client.allowed_scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
        "groups".to_owned(),
    ];
    database.create_oidc_client(&client).await?;

    let mut wrong_client = test_oidc_client(organization.id);
    wrong_client.client_id = wrong_client_id.clone();
    wrong_client.allowed_scopes = client.allowed_scopes.clone();
    database.create_oidc_client(&wrong_client).await?;

    let session = test_mfa_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    database
        .create_consent_grant(&ConsentGrant {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            user_id: user.id,
            client_id: client.id,
            scopes: client.allowed_scopes.clone(),
            created_at: now,
            revoked_at: None,
        })
        .await?;

    let mut config = test_config(cairn_domain::Environment::Development);
    config.signing = Some(test_signing_material()?);
    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config,
    };
    let router = build_router(state);

    let authorize_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/oauth2/authorize?response_type=code&response_mode=query&client_id={client_id}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20email%20groups&state=public-state&nonce=public-nonce&max_age=300&acr_values=urn%3Acairn%3Aacr%3Apassword%2Btotp&code_challenge={OIDC_PUBLIC_FLOW_CODE_CHALLENGE}&code_challenge_method=S256"
                ))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;

    assert!(authorize_response.status().is_redirection());
    assert_eq!(
        authorize_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        authorize_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );
    let callback_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .expect("callback redirect location")
        .to_str()?;
    let callback = Url::parse(callback_location)?;
    assert_eq!(
        callback.as_str().split('?').next().unwrap(),
        "http://localhost:3000/callback"
    );
    let authorization_code = callback
        .query_pairs()
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
        .expect("authorization code");
    assert!(!authorization_code.trim().is_empty());
    assert_eq!(
        callback
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned())),
        Some("public-state".to_owned())
    );
    assert_eq!(
        callback
            .query_pairs()
            .find_map(|(name, value)| (name == "iss").then(|| value.into_owned())),
        Some("http://localhost:8080".to_owned())
    );

    let token_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=authorization_code&client_id={client_id}&code={authorization_code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier={OIDC_PUBLIC_FLOW_CODE_VERIFIER}"
                )))?,
        )
        .await?;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_payload = response_json(token_response).await?;
    assert_eq!(token_payload["token_type"], json!("Bearer"));
    assert_eq!(token_payload["expires_in"], json!(900));
    assert_eq!(token_payload["scope"], json!("openid profile email groups"));
    assert!(token_payload.get("refresh_token").is_none());
    let access_token = token_payload["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let id_token = token_payload["id_token"].as_str().expect("id token");

    let id_token_header = jwt_json_part(id_token, 0);
    assert_eq!(id_token_header["alg"], json!("RS256"));
    assert_eq!(id_token_header["kid"], json!("oidc-public-flow-test"));
    let id_token_claims = jwt_json_part(id_token, 1);
    assert_eq!(id_token_claims["iss"], json!("http://localhost:8080"));
    assert_eq!(id_token_claims["aud"], json!(client_id));
    assert_eq!(id_token_claims["sub"], json!(user.id.to_string()));
    assert_eq!(id_token_claims["nonce"], json!("public-nonce"));
    assert_eq!(
        id_token_claims["auth_time"],
        json!(session.created_at.unix_timestamp())
    );
    assert_eq!(id_token_claims["acr"], json!("urn:cairn:acr:password+totp"));
    assert_eq!(id_token_claims["amr"], json!(["pwd", "otp"]));
    assert_eq!(id_token_claims["groups"], json!(["engineering"]));
    assert_eq!(id_token_claims["name"], json!("OIDC Public Flow User"));
    assert_eq!(id_token_claims["email"], json!(user.email));
    assert_eq!(id_token_claims["email_verified"], json!(true));

    let full_userinfo_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(full_userinfo_response.status(), StatusCode::OK);
    let full_userinfo = response_json(full_userinfo_response).await?;
    assert_eq!(full_userinfo["sub"], json!(user.id.to_string()));
    assert_eq!(full_userinfo["email"], json!(user.email));
    assert_eq!(full_userinfo["email_verified"], json!(true));
    assert_eq!(full_userinfo["name"], json!("OIDC Public Flow User"));
    assert_eq!(full_userinfo["groups"], json!(["engineering"]));

    let openid_only_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/oauth2/authorize?response_type=code&response_mode=query&client_id={client_id}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=openid-only-state&nonce=openid-only-nonce&code_challenge={OIDC_PUBLIC_FLOW_CODE_CHALLENGE}&code_challenge_method=S256"
                ))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(openid_only_response.status().is_redirection());
    let openid_only_location = openid_only_response
        .headers()
        .get(header::LOCATION)
        .expect("openid-only callback redirect location")
        .to_str()?;
    let openid_only_callback = Url::parse(openid_only_location)?;
    let openid_only_code = openid_only_callback
        .query_pairs()
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
        .expect("openid-only authorization code");
    assert_eq!(
        openid_only_callback
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned())),
        Some("openid-only-state".to_owned())
    );
    assert_eq!(
        openid_only_callback
            .query_pairs()
            .find_map(|(name, value)| (name == "iss").then(|| value.into_owned())),
        Some("http://localhost:8080".to_owned())
    );

    let openid_only_token_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=authorization_code&client_id={client_id}&code={openid_only_code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier={OIDC_PUBLIC_FLOW_CODE_VERIFIER}"
                )))?,
        )
        .await?;
    assert_eq!(openid_only_token_response.status(), StatusCode::OK);
    let openid_only_token_payload = response_json(openid_only_token_response).await?;
    assert_eq!(openid_only_token_payload["scope"], json!("openid"));
    let openid_only_access_token = openid_only_token_payload["access_token"]
        .as_str()
        .expect("openid-only access token");
    let openid_only_userinfo_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {openid_only_access_token}"),
                )
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(openid_only_userinfo_response.status(), StatusCode::OK);
    let openid_only_userinfo = response_json(openid_only_userinfo_response).await?;
    assert_eq!(openid_only_userinfo["sub"], json!(user.id.to_string()));
    assert!(openid_only_userinfo.get("email").is_none());
    assert!(openid_only_userinfo.get("email_verified").is_none());
    assert!(openid_only_userinfo.get("name").is_none());
    assert!(openid_only_userinfo.get("groups").is_none());

    let wrong_client_introspection = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={wrong_client_id}&token={access_token}&token_type_hint=access_token"
                )))?,
        )
        .await?;
    assert_eq!(wrong_client_introspection.status(), StatusCode::OK);
    assert_eq!(
        response_json(wrong_client_introspection).await?,
        json!({ "active": false })
    );

    let wrong_client_revocation = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={wrong_client_id}&token={access_token}&token_type_hint=access_token"
                )))?,
        )
        .await?;
    assert_eq!(wrong_client_revocation.status(), StatusCode::OK);

    let owner_introspection = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={client_id}&token={access_token}&token_type_hint=access_token"
                )))?,
        )
        .await?;
    assert_eq!(owner_introspection.status(), StatusCode::OK);
    let owner_introspection_payload = response_json(owner_introspection).await?;
    assert_eq!(owner_introspection_payload["active"], json!(true));
    assert_eq!(owner_introspection_payload["client_id"], json!(client_id));
    assert_eq!(
        owner_introspection_payload["iss"],
        json!("http://localhost:8080")
    );
    assert_eq!(
        owner_introspection_payload["scope"],
        json!("openid profile email groups")
    );
    assert_eq!(
        owner_introspection_payload["sub"],
        json!(user.id.to_string())
    );
    assert_eq!(owner_introspection_payload["token_type"], json!("Bearer"));

    let owner_revocation = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/revoke")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={client_id}&token={access_token}&token_type_hint=access_token"
                )))?,
        )
        .await?;
    assert_eq!(owner_revocation.status(), StatusCode::OK);
    let owner_revocation_body =
        axum::body::to_bytes(owner_revocation.into_body(), usize::MAX).await?;
    assert!(owner_revocation_body.is_empty());

    let revoked_introspection = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={client_id}&token={access_token}&token_type_hint=access_token"
                )))?,
        )
        .await?;
    assert_eq!(revoked_introspection.status(), StatusCode::OK);
    assert_eq!(
        response_json(revoked_introspection).await?,
        json!({ "active": false })
    );

    Ok(())
}

#[tokio::test]
async fn authorization_always_required_consent_policy_overrides_existing_grant()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-always-consent-{}", Uuid::new_v4()),
        "API Always Consent",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("always-consent-user-{}@example.com", Uuid::new_v4()),
        "Always Consent User",
    )?;
    database.create_user(&user, None).await?;
    let template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("always-{}", Uuid::new_v4()),
        name: "Always Require Consent".to_owned(),
        grant_mode: ConsentGrantMode::AlwaysRequired,
        created_at: now,
    };
    database.create_consent_policy_template(&template).await?;
    let mut client = test_oidc_client(organization.id);
    client.consent_policy_template_id = Some(template.id);
    database.create_oidc_client(&client).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    database
        .create_consent_grant(&ConsentGrant {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            user_id: user.id,
            client_id: client.id,
            scopes: vec!["openid".to_owned()],
            created_at: now,
            revoked_at: None,
        })
        .await?;

    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let authorize_query = "response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=state-value&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

    let consent_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/oauth2/authorize?{authorize_query}"))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(consent_response.status().is_redirection());
    let consent_location = consent_response
        .headers()
        .get(header::LOCATION)
        .expect("consent redirect location")
        .to_str()?;
    assert!(consent_location.starts_with("http://localhost:5173/consent?"));
    assert!(consent_location.contains("client_id=public-client"));
    assert!(consent_location.contains("scopes=openid"));

    let consent_url = Url::parse(consent_location)?;
    let return_to = consent_url
        .query_pairs()
        .find_map(|(name, value)| (name == "return_to").then(|| value.into_owned()))
        .expect("return_to query parameter");
    let csrf = TEST_CSRF_TOKEN;
    let consent_approval_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/consent")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(
                    json!({
                        "client_id": "public-client",
                        "return_to": return_to,
                        "scopes": ["openid"]
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(consent_approval_response.status(), StatusCode::CREATED);

    let authorized_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/oauth2/authorize?{authorize_query}"))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(authorized_response.status().is_redirection());
    let callback_location = authorized_response
        .headers()
        .get(header::LOCATION)
        .expect("callback redirect location")
        .to_str()?;
    let callback = Url::parse(callback_location)?;
    assert_eq!(
        callback.origin().ascii_serialization(),
        "http://localhost:3000"
    );
    assert_eq!(callback.path(), "/callback");
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "code" && !value.trim().is_empty() })
    );
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "state" && value == "state-value" })
    );
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| { name == "iss" && value == "http://localhost:8080" })
    );

    let repeated_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/oauth2/authorize?{authorize_query}"))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(repeated_response.status().is_redirection());
    let repeated_location = repeated_response
        .headers()
        .get(header::LOCATION)
        .expect("repeated consent redirect location")
        .to_str()?;
    assert!(repeated_location.starts_with("http://localhost:5173/consent?"));

    let prompt_none_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/oauth2/authorize?{authorize_query}&prompt=none"))
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(prompt_none_response.status().is_redirection());
    assert_eq!(
        prompt_none_response
            .headers()
            .get(header::LOCATION)
            .unwrap(),
        "http://localhost:3000/callback?error=consent_required&iss=http%3A%2F%2Flocalhost%3A8080&error_description=consent%20required&state=state-value"
    );

    Ok(())
}

struct LogoutFixture {
    organization: Organization,
    user: User,
    session: AuthSession,
    signing: SigningMaterial,
    id_token: String,
}

async fn create_logout_fixture(
    database: &Database,
    prefix: &str,
) -> Result<LogoutFixture, Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(format!("{prefix}-{}", Uuid::new_v4()), "API Logout")?;
    database.create_organization(&organization).await?;
    let mut user = User::new(
        organization.id,
        format!("{prefix}-{}@example.com", Uuid::new_v4()),
        "Logout User",
    )?;
    user.email_verified = true;
    database.create_user(&user, None).await?;
    let mut client = test_oidc_client(organization.id);
    client.client_id = format!("{prefix}-client-{}", Uuid::new_v4());
    client.post_logout_redirect_uris =
        vec![RedirectUri::parse("http://localhost:3000/signed-out")?];
    database.create_oidc_client(&client).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    let signing = test_signing_material()?;
    let id_token = logout_id_token(&client, &user, &session, &signing)?;

    Ok(LogoutFixture {
        organization,
        user,
        session,
        signing,
        id_token,
    })
}

fn logout_id_token(
    client: &OidcClient,
    user: &User,
    session: &AuthSession,
    signing: &SigningMaterial,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(issue_id_token(IdTokenIssueRequest {
        issuer: "http://localhost:8080",
        client,
        user,
        scopes: &["openid".to_owned()],
        nonce: None,
        auth_time: Some(session.created_at),
        amr: session.amr.clone(),
        acr: session.acr.clone(),
        groups: None,
        signing,
    })?)
}

fn test_config_with_signing(signing: SigningMaterial) -> crate::config::ApiConfig {
    let mut config = test_config(cairn_domain::Environment::Development);
    config.signing = Some(signing);
    config
}

fn assert_clears_session_cookies(response: &axum::response::Response) {
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("set-cookie header"))
        .collect::<Vec<_>>();

    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("cairn_session=;") && cookie.contains("Max-Age=0")),
        "expected cairn_session clear cookie, got {set_cookies:?}"
    );
    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("cairn_csrf=;") && cookie.contains("Max-Age=0")),
        "expected cairn_csrf clear cookie, got {set_cookies:?}"
    );
}

async fn assert_session_revoked(
    database: &Database,
    session_id: Uuid,
    expected_revoked: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = database
        .get_auth_session(session_id)
        .await?
        .expect("auth session");
    assert_eq!(session.revoked_at.is_some(), expected_revoked);
    Ok(())
}

fn test_signing_material() -> Result<SigningMaterial, Box<dyn std::error::Error>> {
    let private_key = Rsa::generate(2048)?;
    let modulus = URL_SAFE_NO_PAD.encode(private_key.n().to_vec());
    let exponent = URL_SAFE_NO_PAD.encode(private_key.e().to_vec());
    let key_pair = PKey::from_rsa(private_key)?;
    let private_key_pem = String::from_utf8(key_pair.private_key_to_pem_pkcs8()?)?;

    Ok(SigningMaterial {
        key_id: "oidc-public-flow-test".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "oidc-public-flow-test",
            "alg": "RS256",
            "use": "sig",
            "n": modulus,
            "e": exponent,
        }),
        private_key_pem,
    })
}

fn jwt_json_part(token: &str, index: usize) -> Value {
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "JWT must have header, payload, signature");
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[index])
        .expect("JWT part is base64url");
    serde_json::from_slice(&bytes).expect("JWT part is JSON")
}
