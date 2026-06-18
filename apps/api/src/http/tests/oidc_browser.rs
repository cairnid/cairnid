use super::super::cookies::CSRF_HEADER;
use super::super::{AppState, OAUTH_FORM_BODY_MAX_BYTES, OAUTH_QUERY_MAX_BYTES, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_config,
    test_oidc_client, test_session,
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_database::Database;
use cairn_domain::{ConsentGrant, ConsentGrantMode, ConsentPolicyTemplate, User};
use serde_json::json;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

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
