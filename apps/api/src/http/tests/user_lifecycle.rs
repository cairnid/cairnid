use super::super::cookies::CSRF_HEADER;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_access_token,
    test_config, test_mfa_session, test_oidc_client, test_refresh_token, test_session,
};
use axum::{
    extract::Request,
    http::{HeaderName, Method, StatusCode, header},
};
use cairn_authn::hash_token;
use cairn_domain::{AuthorizationCode, Membership, MembershipRole, User};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
#[tokio::test]
async fn deactivated_user_api_flow_rejects_stale_runtime_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-deactivation-{}", Uuid::new_v4()),
        "API Deactivation",
    )?;
    database.create_organization(&organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;

    let admin_user = User::new(
        organization.id,
        format!("admin-{}@example.com", Uuid::new_v4()),
        "Admin User",
    )?;
    let target_user = User::new(
        organization.id,
        format!("target-{}@example.com", Uuid::new_v4()),
        "Target User",
    )?;
    database.create_user(&admin_user, None).await?;
    database.create_user(&target_user, None).await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: admin_user.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;

    let admin_session = test_mfa_session(organization.id, admin_user.id, now);
    let target_session = test_session(organization.id, target_user.id, now);
    database.create_auth_session(&admin_session).await?;
    database.create_auth_session(&target_session).await?;

    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;
    let raw_access_token = format!("access-{}", Uuid::new_v4());
    let raw_refresh_token = format!("refresh-{}", Uuid::new_v4());
    let refresh_family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        target_user.id,
        client.id,
        &raw_access_token,
        Some(refresh_family_id),
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        target_user.id,
        client.id,
        &raw_refresh_token,
        refresh_family_id,
        now,
    );
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;
    let raw_authorization_code = format!("code-{}", Uuid::new_v4());
    let authorization_code = AuthorizationCode {
        code_hash: hash_token(&raw_authorization_code),
        organization_id: organization.id,
        user_id: target_user.id,
        session_id: target_session.id,
        client_id: client.id,
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scopes: vec!["openid".to_owned()],
        nonce: Some("nonce-value".to_owned()),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        code_challenge_method: cairn_domain::PkceMethod::S256,
        created_at: now,
        expires_at: now + Duration::minutes(5),
        used_at: None,
    };
    database
        .insert_authorization_code(&authorization_code)
        .await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);
    let csrf = TEST_CSRF_TOKEN;

    let deactivate_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/users/{}/status", target_user.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::from(r#"{"status":"suspended"}"#))?,
        )
        .await?;
    assert_eq!(deactivate_response.status(), StatusCode::OK);
    let payload = response_json(deactivate_response).await?;
    assert_eq!(payload["status"], json!("suspended"));

    assert!(
        database
            .get_auth_session(target_session.id)
            .await?
            .expect("target session exists")
            .revoked_at
            .is_some()
    );
    assert!(
        database
            .get_access_token(&access_token.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        database
            .get_refresh_token(&refresh_token.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at
            .is_some()
    );

    sqlx::query("UPDATE auth_sessions SET revoked_at = NULL WHERE id = $1")
        .bind(target_session.id)
        .execute(database.pool())
        .await?;
    sqlx::query("UPDATE access_tokens SET revoked_at = NULL WHERE token_hash = $1")
        .bind(&access_token.token_hash)
        .execute(database.pool())
        .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NULL WHERE token_hash = $1")
        .bind(&refresh_token.token_hash)
        .execute(database.pool())
        .await?;

    let stale_session_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/session/me")
                .header(header::COOKIE, session_cookie(target_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(stale_session_response.status(), StatusCode::UNAUTHORIZED);

    let userinfo_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {raw_access_token}"))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(userinfo_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        userinfo_response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("bearer challenge"),
        "Bearer realm=\"cairn\", error=\"invalid_token\", error_description=\"invalid bearer token\""
    );

    let introspection_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "client_id={}&token={raw_access_token}&token_type_hint=access_token",
                    client.client_id
                )))?,
        )
        .await?;
    assert_eq!(introspection_response.status(), StatusCode::OK);
    let payload = response_json(introspection_response).await?;
    assert_eq!(payload, json!({ "active": false }));

    let authorization_code_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "grant_type=authorization_code&client_id={}&code={raw_authorization_code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        client.client_id
                    )))?,
            )
            .await?;
    assert_eq!(
        authorization_code_response.status(),
        StatusCode::BAD_REQUEST
    );
    let payload = response_json(authorization_code_response).await?;
    assert_eq!(payload["error"], json!("invalid_grant"));
    assert_eq!(
        payload["error_description"],
        json!("session expired or revoked")
    );

    let refresh_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=refresh_token&client_id={}&refresh_token={raw_refresh_token}",
                    client.client_id
                )))?,
        )
        .await?;
    assert_eq!(refresh_response.status(), StatusCode::BAD_REQUEST);
    let payload = response_json(refresh_response).await?;
    assert_eq!(payload["error"], json!("invalid_grant"));
    assert_eq!(
        payload["error_description"],
        json!("refresh token expired or revoked")
    );

    Ok(())
}
