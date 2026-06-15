use super::super::cookies::CSRF_HEADER;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_access_token,
    test_config, test_mfa_session, test_refresh_token, test_session,
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_authn::hash_token;
use cairn_domain::{
    AuthorizationCode, ConsentGrant, Membership, MembershipRole, OidcClient, OidcClientStatus,
    OidcGrantType, RedirectUri, User,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
#[tokio::test]
async fn admin_client_consent_grants_are_client_and_tenant_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-client-consent-{}", Uuid::new_v4()),
        "API Client Consent",
    )?;
    database.create_organization(&organization).await?;
    let other_organization = Organization::new(
        format!("api-client-consent-other-{}", Uuid::new_v4()),
        "API Client Consent Other",
    )?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;

    let admin_user = User::new(
        organization.id,
        format!("client-consent-admin-{}@example.com", Uuid::new_v4()),
        "Client Consent Admin",
    )?;
    let target_user = User::new(
        organization.id,
        format!("client-consent-target-{}@example.com", Uuid::new_v4()),
        "Client Consent Target",
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

    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("client-consent-target-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Client Consent Target".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned(), "email".to_owned(), "groups".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    let other_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("client-consent-other-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Client Consent Other".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    let other_tenant_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: other_organization.id,
        client_id: format!("client-consent-foreign-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Client Consent Foreign".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    database.create_oidc_client(&client).await?;
    database.create_oidc_client(&other_client).await?;
    database.create_oidc_client(&other_tenant_client).await?;

    let active_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: target_user.id,
        client_id: client.id,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        created_at: now + Duration::seconds(2),
        revoked_at: None,
    };
    let revoked_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: target_user.id,
        client_id: client.id,
        scopes: vec!["openid".to_owned(), "groups".to_owned()],
        created_at: now + Duration::seconds(3),
        revoked_at: Some(now + Duration::seconds(4)),
    };
    let other_client_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: target_user.id,
        client_id: other_client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(5),
        revoked_at: None,
    };
    database.create_consent_grant(&active_grant).await?;
    database.create_consent_grant(&revoked_grant).await?;
    database.create_consent_grant(&other_client_grant).await?;
    let refresh_family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        target_user.id,
        client.id,
        "client-consent-access",
        Some(refresh_family_id),
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        target_user.id,
        client.id,
        "client-consent-refresh",
        refresh_family_id,
        now,
    );
    let target_session = test_session(organization.id, target_user.id, now);
    database.create_auth_session(&target_session).await?;
    let authorization_code = AuthorizationCode {
        code_hash: hash_token("client-consent-code"),
        organization_id: organization.id,
        user_id: target_user.id,
        session_id: target_session.id,
        client_id: client.id,
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        nonce: None,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        code_challenge_method: cairn_domain::PkceMethod::S256,
        created_at: now,
        expires_at: now + Duration::minutes(5),
        used_at: None,
    };
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;
    database
        .insert_authorization_code(&authorization_code)
        .await?;

    let admin_session = test_mfa_session(organization.id, admin_user.id, now);
    database.create_auth_session(&admin_session).await?;
    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };

    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/consent-grants?limit=10",
                    client.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response_json(response).await?;
    let items = payload["items"]
        .as_array()
        .expect("consent grant response is an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], revoked_grant.id.to_string());
    assert!(items[0]["revoked_at"].is_string());
    assert_eq!(items[1]["id"], active_grant.id.to_string());
    assert_eq!(items[1]["organization_id"], organization.id.to_string());
    assert_eq!(items[1]["user_id"], target_user.id.to_string());
    assert_eq!(items[1]["user_email"], target_user.email);
    assert_eq!(items[1]["user_display_name"], target_user.display_name);
    assert_eq!(items[1]["client_id"], client.id.to_string());
    assert_eq!(items[1]["scopes"], json!(["openid", "email"]));
    assert_eq!(items[1]["revoked_at"], Value::Null);
    assert_eq!(payload["next_cursor"], Value::Null);

    let active_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/consent-grants?limit=10&status=active",
                    client.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(active_response.status(), StatusCode::OK);
    let active_payload = response_json(active_response).await?;
    let active_items = active_payload["items"]
        .as_array()
        .expect("active consent grant response is an array");
    assert_eq!(active_items.len(), 1);
    assert_eq!(active_items[0]["id"], active_grant.id.to_string());

    let csrf_token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
    let revocation_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/consent-grants/{}",
                    client.id, active_grant.id
                ))
                .header(
                    header::COOKIE,
                    session_cookie(admin_session.id, Some(csrf_token)),
                )
                .header(CSRF_HEADER, csrf_token)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(revocation_response.status(), StatusCode::OK);
    let revocation_payload = response_json(revocation_response).await?;
    assert_eq!(
        revocation_payload["grant"]["id"],
        active_grant.id.to_string()
    );
    assert!(revocation_payload["grant"]["revoked_at"].is_string());
    assert_eq!(revocation_payload["consent_grants_revoked"], json!(1));
    assert_eq!(
        revocation_payload["authorization_codes_invalidated"],
        json!(1)
    );
    assert_eq!(revocation_payload["access_tokens_revoked"], json!(1));
    assert_eq!(revocation_payload["refresh_tokens_revoked"], json!(1));
    assert!(
        state
            .database
            .get_access_token(&access_token.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        state
            .database
            .get_refresh_token(&refresh_token.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        state
            .database
            .get_authorization_code(&authorization_code.code_hash)
            .await?
            .expect("authorization code exists")
            .used_at
            .is_some()
    );

    let cross_tenant_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/consent-grants",
                    other_tenant_client.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(cross_tenant_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(cross_tenant_response).await?,
        json!({ "error": "client not found" })
    );

    Ok(())
}

#[tokio::test]
async fn session_consent_grants_are_user_scoped_and_revoke_runtime_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-session-consent-{}", Uuid::new_v4()),
        "API Session Consent",
    )?;
    database.create_organization(&organization).await?;

    let user = User::new(
        organization.id,
        format!("session-consent-user-{}@example.com", Uuid::new_v4()),
        "Session Consent User",
    )?;
    let other_user = User::new(
        organization.id,
        format!("session-consent-other-{}@example.com", Uuid::new_v4()),
        "Other Session Consent User",
    )?;
    database.create_user(&user, None).await?;
    database.create_user(&other_user, None).await?;
    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("session-consent-client-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Session Consent Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    database.create_oidc_client(&client).await?;

    let active_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: user.id,
        client_id: client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now + Duration::seconds(2),
        revoked_at: None,
    };
    let revoked_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: user.id,
        client_id: client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(1),
        revoked_at: Some(now + Duration::seconds(3)),
    };
    let other_user_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: other_user.id,
        client_id: client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(4),
        revoked_at: None,
    };
    database.create_consent_grant(&active_grant).await?;
    database.create_consent_grant(&revoked_grant).await?;
    database.create_consent_grant(&other_user_grant).await?;

    let family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        user.id,
        client.id,
        "session-consent-access",
        Some(family_id),
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        "session-consent-refresh",
        family_id,
        now,
    );
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;

    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    let authorization_code = AuthorizationCode {
        code_hash: hash_token("session-consent-code"),
        organization_id: organization.id,
        user_id: user.id,
        session_id: session.id,
        client_id: client.id,
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        nonce: None,
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
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };

    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/session/consent-grants?limit=10&status=all")
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response_json(response).await?;
    let items = payload["items"]
        .as_array()
        .expect("session consent response is an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], active_grant.id.to_string());
    assert_eq!(items[0]["client_id"], client.id.to_string());
    assert_eq!(items[0]["client_public_id"], client.client_id);
    assert_eq!(items[0]["client_name"], client.name);
    assert_eq!(items[0]["scopes"], json!(["openid", "profile"]));
    assert_eq!(items[0]["revoked_at"], Value::Null);
    assert_eq!(items[1]["id"], revoked_grant.id.to_string());
    assert!(items[1]["revoked_at"].is_string());

    let active_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/session/consent-grants?limit=10&status=active")
                .header(header::COOKIE, session_cookie(session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(active_response.status(), StatusCode::OK);
    let active_payload = response_json(active_response).await?;
    let active_items = active_payload["items"]
        .as_array()
        .expect("active session consent response is an array");
    assert_eq!(active_items.len(), 1);
    assert_eq!(active_items[0]["id"], active_grant.id.to_string());

    let foreign_grant_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/session/consent-grants/{}",
                    other_user_grant.id
                ))
                .header(
                    header::COOKIE,
                    session_cookie(session.id, Some(TEST_CSRF_TOKEN)),
                )
                .header(CSRF_HEADER, TEST_CSRF_TOKEN)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_grant_response.status(), StatusCode::NOT_FOUND);

    let revoke_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/session/consent-grants/{}",
                    active_grant.id
                ))
                .header(
                    header::COOKIE,
                    session_cookie(session.id, Some(TEST_CSRF_TOKEN)),
                )
                .header(CSRF_HEADER, TEST_CSRF_TOKEN)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_payload = response_json(revoke_response).await?;
    assert_eq!(revoke_payload["grant"]["id"], active_grant.id.to_string());
    assert_eq!(revoke_payload["consent_grants_revoked"], json!(1));
    assert_eq!(revoke_payload["authorization_codes_invalidated"], json!(1));
    assert_eq!(revoke_payload["access_tokens_revoked"], json!(1));
    assert_eq!(revoke_payload["refresh_tokens_revoked"], json!(1));
    assert!(
        state
            .database
            .get_access_token(&access_token.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        state
            .database
            .get_authorization_code(&authorization_code.code_hash)
            .await?
            .expect("authorization code exists")
            .used_at
            .is_some()
    );
    assert!(
        state
            .database
            .get_refresh_token(&refresh_token.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        state
            .database
            .has_active_consent_grant(
                organization.id,
                other_user.id,
                client.id,
                &["openid".to_owned()]
            )
            .await?
    );

    Ok(())
}
