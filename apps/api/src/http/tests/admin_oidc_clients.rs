use super::super::content_type::OAUTH_FORM_CONTENT_TYPE;
use super::super::cookies::CSRF_HEADER;
use super::super::oauth_client::authenticate_oauth_client;
use super::super::oauth_http::OAuthClientAuth;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_access_token,
    test_config, test_mfa_session, test_oidc_client, test_refresh_token, test_session,
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_authn::hash_token;
use cairn_domain::{
    AuthorizationCode, ConsentGrantMode, ConsentPolicyTemplate, Membership, MembershipRole,
    OidcClient, OidcClientStatus, OidcGrantType, RedirectUri, User,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
#[tokio::test]
async fn admin_consent_policy_templates_can_be_created_listed_and_assigned_to_clients()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-consent-policy-{}", Uuid::new_v4()),
        "API Consent Policy",
    )?;
    let other_organization = Organization::new(
        format!("api-consent-policy-other-{}", Uuid::new_v4()),
        "API Consent Policy Other",
    )?;
    database.create_organization(&organization).await?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("consent-policy-admin-{}@example.com", Uuid::new_v4()),
        "Consent Policy Admin",
    )?;
    database.create_user(&admin_user, None).await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: admin_user.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;
    let other_template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: other_organization.id,
        slug: format!("foreign-{}", Uuid::new_v4()),
        name: "Foreign Always Require Consent".to_owned(),
        grant_mode: ConsentGrantMode::AlwaysRequired,
        created_at: now,
    };
    database
        .create_consent_policy_template(&other_template)
        .await?;

    let admin_session = test_mfa_session(organization.id, admin_user.id, now);
    database.create_auth_session(&admin_session).await?;
    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let csrf = TEST_CSRF_TOKEN;

    let create_template_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/oidc/consent-policy-templates")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(format!(
                    r#"{{
                            "slug":"always-{}",
                            "name":"Always Require Consent",
                            "grant_mode":"always_required"
                        }}"#,
                    Uuid::new_v4()
                )))?,
        )
        .await?;
    assert_eq!(create_template_response.status(), StatusCode::CREATED);
    let template_payload = response_json(create_template_response).await?;
    let template_id = Uuid::parse_str(template_payload["id"].as_str().expect("template id"))?;
    assert_eq!(template_payload["grant_mode"], json!("always_required"));

    let list_templates_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/oidc/consent-policy-templates?limit=10")
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(list_templates_response.status(), StatusCode::OK);
    let list_payload = response_json(list_templates_response).await?;
    let items = list_payload["items"]
        .as_array()
        .expect("template list is an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], template_id.to_string());

    let create_client_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/oidc/clients")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(format!(
                    r#"{{
                            "client_id":"policy-client-{}",
                            "name":"Policy Client",
                            "redirect_uris":["http://localhost:3000/callback"],
                            "allowed_scopes":["openid"],
                            "public_client":true,
                            "consent_policy_template_id":"{}"
                        }}"#,
                    Uuid::new_v4(),
                    template_id
                )))?,
        )
        .await?;
    assert_eq!(create_client_response.status(), StatusCode::CREATED);
    let client_payload = response_json(create_client_response).await?;
    assert_eq!(
        client_payload["client"]["consent_policy_template_id"],
        template_id.to_string()
    );
    assert_eq!(client_payload["client"]["has_client_secret"], json!(false));
    assert!(client_payload["client"].get("client_secret_hash").is_none());

    let foreign_template_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/oidc/clients")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(format!(
                    r#"{{
                            "client_id":"foreign-policy-client-{}",
                            "name":"Foreign Policy Client",
                            "redirect_uris":["http://localhost:3000/callback"],
                            "allowed_scopes":["openid"],
                            "public_client":true,
                            "consent_policy_template_id":"{}"
                        }}"#,
                    Uuid::new_v4(),
                    other_template.id
                )))?,
        )
        .await?;
    assert_eq!(foreign_template_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign_template_response).await?,
        json!({ "error": "consent policy template not found" })
    );

    Ok(())
}

#[tokio::test]
async fn admin_client_secret_rotation_returns_secret_once_and_suppresses_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-client-secret-rotation-{}", Uuid::new_v4()),
        "API Client Secret Rotation",
    )?;
    database.create_organization(&organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("client-secret-admin-{}@example.com", Uuid::new_v4()),
        "Client Secret Admin",
    )?;
    database.create_user(&admin_user, None).await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: admin_user.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;

    let old_secret = "old-client-secret";
    let confidential_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("rotate-secret-confidential-{}", Uuid::new_v4()),
        client_secret_hash: Some(hash_token(old_secret)),
        consent_policy_template_id: None,
        name: "Rotate Secret Confidential".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned(), "email".to_owned()],
        grant_types: vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ],
        public_client: false,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    let public_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("rotate-secret-public-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Rotate Secret Public".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    database.create_oidc_client(&confidential_client).await?;
    database.create_oidc_client(&public_client).await?;

    let admin_session = test_mfa_session(organization.id, admin_user.id, now);
    database.create_auth_session(&admin_session).await?;
    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let csrf = TEST_CSRF_TOKEN;

    let rotate_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/secret/rotate",
                    confidential_client.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(rotate_response.status(), StatusCode::OK);
    let rotate_payload = response_json(rotate_response).await?;
    assert_eq!(
        rotate_payload["client"]["id"],
        confidential_client.id.to_string()
    );
    assert_eq!(rotate_payload["client"]["has_client_secret"], json!(true));
    assert!(rotate_payload["client"].get("client_secret_hash").is_none());
    let rotated_secret = rotate_payload["client_secret"]
        .as_str()
        .expect("rotated secret is returned once")
        .to_owned();
    assert!(!rotated_secret.is_empty());

    let stored_client = database
        .get_oidc_client(confidential_client.id)
        .await?
        .expect("rotated client exists");
    assert_ne!(
        stored_client.client_secret_hash,
        confidential_client.client_secret_hash
    );
    assert!(
        authenticate_oauth_client(
            &stored_client,
            &OAuthClientAuth {
                client_id: Some(confidential_client.client_id.clone()),
                client_secret: Some(rotated_secret),
            },
        )
        .is_ok()
    );
    assert!(
        authenticate_oauth_client(
            &stored_client,
            &OAuthClientAuth {
                client_id: Some(confidential_client.client_id.clone()),
                client_secret: Some(old_secret.to_owned()),
            },
        )
        .is_err()
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "admin.client_secret_rotated")
        .expect("secret rotation audit event");
    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(admin_user.id));
    assert_eq!(event.target, confidential_client.id.to_string());
    assert_eq!(
        event.metadata["client_id"],
        json!(confidential_client.client_id)
    );

    let public_rotate_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/oidc/clients/{}/secret/rotate",
                    public_client.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(public_rotate_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(public_rotate_response).await?,
        json!({ "error": "public clients do not have secrets" })
    );

    Ok(())
}

#[tokio::test]
async fn admin_client_status_disable_revokes_credentials_and_blocks_protocol_use()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-client-status-{}", Uuid::new_v4()),
        "API Client Status",
    )?;
    database.create_organization(&organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("client-status-admin-{}@example.com", Uuid::new_v4()),
        "Client Status Admin",
    )?;
    let target_user = User::new(
        organization.id,
        format!("client-status-target-{}@example.com", Uuid::new_v4()),
        "Client Status Target",
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
    let mut client = test_oidc_client(organization.id);
    client.client_id = format!("status-client-{}", Uuid::new_v4());
    database.create_oidc_client(&client).await?;
    let raw_access_token = format!("client-status-access-{}", Uuid::new_v4());
    let raw_refresh_token = format!("client-status-refresh-{}", Uuid::new_v4());
    let family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        target_user.id,
        client.id,
        &raw_access_token,
        Some(family_id),
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        target_user.id,
        client.id,
        &raw_refresh_token,
        family_id,
        now,
    );
    let raw_authorization_code = format!("client-status-code-{}", Uuid::new_v4());
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
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;
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

    let disable_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/oidc/clients/{}/status", client.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(r#"{"status":"disabled"}"#))?,
        )
        .await?;
    assert_eq!(disable_response.status(), StatusCode::OK);
    let disable_payload = response_json(disable_response).await?;
    assert_eq!(disable_payload["client"]["id"], client.id.to_string());
    assert_eq!(disable_payload["client"]["status"], json!("disabled"));
    assert_eq!(disable_payload["authorization_codes_invalidated"], json!(1));
    assert_eq!(disable_payload["access_tokens_revoked"], json!(1));
    assert_eq!(disable_payload["refresh_tokens_revoked"], json!(1));
    assert_eq!(
        database
            .get_oidc_client(client.id)
            .await?
            .expect("client exists")
            .status,
        OidcClientStatus::Disabled
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
    assert!(
        database
            .get_authorization_code(&authorization_code.code_hash)
            .await?
            .expect("authorization code exists")
            .used_at
            .is_some()
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "admin.client_status_updated")
        .expect("client status audit event");
    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(admin_user.id));
    assert_eq!(event.target, client.id.to_string());
    assert_eq!(event.metadata["client_id"], json!(client.client_id.clone()));
    assert_eq!(event.metadata["status"], json!("disabled"));
    assert_eq!(event.metadata["access_tokens_revoked"], json!(1));

    sqlx::query("UPDATE access_tokens SET revoked_at = NULL WHERE token_hash = $1")
        .bind(&access_token.token_hash)
        .execute(database.pool())
        .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NULL WHERE token_hash = $1")
        .bind(&refresh_token.token_hash)
        .execute(database.pool())
        .await?;
    sqlx::query("UPDATE authorization_codes SET used_at = NULL WHERE code_hash = $1")
        .bind(&authorization_code.code_hash)
        .execute(database.pool())
        .await?;

    let authorization_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/oauth2/authorize?response_type=code&client_id={}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
                    client.client_id
                ))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert!(authorization_response.status().is_redirection());
    let location = authorization_response
        .headers()
        .get(header::LOCATION)
        .expect("authorization redirect location")
        .to_str()?;
    assert!(location.contains("error=unauthorized_client"));

    let refresh_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, OAUTH_FORM_CONTENT_TYPE)
                .body(axum::body::Body::from(format!(
                    "grant_type=refresh_token&refresh_token={raw_refresh_token}&client_id={}",
                    client.client_id
                )))?,
        )
        .await?;
    assert_eq!(refresh_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(refresh_response).await?["error"],
        "invalid_client"
    );

    let authorization_code_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, OAUTH_FORM_CONTENT_TYPE)
                    .body(axum::body::Body::from(format!(
                        "grant_type=authorization_code&client_id={}&code={raw_authorization_code}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        client.client_id
                    )))?,
            )
            .await?;
    assert_eq!(
        authorization_code_response.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        response_json(authorization_code_response).await?["error"],
        "invalid_client"
    );

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

    let introspection_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header(header::CONTENT_TYPE, OAUTH_FORM_CONTENT_TYPE)
                .body(axum::body::Body::from(format!(
                    "client_id={}&token={raw_access_token}&token_type_hint=access_token",
                    client.client_id
                )))?,
        )
        .await?;
    assert_eq!(introspection_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(introspection_response).await?["error"],
        "invalid_client"
    );

    let reactivate_response = router
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/oidc/clients/{}/status", client.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(r#"{"status":"active"}"#))?,
        )
        .await?;
    assert_eq!(reactivate_response.status(), StatusCode::OK);
    let reactivate_payload = response_json(reactivate_response).await?;
    assert_eq!(reactivate_payload["client"]["status"], json!("active"));
    assert_eq!(reactivate_payload["access_tokens_revoked"], json!(0));

    Ok(())
}
