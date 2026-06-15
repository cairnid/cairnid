use super::super::cookies::CSRF_HEADER;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_access_token,
    test_config, test_oidc_client, test_refresh_token, test_session,
};
use axum::{
    extract::Request,
    http::{HeaderName, Method, StatusCode, header},
};
use cairn_authn::{hash_password, hash_token, verify_password};
use cairn_database::SessionRequestContext;
use cairn_domain::{AccountToken, AccountTokenKind, AuthSession, MfaCredential, MfaKind, User};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn session_password_change_rotates_session_and_revokes_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-password-change-{}", Uuid::new_v4()),
        "API Password Change",
    )?;
    database.create_organization(&organization).await?;

    let old_password = "old-password-1234";
    let new_password = "new-password-1234";
    let user = User::new(
        organization.id,
        format!("password-change-{}@example.com", Uuid::new_v4()),
        "Password Change User",
    )?;
    let password_hash = hash_password(&SecretString::from(old_password.to_owned()))?;
    database.create_user(&user, Some(&password_hash)).await?;
    let current_session = test_session(organization.id, user.id, now);
    let second_session = test_session(organization.id, user.id, now);
    database.create_auth_session(&current_session).await?;
    database.create_auth_session(&second_session).await?;

    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;
    let refresh_family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        user.id,
        client.id,
        "password-change-access",
        Some(refresh_family_id),
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        "password-change-refresh",
        refresh_family_id,
        now,
    );
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;
    let recovery_token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        kind: AccountTokenKind::PasswordRecovery,
        user_id: Some(user.id),
        email: user.email.clone(),
        token_hash: hash_token("password-change-recovery"),
        created_by_user_id: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    database.insert_account_token(&recovery_token).await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);
    let csrf = TEST_CSRF_TOKEN;
    let wrong_password_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/session/password/change")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    session_cookie(current_session.id, Some(csrf)),
                )
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::from(format!(
                    r#"{{"current_password":"wrong-password","new_password":"{new_password}"}}"#
                )))?,
        )
        .await?;
    assert_eq!(wrong_password_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(wrong_password_response).await?,
        json!({ "error": "invalid credentials" })
    );
    assert_eq!(
        database
            .get_auth_session(current_session.id)
            .await?
            .expect("current session exists")
            .revoked_at,
        None
    );
    let notification_count_after_failure: i64 = sqlx::query_scalar(
        r#"
            SELECT COUNT(*)
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
              AND template = 'password_changed_notification'
            "#,
    )
    .bind(organization.id)
    .bind(&user.email)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(notification_count_after_failure, 0);

    let change_response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/session/password/change")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    session_cookie(current_session.id, Some(csrf)),
                )
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.24")
                .header(header::USER_AGENT, "Cairn-Test/1.0")
                .body(axum::body::Body::from(format!(
                    r#"{{"current_password":"{old_password}","new_password":"{new_password}"}}"#
                )))?,
        )
        .await?;
    assert_eq!(change_response.status(), StatusCode::OK);
    let set_cookie = change_response
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .expect("session cookie is rotated");
    let payload = response_json(change_response).await?;
    assert_eq!(payload["status"], json!("changed"));
    assert_eq!(payload["sessions_revoked"], json!(2));
    assert_eq!(payload["access_tokens_revoked"], json!(1));
    assert_eq!(payload["refresh_tokens_revoked"], json!(1));
    assert_eq!(payload["account_tokens_consumed"], json!(1));
    assert_eq!(payload["acr"], json!("urn:cairn:acr:password"));
    assert_eq!(payload["amr"], json!(["pwd"]));

    let active_sessions: Vec<Uuid> = sqlx::query_scalar(
        r#"
            SELECT id
            FROM auth_sessions
            WHERE organization_id = $1 AND user_id = $2 AND revoked_at IS NULL
            "#,
    )
    .bind(organization.id)
    .bind(user.id)
    .fetch_all(database.pool())
    .await?;
    assert_eq!(active_sessions.len(), 1);
    assert_ne!(active_sessions[0], current_session.id);
    assert_ne!(active_sessions[0], second_session.id);
    assert!(
        set_cookie
            .to_str()?
            .starts_with(&format!("cairn_session={}", active_sessions[0]))
    );
    assert!(
        database
            .get_auth_session(current_session.id)
            .await?
            .expect("current session exists")
            .revoked_at
            .is_some()
    );
    assert!(
        database
            .get_auth_session(second_session.id)
            .await?
            .expect("second session exists")
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
    let consumed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM account_tokens WHERE id = $1")
            .bind(recovery_token.id)
            .fetch_one(database.pool())
            .await?;
    assert!(consumed_at.is_some());
    let updated_password_hash = database
        .get_user_with_password(organization.id, user.id)
        .await?
        .expect("user exists")
        .password_hash
        .expect("password hash exists");
    assert!(
        verify_password(
            &SecretString::from(new_password.to_owned()),
            &updated_password_hash
        )
        .is_ok()
    );
    assert!(
        verify_password(
            &SecretString::from(old_password.to_owned()),
            &updated_password_hash
        )
        .is_err()
    );
    type PasswordChangeNotificationOutboxRow = (
        Uuid,
        String,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        sqlx::types::Json<Value>,
    );

    let (
        notification_id,
        notification_subject,
        notification_body,
        notification_action_path,
        notification_ciphertext,
        notification_nonce,
        sqlx::types::Json(notification_metadata),
    ): PasswordChangeNotificationOutboxRow = sqlx::query_as(
        r#"
            SELECT id, subject, body_text, action_path, delivery_token_ciphertext,
                   delivery_token_nonce, metadata
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
              AND template = 'password_changed_notification'
            "#,
    )
    .bind(organization.id)
    .bind(&user.email)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        notification_subject,
        "Your Cairn Identity password was changed"
    );
    assert!(notification_body.contains("Your Cairn Identity password was changed."));
    assert!(notification_body.contains("IP address: Unknown"));
    assert!(notification_body.contains("Browser: Cairn-Test/1.0"));
    assert_eq!(notification_action_path, None);
    assert_eq!(notification_ciphertext, None);
    assert_eq!(notification_nonce, None);
    assert_eq!(
        notification_metadata["kind"],
        json!("password_changed_notification")
    );
    assert_eq!(notification_metadata["user_id"], json!(user.id));

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "account.password_changed")
        .expect("password change audit event");
    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(user.id));
    assert_eq!(event.target, user.id.to_string());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Test/1.0"));
    assert_eq!(event.metadata["sessions_revoked"], json!(2));
    assert_eq!(
        event.metadata["notification_email_outbox_id"],
        json!(notification_id)
    );
    assert!(!event.metadata.to_string().contains(old_password));
    assert!(!event.metadata.to_string().contains(new_password));

    Ok(())
}

#[tokio::test]
async fn session_password_change_requires_recent_mfa_when_factor_is_enrolled()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-password-change-mfa-{}", Uuid::new_v4()),
        "API Password Change MFA",
    )?;
    database.create_organization(&organization).await?;

    let old_password = "old-password-1234";
    let user = User::new(
        organization.id,
        format!("password-change-mfa-{}@example.com", Uuid::new_v4()),
        "Password Change MFA User",
    )?;
    let password_hash = hash_password(&SecretString::from(old_password.to_owned()))?;
    database.create_user(&user, Some(&password_hash)).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;
    database
        .create_mfa_credential(&MfaCredential {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            user_id: user.id,
            kind: MfaKind::Totp,
            label: "Authenticator".to_owned(),
            secret_metadata: json!({
                "status": "active",
                "secret_ciphertext": "placeholder",
                "secret_nonce": "placeholder"
            }),
            created_at: now,
            last_used_at: None,
        })
        .await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let csrf = TEST_CSRF_TOKEN;
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/session/password/change")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::from(format!(
                    r#"{{"current_password":"{old_password}","new_password":"new-password-1234"}}"#
                )))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await?,
        json!({ "error": "fresh MFA verification required" })
    );
    assert_eq!(
        database
            .get_auth_session(session.id)
            .await?
            .expect("session exists")
            .revoked_at,
        None
    );
    let unchanged_hash = database
        .get_user_with_password(organization.id, user.id)
        .await?
        .expect("user exists")
        .password_hash
        .expect("password hash exists");
    assert!(
        verify_password(
            &SecretString::from(old_password.to_owned()),
            &unchanged_hash
        )
        .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn browser_session_list_and_revoke_are_current_user_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-browser-sessions-{}", Uuid::new_v4()),
        "API Browser Sessions",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("browser-sessions-{}@example.com", Uuid::new_v4()),
        "Browser Sessions User",
    )?;
    let other_user = User::new(
        organization.id,
        format!("browser-sessions-other-{}@example.com", Uuid::new_v4()),
        "Other Browser Sessions User",
    )?;
    database.create_user(&user, None).await?;
    database.create_user(&other_user, None).await?;

    let current_session = test_session(organization.id, user.id, now);
    let other_session = test_session(organization.id, user.id, now - Duration::minutes(5));
    let expired_session = AuthSession {
        expires_at: now - Duration::minutes(1),
        ..test_session(organization.id, user.id, now - Duration::hours(2))
    };
    let foreign_user_session =
        test_session(organization.id, other_user.id, now - Duration::minutes(10));
    database
        .create_auth_session_with_context(
            &current_session,
            SessionRequestContext::new(Some("203.0.113.20"), Some("Current Browser/1.0")),
        )
        .await?;
    database
        .create_auth_session_with_context(
            &other_session,
            SessionRequestContext::new(Some("203.0.113.21"), Some("Old Browser/1.0")),
        )
        .await?;
    database.create_auth_session(&expired_session).await?;
    database.create_auth_session(&foreign_user_session).await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);
    let csrf = TEST_CSRF_TOKEN;

    let list_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/session/browser-sessions")
                .header(header::COOKIE, session_cookie(current_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let payload = response_json(list_response).await?;
    let sessions = payload["sessions"]
        .as_array()
        .expect("sessions response is an array");
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .any(|session| session["id"] == json!(current_session.id)
                && session["current"] == json!(true)
                && session["created_ip_address"] == json!("203.0.113.20")
                && session["created_user_agent"] == json!("Current Browser/1.0"))
    );
    assert!(
        sessions
            .iter()
            .any(|session| session["id"] == json!(other_session.id)
                && session["current"] == json!(false))
    );

    let self_revoke_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/session/browser-sessions/{}",
                    current_session.id
                ))
                .header(
                    header::COOKIE,
                    session_cookie(current_session.id, Some(csrf)),
                )
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(self_revoke_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(self_revoke_response).await?,
        json!({ "error": "use logout to revoke current session" })
    );

    let revoke_response = router
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/session/browser-sessions/{}",
                    other_session.id
                ))
                .header(
                    header::COOKIE,
                    session_cookie(current_session.id, Some(csrf)),
                )
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.50")
                .header(header::USER_AGENT, "Cairn-Test/1.0")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(revoke_response).await?,
        json!({ "status": "revoked", "session_id": other_session.id })
    );
    assert_eq!(
        database
            .get_auth_session(current_session.id)
            .await?
            .expect("current session exists")
            .revoked_at,
        None
    );
    assert!(
        database
            .get_auth_session(other_session.id)
            .await?
            .expect("other session exists")
            .revoked_at
            .is_some()
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "session.revoked_by_user")
        .expect("session revocation audit event");
    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(user.id));
    assert_eq!(event.target, other_session.id.to_string());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Test/1.0"));
    assert_eq!(
        event.metadata["current_session_id"],
        json!(current_session.id)
    );

    Ok(())
}
