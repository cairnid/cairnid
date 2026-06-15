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
use cairn_domain::{AccountToken, AccountTokenKind, User};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn login_writes_session_audit_event_with_request_context()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-login-audit-{}", Uuid::new_v4()),
        "API Login Audit",
    )?;
    database.create_organization(&organization).await?;

    let password = "correct-password";
    let user = User::new(
        organization.id,
        format!("login-audit-{}@example.com", Uuid::new_v4()),
        "Login Audit User",
    )?;
    let password_hash = hash_password(&SecretString::from(password.to_owned()))?;
    database.create_user(&user, Some(&password_hash)).await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let csrf = TEST_CSRF_TOKEN;
    let router = build_router(state);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/session/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("cairn_csrf={csrf}"))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(
                    HeaderName::from_static("x-forwarded-for"),
                    "203.0.113.55, 10.0.0.1",
                )
                .header(header::USER_AGENT, "Cairn-Test/1.0")
                .body(axum::body::Body::from(format!(
                    r#"{{"email":"{}","password":"{password}"}}"#,
                    user.email
                )))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .is_some_and(|cookie| cookie
                .to_str()
                .is_ok_and(|value| value.starts_with("cairn_session=")))
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "session.logged_in")
        .expect("login audit event");

    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(user.id));
    let session_id = event.target.parse::<Uuid>()?;
    assert!(!session_id.is_nil());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Test/1.0"));
    assert_eq!(event.metadata["acr"], json!("urn:cairn:acr:password"));
    assert_eq!(event.metadata["amr"], json!(["pwd"]));
    type NewLoginNotificationOutboxRow = (
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
    ): NewLoginNotificationOutboxRow = sqlx::query_as(
        r#"
            SELECT id, subject, body_text, action_path, delivery_token_ciphertext,
                   delivery_token_nonce, metadata
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
              AND template = 'new_login_notification'
            "#,
    )
    .bind(organization.id)
    .bind(&user.email)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(notification_subject, "New Cairn Identity sign-in");
    assert!(notification_body.contains("A new Cairn Identity sign-in was detected."));
    assert!(notification_body.contains("IP address: Unknown"));
    assert!(notification_body.contains("Browser: Cairn-Test/1.0"));
    assert_eq!(notification_action_path, None);
    assert_eq!(notification_ciphertext, None);
    assert_eq!(notification_nonce, None);
    assert_eq!(
        notification_metadata["kind"],
        json!("new_login_notification")
    );
    assert_eq!(notification_metadata["user_id"], json!(user.id));
    assert_eq!(notification_metadata["session_id"], json!(session_id));
    assert_eq!(
        event.metadata["new_context_notification_email_outbox_id"],
        json!(notification_id)
    );

    let repeated_response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/session/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("cairn_csrf={csrf}"))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(
                    HeaderName::from_static("x-forwarded-for"),
                    "203.0.113.55, 10.0.0.1",
                )
                .header(header::USER_AGENT, "Cairn-Test/1.0")
                .body(axum::body::Body::from(format!(
                    r#"{{"email":"{}","password":"{password}"}}"#,
                    user.email
                )))?,
        )
        .await?;
    assert_eq!(repeated_response.status(), StatusCode::OK);
    let notification_count: i64 = sqlx::query_scalar(
        r#"
            SELECT COUNT(*)
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
              AND template = 'new_login_notification'
            "#,
    )
    .bind(organization.id)
    .bind(&user.email)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(notification_count, 1);

    Ok(())
}

#[tokio::test]
async fn password_recovery_completion_revokes_runtime_credentials_and_audits_counts()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-password-recovery-complete-{}", Uuid::new_v4()),
        "API Password Recovery Complete",
    )?;
    database.create_organization(&organization).await?;

    let old_password = "old-recovery-password";
    let new_password = "new-recovery-password";
    let user = User::new(
        organization.id,
        format!("password-recovery-complete-{}@example.com", Uuid::new_v4()),
        "Password Recovery Complete User",
    )?;
    let old_password_hash = hash_password(&SecretString::from(old_password.to_owned()))?;
    database
        .create_user(&user, Some(&old_password_hash))
        .await?;

    let client = test_oidc_client(organization.id);
    database.create_oidc_client(&client).await?;
    let now = OffsetDateTime::now_utc();
    let first_session = test_session(organization.id, user.id, now - Duration::minutes(10));
    let second_session = test_session(organization.id, user.id, now - Duration::minutes(5));
    database.create_auth_session(&first_session).await?;
    database.create_auth_session(&second_session).await?;

    let family_id = Uuid::new_v4();
    let access_token = test_access_token(
        organization.id,
        user.id,
        client.id,
        "password-recovery-access-token",
        None,
        now,
    );
    let refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        "password-recovery-refresh-token",
        family_id,
        now,
    );
    database.insert_access_token(&access_token).await?;
    database.insert_refresh_token(&refresh_token).await?;

    let raw_recovery_token = "password-recovery-complete-token";
    let recovery_token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        kind: AccountTokenKind::PasswordRecovery,
        user_id: Some(user.id),
        email: user.email.clone(),
        token_hash: hash_token(raw_recovery_token),
        created_by_user_id: None,
        created_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    let sibling_recovery_token = AccountToken {
        id: Uuid::new_v4(),
        token_hash: hash_token("password-recovery-complete-sibling"),
        ..recovery_token.clone()
    };
    database.insert_account_token(&recovery_token).await?;
    database
        .insert_account_token(&sibling_recovery_token)
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
                .uri("/api/v1/session/password-recovery/complete")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("cairn_csrf={csrf}"))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.44")
                .header(header::USER_AGENT, "Cairn-Recovery/1.0")
                .body(axum::body::Body::from(format!(
                    r#"{{"token":"{raw_recovery_token}","password":"{new_password}"}}"#
                )))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let payload = response_json(response).await?;
    assert_eq!(payload["status"], json!("ok"));
    assert_eq!(payload["sessions_revoked"], json!(2));
    assert_eq!(payload["access_tokens_revoked"], json!(1));
    assert_eq!(payload["refresh_tokens_revoked"], json!(1));
    assert_eq!(payload["account_tokens_consumed"], json!(2));

    let user_with_password = database
        .get_user_with_password(organization.id, user.id)
        .await?
        .expect("user exists");
    assert!(user_with_password.user.email_verified);
    let updated_password_hash = user_with_password
        .password_hash
        .expect("password hash exists after recovery");
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
    assert!(
        database
            .get_auth_session(first_session.id)
            .await?
            .expect("first session exists")
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

    let consumed_recovery_tokens: i64 = sqlx::query_scalar(
        r#"
            SELECT COUNT(*)
            FROM account_tokens
            WHERE id IN ($1, $2) AND consumed_at IS NOT NULL
            "#,
    )
    .bind(recovery_token.id)
    .bind(sibling_recovery_token.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(consumed_recovery_tokens, 2);
    type PasswordRecoveredNotificationOutboxRow = (
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
    ): PasswordRecoveredNotificationOutboxRow = sqlx::query_as(
        r#"
            SELECT id, subject, body_text, action_path, delivery_token_ciphertext,
                   delivery_token_nonce, metadata
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
              AND template = 'password_recovered_notification'
            "#,
    )
    .bind(organization.id)
    .bind(&user.email)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        notification_subject,
        "Your Cairn Identity password was reset"
    );
    assert!(
        notification_body
            .contains("Your Cairn Identity password was reset using account recovery.")
    );
    assert!(notification_body.contains("IP address: Unknown"));
    assert!(notification_body.contains("Browser: Cairn-Recovery/1.0"));
    assert_eq!(notification_action_path, None);
    assert_eq!(notification_ciphertext, None);
    assert_eq!(notification_nonce, None);
    assert_eq!(
        notification_metadata["kind"],
        json!("password_recovered_notification")
    );
    assert_eq!(
        notification_metadata["account_token_id"],
        json!(recovery_token.id)
    );
    assert_eq!(notification_metadata["user_id"], json!(user.id));

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "account.password_recovered")
        .expect("password recovery audit event");
    assert_eq!(event.actor_kind, AuditActorKind::System);
    assert_eq!(event.actor_id, None);
    assert_eq!(event.target, user.id.to_string());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Recovery/1.0"));
    assert_eq!(event.metadata["email"], json!(user.email));
    assert_eq!(event.metadata["sessions_revoked"], json!(2));
    assert_eq!(event.metadata["access_tokens_revoked"], json!(1));
    assert_eq!(event.metadata["refresh_tokens_revoked"], json!(1));
    assert_eq!(event.metadata["account_tokens_consumed"], json!(2));
    assert_eq!(
        event.metadata["notification_email_outbox_id"],
        json!(notification_id)
    );
    assert!(!event.metadata.to_string().contains(old_password));
    assert!(!event.metadata.to_string().contains(new_password));

    Ok(())
}

#[tokio::test]
async fn logout_revokes_session_and_writes_audit_event() -> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-logout-audit-{}", Uuid::new_v4()),
        "API Logout Audit",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("logout-audit-{}@example.com", Uuid::new_v4()),
        "Logout Audit User",
    )?;
    database.create_user(&user, None).await?;
    let session = test_session(organization.id, user.id, now);
    database.create_auth_session(&session).await?;

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
                .uri("/api/v1/session/logout")
                .header(header::COOKIE, session_cookie(session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.42")
                .header(header::USER_AGENT, "Cairn-Test/1.0")
                .body(axum::body::Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|cookie| cookie.to_str().expect("set-cookie is ascii"))
        .collect::<Vec<_>>();
    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("cairn_session=;"))
    );
    assert!(
        set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("cairn_csrf=;"))
    );
    assert!(
        database
            .get_auth_session(session.id)
            .await?
            .expect("session exists")
            .revoked_at
            .is_some()
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "session.logged_out")
        .expect("logout audit event");

    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(user.id));
    assert_eq!(event.target, session.id.to_string());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Test/1.0"));
    assert_eq!(event.metadata["initiator"], json!("browser"));
    assert_eq!(event.metadata["acr"], json!("urn:cairn:acr:password"));
    assert_eq!(event.metadata["amr"], json!(["pwd"]));

    Ok(())
}
