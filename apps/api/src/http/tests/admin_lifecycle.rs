use super::super::cookies::CSRF_HEADER;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_config,
    test_mfa_session,
};
use axum::{
    extract::Request,
    http::{HeaderName, Method, StatusCode, header},
};
use cairn_domain::{Membership, MembershipRole, User, UserStatus};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn admin_account_lifecycle_requests_are_scoped_and_audited()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-admin-lifecycle-{}", Uuid::new_v4()),
        "API Admin Lifecycle",
    )?;
    let other_organization = Organization::new(
        format!("api-admin-lifecycle-other-{}", Uuid::new_v4()),
        "API Admin Lifecycle Other",
    )?;
    database.create_organization(&organization).await?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("admin-lifecycle-{}@example.com", Uuid::new_v4()),
        "Admin Lifecycle",
    )?;
    let target_user = User::new(
        organization.id,
        format!("target-lifecycle-{}@example.com", Uuid::new_v4()),
        "Target Lifecycle",
    )?;
    let passwordless_user = User::new(
        organization.id,
        format!("passwordless-lifecycle-{}@example.com", Uuid::new_v4()),
        "Passwordless Lifecycle",
    )?;
    let mut suspended_user = User::new(
        organization.id,
        format!("suspended-lifecycle-{}@example.com", Uuid::new_v4()),
        "Suspended Lifecycle",
    )?;
    suspended_user.status = UserStatus::Suspended;
    let foreign_user = User::new(
        other_organization.id,
        format!("foreign-lifecycle-{}@example.com", Uuid::new_v4()),
        "Foreign Lifecycle",
    )?;
    database.create_user(&admin_user, None).await?;
    database
        .create_user(&target_user, Some("stored-password-hash"))
        .await?;
    database.create_user(&passwordless_user, None).await?;
    database
        .create_user(&suspended_user, Some("stored-password-hash"))
        .await?;
    database
        .create_user(&foreign_user, Some("stored-password-hash"))
        .await?;
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
    database.create_auth_session(&admin_session).await?;
    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);
    let csrf = TEST_CSRF_TOKEN;

    let foreign_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/users/{}/email-verification/request",
                    foreign_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_response.status(), StatusCode::NOT_FOUND);

    let suspended_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/users/{}/email-verification/request",
                    suspended_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(suspended_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(suspended_response).await?,
        json!({ "error": "user must be active" })
    );

    let passwordless_recovery_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/users/{}/password-recovery/request",
                    passwordless_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(
        passwordless_recovery_response.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        response_json(passwordless_recovery_response).await?,
        json!({ "error": "user does not have password credentials" })
    );

    let verification_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/users/{}/email-verification/request",
                    target_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.80")
                .header(header::USER_AGENT, "Cairn-Admin-Lifecycle/1.0")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification_payload = response_json(verification_response).await?;
    assert_eq!(verification_payload["status"], json!("queued"));
    assert_eq!(
        verification_payload["recipient_email"],
        json!(target_user.email)
    );
    assert!(verification_payload.get("preview_url").is_none());

    let recovery_response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/v1/users/{}/password-recovery/request",
                    target_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.81")
                .header(header::USER_AGENT, "Cairn-Admin-Lifecycle/2.0")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(recovery_response.status(), StatusCode::OK);
    let recovery_payload = response_json(recovery_response).await?;
    assert_eq!(recovery_payload["status"], json!("queued"));
    assert_eq!(
        recovery_payload["recipient_email"],
        json!(target_user.email)
    );
    assert!(recovery_payload.get("preview_url").is_none());

    type LifecycleTokenRow = (String, Option<Uuid>, Option<Uuid>, sqlx::types::Json<Value>);
    type LifecycleOutboxRow = (String, String, Option<String>, sqlx::types::Json<Value>);

    let lifecycle_tokens: Vec<LifecycleTokenRow> = sqlx::query_as(
        r#"
            SELECT kind, user_id, created_by_user_id, metadata
            FROM account_tokens
            WHERE organization_id = $1 AND user_id = $2
            ORDER BY kind ASC
            "#,
    )
    .bind(organization.id)
    .bind(target_user.id)
    .fetch_all(database.pool())
    .await?;
    assert_eq!(lifecycle_tokens.len(), 2);
    assert!(
        lifecycle_tokens
            .iter()
            .any(|(kind, user_id, created_by_user_id, metadata)| {
                kind == "email_verification"
                    && *user_id == Some(target_user.id)
                    && *created_by_user_id == Some(admin_user.id)
                    && metadata.0["initiator"] == json!("admin")
            })
    );
    assert!(
        lifecycle_tokens
            .iter()
            .any(|(kind, user_id, created_by_user_id, metadata)| {
                kind == "password_recovery"
                    && *user_id == Some(target_user.id)
                    && *created_by_user_id == Some(admin_user.id)
                    && metadata.0["initiator"] == json!("admin")
            })
    );

    let outbox_messages: Vec<LifecycleOutboxRow> = sqlx::query_as(
        r#"
            SELECT template, recipient_email, action_path, metadata
            FROM email_outbox
            WHERE organization_id = $1 AND recipient_email = $2
            ORDER BY template ASC
            "#,
    )
    .bind(organization.id)
    .bind(&target_user.email)
    .fetch_all(database.pool())
    .await?;
    assert_eq!(outbox_messages.len(), 2);
    assert!(
        outbox_messages
            .iter()
            .any(|(template, recipient_email, action_path, metadata)| {
                template == "email_verification"
                    && recipient_email == &target_user.email
                    && action_path.as_deref() == Some("/verify-email")
                    && metadata.0["kind"] == json!("email_verification")
            })
    );
    assert!(
        outbox_messages
            .iter()
            .any(|(template, recipient_email, action_path, metadata)| {
                template == "password_recovery"
                    && recipient_email == &target_user.email
                    && action_path.as_deref() == Some("/reset-password")
                    && metadata.0["kind"] == json!("password_recovery")
            })
    );

    let events = database.list_audit_events(organization.id, 20).await?;
    let verification_event = events
        .iter()
        .find(|event| event.action == "admin.email_verification_requested")
        .expect("admin verification audit event");
    assert_eq!(verification_event.actor_kind, AuditActorKind::User);
    assert_eq!(verification_event.actor_id, Some(admin_user.id));
    assert_eq!(verification_event.target, target_user.id.to_string());
    assert_eq!(verification_event.ip_address.as_deref(), None);
    assert_eq!(
        verification_event.user_agent.as_deref(),
        Some("Cairn-Admin-Lifecycle/1.0")
    );
    assert_eq!(
        verification_event.metadata["email"],
        json!(target_user.email)
    );

    let recovery_event = events
        .iter()
        .find(|event| event.action == "admin.password_recovery_requested")
        .expect("admin recovery audit event");
    assert_eq!(recovery_event.actor_kind, AuditActorKind::User);
    assert_eq!(recovery_event.actor_id, Some(admin_user.id));
    assert_eq!(recovery_event.target, target_user.id.to_string());
    assert_eq!(recovery_event.ip_address.as_deref(), None);
    assert_eq!(
        recovery_event.user_agent.as_deref(),
        Some("Cairn-Admin-Lifecycle/2.0")
    );
    assert_eq!(recovery_event.metadata["email"], json!(target_user.email));

    Ok(())
}
