use super::super::cookies::CSRF_HEADER;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_config,
    test_mfa_session, test_session,
};
use axum::{
    extract::Request,
    http::{HeaderName, Method, StatusCode, header},
};
use cairn_database::SessionRequestContext;
use cairn_domain::{AuthSession, Membership, MembershipRole, User};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn admin_user_browser_session_list_and_revoke_are_tenant_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-admin-browser-sessions-{}", Uuid::new_v4()),
        "API Admin Browser Sessions",
    )?;
    let other_organization = Organization::new(
        format!("api-admin-browser-sessions-other-{}", Uuid::new_v4()),
        "API Admin Browser Sessions Other",
    )?;
    database.create_organization(&organization).await?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("admin-browser-sessions-{}@example.com", Uuid::new_v4()),
        "Admin Browser Sessions",
    )?;
    let target_user = User::new(
        organization.id,
        format!("target-browser-sessions-{}@example.com", Uuid::new_v4()),
        "Target Browser Sessions",
    )?;
    let other_user = User::new(
        organization.id,
        format!("other-browser-sessions-{}@example.com", Uuid::new_v4()),
        "Other Browser Sessions",
    )?;
    let foreign_user = User::new(
        other_organization.id,
        format!("foreign-browser-sessions-{}@example.com", Uuid::new_v4()),
        "Foreign Browser Sessions",
    )?;
    database.create_user(&admin_user, None).await?;
    database.create_user(&target_user, None).await?;
    database.create_user(&other_user, None).await?;
    database.create_user(&foreign_user, None).await?;
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
    let target_session = test_session(organization.id, target_user.id, now - Duration::minutes(5));
    let second_target_session =
        test_session(organization.id, target_user.id, now - Duration::minutes(10));
    let expired_target_session = AuthSession {
        expires_at: now - Duration::minutes(1),
        ..test_session(organization.id, target_user.id, now - Duration::hours(2))
    };
    let other_user_session = test_session(organization.id, other_user.id, now);
    let foreign_session = test_session(other_organization.id, foreign_user.id, now);
    database.create_auth_session(&admin_session).await?;
    database
        .create_auth_session_with_context(
            &target_session,
            SessionRequestContext::new(Some("203.0.113.30"), Some("Target Browser/1.0")),
        )
        .await?;
    database
        .create_auth_session_with_context(
            &second_target_session,
            SessionRequestContext::new(Some("203.0.113.31"), Some("Target Browser/2.0")),
        )
        .await?;
    database
        .create_auth_session(&expired_target_session)
        .await?;
    database.create_auth_session(&other_user_session).await?;
    database.create_auth_session(&foreign_session).await?;

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
                .uri(format!("/api/v1/users/{}/browser-sessions", target_user.id))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let payload = response_json(list_response).await?;
    let sessions = payload["sessions"]
        .as_array()
        .expect("admin sessions response is an array");
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .any(|session| session["id"] == json!(target_session.id)
                && session["current"] == json!(false)
                && session["created_ip_address"] == json!("203.0.113.30")
                && session["created_user_agent"] == json!("Target Browser/1.0"))
    );
    assert!(
        sessions
            .iter()
            .all(|session| session["id"] != json!(other_user_session.id)
                && session["id"] != json!(foreign_session.id)
                && session["id"] != json!(expired_target_session.id))
    );

    let missing_user_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/users/{}/browser-sessions",
                    foreign_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(missing_user_response.status(), StatusCode::NOT_FOUND);

    let self_revoke_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/users/{}/browser-sessions/{}",
                    admin_user.id, admin_session.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(self_revoke_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(self_revoke_response).await?,
        json!({ "error": "use logout to revoke current session" })
    );

    let foreign_session_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/users/{}/browser-sessions/{}",
                    target_user.id, other_user_session.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_session_response.status(), StatusCode::NOT_FOUND);

    let revoke_response = router
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/users/{}/browser-sessions/{}",
                    target_user.id, target_session.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(HeaderName::from_static(CSRF_HEADER), csrf)
                .header(HeaderName::from_static("x-real-ip"), "198.51.100.70")
                .header(header::USER_AGENT, "Cairn-Admin-Test/1.0")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(revoke_response).await?,
        json!({ "status": "revoked", "session_id": target_session.id })
    );
    assert!(
        database
            .get_auth_session(target_session.id)
            .await?
            .expect("target session exists")
            .revoked_at
            .is_some()
    );
    assert_eq!(
        database
            .get_auth_session(admin_session.id)
            .await?
            .expect("admin session exists")
            .revoked_at,
        None
    );

    let events = database.list_audit_events(organization.id, 10).await?;
    let event = events
        .iter()
        .find(|event| event.action == "admin.user_session_revoked")
        .expect("admin user session revocation audit event");
    assert_eq!(event.actor_kind, AuditActorKind::User);
    assert_eq!(event.actor_id, Some(admin_user.id));
    assert_eq!(event.target, target_session.id.to_string());
    assert_eq!(event.ip_address.as_deref(), None);
    assert_eq!(event.user_agent.as_deref(), Some("Cairn-Admin-Test/1.0"));
    assert_eq!(event.metadata["subject_user_id"], json!(target_user.id));
    assert_eq!(event.metadata["admin_session_id"], json!(admin_session.id));

    Ok(())
}
