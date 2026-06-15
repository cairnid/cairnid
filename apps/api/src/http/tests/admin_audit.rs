use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    api_test_database, response_json, session_cookie, test_audit_event, test_config,
    test_mfa_session,
};
use axum::{
    extract::Request,
    http::{HeaderName, Method, StatusCode, header},
};
use cairn_audit::AuditEventBuilder;
use cairn_domain::{
    Membership, MembershipRole, OidcClient, OidcClientStatus, OidcGrantType, RedirectUri, User,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
#[tokio::test]
async fn admin_user_security_events_are_tenant_scoped_and_paginated()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::{AuditActorKind, Organization};
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_300)?;
    let organization = Organization::new(
        format!("api-user-security-events-{}", Uuid::new_v4()),
        "API User Security Events",
    )?;
    let other_organization = Organization::new(
        format!("api-user-security-events-other-{}", Uuid::new_v4()),
        "API User Security Events Other",
    )?;
    database.create_organization(&organization).await?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;
    let admin_user = User::new(
        organization.id,
        format!("security-events-admin-{}@example.com", Uuid::new_v4()),
        "Security Events Admin",
    )?;
    let target_user = User::new(
        organization.id,
        format!("security-events-target-{}@example.com", Uuid::new_v4()),
        "Security Events Target",
    )?;
    let foreign_user = User::new(
        other_organization.id,
        format!("security-events-foreign-{}@example.com", Uuid::new_v4()),
        "Security Events Foreign",
    )?;
    database.create_user(&admin_user, None).await?;
    database.create_user(&target_user, None).await?;
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

    let direct_target = test_audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "account.password_changed",
        target_user.id.to_string(),
        now + Duration::seconds(1),
        json!({}),
    );
    let actor_event = test_audit_event(
        organization.id,
        AuditActorKind::User,
        Some(target_user.id),
        "session.logged_in",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(2),
        json!({}),
    );
    let subject_metadata = test_audit_event(
        organization.id,
        AuditActorKind::User,
        Some(admin_user.id),
        "admin.user_session_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(3),
        json!({ "subject_user_id": target_user.id }),
    );
    let user_metadata = test_audit_event(
        organization.id,
        AuditActorKind::User,
        Some(admin_user.id),
        "admin.consent_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(4),
        json!({ "user_id": target_user.id }),
    );
    let unrelated_event = test_audit_event(
        organization.id,
        AuditActorKind::User,
        Some(admin_user.id),
        "session.logged_in",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(5),
        json!({}),
    );
    let foreign_event = test_audit_event(
        other_organization.id,
        AuditActorKind::User,
        Some(admin_user.id),
        "admin.user_session_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(6),
        json!({ "subject_user_id": target_user.id }),
    );
    for event in [
        &direct_target,
        &actor_event,
        &subject_metadata,
        &user_metadata,
        &unrelated_event,
        &foreign_event,
    ] {
        database.insert_audit_event(event).await?;
    }

    let admin_session = test_mfa_session(organization.id, admin_user.id, now);
    database.create_auth_session(&admin_session).await?;
    let state = AppState {
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);

    let foreign_user_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/users/{}/security-events", foreign_user.id))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_user_response.status(), StatusCode::NOT_FOUND);

    let first_page_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/users/{}/security-events?limit=2",
                    target_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(first_page_response.status(), StatusCode::OK);
    let first_page = response_json(first_page_response).await?;
    let first_items = first_page["items"]
        .as_array()
        .expect("first security-events page");
    assert_eq!(first_items.len(), 2);
    assert_eq!(first_items[0]["id"], user_metadata.id.to_string());
    assert_eq!(first_items[1]["id"], subject_metadata.id.to_string());
    let next_cursor = first_page["next_cursor"]
        .as_str()
        .expect("first security-events page has cursor");

    let second_page_response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/users/{}/security-events?limit=2&cursor={}",
                    target_user.id, next_cursor
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(second_page_response.status(), StatusCode::OK);
    let second_page = response_json(second_page_response).await?;
    let second_items = second_page["items"]
        .as_array()
        .expect("second security-events page");
    assert_eq!(second_items.len(), 2);
    assert_eq!(second_items[0]["id"], actor_event.id.to_string());
    assert_eq!(second_items[1]["id"], direct_target.id.to_string());
    assert_eq!(second_page["next_cursor"], Value::Null);

    Ok(())
}

#[tokio::test]
async fn admin_list_routes_apply_limit_and_reject_invalid_query()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-admin-list-{}", Uuid::new_v4()),
        "API Admin List",
    )?;
    database.create_organization(&organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now);
    database.create_group(&admin_group).await?;

    let admin_user = User::new(
        organization.id,
        format!("admin-list-admin-{}@example.com", Uuid::new_v4()),
        "Admin List Admin",
    )?;
    let target_user = User::new(
        organization.id,
        format!("admin-list-target-{}@example.com", Uuid::new_v4()),
        "Admin List Target",
    )?;
    database.create_user(&admin_user, None).await?;
    database.create_user(&target_user, None).await?;
    let public_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("admin-list-public-client-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Admin List Public Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: now,
    };
    let confidential_client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("admin-list-target-client-{}", Uuid::new_v4()),
        client_secret_hash: Some("hashed-secret".to_owned()),
        consent_policy_template_id: None,
        name: "Admin List Confidential Target".to_owned(),
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
    database.create_oidc_client(&public_client).await?;
    database.create_oidc_client(&confidential_client).await?;
    let audit_event = AuditEventBuilder::user(
        organization.id,
        admin_user.id,
        "admin.user_created",
        target_user.id.to_string(),
    )
    .metadata(json!({ "email": target_user.email }))
    .build();
    database.insert_audit_event(&audit_event).await?;
    let ignored_audit_event =
        AuditEventBuilder::system(organization.id, "system.started", "control-plane").build();
    database.insert_audit_event(&ignored_audit_event).await?;
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
        database,
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };

    let limited_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users?limit=1")
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(limited_response.status(), StatusCode::OK);
    let limited_payload = response_json(limited_response).await?;
    assert_eq!(
        limited_payload["items"]
            .as_array()
            .expect("users response is an array")
            .len(),
        1
    );
    let next_cursor = limited_payload["next_cursor"]
        .as_str()
        .expect("limited response includes next cursor")
        .to_owned();

    let second_page_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/users?limit=1&cursor={next_cursor}"))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(second_page_response.status(), StatusCode::OK);
    let second_page_payload = response_json(second_page_response).await?;
    assert_eq!(
        second_page_payload["items"]
            .as_array()
            .expect("users response is an array")
            .len(),
        1
    );
    assert_eq!(second_page_payload["next_cursor"], Value::Null);

    let filtered_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users?limit=10&q=admin-list-target&status=active")
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(filtered_response.status(), StatusCode::OK);
    let filtered_payload = response_json(filtered_response).await?;
    let filtered_items = filtered_payload["items"]
        .as_array()
        .expect("users response is an array");
    assert_eq!(filtered_items.len(), 1);
    assert_eq!(filtered_items[0]["id"], target_user.id.to_string());

    let filtered_client_response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(
                        "/api/v1/oidc/clients?limit=10&q=admin-list-target-client&client_type=confidential&grant_type=client_credentials&scope=email",
                    )
                    .header(header::COOKIE, session_cookie(admin_session.id, None))
                    .body(axum::body::Body::empty())?,
            )
            .await?;
    assert_eq!(filtered_client_response.status(), StatusCode::OK);
    let filtered_client_payload = response_json(filtered_client_response).await?;
    let filtered_client_items = filtered_client_payload["items"]
        .as_array()
        .expect("client response is an array");
    assert_eq!(filtered_client_items.len(), 1);
    assert_eq!(
        filtered_client_items[0]["id"],
        confidential_client.id.to_string()
    );
    assert_eq!(filtered_client_items[0]["has_client_secret"], json!(true));
    assert!(filtered_client_items[0].get("client_secret_hash").is_none());

    let filtered_audit_response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/api/v1/audit-events?limit=10&action=admin.user&target={}&actor_kind=user&actor_id={}",
                        target_user.id, admin_user.id
                    ))
                    .header(header::COOKIE, session_cookie(admin_session.id, None))
                    .body(axum::body::Body::empty())?,
            )
            .await?;
    assert_eq!(filtered_audit_response.status(), StatusCode::OK);
    let filtered_audit_payload = response_json(filtered_audit_response).await?;
    let filtered_audit_items = filtered_audit_payload["items"]
        .as_array()
        .expect("audit response is an array");
    assert_eq!(filtered_audit_items.len(), 1);
    assert_eq!(filtered_audit_items[0]["id"], audit_event.id.to_string());

    let audit_export_response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/audit-events/export?limit=1&action=admin.user&target={}",
                    target_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(audit_export_response.status(), StatusCode::OK);
    assert_eq!(
        audit_export_response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap(),
        "application/x-ndjson"
    );
    assert_eq!(
        audit_export_response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment; filename=\"cairn-audit-events.ndjson\""
    );
    assert_eq!(
        audit_export_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        audit_export_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );
    assert!(
        audit_export_response
            .headers()
            .get(HeaderName::from_static("x-cairn-next-cursor"))
            .is_none()
    );
    let audit_export_body =
        axum::body::to_bytes(audit_export_response.into_body(), usize::MAX).await?;
    let audit_export_body = std::str::from_utf8(&audit_export_body)?;
    let audit_export_lines = audit_export_body.lines().collect::<Vec<_>>();
    assert_eq!(audit_export_lines.len(), 1);
    let exported_event = serde_json::from_str::<Value>(audit_export_lines[0])?;
    assert_eq!(exported_event["id"], audit_event.id.to_string());

    let invalid_response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users?limit=251")
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        invalid_response.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );
    assert_eq!(
        response_json(invalid_response).await?,
        json!({ "error": "admin list limit out of range" })
    );

    Ok(())
}
