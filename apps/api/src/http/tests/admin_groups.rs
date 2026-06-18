use super::super::cookies::CSRF_HEADER;
use super::super::session_auth::bootstrap_admin_group;
use super::super::{AppState, build_router};
use super::{
    TEST_CSRF_TOKEN, api_test_database, response_json, session_cookie, test_config,
    test_mfa_session,
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_domain::{Group, Membership, MembershipRole, Organization, User};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn admin_groups_api_is_tenant_scoped_csrf_protected_and_persisted()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::from_unix_timestamp(1_800_001_000)?;
    let organization = Organization::new(
        format!("api-admin-groups-{}", Uuid::new_v4()),
        "API Admin Groups",
    )?;
    let other_organization = Organization::new(
        format!("api-admin-groups-other-{}", Uuid::new_v4()),
        "API Admin Groups Other",
    )?;
    database.create_organization(&organization).await?;
    database.create_organization(&other_organization).await?;

    let admin_group = bootstrap_admin_group(organization.id, now + Duration::seconds(30));
    let group_a = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("api-admin-groups-a-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "API Admin Groups A".to_owned(),
        created_at: now + Duration::seconds(20),
    };
    let group_b = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("api-admin-groups-b-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "API Admin Groups B".to_owned(),
        created_at: now + Duration::seconds(10),
    };
    let foreign_group = Group {
        id: Uuid::new_v4(),
        organization_id: other_organization.id,
        slug: format!("api-admin-groups-foreign-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "API Admin Groups Foreign".to_owned(),
        created_at: now,
    };
    for group in [&admin_group, &group_a, &group_b, &foreign_group] {
        database.create_group(group).await?;
    }

    let admin_user = User::new(
        organization.id,
        format!("admin-groups-admin-{}@example.com", Uuid::new_v4()),
        "Admin Groups Admin",
    )?;
    let owner_user = User::new(
        organization.id,
        format!("admin-groups-owner-{}@example.com", Uuid::new_v4()),
        "Admin Groups Owner",
    )?;
    let member_user = User::new(
        organization.id,
        format!("admin-groups-member-{}@example.com", Uuid::new_v4()),
        "Admin Groups Member",
    )?;
    let foreign_user = User::new(
        other_organization.id,
        format!("admin-groups-foreign-{}@example.com", Uuid::new_v4()),
        "Admin Groups Foreign",
    )?;
    for user in [&admin_user, &owner_user, &member_user, &foreign_user] {
        database.create_user(user, None).await?;
    }
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: admin_user.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now + Duration::seconds(30),
        })
        .await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: owner_user.id,
            group_id: group_a.id,
            role: MembershipRole::Owner,
            created_at: now + Duration::seconds(20),
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

    let limited_groups_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/groups?limit=2")
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(limited_groups_response.status(), StatusCode::OK);
    let limited_groups_payload = response_json(limited_groups_response).await?;
    let limited_groups = limited_groups_payload["items"]
        .as_array()
        .expect("groups response is an array");
    assert_eq!(limited_groups.len(), 2);
    assert_eq!(limited_groups[0]["id"], admin_group.id.to_string());
    assert_eq!(limited_groups[1]["id"], group_a.id.to_string());
    assert!(
        limited_groups
            .iter()
            .all(|group| group["organization_id"] == organization.id.to_string())
    );
    let next_cursor = limited_groups_payload["next_cursor"]
        .as_str()
        .expect("limited group response includes next cursor")
        .to_owned();

    let second_groups_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/groups?limit=2&cursor={next_cursor}"))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(second_groups_response.status(), StatusCode::OK);
    let second_groups_payload = response_json(second_groups_response).await?;
    let second_groups = second_groups_payload["items"]
        .as_array()
        .expect("groups response is an array");
    assert_eq!(second_groups.len(), 1);
    assert_eq!(second_groups[0]["id"], group_b.id.to_string());
    assert_eq!(second_groups_payload["next_cursor"], json!(null));

    let create_group_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/groups")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(
                    json!({
                        "slug": format!("api-created-group-{}", Uuid::new_v4()),
                        "display_name": "API Created Group"
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(create_group_response.status(), StatusCode::CREATED);
    let created_group_payload = response_json(create_group_response).await?;
    let created_group_id = Uuid::parse_str(
        created_group_payload["id"]
            .as_str()
            .expect("created group id"),
    )?;
    assert_eq!(
        created_group_payload["organization_id"],
        organization.id.to_string()
    );
    assert_eq!(created_group_payload["display_name"], "API Created Group");
    assert!(
        database
            .get_group(organization.id, created_group_id)
            .await?
            .is_some()
    );

    let missing_csrf_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/api/v1/groups/{created_group_id}/memberships/{}",
                    member_user.id
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .body(axum::body::Body::from(
                    json!({ "role": "member" }).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(missing_csrf_response).await?,
        json!({ "error": "missing CSRF header" })
    );
    assert!(
        database
            .get_group_membership(organization.id, created_group_id, member_user.id)
            .await?
            .is_none()
    );

    let upsert_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/api/v1/groups/{created_group_id}/memberships/{}",
                    member_user.id
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(
                    json!({ "role": "owner" }).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(upsert_response.status(), StatusCode::OK);
    let upsert_payload = response_json(upsert_response).await?;
    assert_eq!(
        upsert_payload["organization_id"],
        organization.id.to_string()
    );
    assert_eq!(upsert_payload["group_id"], created_group_id.to_string());
    assert_eq!(upsert_payload["user_id"], member_user.id.to_string());
    assert_eq!(upsert_payload["role"], "owner");
    assert_eq!(
        database
            .get_group_membership(organization.id, created_group_id, member_user.id)
            .await?
            .expect("membership is persisted")
            .role,
        MembershipRole::Owner
    );

    let memberships_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/groups/{created_group_id}/memberships"))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(memberships_response.status(), StatusCode::OK);
    let memberships_payload = response_json(memberships_response).await?;
    let memberships = memberships_payload["items"]
        .as_array()
        .expect("memberships response is an array");
    assert_eq!(memberships.len(), 1);
    assert_eq!(
        memberships[0]["organization_id"],
        organization.id.to_string()
    );
    assert_eq!(memberships[0]["group_id"], created_group_id.to_string());
    assert_eq!(memberships[0]["user_id"], member_user.id.to_string());
    assert_eq!(memberships[0]["role"], "owner");
    assert_eq!(memberships_payload["next_cursor"], json!(null));

    let foreign_group_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/groups/{}/memberships", foreign_group.id))
                .header(header::COOKIE, session_cookie(admin_session.id, None))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(foreign_group_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign_group_response).await?,
        json!({ "error": "group not found" })
    );

    let foreign_user_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "/api/v1/groups/{created_group_id}/memberships/{}",
                    foreign_user.id
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::from(
                    json!({ "role": "member" }).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(foreign_user_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign_user_response).await?,
        json!({ "error": "group or user not found" })
    );

    let delete_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/api/v1/groups/{created_group_id}/memberships/{}",
                    member_user.id
                ))
                .header(header::COOKIE, session_cookie(admin_session.id, Some(csrf)))
                .header(CSRF_HEADER, csrf)
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(delete_response.status(), StatusCode::OK);
    assert_eq!(
        response_json(delete_response).await?,
        json!({ "status": "deleted" })
    );
    assert!(
        database
            .get_group_membership(organization.id, created_group_id, member_user.id)
            .await?
            .is_none()
    );

    Ok(())
}
