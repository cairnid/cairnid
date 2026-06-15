use super::{api_test_database, response_json, test_config};
use crate::http::content_type::SCIM_CONTENT_TYPE;
use crate::http::scim_projection::{ScimProjection, ScimProjectionPath, scim_apply_projection};
use crate::http::scim_protocol::{
    SCIM_GROUP_SCHEMA, SCIM_SEARCH_REQUEST_SCHEMA, SCIM_USER_SCHEMA, scim_json_response,
};
use crate::http::scim_resource::{scim_group_resource, scim_user_resource};
use crate::http::{AppState, build_router};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_database::{Database, ScimGroupMember};
use cairn_domain::{Group, Membership, MembershipRole, Organization, User};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use tower::ServiceExt as _;

#[tokio::test]
async fn scim_search_routes_apply_bearer_auth_and_list_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-scim-search-{}", Uuid::new_v4()),
        "API SCIM Search",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("api-scim-search-{}@example.com", Uuid::new_v4()),
        "API SCIM Search User",
    )?;
    database.create_user(&user, None).await?;
    let group = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("api-scim-search-{}", Uuid::new_v4()),
        scim_external_id: Some(format!("scim-search-group-{}", Uuid::new_v4())),
        display_name: "API SCIM Search Group".to_owned(),
        created_at: OffsetDateTime::now_utc(),
    };
    database.create_group(&group).await?;
    database
        .create_membership(&Membership {
            organization_id: organization.id,
            user_id: user.id,
            group_id: group.id,
            role: MembershipRole::Member,
            created_at: OffsetDateTime::now_utc(),
        })
        .await?;

    let mut config = test_config(cairn_domain::Environment::Development);
    config.scim.bearer_token_sha256_hashes = vec![Sha256::digest(b"route-scim-secret").into()];
    let state = AppState {
        database,
        organization_id: organization.id,
        config,
    };
    let router = build_router(state);

    let user_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scim/v2/Users/.search")
                .header(header::AUTHORIZATION, "Bearer route-scim-secret")
                .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
                .body(axum::body::Body::from(
                    json!({
                        "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
                        "filter": format!("userName eq \"{}\"", user.email),
                        "attributes": ["userName", "emails.value"],
                        "count": 1
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(user_response.status(), StatusCode::OK);
    let user_payload = response_json(user_response).await?;
    assert_eq!(user_payload["totalResults"], json!(1));
    assert_eq!(user_payload["Resources"][0]["id"], json!(user.id));
    assert_eq!(user_payload["Resources"][0]["userName"], json!(user.email));
    assert!(user_payload["Resources"][0].get("displayName").is_none());

    let group_response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scim/v2/Groups/.search")
                .header(header::AUTHORIZATION, "Bearer route-scim-secret")
                .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
                .body(axum::body::Body::from(
                    json!({
                        "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
                        "filter": "displayName eq \"API SCIM Search Group\"",
                        "attributes": ["displayName", "members.value"],
                        "count": 1
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(group_response.status(), StatusCode::OK);
    let group_payload = response_json(group_response).await?;
    assert_eq!(group_payload["totalResults"], json!(1));
    assert_eq!(group_payload["Resources"][0]["id"], json!(group.id));
    assert_eq!(
        group_payload["Resources"][0]["members"][0]["value"],
        json!(user.id)
    );

    Ok(())
}

#[tokio::test]
async fn scim_user_create_does_not_mark_supplied_email_verified()
-> Result<(), Box<dyn std::error::Error>> {
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let organization = Organization::new(
        format!("api-scim-email-verified-{}", Uuid::new_v4()),
        "API SCIM Email Verified",
    )?;
    database.create_organization(&organization).await?;

    let mut config = test_config(cairn_domain::Environment::Development);
    config.scim.bearer_token_sha256_hashes = vec![Sha256::digest(b"route-scim-secret").into()];
    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config,
    };
    let router = build_router(state);
    let email = format!("scim-email-verified-{}@example.com", Uuid::new_v4());

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scim/v2/Users")
                .header(header::AUTHORIZATION, "Bearer route-scim-secret")
                .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
                .body(axum::body::Body::from(
                    json!({
                        "schemas": [SCIM_USER_SCHEMA],
                        "userName": email.clone(),
                        "displayName": "SCIM Email Verified",
                        "active": true,
                        "emails": [{
                            "value": email.clone(),
                            "type": "work",
                            "primary": true
                        }]
                    })
                    .to_string(),
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let user = database
        .find_user_by_email(organization.id, &email)
        .await?
        .expect("SCIM-created user exists")
        .user;
    assert!(!user.email_verified);

    Ok(())
}

#[tokio::test]
async fn scim_user_resource_uses_standard_shape_and_location() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let mut user =
        User::new(state.organization_id, "user@example.com", "User Example").expect("valid user");
    user.scim_external_id = Some("hr-123".to_owned());

    let resource = scim_user_resource(&state, &user);
    assert_eq!(resource["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(resource["userName"], json!("user@example.com"));
    assert_eq!(resource["externalId"], json!("hr-123"));
    assert_eq!(resource["active"], json!(true));
    assert_eq!(
        resource["meta"]["location"],
        json!(format!("http://localhost:8080/scim/v2/Users/{}", user.id))
    );

    let response = scim_json_response(StatusCode::OK, resource);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        SCIM_CONTENT_TYPE
    );
}

#[tokio::test]
async fn scim_user_resource_projection_includes_requested_attributes_only() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let mut user =
        User::new(state.organization_id, "user@example.com", "User Example").expect("valid user");
    user.scim_external_id = Some("hr-123".to_owned());

    let projected = scim_apply_projection(
        scim_user_resource(&state, &user),
        &ScimProjection::Include(vec![
            ScimProjectionPath::top("userName"),
            ScimProjectionPath::sub("emails", "value"),
            ScimProjectionPath::sub("meta", "location"),
        ]),
    );

    assert_eq!(projected["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(projected["id"], json!(user.id.to_string()));
    assert_eq!(projected["userName"], json!("user@example.com"));
    assert_eq!(
        projected["emails"],
        json!([{ "value": "user@example.com" }])
    );
    assert_eq!(
        projected["meta"]["location"],
        json!(format!("http://localhost:8080/scim/v2/Users/{}", user.id))
    );
    assert!(projected.get("displayName").is_none());
    assert!(projected.get("externalId").is_none());
    assert!(projected.get("active").is_none());
}

#[tokio::test]
async fn scim_user_resource_projection_excludes_default_attributes_but_keeps_minimum() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let mut user =
        User::new(state.organization_id, "user@example.com", "User Example").expect("valid user");
    user.scim_external_id = Some("hr-123".to_owned());

    let projected = scim_apply_projection(
        scim_user_resource(&state, &user),
        &ScimProjection::Exclude(vec![
            ScimProjectionPath::top("emails"),
            ScimProjectionPath::top("meta"),
            ScimProjectionPath::top("id"),
        ]),
    );

    assert_eq!(projected["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(projected["id"], json!(user.id.to_string()));
    assert_eq!(projected["userName"], json!("user@example.com"));
    assert_eq!(projected["externalId"], json!("hr-123"));
    assert!(projected.get("emails").is_none());
    assert!(projected.get("meta").is_none());
}

#[tokio::test]
async fn scim_group_resource_uses_standard_shape_and_member_refs() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let now = OffsetDateTime::now_utc();
    let group = Group {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        slug: "engineering".to_owned(),
        scim_external_id: Some("group-123".to_owned()),
        display_name: "Engineering".to_owned(),
        created_at: now,
    };
    let user_id = Uuid::new_v4();
    let members = vec![ScimGroupMember {
        group_id: group.id,
        user_id,
        email: "user@example.com".to_owned(),
        display_name: "User Example".to_owned(),
        role: MembershipRole::Member,
        created_at: now,
    }];

    let resource = scim_group_resource(&state, &group, &members);
    assert_eq!(resource["schemas"], json!([SCIM_GROUP_SCHEMA]));
    assert_eq!(resource["displayName"], json!("Engineering"));
    assert_eq!(resource["externalId"], json!("group-123"));
    assert_eq!(resource["members"][0]["value"], json!(user_id.to_string()));
    assert_eq!(
        resource["members"][0]["$ref"],
        json!(format!("http://localhost:8080/scim/v2/Users/{user_id}"))
    );
    assert_eq!(
        resource["meta"]["location"],
        json!(format!("http://localhost:8080/scim/v2/Groups/{}", group.id))
    );
}

#[tokio::test]
async fn scim_group_resource_projection_handles_member_sub_attributes() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
        .expect("lazy pool");
    let state = AppState {
        database: Database::from_pool(pool),
        organization_id: Uuid::new_v4(),
        config: test_config(cairn_domain::Environment::Development),
    };
    let now = OffsetDateTime::now_utc();
    let group = Group {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        slug: "engineering".to_owned(),
        scim_external_id: Some("group-123".to_owned()),
        display_name: "Engineering".to_owned(),
        created_at: now,
    };
    let user_id = Uuid::new_v4();
    let members = vec![ScimGroupMember {
        group_id: group.id,
        user_id,
        email: "user@example.com".to_owned(),
        display_name: "User Example".to_owned(),
        role: MembershipRole::Member,
        created_at: now,
    }];

    let included = scim_apply_projection(
        scim_group_resource(&state, &group, &members),
        &ScimProjection::Include(vec![
            ScimProjectionPath::top("displayName"),
            ScimProjectionPath::sub("members", "value"),
            ScimProjectionPath::sub("members", "$ref"),
        ]),
    );

    assert_eq!(included["schemas"], json!([SCIM_GROUP_SCHEMA]));
    assert_eq!(included["id"], json!(group.id.to_string()));
    assert_eq!(included["displayName"], json!("Engineering"));
    assert_eq!(
        included["members"],
        json!([{
            "value": user_id.to_string(),
            "$ref": format!("http://localhost:8080/scim/v2/Users/{user_id}")
        }])
    );
    assert!(included.get("externalId").is_none());
    assert!(included.get("meta").is_none());

    let excluded = scim_apply_projection(
        scim_group_resource(&state, &group, &members),
        &ScimProjection::Exclude(vec![
            ScimProjectionPath::sub("members", "display"),
            ScimProjectionPath::sub("members", "type"),
        ]),
    );
    assert_eq!(excluded["members"][0]["value"], json!(user_id.to_string()));
    assert!(excluded["members"][0].get("display").is_none());
    assert!(excluded["members"][0].get("type").is_none());
}
