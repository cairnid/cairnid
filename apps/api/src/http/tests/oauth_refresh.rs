use super::super::{AppState, build_router};
use super::{api_test_database, response_json, test_config, test_oidc_client, test_refresh_token};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
};
use cairn_authn::hash_token;
use cairn_domain::User;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
#[tokio::test]
async fn refresh_token_endpoint_persists_narrowed_scope_and_rejects_excess_scope()
-> Result<(), Box<dyn std::error::Error>> {
    use cairn_domain::Organization;
    use tower::ServiceExt as _;

    let Some(database) = api_test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("api-refresh-scope-{}", Uuid::new_v4()),
        "API Refresh Scope",
    )?;
    database.create_organization(&organization).await?;

    let user = User::new(
        organization.id,
        format!("refresh-scope-{}@example.com", Uuid::new_v4()),
        "Refresh Scope User",
    )?;
    database.create_user(&user, None).await?;

    let mut client = test_oidc_client(organization.id);
    client.client_id = format!("refresh-scope-client-{}", Uuid::new_v4());
    client.allowed_scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
        "offline_access".to_owned(),
    ];
    database.create_oidc_client(&client).await?;

    let family_id = Uuid::new_v4();
    let raw_refresh_token = format!("refresh-scope-{}", Uuid::new_v4());
    let mut refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        &raw_refresh_token,
        family_id,
        now,
    );
    refresh_token.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
        "offline_access".to_owned(),
    ];
    database.insert_refresh_token(&refresh_token).await?;

    let excessive_raw_refresh_token = format!("refresh-scope-excessive-{}", Uuid::new_v4());
    let mut excessive_refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        &excessive_raw_refresh_token,
        Uuid::new_v4(),
        now,
    );
    excessive_refresh_token.scopes = refresh_token.scopes.clone();
    database
        .insert_refresh_token(&excessive_refresh_token)
        .await?;
    let offline_family_id = Uuid::new_v4();
    let offline_raw_refresh_token = format!("refresh-scope-offline-{}", Uuid::new_v4());
    let mut offline_refresh_token = test_refresh_token(
        organization.id,
        user.id,
        client.id,
        &offline_raw_refresh_token,
        offline_family_id,
        now,
    );
    offline_refresh_token.scopes = refresh_token.scopes.clone();
    database
        .insert_refresh_token(&offline_refresh_token)
        .await?;

    let state = AppState {
        database: database.clone(),
        organization_id: organization.id,
        config: test_config(cairn_domain::Environment::Development),
    };
    let router = build_router(state);

    let excessive_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "grant_type=refresh_token&client_id={}&refresh_token={excessive_raw_refresh_token}&scope=openid%20admin",
                        client.client_id
                    )))?,
            )
            .await?;
    assert_eq!(excessive_response.status(), StatusCode::BAD_REQUEST);
    let payload = response_json(excessive_response).await?;
    assert_eq!(payload["error"], json!("invalid_scope"));
    assert_eq!(
        payload["error_description"],
        json!("requested scope exceeds original grant")
    );
    assert!(
        database
            .get_refresh_token(&excessive_refresh_token.token_hash)
            .await?
            .expect("excessive refresh token exists")
            .rotated_at
            .is_none()
    );

    let narrowed_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "grant_type=refresh_token&client_id={}&refresh_token={raw_refresh_token}&scope=openid%20profile",
                        client.client_id
                    )))?,
            )
            .await?;
    assert_eq!(narrowed_response.status(), StatusCode::OK);
    let payload = response_json(narrowed_response).await?;
    assert_eq!(payload["token_type"], json!("Bearer"));
    assert_eq!(payload["expires_in"], json!(900));
    assert_eq!(payload["scope"], json!("openid profile"));
    assert!(payload.get("id_token").is_none());
    assert!(payload.get("refresh_token").is_none());
    let access_token = payload["access_token"]
        .as_str()
        .expect("access token returned");

    let original = database
        .get_refresh_token(&refresh_token.token_hash)
        .await?
        .expect("original refresh token exists");
    assert!(original.rotated_at.is_some());

    let successor_refresh_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1")
            .bind(family_id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(successor_refresh_count, 1);

    let access = database
        .get_access_token(&hash_token(access_token))
        .await?
        .expect("access token exists");
    assert_eq!(access.refresh_family_id, Some(family_id));
    assert_eq!(access.scopes, vec!["openid", "profile"]);

    let offline_response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth2/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "grant_type=refresh_token&client_id={}&refresh_token={offline_raw_refresh_token}&scope=openid%20offline_access",
                        client.client_id
                    )))?,
            )
            .await?;
    assert_eq!(offline_response.status(), StatusCode::OK);
    let payload = response_json(offline_response).await?;
    assert_eq!(payload["scope"], json!("openid offline_access"));
    let next_refresh_token = payload["refresh_token"]
        .as_str()
        .expect("offline refresh rotation returns successor");
    let offline_access_token = payload["access_token"]
        .as_str()
        .expect("offline access token returned");
    let offline_successor = database
        .get_refresh_token(&hash_token(next_refresh_token))
        .await?
        .expect("offline successor refresh token exists");
    assert_eq!(offline_successor.family_id, offline_family_id);
    assert_eq!(offline_successor.scopes, vec!["openid", "offline_access"]);
    let offline_access = database
        .get_access_token(&hash_token(offline_access_token))
        .await?
        .expect("offline access token exists");
    assert_eq!(offline_access.refresh_family_id, Some(offline_family_id));
    assert_eq!(offline_access.scopes, vec!["openid", "offline_access"]);

    Ok(())
}
