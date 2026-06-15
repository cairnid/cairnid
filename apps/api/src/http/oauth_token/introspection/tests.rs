use super::*;
use cairn_authn::hash_token;
use cairn_database::AccessTokenRecord;
use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType, RedirectUri, RefreshToken};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[test]
fn active_introspection_response_contains_bounded_metadata() {
    let organization_id = Uuid::new_v4();
    let client = test_oidc_client(organization_id);
    let user_id = Uuid::new_v4();
    let issued_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp");
    let expires_at = issued_at + Duration::minutes(15);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];

    let response = active_introspection_response(
        "http://localhost:8080/",
        &client,
        &scopes,
        Some(user_id),
        Some("Bearer"),
        issued_at,
        expires_at,
    );

    assert_eq!(response["active"], json!(true));
    assert_eq!(response["client_id"], json!(client.client_id));
    assert_eq!(response["scope"], json!("openid profile"));
    assert_eq!(response["sub"], json!(user_id.to_string()));
    assert_eq!(response["token_type"], json!("Bearer"));
    assert_eq!(response["iss"], json!("http://localhost:8080"));
    assert_eq!(response["iat"], json!(issued_at.unix_timestamp()));
    assert_eq!(response["exp"], json!(expires_at.unix_timestamp()));

    let refresh_response = active_introspection_response(
        "http://localhost:8080",
        &client,
        &scopes,
        Some(user_id),
        None,
        issued_at,
        expires_at,
    );
    assert!(refresh_response.get("token_type").is_none());
    assert_eq!(
        inactive_introspection_response(),
        json!({ "active": false })
    );
}

#[test]
fn introspection_access_token_state_is_client_and_tenant_bound() {
    let organization_id = Uuid::new_v4();
    let client = test_oidc_client(organization_id);
    let now = OffsetDateTime::now_utc();
    let token = AccessTokenRecord {
        token_hash: hash_token("access-token"),
        organization_id,
        user_id: Some(Uuid::new_v4()),
        client_id: client.id,
        scopes: vec!["openid".to_owned()],
        refresh_family_id: None,
        created_at: now,
        expires_at: now + Duration::minutes(15),
        revoked_at: None,
    };

    assert!(access_token_active_for_client(&token, &client, now));

    let mut wrong_client = token.clone();
    wrong_client.client_id = Uuid::new_v4();
    assert!(!access_token_active_for_client(&wrong_client, &client, now));

    let mut wrong_tenant = token.clone();
    wrong_tenant.organization_id = Uuid::new_v4();
    assert!(!access_token_active_for_client(&wrong_tenant, &client, now));

    let mut expired = token.clone();
    expired.expires_at = now;
    assert!(!access_token_active_for_client(&expired, &client, now));

    let mut revoked = token;
    revoked.revoked_at = Some(now);
    assert!(!access_token_active_for_client(&revoked, &client, now));
}

#[test]
fn introspection_refresh_token_state_rejects_rotated_tokens() {
    let organization_id = Uuid::new_v4();
    let client = test_oidc_client(organization_id);
    let now = OffsetDateTime::now_utc();
    let token = RefreshToken {
        id: Uuid::new_v4(),
        token_hash: hash_token("refresh-token"),
        family_id: Uuid::new_v4(),
        organization_id,
        user_id: Some(Uuid::new_v4()),
        client_id: client.id,
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        created_at: now,
        expires_at: now + Duration::days(30),
        rotated_at: None,
        revoked_at: None,
    };

    assert!(refresh_token_active_for_client(&token, &client, now));

    let mut rotated = token.clone();
    rotated.rotated_at = Some(now);
    assert!(!refresh_token_active_for_client(&rotated, &client, now));

    let mut wrong_client = token.clone();
    wrong_client.client_id = Uuid::new_v4();
    assert!(!refresh_token_active_for_client(
        &wrong_client,
        &client,
        now
    ));

    let mut wrong_tenant = token.clone();
    wrong_tenant.organization_id = Uuid::new_v4();
    assert!(!refresh_token_active_for_client(
        &wrong_tenant,
        &client,
        now
    ));

    let mut expired = token.clone();
    expired.expires_at = now;
    assert!(!refresh_token_active_for_client(&expired, &client, now));

    let mut revoked = token;
    revoked.revoked_at = Some(now);
    assert!(!refresh_token_active_for_client(&revoked, &client, now));
}

#[test]
fn token_type_hint_lookup_order_matches_supported_rfc_hints() {
    assert_eq!(
        token_type_hint_lookup_order(Some("access_token")),
        [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
    );
    assert_eq!(
        token_type_hint_lookup_order(Some("refresh_token")),
        [TokenTypeHint::RefreshToken, TokenTypeHint::AccessToken]
    );
    assert_eq!(
        token_type_hint_lookup_order(None),
        [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
    );
}

#[test]
fn token_type_hint_lookup_order_ignores_unknown_hints() {
    assert_eq!(TokenTypeHint::parse(Some("unknown")), None);
    assert_eq!(
        token_type_hint_lookup_order(Some("unknown")),
        [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
    );
    assert_eq!(
        token_type_hint_lookup_order(Some(" refresh_token")),
        [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
    );
}

fn test_oidc_client(organization_id: Uuid) -> OidcClient {
    OidcClient {
        id: Uuid::new_v4(),
        organization_id,
        client_id: "public-client".to_owned(),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Public Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback").unwrap()],
        post_logout_redirect_uris: Vec::new(),
        allowed_scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_types: vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ],
        public_client: false,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    }
}
