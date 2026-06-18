use super::*;
use crate::config::{AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig};
use axum::response::Response;
use cairn_authn::hash_token;
use cairn_database::AccessTokenRecord;
use cairn_domain::{
    AuditActorKind, AuditEvent, AuthSession, OidcClient, OidcClientStatus, OidcGrantType,
    RedirectUri, RefreshToken,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const TEST_CSRF_TOKEN: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";

mod admin_audit;
mod admin_groups;
mod admin_lifecycle;
mod admin_oidc_clients;
mod admin_sessions;
mod consent_grants;
mod http_security;
mod oauth;
mod oauth_parsers;
mod oauth_refresh;
mod oidc_browser;
mod scim;
mod session_lifecycle;
mod session_security;
mod user_lifecycle;
async fn api_test_database() -> Result<Option<Database>, Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("CAIRN_DATABASE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipping API Postgres integration test; CAIRN_DATABASE_TEST_URL is not set");
        return Ok(None);
    };

    let database = Database::connect(&database_url).await?;
    database.migrate().await?;
    Ok(Some(database))
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&body)?)
}

fn session_cookie(session_id: Uuid, csrf: Option<&str>) -> String {
    match csrf {
        Some(csrf) => format!("cairn_session={session_id}; cairn_csrf={csrf}"),
        None => format!("cairn_session={session_id}"),
    }
}

fn test_session(organization_id: Uuid, user_id: Uuid, created_at: OffsetDateTime) -> AuthSession {
    AuthSession {
        id: Uuid::new_v4(),
        organization_id,
        user_id,
        acr: "urn:cairn:acr:password".to_owned(),
        amr: vec!["pwd".to_owned()],
        created_at,
        expires_at: created_at + Duration::hours(1),
        revoked_at: None,
    }
}

fn test_mfa_session(
    organization_id: Uuid,
    user_id: Uuid,
    created_at: OffsetDateTime,
) -> AuthSession {
    AuthSession {
        acr: "urn:cairn:acr:password+totp".to_owned(),
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        ..test_session(organization_id, user_id, created_at)
    }
}

fn test_audit_event(
    organization_id: Uuid,
    actor_kind: AuditActorKind,
    actor_id: Option<Uuid>,
    action: impl Into<String>,
    target: impl Into<String>,
    created_at: OffsetDateTime,
    metadata: Value,
) -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        organization_id,
        actor_kind,
        actor_id,
        action: action.into(),
        target: target.into(),
        ip_address: None,
        user_agent: None,
        metadata,
        created_at,
    }
}

fn test_access_token(
    organization_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    raw_token: &str,
    refresh_family_id: Option<Uuid>,
    created_at: OffsetDateTime,
) -> AccessTokenRecord {
    AccessTokenRecord {
        token_hash: hash_token(raw_token),
        organization_id,
        user_id: Some(user_id),
        client_id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        refresh_family_id,
        created_at,
        expires_at: created_at + Duration::minutes(15),
        revoked_at: None,
    }
}

fn test_refresh_token(
    organization_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    raw_token: &str,
    family_id: Uuid,
    created_at: OffsetDateTime,
) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        token_hash: hash_token(raw_token),
        family_id,
        organization_id,
        user_id: Some(user_id),
        client_id,
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        created_at,
        expires_at: created_at + Duration::days(30),
        rotated_at: None,
        revoked_at: None,
    }
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
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
        ],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn test_config(environment: cairn_domain::Environment) -> ApiConfig {
    ApiConfig {
        environment,
        bind: "127.0.0.1:8080".to_owned(),
        issuer: "http://localhost:8080".to_owned(),
        public_web_origin: "http://localhost:5173".to_owned(),
        database_url: "postgres://cairn:cairn@localhost:5432/cairn_identity".to_owned(),
        default_org_slug: "default".to_owned(),
        scim: ScimConfig {
            bearer_token_sha256_hashes: Vec::new(),
        },
        audit: AuditOperationsConfig {
            retention_days: 365,
            purge_batch_size: 1000,
            export_max_rows: 10_000,
        },
        email_delivery: EmailDeliveryConfig {
            provider: EmailProviderConfig::Stdout,
            batch_size: 10,
            max_attempts: 5,
            retry_seconds: 300,
            sending_timeout_seconds: 900,
        },
        request_identity: crate::config::RequestIdentityConfig {
            trusted_proxy_ips: Vec::new(),
        },
        bootstrap_setup_secret_hash: None,
        signing: None,
        key_encryption_key: None,
    }
}
