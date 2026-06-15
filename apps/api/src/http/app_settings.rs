use crate::config::ApiConfig;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use cairn_oidc::{OAuthErrorBody, SigningMaterial, decrypt_signing_material};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{AppState, api_response::ApiError, session_auth::require_admin_session};

pub(super) async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let database_signing_configured = state.database.active_signing_key().await?.is_some();
    Ok(Json(settings_payload(
        &state.config,
        state.organization_id,
        database_signing_configured,
    )))
}

fn settings_payload(
    config: &ApiConfig,
    organization_id: Uuid,
    database_signing_configured: bool,
) -> Value {
    json!({
        "issuer": config.issuer,
        "public_web_origin": config.public_web_origin,
        "organization_id": organization_id,
        "signing_configured": database_signing_configured || config.signing.is_some(),
        "database_signing_configured": database_signing_configured,
        "key_encryption_configured": config.key_encryption_key.is_some()
    })
}

pub(super) async fn resolve_signing_material(
    state: &AppState,
) -> Result<SigningMaterial, ApiError> {
    if let Some(key_encryption_key) = &state.config.key_encryption_key
        && let Some(stored) = state.database.active_signing_key().await?
    {
        return decrypt_signing_material(&stored, key_encryption_key).map_err(|err| {
            ApiError::oauth(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthErrorBody::invalid_request(err.to_string()),
            )
        });
    }

    state.config.signing.clone().ok_or_else(|| {
        ApiError::oauth(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorBody::invalid_request("RS256 signing key is not configured"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use cairn_domain::Environment;

    #[test]
    fn settings_payload_reports_configured_static_signing_material() {
        let mut config = test_config();
        config.signing = Some(SigningMaterial {
            key_id: "static-key".to_owned(),
            private_key_pem: "private".to_owned(),
            public_jwk: json!({ "kid": "static-key" }),
        });
        let organization_id = Uuid::new_v4();

        let payload = settings_payload(&config, organization_id, false);

        assert_eq!(payload["issuer"], json!("http://localhost:8080"));
        assert_eq!(payload["public_web_origin"], json!("http://localhost:5173"));
        assert_eq!(payload["organization_id"], json!(organization_id));
        assert_eq!(payload["signing_configured"], json!(true));
        assert_eq!(payload["database_signing_configured"], json!(false));
        assert_eq!(payload["key_encryption_configured"], json!(false));
    }

    #[test]
    fn settings_payload_reports_database_signing_without_static_key() {
        let config = test_config();
        let payload = settings_payload(&config, Uuid::new_v4(), true);

        assert_eq!(payload["signing_configured"], json!(true));
        assert_eq!(payload["database_signing_configured"], json!(true));
    }

    fn test_config() -> ApiConfig {
        ApiConfig {
            environment: Environment::Development,
            bind: "127.0.0.1:0".to_owned(),
            issuer: "http://localhost:8080".to_owned(),
            public_web_origin: "http://localhost:5173".to_owned(),
            database_url: "postgres://postgres:postgres@127.0.0.1/cairn_identity".to_owned(),
            default_org_slug: "default".to_owned(),
            scim: ScimConfig {
                bearer_token_sha256_hashes: vec![],
            },
            audit: AuditOperationsConfig {
                retention_days: 365,
                purge_batch_size: 1000,
                export_max_rows: 10_000,
            },
            email_delivery: EmailDeliveryConfig {
                provider: EmailProviderConfig::Disabled,
                batch_size: 100,
                max_attempts: 5,
                retry_seconds: 60,
                sending_timeout_seconds: 300,
            },
            request_identity: crate::config::RequestIdentityConfig {
                trusted_proxy_ips: Vec::new(),
            },
            bootstrap_setup_secret_hash: None,
            signing: None,
            key_encryption_key: None,
        }
    }
}
