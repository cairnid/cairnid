use axum::{Json, extract::State};
use cairn_domain::SigningKey;
use cairn_oidc::{JwkSet, ProviderMetadata, SigningMaterial};
use serde_json::{Value, json};

use super::{AppState, api_response::ApiError};

pub(super) async fn healthz(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state.database.health_check().await?;
    Ok(Json(json!({ "status": "ok" })))
}

pub(super) async fn openid_configuration(State(state): State<AppState>) -> Json<ProviderMetadata> {
    Json(ProviderMetadata::new(&state.config.issuer))
}

pub(super) async fn jwks(State(state): State<AppState>) -> Result<Json<JwkSet>, ApiError> {
    let active_keys = state.database.active_jwks().await?;
    Ok(Json(jwk_set_from_sources(
        active_keys,
        state.config.signing.as_ref(),
    )))
}

fn jwk_set_from_sources(
    active_keys: Vec<SigningKey>,
    static_signing: Option<&SigningMaterial>,
) -> JwkSet {
    if !active_keys.is_empty() {
        return JwkSet {
            keys: active_keys.into_iter().map(|key| key.public_jwk).collect(),
        };
    }

    static_signing
        .map(SigningMaterial::jwk_set)
        .unwrap_or_else(JwkSet::empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn jwks_prefers_database_keys_then_static_signing_then_empty() {
        let static_signing = SigningMaterial {
            key_id: "static".to_owned(),
            private_key_pem: "private".to_owned(),
            public_jwk: json!({ "kid": "static" }),
        };
        let database_key = SigningKey {
            kid: "database".to_owned(),
            algorithm: "RS256".to_owned(),
            public_jwk: json!({ "kid": "database" }),
            signing_active: true,
            created_at: OffsetDateTime::now_utc(),
            retired_at: None,
        };

        assert_eq!(
            jwk_set_from_sources(vec![database_key], Some(&static_signing)).keys,
            vec![json!({ "kid": "database" })]
        );
        assert_eq!(
            jwk_set_from_sources(vec![], Some(&static_signing)).keys,
            vec![json!({ "kid": "static" })]
        );
        assert_eq!(jwk_set_from_sources(vec![], None).keys, Vec::<Value>::new());
    }

    #[test]
    fn openid_configuration_uses_issuer_for_public_endpoint_urls() {
        let metadata = ProviderMetadata::new("https://id.example.com/");

        assert_eq!(metadata.issuer, "https://id.example.com");
        assert_eq!(
            metadata.jwks_uri,
            "https://id.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            metadata.authorization_endpoint,
            "https://id.example.com/oauth2/authorize"
        );
    }
}
