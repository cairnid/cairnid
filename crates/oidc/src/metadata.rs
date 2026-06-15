use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    pub prompt_values_supported: Vec<String>,
    pub display_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
}

impl ProviderMetadata {
    pub fn new(issuer: &str) -> Self {
        let issuer = issuer.trim_end_matches('/').to_owned();
        Self {
            authorization_endpoint: format!("{issuer}/oauth2/authorize"),
            token_endpoint: format!("{issuer}/oauth2/token"),
            userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
            end_session_endpoint: format!("{issuer}/oauth2/logout"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            introspection_endpoint: format!("{issuer}/oauth2/introspect"),
            revocation_endpoint: format!("{issuer}/oauth2/revoke"),
            issuer,
            response_types_supported: vec!["code".to_owned()],
            response_modes_supported: vec!["query".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
                "client_credentials".to_owned(),
            ],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
            scopes_supported: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
                "groups".to_owned(),
                "offline_access".to_owned(),
            ],
            claims_supported: vec![
                "sub".to_owned(),
                "iss".to_owned(),
                "aud".to_owned(),
                "exp".to_owned(),
                "iat".to_owned(),
                "auth_time".to_owned(),
                "nonce".to_owned(),
                "email".to_owned(),
                "email_verified".to_owned(),
                "name".to_owned(),
                "amr".to_owned(),
                "acr".to_owned(),
                "groups".to_owned(),
            ],
            acr_values_supported: vec![
                "urn:cairn:acr:password".to_owned(),
                "urn:cairn:acr:password+totp".to_owned(),
                "urn:cairn:acr:password+recovery_code".to_owned(),
                "urn:cairn:acr:password+webauthn".to_owned(),
            ],
            prompt_values_supported: vec![
                "none".to_owned(),
                "login".to_owned(),
                "consent".to_owned(),
            ],
            display_values_supported: vec![
                "page".to_owned(),
                "popup".to_owned(),
                "touch".to_owned(),
                "wap".to_owned(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_owned(),
                "client_secret_basic".to_owned(),
                "none".to_owned(),
            ],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            authorization_response_iss_parameter_supported: true,
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            require_request_uri_registration: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwkSet {
    pub keys: Vec<Value>,
}

impl JwkSet {
    pub fn empty() -> Self {
        Self { keys: vec![] }
    }
}
