use cairn_database::{ConsentGrantRevocation, ConsentGrantSummary};
use cairn_domain::{ConsentGrantMode, OidcClient, OidcClientStatus, OidcGrantType, RedirectUri};
use cairn_oidc::scope_token_is_valid;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::api_response::ApiError;

#[derive(Debug, Serialize)]
pub(in crate::http) struct AdminOidcClient {
    id: Uuid,
    organization_id: Uuid,
    client_id: String,
    consent_policy_template_id: Option<Uuid>,
    name: String,
    redirect_uris: Vec<RedirectUri>,
    post_logout_redirect_uris: Vec<RedirectUri>,
    allowed_scopes: Vec<String>,
    grant_types: Vec<OidcGrantType>,
    public_client: bool,
    require_pkce: bool,
    status: OidcClientStatus,
    has_client_secret: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl From<OidcClient> for AdminOidcClient {
    fn from(client: OidcClient) -> Self {
        Self {
            id: client.id,
            organization_id: client.organization_id,
            client_id: client.client_id,
            consent_policy_template_id: client.consent_policy_template_id,
            name: client.name,
            redirect_uris: client.redirect_uris,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            allowed_scopes: client.allowed_scopes,
            grant_types: client.grant_types,
            public_client: client.public_client,
            require_pkce: client.require_pkce,
            status: client.status,
            has_client_secret: client.client_secret_hash.is_some(),
            created_at: client.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct CreateOidcClientResponse {
    pub(in crate::http::admin_oidc) client: AdminOidcClient,
    pub(in crate::http::admin_oidc) client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct RotateClientSecretResponse {
    pub(in crate::http::admin_oidc) client: AdminOidcClient,
    pub(in crate::http::admin_oidc) client_secret: String,
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct UpdateOidcClientStatusResponse {
    pub(in crate::http::admin_oidc) client: AdminOidcClient,
    pub(in crate::http::admin_oidc) authorization_codes_invalidated: u64,
    pub(in crate::http::admin_oidc) access_tokens_revoked: u64,
    pub(in crate::http::admin_oidc) refresh_tokens_revoked: u64,
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct AdminConsentGrantSummary {
    pub(in crate::http::admin_oidc) id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    user_email: String,
    user_display_name: String,
    client_id: Uuid,
    scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(in crate::http::admin_oidc) created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    revoked_at: Option<OffsetDateTime>,
}

impl From<ConsentGrantSummary> for AdminConsentGrantSummary {
    fn from(grant: ConsentGrantSummary) -> Self {
        Self {
            id: grant.id,
            organization_id: grant.organization_id,
            user_id: grant.user_id,
            user_email: grant.user_email,
            user_display_name: grant.user_display_name,
            client_id: grant.client_id,
            scopes: grant.scopes,
            created_at: grant.created_at,
            revoked_at: grant.revoked_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct AdminConsentGrantRevocationResponse {
    grant: AdminConsentGrantSummary,
    consent_grants_revoked: u64,
    authorization_codes_invalidated: u64,
    access_tokens_revoked: u64,
    refresh_tokens_revoked: u64,
}

impl From<ConsentGrantRevocation> for AdminConsentGrantRevocationResponse {
    fn from(revocation: ConsentGrantRevocation) -> Self {
        Self {
            grant: AdminConsentGrantSummary::from(revocation.grant),
            consent_grants_revoked: revocation.consent_grants_revoked,
            authorization_codes_invalidated: revocation.authorization_codes_invalidated,
            access_tokens_revoked: revocation.access_tokens_revoked,
            refresh_tokens_revoked: revocation.refresh_tokens_revoked,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct UpdateClientStatusRequest {
    pub(in crate::http::admin_oidc) status: OidcClientStatus,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateConsentPolicyTemplateRequest {
    pub(in crate::http::admin_oidc) slug: String,
    pub(in crate::http::admin_oidc) name: String,
    pub(in crate::http::admin_oidc) grant_mode: ConsentGrantMode,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct CreateClientRequest {
    pub(in crate::http::admin_oidc) client_id: String,
    pub(in crate::http::admin_oidc) name: String,
    pub(in crate::http::admin_oidc) redirect_uris: Vec<String>,
    #[serde(default)]
    pub(in crate::http::admin_oidc) post_logout_redirect_uris: Vec<String>,
    #[serde(default = "default_scopes")]
    pub(in crate::http::admin_oidc) allowed_scopes: Vec<String>,
    #[serde(default)]
    pub(in crate::http::admin_oidc) public_client: bool,
    #[serde(default)]
    pub(in crate::http::admin_oidc) consent_policy_template_id: Option<Uuid>,
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}

pub(in crate::http) fn validate_allowed_client_scopes(
    scopes: Vec<String>,
) -> Result<Vec<String>, ApiError> {
    let mut allowed_scopes = Vec::new();
    for scope in scopes {
        if !scope_token_is_valid(&scope) {
            return Err(ApiError::bad_request("invalid client scope"));
        }
        if !allowed_scopes.iter().any(|existing| existing == &scope) {
            allowed_scopes.push(scope);
        }
    }
    if !allowed_scopes.iter().any(|scope| scope == "openid") {
        allowed_scopes.push("openid".to_owned());
    }
    Ok(allowed_scopes)
}
