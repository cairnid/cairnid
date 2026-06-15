use crate::{
    ClientId, ConsentAuthorizationId, ConsentGrantId, ConsentPolicyTemplateId, DomainError,
    OrganizationId, RefreshTokenId, SessionId, UserId, checked_string,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OidcGrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
}

impl OidcGrantType {
    pub fn as_protocol_value(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OidcClientStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentGrantMode {
    RequiredOnce,
    AlwaysRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentPolicyTemplate {
    pub id: ConsentPolicyTemplateId,
    pub organization_id: OrganizationId,
    pub slug: String,
    pub name: String,
    pub grant_mode: ConsentGrantMode,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectUri {
    pub value: String,
}

impl RedirectUri {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = checked_string("redirect_uri", value.into(), 2048)?;
        if super::validation::is_https_url(&value)
            || super::validation::is_localhost_http_url(&value)
        {
            Ok(Self { value })
        } else {
            Err(DomainError::InsecureRedirectUri)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcClient {
    pub id: ClientId,
    pub organization_id: OrganizationId,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub consent_policy_template_id: Option<ConsentPolicyTemplateId>,
    pub name: String,
    pub redirect_uris: Vec<RedirectUri>,
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    pub allowed_scopes: Vec<String>,
    pub grant_types: Vec<OidcGrantType>,
    pub public_client: bool,
    pub require_pkce: bool,
    pub status: OidcClientStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl OidcClient {
    pub fn allows_redirect_uri(&self, candidate: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri.value == candidate)
    }

    pub fn allows_post_logout_redirect_uri(&self, candidate: &str) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|uri| uri.value == candidate)
    }

    pub fn allows_grant(&self, grant_type: OidcGrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSession {
    pub id: SessionId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub acr: String,
    pub amr: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentGrant {
    pub id: ConsentGrantId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentAuthorization {
    pub id: ConsentAuthorizationId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub client_id: ClientId,
    pub authorization_request_hash: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PkceMethod {
    S256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub code_hash: String,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: PkceMethod,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub token_hash: String,
    pub family_id: Uuid,
    pub organization_id: OrganizationId,
    pub user_id: Option<UserId>,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub rotated_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}
