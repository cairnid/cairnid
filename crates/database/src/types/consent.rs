use cairn_domain::{ClientId, ConsentGrantId, OrganizationId, SessionId, UserId};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantSummary {
    pub id: ConsentGrantId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub user_email: String,
    pub user_display_name: String,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConsentGrantSummary {
    pub id: ConsentGrantId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub client_public_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantRevocation {
    pub grant: ConsentGrantSummary,
    pub consent_grants_revoked: u64,
    pub authorization_codes_invalidated: u64,
    pub access_tokens_revoked: u64,
    pub refresh_tokens_revoked: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ConsentAuthorizationConsumption<'a> {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub client_id: ClientId,
    pub authorization_request_hash: &'a str,
    pub scopes: &'a [String],
    pub at: OffsetDateTime,
}
