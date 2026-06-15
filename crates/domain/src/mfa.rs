use crate::{MfaCredentialId, OrganizationId, UserId, WebAuthnChallengeId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MfaKind {
    Totp,
    WebAuthn,
    RecoveryCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MfaCredential {
    pub id: MfaCredentialId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub kind: MfaKind,
    pub label: String,
    pub secret_metadata: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnChallengeKind {
    Registration,
    Authentication,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebAuthnChallenge {
    pub id: WebAuthnChallengeId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub kind: WebAuthnChallengeKind,
    pub state: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
}
