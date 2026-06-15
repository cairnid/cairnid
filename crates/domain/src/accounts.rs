use crate::{AccountTokenId, OrganizationId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountTokenKind {
    EmailVerification,
    PasswordRecovery,
    Invitation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountToken {
    pub id: AccountTokenId,
    pub organization_id: OrganizationId,
    pub kind: AccountTokenKind,
    pub user_id: Option<UserId>,
    pub email: String,
    pub token_hash: String,
    pub created_by_user_id: Option<UserId>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
    pub metadata: Value,
}
