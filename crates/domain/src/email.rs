use crate::{EmailOutboxId, OrganizationId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailOutboxMessage {
    pub id: EmailOutboxId,
    pub organization_id: OrganizationId,
    pub recipient_email: String,
    pub subject: String,
    pub body_text: String,
    pub template: String,
    pub action_path: Option<String>,
    pub delivery_token_ciphertext: Option<Vec<u8>>,
    pub delivery_token_nonce: Option<Vec<u8>>,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub provider_message_id: Option<String>,
    pub metadata: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_attempt_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub sent_at: Option<OffsetDateTime>,
}
