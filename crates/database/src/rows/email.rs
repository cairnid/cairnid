use crate::DatabaseError;
use cairn_domain::EmailOutboxMessage;
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct EmailOutboxDeliveryToken {
    pub id: Uuid,
    pub delivery_token_ciphertext: Vec<u8>,
    pub delivery_token_nonce: Vec<u8>,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReencryptedEmailOutboxDeliveryToken {
    pub id: Uuid,
    pub delivery_token_ciphertext: Vec<u8>,
    pub delivery_token_nonce: Vec<u8>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct EmailOutboxRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) recipient_email: String,
    pub(crate) subject: String,
    pub(crate) body_text: String,
    pub(crate) template: String,
    pub(crate) action_path: Option<String>,
    pub(crate) delivery_token_ciphertext: Option<Vec<u8>>,
    pub(crate) delivery_token_nonce: Option<Vec<u8>>,
    pub(crate) status: String,
    pub(crate) attempts: i32,
    pub(crate) last_error: Option<String>,
    pub(crate) provider_message_id: Option<String>,
    pub(crate) metadata: Json<Value>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
    pub(crate) next_attempt_at: Option<OffsetDateTime>,
    pub(crate) sent_at: Option<OffsetDateTime>,
}

impl EmailOutboxRow {
    pub(crate) fn into_message(self) -> EmailOutboxMessage {
        EmailOutboxMessage {
            id: self.id,
            organization_id: self.organization_id,
            recipient_email: self.recipient_email,
            subject: self.subject,
            body_text: self.body_text,
            template: self.template,
            action_path: self.action_path,
            delivery_token_ciphertext: self.delivery_token_ciphertext,
            delivery_token_nonce: self.delivery_token_nonce,
            status: self.status,
            attempts: self.attempts,
            last_error: self.last_error,
            provider_message_id: self.provider_message_id,
            metadata: self.metadata.0,
            created_at: self.created_at,
            updated_at: self.updated_at,
            next_attempt_at: self.next_attempt_at,
            sent_at: self.sent_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct EmailOutboxDeliveryTokenRow {
    pub(crate) id: Uuid,
    pub(crate) delivery_token_ciphertext: Option<Vec<u8>>,
    pub(crate) delivery_token_nonce: Option<Vec<u8>>,
    pub(crate) metadata: Json<Value>,
}

impl EmailOutboxDeliveryTokenRow {
    pub(crate) fn try_into_token(self) -> Result<EmailOutboxDeliveryToken, DatabaseError> {
        Ok(EmailOutboxDeliveryToken {
            id: self.id,
            delivery_token_ciphertext: self
                .delivery_token_ciphertext
                .ok_or(DatabaseError::NotFound)?,
            delivery_token_nonce: self.delivery_token_nonce.ok_or(DatabaseError::NotFound)?,
            metadata: self.metadata.0,
        })
    }
}
