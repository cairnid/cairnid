#![forbid(unsafe_code)]

mod delivery;
mod provider;
mod rendering;

pub use delivery::deliver_once;
pub use provider::smoke_provider;

use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EmailDeliveryError {
    #[error("email delivery is disabled")]
    Disabled,
    #[error("CAIRN_KEY_ENCRYPTION_KEY is required to render lifecycle email action URLs")]
    MissingKeyEncryptionKey,
    #[error("email outbox message {id} is missing {field}")]
    MissingMessageField { id: Uuid, field: &'static str },
    #[error("email outbox message {id} has invalid metadata field {field}")]
    InvalidMetadata { id: Uuid, field: &'static str },
    #[error("email outbox token decryption failed")]
    TokenDecryption(#[from] cairn_oidc::OidcError),
    #[error("email provider command failed: {0}")]
    ProviderCommand(String),
    #[error("email provider command task failed")]
    ProviderCommandJoin,
    #[error("email provider payload serialization failed")]
    PayloadSerialization(#[from] serde_json::Error),
    #[error("smoke recipient email must be non-empty and contain @")]
    InvalidSmokeRecipient,
    #[error("database operation failed")]
    Database(#[from] cairn_database::DatabaseError),
}

impl EmailDeliveryError {
    pub(super) fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::MissingKeyEncryptionKey
                | Self::MissingMessageField { .. }
                | Self::InvalidMetadata { .. }
                | Self::TokenDecryption(_)
                | Self::PayloadSerialization(_)
        )
    }
}

pub(super) fn truncate_error(error: &str) -> String {
    const MAX_ERROR_LEN: usize = 500;
    error.chars().take(MAX_ERROR_LEN).collect()
}
