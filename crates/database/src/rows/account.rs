use crate::{DatabaseError, codec::account_token_kind_from_str};
use cairn_domain::AccountToken;
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AccountTokenRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) kind: String,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) email: String,
    pub(crate) token_hash: String,
    pub(crate) created_by_user_id: Option<Uuid>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) consumed_at: Option<OffsetDateTime>,
    pub(crate) metadata: Json<Value>,
}

impl AccountTokenRow {
    pub(crate) fn try_into_token(self) -> Result<AccountToken, DatabaseError> {
        Ok(AccountToken {
            id: self.id,
            organization_id: self.organization_id,
            kind: account_token_kind_from_str(&self.kind)?,
            user_id: self.user_id,
            email: self.email,
            token_hash: self.token_hash,
            created_by_user_id: self.created_by_user_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
            metadata: self.metadata.0,
        })
    }
}
