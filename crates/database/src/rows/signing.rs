use crate::DatabaseError;
use cairn_domain::{SigningKey, SigningKeyMaterial};
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct SigningKeyRow {
    pub(crate) kid: String,
    pub(crate) algorithm: String,
    pub(crate) public_jwk: Json<Value>,
    pub(crate) signing_active: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) retired_at: Option<OffsetDateTime>,
}

impl From<SigningKeyRow> for SigningKey {
    fn from(row: SigningKeyRow) -> Self {
        Self {
            kid: row.kid,
            algorithm: row.algorithm,
            public_jwk: row.public_jwk.0,
            signing_active: row.signing_active,
            created_at: row.created_at,
            retired_at: row.retired_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct SigningKeyMaterialRow {
    pub(crate) kid: String,
    pub(crate) algorithm: String,
    pub(crate) public_jwk: Json<Value>,
    pub(crate) private_key_ciphertext: Option<Vec<u8>>,
    pub(crate) private_key_nonce: Option<Vec<u8>>,
    pub(crate) signing_active: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) retired_at: Option<OffsetDateTime>,
}

impl SigningKeyMaterialRow {
    pub(crate) fn try_into_material(self) -> Result<SigningKeyMaterial, DatabaseError> {
        Ok(SigningKeyMaterial {
            kid: self.kid,
            algorithm: self.algorithm,
            public_jwk: self.public_jwk.0,
            private_key_ciphertext: self.private_key_ciphertext.ok_or(DatabaseError::NotFound)?,
            private_key_nonce: self.private_key_nonce.ok_or(DatabaseError::NotFound)?,
            signing_active: self.signing_active,
            created_at: self.created_at,
            retired_at: self.retired_at,
        })
    }
}
