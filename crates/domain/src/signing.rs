use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: String,
    pub public_jwk: Value,
    pub signing_active: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retired_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigningKeyMaterial {
    pub kid: String,
    pub algorithm: String,
    pub public_jwk: Value,
    pub private_key_ciphertext: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub signing_active: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retired_at: Option<OffsetDateTime>,
}
