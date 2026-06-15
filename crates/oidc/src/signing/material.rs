use serde_json::Value;
use zeroize::Zeroize;

use crate::JwkSet;

#[derive(Clone)]
pub struct SigningMaterial {
    pub key_id: String,
    pub private_key_pem: String,
    pub public_jwk: Value,
}

impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningMaterial")
            .field("key_id", &self.key_id)
            .field("private_key_pem", &"[redacted]")
            .field("public_jwk", &self.public_jwk)
            .finish()
    }
}

impl Drop for SigningMaterial {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

impl SigningMaterial {
    pub fn jwk_set(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk.clone()],
        }
    }
}
