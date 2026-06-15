use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct GeneratedSecret {
    pub id: Uuid,
    pub value: SecretString,
    pub hash: String,
}

pub fn generate_secret(byte_len: usize) -> SecretString {
    let mut bytes = Zeroizing::new(vec![0_u8; byte_len]);
    rand::rng().fill(bytes.as_mut_slice());
    let value = URL_SAFE_NO_PAD.encode(bytes.as_slice());
    SecretString::from(value)
}

pub fn generate_hashed_secret(byte_len: usize) -> GeneratedSecret {
    let value = generate_secret(byte_len);
    let hash = hash_token(value.expose_secret());
    GeneratedSecret {
        id: Uuid::new_v4(),
        value,
        hash,
    }
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn verify_token_hash(token: &str, expected_hash: &str) -> bool {
    constant_time_eq(hash_token(token).as_bytes(), expected_hash.as_bytes())
}

pub fn zeroizing_string(value: impl Into<String>) -> Zeroizing<String> {
    Zeroizing::new(value.into())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left = left.get(index).copied().unwrap_or_default();
        let right = right.get(index).copied().unwrap_or_default();
        diff |= usize::from(left ^ right);
    }
    diff == 0
}
