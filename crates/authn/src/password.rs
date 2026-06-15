use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use secrecy::{ExposeSecret, SecretString};

use crate::error::AuthnError;

pub fn hash_password(password: &SecretString) -> Result<String, AuthnError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthnError::PasswordHash)
}

pub fn verify_password(password: &SecretString, password_hash: &str) -> Result<(), AuthnError> {
    let parsed = PasswordHash::new(password_hash).map_err(|_| AuthnError::PasswordHashParse)?;
    Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed)
        .map_err(|_| AuthnError::InvalidCredential)
}
