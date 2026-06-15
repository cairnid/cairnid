#![forbid(unsafe_code)]

mod error;
mod password;
mod pkce;
mod secrets;
mod totp;
mod webauthn_config;

#[cfg(test)]
mod tests;

pub use error::AuthnError;
pub use password::{hash_password, verify_password};
pub use pkce::{
    pkce_challenge, validate_pkce_code_challenge, validate_pkce_code_verifier, verify_pkce,
};
pub use secrets::{
    GeneratedSecret, generate_hashed_secret, generate_secret, hash_token, verify_token_hash,
    zeroizing_string,
};
pub use totp::TotpProfile;
pub use webauthn_config::{WebAuthnConfig, passkey_credential_id};
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
};
