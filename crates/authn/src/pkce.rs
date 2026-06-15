use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_domain::PkceMethod;
use sha2::{Digest, Sha256};

use crate::error::AuthnError;

pub fn pkce_challenge(verifier: &str, method: PkceMethod) -> String {
    match method {
        PkceMethod::S256 => {
            let digest = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
    }
}

pub fn validate_pkce_code_verifier(verifier: &str) -> Result<(), AuthnError> {
    validate_pkce_unreserved(verifier)
}

pub fn validate_pkce_code_challenge(challenge: &str) -> Result<(), AuthnError> {
    validate_pkce_unreserved(challenge)
}

fn validate_pkce_unreserved(value: &str) -> Result<(), AuthnError> {
    let len = value.len();
    if !(43..=128).contains(&len) || !value.bytes().all(is_pkce_unreserved) {
        return Err(AuthnError::InvalidPkceSyntax);
    }
    Ok(())
}

fn is_pkce_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

pub fn verify_pkce(
    verifier: &str,
    expected_challenge: &str,
    method: PkceMethod,
) -> Result<(), AuthnError> {
    validate_pkce_code_verifier(verifier)?;
    validate_pkce_code_challenge(expected_challenge)?;
    if pkce_challenge(verifier, method) == expected_challenge {
        Ok(())
    } else {
        Err(AuthnError::InvalidPkce)
    }
}
