#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    #[error("password hash failed")]
    PasswordHash,
    #[error("password hash parse failed")]
    PasswordHashParse,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("PKCE verifier does not match challenge")]
    InvalidPkce,
    #[error("PKCE value has invalid syntax")]
    InvalidPkceSyntax,
    #[error("TOTP configuration failed: {0}")]
    Totp(String),
    #[error("WebAuthn configuration failed: {0}")]
    WebAuthn(String),
}
