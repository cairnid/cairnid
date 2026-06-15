#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("missing response type")]
    MissingResponseType,
    #[error("unsupported response type")]
    UnsupportedResponseType,
    #[error("unsupported grant type")]
    UnsupportedGrantType,
    #[error("invalid redirect URI")]
    InvalidRedirectUri,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid max_age")]
    InvalidMaxAge,
    #[error("invalid prompt")]
    InvalidPrompt,
    #[error("invalid display")]
    InvalidDisplay,
    #[error("unsupported response mode")]
    UnsupportedResponseMode,
    #[error("unsupported claims parameter")]
    UnsupportedClaimsParameter,
    #[error("unsupported request parameter")]
    UnsupportedRequestParameter,
    #[error("unsupported request_uri parameter")]
    UnsupportedRequestUriParameter,
    #[error("invalid id_token_hint")]
    InvalidIdTokenHint,
    #[error("PKCE is required")]
    PkceRequired,
    #[error("invalid PKCE code challenge")]
    InvalidPkceChallenge,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    #[error("signing key is not configured")]
    SigningKeyMissing,
    #[error("invalid key encryption key")]
    InvalidKeyEncryptionKey,
    #[error("signing key generation failed")]
    SigningKeyGeneration,
    #[error("signing key encryption failed")]
    SigningKeyEncryption,
    #[error("secret encryption failed")]
    SecretEncryption,
    #[error("secret decryption failed")]
    SecretDecryption,
    #[error("signing key decryption failed")]
    SigningKeyDecryption,
    #[error("stored signing key is invalid")]
    InvalidSigningKey,
    #[error("token signing failed")]
    TokenSigning,
}
