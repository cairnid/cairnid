#![forbid(unsafe_code)]

mod authorization;
mod claims;
mod error;
mod metadata;
mod oauth_types;
mod redirects;
mod signing;

pub use self::authorization::{
    AuthorizationDisplay, AuthorizationPrompt, AuthorizationRequest, AuthorizationResponseMode,
    ValidatedAuthorizationRequest, parse_scopes, scope_token_is_valid,
    verify_authorization_code_pkce,
};
pub use self::claims::{
    IdTokenClaims, IdTokenIssueRequest, issue_id_token, userinfo, validate_logout_id_token_hint,
    validate_logout_id_token_hint_issuer,
};
pub use self::error::OidcError;
pub use self::metadata::{JwkSet, ProviderMetadata};
pub use self::oauth_types::{EndSessionRequest, OAuthErrorBody, TokenRequest, TokenResponse};
pub use self::redirects::{
    append_authorization_error_response_params, append_authorization_response_params,
    append_post_logout_redirect_params,
};
pub use self::signing::{
    EncryptedSecret, KeyEncryptionKey, SigningMaterial, decrypt_secret, decrypt_signing_material,
    encrypt_secret, encrypt_signing_material, generate_encrypted_signing_key,
    generate_key_encryption_key, reencrypt_signing_key_material,
};

#[cfg(test)]
mod tests;
