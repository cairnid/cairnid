use serde::Serialize;
use time::OffsetDateTime;

pub struct OidcMetadataSmokeInputs {
    pub issuer: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct OidcMetadataSmokeReport {
    pub status: &'static str,
    pub issuer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub checks: Vec<OidcMetadataSmokeCheck>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct OidcMetadataSmokeCheck {
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcMetadataSmokeError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid OIDC metadata smoke input: {0}")]
    InvalidInput(String),
    #[error("OIDC metadata smoke HTTP request failed")]
    Request(#[from] reqwest::Error),
    #[error("{path} returned {actual}, expected {expected}")]
    UnexpectedStatus {
        path: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("invalid OpenID discovery metadata: {0}")]
    InvalidDiscovery(String),
    #[error("invalid JWKS metadata: {0}")]
    InvalidJwks(String),
}
