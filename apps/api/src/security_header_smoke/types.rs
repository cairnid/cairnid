use serde::Serialize;
use time::OffsetDateTime;

pub struct SecurityHeaderSmokeInputs {
    pub api_base_url: String,
    pub web_base_url: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SecurityHeaderSmokeReport {
    pub status: &'static str,
    pub api_base_url: String,
    pub web_base_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub checks: Vec<SecurityHeaderSmokeCheck>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SecurityHeaderSmokeCheck {
    pub service: &'static str,
    pub path: &'static str,
    pub status: &'static str,
    pub status_code: u16,
    pub content_security_policy: bool,
    pub strict_transport_security: bool,
    pub x_content_type_options_nosniff: bool,
    pub x_frame_options_deny: bool,
    pub referrer_policy_no_referrer: bool,
    pub permissions_policy_restrictive: bool,
    pub cross_origin_opener_policy_same_origin: bool,
    pub cache_control_no_store: Option<bool>,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityHeaderSmokeError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid security-header smoke input: {0}")]
    InvalidInput(String),
    #[error("security-header HTTP request failed")]
    Request(#[from] reqwest::Error),
    #[error("{service} {path} returned {actual}, expected {expected}")]
    UnexpectedStatus {
        service: &'static str,
        path: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("{service} {path} header {header_name} was {actual}, expected {expected}")]
    UnexpectedHeader {
        service: &'static str,
        path: &'static str,
        header_name: &'static str,
        expected: &'static str,
        actual: String,
    },
}
