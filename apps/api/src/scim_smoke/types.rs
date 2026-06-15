use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ScimSmokeInputs {
    pub base_url: String,
    pub bearer_token: String,
    pub secondary_bearer_token: Option<String>,
    pub rejected_bearer_token: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScimSmokeReport {
    pub status: &'static str,
    pub base_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub secondary_token_checked: bool,
    pub rejected_token_checked: bool,
    pub created_user_ids: Vec<Uuid>,
    pub soft_deleted_user_ids: Vec<Uuid>,
    pub deleted_group_id: Uuid,
    pub checks: Vec<ScimSmokeCheck>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScimSmokeCheck {
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScimSmokeError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid SCIM smoke input: {0}")]
    InvalidInput(String),
    #[error("SCIM HTTP request failed")]
    Request(#[from] reqwest::Error),
    #[error("SCIM request {method} {url} returned {actual}, expected {expected}: {body}")]
    UnexpectedStatus {
        method: String,
        url: String,
        expected: u16,
        actual: u16,
        body: String,
    },
    #[error(
        "SCIM response {method} {url} returned content type {actual}, expected application/scim+json"
    )]
    UnexpectedContentType {
        method: String,
        url: String,
        actual: String,
    },
    #[error("SCIM smoke assertion failed: {0}")]
    Assertion(String),
}
