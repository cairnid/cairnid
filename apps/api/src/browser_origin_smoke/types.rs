use serde::Serialize;
use time::OffsetDateTime;

pub struct BrowserOriginSmokeInputs {
    pub base_url: String,
    pub hostile_origin: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BrowserOriginSmokeReport {
    pub status: &'static str,
    pub base_url: String,
    pub hostile_origin: String,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub routes_checked: usize,
    pub checks: Vec<BrowserOriginSmokeCheck>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BrowserOriginSmokeCheck {
    pub name: &'static str,
    pub method: &'static str,
    pub path: String,
    pub status: &'static str,
    pub origin_status: u16,
    pub referer_status: u16,
    pub no_store: bool,
    pub pragma_no_cache: bool,
    pub content_type_options_nosniff: bool,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BrowserOriginSmokeError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid browser-origin smoke input: {0}")]
    InvalidInput(String),
    #[error("browser-origin HTTP request failed")]
    Request(#[from] reqwest::Error),
    #[error("{route_name} {signal} request returned {actual}, expected 403 Forbidden: {body}")]
    UnexpectedStatus {
        route_name: &'static str,
        signal: &'static str,
        actual: u16,
        body: String,
    },
    #[error(
        "{route_name} {signal} response header {header_name} was {actual}, expected {expected}"
    )]
    UnexpectedHeader {
        route_name: &'static str,
        signal: &'static str,
        header_name: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("{route_name} {signal} response body did not contain error=\"invalid request origin\"")]
    UnexpectedBody {
        route_name: &'static str,
        signal: &'static str,
    },
}
