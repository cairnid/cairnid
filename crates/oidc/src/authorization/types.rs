use cairn_domain::PkceMethod;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub display: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub ui_locales: Option<String>,
    #[serde(default)]
    pub claims_locales: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub claims: Option<String>,
    #[serde(default)]
    pub request: Option<String>,
    #[serde(default)]
    pub request_uri: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<i64>,
    pub response_mode: AuthorizationResponseMode,
    pub prompt: AuthorizationPrompt,
    pub display: AuthorizationDisplay,
    pub acr_values: Vec<String>,
    pub ui_locales: Vec<String>,
    pub claims_locales: Vec<String>,
    pub login_hint: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: PkceMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationPrompt {
    Default,
    None,
    Login,
    Consent,
    LoginConsent,
}

impl AuthorizationPrompt {
    pub fn is_none(self) -> bool {
        matches!(self, Self::None)
    }

    pub fn requires_login(self) -> bool {
        matches!(self, Self::Login | Self::LoginConsent)
    }

    pub fn requires_consent(self) -> bool {
        matches!(self, Self::Consent | Self::LoginConsent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResponseMode {
    Query,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDisplay {
    Default,
    Page,
    Popup,
    Touch,
    Wap,
}
