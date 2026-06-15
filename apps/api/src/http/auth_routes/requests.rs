use cairn_authn::PublicKeyCredential;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub(in crate::http) struct BootstrapRequest {
    pub(in crate::http::auth_routes) email: String,
    pub(in crate::http::auth_routes) display_name: String,
    pub(in crate::http::auth_routes) password: String,
    #[serde(default)]
    pub(in crate::http::auth_routes) setup_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct LoginRequest {
    pub(in crate::http::auth_routes) email: String,
    pub(in crate::http::auth_routes) password: String,
    #[serde(default)]
    pub(in crate::http::auth_routes) totp_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) recovery_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) mfa_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) webauthn_challenge_id: Option<Uuid>,
    #[serde(default)]
    pub(in crate::http::auth_routes) webauthn_credential: Option<PublicKeyCredential>,
}

impl LoginRequest {
    pub(in crate::http::auth_routes) fn mfa_code(&self) -> Option<&str> {
        self.mfa_code
            .as_deref()
            .or(self.totp_code.as_deref())
            .or(self.recovery_code.as_deref())
            .filter(|code| !code.trim().is_empty())
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct ReauthenticateRequest {
    pub(in crate::http::auth_routes) password: String,
    #[serde(default)]
    pub(in crate::http::auth_routes) totp_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) recovery_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) mfa_code: Option<String>,
    #[serde(default)]
    pub(in crate::http::auth_routes) webauthn_challenge_id: Option<Uuid>,
    #[serde(default)]
    pub(in crate::http::auth_routes) webauthn_credential: Option<PublicKeyCredential>,
}

impl ReauthenticateRequest {
    pub(in crate::http::auth_routes) fn mfa_code(&self) -> Option<&str> {
        self.mfa_code
            .as_deref()
            .or(self.totp_code.as_deref())
            .or(self.recovery_code.as_deref())
            .filter(|code| !code.trim().is_empty())
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct ChangePasswordRequest {
    pub(in crate::http::auth_routes) current_password: String,
    pub(in crate::http::auth_routes) new_password: String,
}
