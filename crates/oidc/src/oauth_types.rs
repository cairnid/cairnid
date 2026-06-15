use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EndSessionRequest {
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub logout_hint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub ui_locales: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OAuthErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl OAuthErrorBody {
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_request".to_owned(),
            error_description: Some(oauth_error_description(description)),
        }
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant".to_owned(),
            error_description: Some(oauth_error_description(description)),
        }
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_scope".to_owned(),
            error_description: Some(oauth_error_description(description)),
        }
    }

    pub fn invalid_client() -> Self {
        Self {
            error: "invalid_client".to_owned(),
            error_description: Some("client authentication failed".to_owned()),
        }
    }

    pub fn unauthorized_client(description: impl Into<String>) -> Self {
        Self {
            error: "unauthorized_client".to_owned(),
            error_description: Some(oauth_error_description(description)),
        }
    }

    pub fn unsupported_grant_type() -> Self {
        Self {
            error: "unsupported_grant_type".to_owned(),
            error_description: None,
        }
    }
}

pub(crate) fn oauth_error_description(description: impl Into<String>) -> String {
    description
        .into()
        .chars()
        .map(|character| {
            if is_oauth_error_text_character(character) {
                character
            } else {
                ' '
            }
        })
        .collect()
}

pub(crate) fn is_oauth_error_text_character(character: char) -> bool {
    matches!(character as u32, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}
