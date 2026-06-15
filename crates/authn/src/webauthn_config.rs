use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{Passkey, Url, Webauthn, WebauthnBuilder};

use crate::error::AuthnError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebAuthnConfig {
    pub relying_party_id: String,
    pub relying_party_origin: String,
}

impl WebAuthnConfig {
    pub fn from_origin(origin: impl Into<String>) -> Result<Self, AuthnError> {
        let relying_party_origin = origin.into();
        let parsed = Url::parse(&relying_party_origin)
            .map_err(|err| AuthnError::WebAuthn(err.to_string()))?;
        let relying_party_id = parsed
            .host_str()
            .ok_or_else(|| AuthnError::WebAuthn("origin must include a host".to_owned()))?
            .to_owned();

        Ok(Self {
            relying_party_id,
            relying_party_origin,
        })
    }

    pub fn build(&self) -> Result<Webauthn, AuthnError> {
        let origin = Url::parse(&self.relying_party_origin)
            .map_err(|err| AuthnError::WebAuthn(err.to_string()))?;

        WebauthnBuilder::new(&self.relying_party_id, &origin)
            .map_err(|err| AuthnError::WebAuthn(err.to_string()))?
            .build()
            .map_err(|err| AuthnError::WebAuthn(err.to_string()))
    }
}

pub fn passkey_credential_id(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}
