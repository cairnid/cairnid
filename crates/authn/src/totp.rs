use secrecy::{ExposeSecret, SecretString};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AuthnError;

#[derive(Clone)]
pub struct TotpProfile {
    pub issuer: String,
    pub account_name: String,
    pub secret: SecretString,
}

impl TotpProfile {
    pub fn new(
        issuer: impl Into<String>,
        account_name: impl Into<String>,
        secret: SecretString,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            account_name: account_name.into(),
            secret,
        }
    }

    pub fn build(&self) -> Result<TOTP, AuthnError> {
        let secret_bytes = Secret::Raw(self.secret.expose_secret().as_bytes().to_vec())
            .to_bytes()
            .map_err(|err| AuthnError::Totp(err.to_string()))?;

        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.issuer.clone()),
            self.account_name.clone(),
        )
        .map_err(|err| AuthnError::Totp(err.to_string()))
    }

    pub fn verify_current(&self, code: &str) -> Result<bool, AuthnError> {
        self.build()?
            .check_current(code)
            .map_err(|err| AuthnError::Totp(err.to_string()))
    }
}
