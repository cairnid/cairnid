use reqwest::{Method, StatusCode};

use super::super::{CHECK_REJECTED_TOKEN, CHECK_SECONDARY_TOKEN, ScimSmokeError};
use super::ScimSmokeRun;

pub(super) fn validate_rotation_tokens(
    bearer_token: &str,
    secondary_bearer_token: &Option<String>,
    rejected_bearer_token: &Option<String>,
) -> Result<(), ScimSmokeError> {
    if secondary_bearer_token.as_deref() == Some(bearer_token) {
        return Err(ScimSmokeError::InvalidInput(
            "CAIRN_SCIM_SECONDARY_BEARER_TOKEN must differ from CAIRN_SCIM_BEARER_TOKEN".to_owned(),
        ));
    }
    if rejected_bearer_token.as_deref() == Some(bearer_token) {
        return Err(ScimSmokeError::InvalidInput(
            "CAIRN_SCIM_REJECTED_BEARER_TOKEN must differ from CAIRN_SCIM_BEARER_TOKEN".to_owned(),
        ));
    }
    if secondary_bearer_token.is_some() && secondary_bearer_token == rejected_bearer_token {
        return Err(ScimSmokeError::InvalidInput(
            "CAIRN_SCIM_REJECTED_BEARER_TOKEN must differ from CAIRN_SCIM_SECONDARY_BEARER_TOKEN"
                .to_owned(),
        ));
    }
    Ok(())
}

impl ScimSmokeRun {
    pub(super) async fn check_secondary_token_if_configured(
        &mut self,
    ) -> Result<(), ScimSmokeError> {
        let Some(token) = self.secondary_bearer_token.as_deref() else {
            return Ok(());
        };
        self.request(
            token,
            Method::GET,
            "ServiceProviderConfig",
            &[],
            None,
            StatusCode::OK,
        )
        .await?;
        self.pass(
            CHECK_SECONDARY_TOKEN,
            "configured secondary SCIM bearer token reached ServiceProviderConfig",
        );
        Ok(())
    }

    pub(super) async fn check_rejected_token_if_configured(
        &mut self,
    ) -> Result<(), ScimSmokeError> {
        let Some(token) = self.rejected_bearer_token.as_deref() else {
            return Ok(());
        };
        self.request(
            token,
            Method::GET,
            "ServiceProviderConfig",
            &[],
            None,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        self.pass(
            CHECK_REJECTED_TOKEN,
            "configured rejected SCIM bearer token returned 401 Unauthorized",
        );
        Ok(())
    }
}
