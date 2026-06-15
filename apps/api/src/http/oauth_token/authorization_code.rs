use axum::http::StatusCode;
use cairn_oidc::OAuthErrorBody;

use super::super::{api_response::ApiError, oauth_http::required_oauth_form_parameter};

pub(in crate::http) fn validate_authorization_code_redirect_uri(
    request_redirect_uri: Option<&str>,
    stored_redirect_uri: &str,
) -> Result<(), ApiError> {
    let request_redirect_uri = required_oauth_form_parameter(request_redirect_uri, "redirect_uri")?;
    if request_redirect_uri != stored_redirect_uri {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("redirect_uri mismatch"),
        ));
    }
    Ok(())
}

pub(in crate::http) fn required_authorization_code_verifier(
    code_verifier: Option<&str>,
) -> Result<&str, ApiError> {
    required_oauth_form_parameter(code_verifier, "code_verifier")
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::super::super::api_response::ApiError;
    use super::{required_authorization_code_verifier, validate_authorization_code_redirect_uri};

    #[test]
    fn authorization_code_exchange_required_parameters_use_invalid_request() {
        let missing_redirect =
            validate_authorization_code_redirect_uri(None, "http://localhost:3000/callback")
                .expect_err("missing redirect_uri should fail");
        assert!(matches!(
            missing_redirect,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing redirect_uri")
        ));
        let blank_redirect =
            validate_authorization_code_redirect_uri(Some("   "), "http://localhost:3000/callback")
                .expect_err("blank redirect_uri should fail");
        assert!(matches!(
            blank_redirect,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing redirect_uri")
        ));

        let mismatched_redirect = validate_authorization_code_redirect_uri(
            Some("http://localhost:3000/other"),
            "http://localhost:3000/callback",
        )
        .expect_err("mismatched redirect_uri should fail");
        assert!(matches!(
            mismatched_redirect,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_grant"
                && body.error_description.as_deref() == Some("redirect_uri mismatch")
        ));

        let missing_verifier =
            required_authorization_code_verifier(None).expect_err("missing verifier should fail");
        assert!(matches!(
            missing_verifier,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing code_verifier")
        ));
        let blank_verifier = required_authorization_code_verifier(Some(" "))
            .expect_err("blank verifier should fail");
        assert!(matches!(
            blank_verifier,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing code_verifier")
        ));
        assert_eq!(
            required_authorization_code_verifier(Some("verifier")).expect("verifier"),
            "verifier"
        );
    }
}
