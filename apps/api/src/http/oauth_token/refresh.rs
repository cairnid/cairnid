use super::super::{api_response::ApiError, oauth_http::required_oauth_form_parameter};

pub(in crate::http) fn required_refresh_token(
    refresh_token: Option<&str>,
) -> Result<&str, ApiError> {
    required_oauth_form_parameter(refresh_token, "refresh_token")
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::super::super::api_response::ApiError;
    use super::required_refresh_token;

    #[test]
    fn refresh_token_exchange_required_parameters_use_invalid_request() {
        for missing in [None, Some(""), Some("   ")] {
            let error =
                required_refresh_token(missing).expect_err("missing refresh_token should fail");
            assert!(matches!(
                error,
                ApiError::OAuth {
                    status: StatusCode::BAD_REQUEST,
                    ref body,
                } if body.error == "invalid_request"
                    && body.error_description.as_deref() == Some("missing refresh_token")
            ));
        }

        assert_eq!(
            required_refresh_token(Some("refresh-token")).expect("refresh token"),
            "refresh-token"
        );
    }
}
