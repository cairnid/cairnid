use cairn_oidc::{AuthorizationRequest, OidcError, append_authorization_error_response_params};

pub(in crate::http) fn authorization_error_redirect(
    request: &AuthorizationRequest,
    issuer: &str,
    error: OidcError,
) -> String {
    let (error_code, error_description) = authorization_error_parts(error);
    authorization_error_redirect_with_code(request, issuer, error_code, Some(error_description))
}

pub(in crate::http) fn authorization_error_redirect_with_code(
    request: &AuthorizationRequest,
    issuer: &str,
    error_code: &str,
    error_description: Option<&str>,
) -> String {
    append_authorization_error_response_params(
        &request.redirect_uri,
        error_code,
        error_description,
        request.state.as_deref(),
        issuer,
    )
}

pub(super) fn authorization_error_parts(error: OidcError) -> (&'static str, &'static str) {
    match error {
        OidcError::MissingResponseType => ("invalid_request", "missing response_type"),
        OidcError::UnsupportedResponseType => {
            ("unsupported_response_type", "unsupported response type")
        }
        OidcError::UnsupportedGrantType => (
            "unauthorized_client",
            "client is not allowed to use authorization code flow",
        ),
        OidcError::InvalidScope => ("invalid_scope", "invalid scope"),
        OidcError::InvalidMaxAge => ("invalid_request", "invalid max_age"),
        OidcError::InvalidPrompt => ("invalid_request", "invalid prompt"),
        OidcError::InvalidDisplay => ("invalid_request", "invalid display"),
        OidcError::UnsupportedResponseMode => ("invalid_request", "unsupported response mode"),
        OidcError::UnsupportedClaimsParameter => {
            ("invalid_request", "unsupported claims parameter")
        }
        OidcError::UnsupportedRequestParameter => {
            ("invalid_request", "unsupported request parameter")
        }
        OidcError::UnsupportedRequestUriParameter => {
            ("invalid_request", "unsupported request_uri parameter")
        }
        OidcError::PkceRequired => ("invalid_request", "PKCE S256 is required"),
        OidcError::InvalidPkceChallenge => ("invalid_request", "invalid PKCE code_challenge"),
        OidcError::InvalidRedirectUri => ("invalid_request", "invalid redirect URI"),
        _ => ("invalid_request", "invalid authorization request"),
    }
}
