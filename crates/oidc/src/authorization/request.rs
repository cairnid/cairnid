use cairn_authn::validate_pkce_code_challenge;
use cairn_domain::{OidcClient, OidcGrantType, PkceMethod};
use serde_json::Value;

use crate::OidcError;

use super::{
    parsing::{
        optional_parameter_is_present, parse_display, parse_prompt, parse_response_mode,
        parse_space_delimited_unique,
    },
    scopes::parse_scopes,
    types::{AuthorizationRequest, ValidatedAuthorizationRequest},
};

impl AuthorizationRequest {
    pub fn validate(self, client: &OidcClient) -> Result<ValidatedAuthorizationRequest, OidcError> {
        if self.response_type.is_empty() {
            return Err(OidcError::MissingResponseType);
        }
        if self.response_type != "code" {
            return Err(OidcError::UnsupportedResponseType);
        }

        if !client.allows_grant(OidcGrantType::AuthorizationCode) {
            return Err(OidcError::UnsupportedGrantType);
        }

        if !client.allows_redirect_uri(&self.redirect_uri) {
            return Err(OidcError::InvalidRedirectUri);
        }

        let mut scopes = parse_scopes(&self.scope)?;
        if optional_parameter_is_present(&self.request) {
            return Err(OidcError::UnsupportedRequestParameter);
        }
        if optional_parameter_is_present(&self.request_uri) {
            return Err(OidcError::UnsupportedRequestUriParameter);
        }
        for scope in additional_scopes_for_supported_claims(self.claims.as_deref())? {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.to_owned());
            }
        }
        if !scopes.iter().any(|scope| scope == "openid") {
            return Err(OidcError::InvalidScope);
        }
        if scopes
            .iter()
            .any(|scope| !client.allowed_scopes.iter().any(|allowed| allowed == scope))
        {
            return Err(OidcError::InvalidScope);
        }
        if scopes.iter().any(|scope| scope == "offline_access")
            && !client.allows_grant(OidcGrantType::RefreshToken)
        {
            return Err(OidcError::InvalidScope);
        }

        if self.max_age.is_some_and(|max_age| max_age < 0) {
            return Err(OidcError::InvalidMaxAge);
        }

        let response_mode = parse_response_mode(self.response_mode.as_deref())?;
        let prompt = parse_prompt(self.prompt.as_deref())?;
        let display = parse_display(self.display.as_deref())?;
        let acr_values = parse_space_delimited_unique(self.acr_values.as_deref());
        let ui_locales = parse_space_delimited_unique(self.ui_locales.as_deref());
        let claims_locales = parse_space_delimited_unique(self.claims_locales.as_deref());
        let code_challenge = self.code_challenge.ok_or(OidcError::PkceRequired)?;
        validate_pkce_code_challenge(&code_challenge)
            .map_err(|_| OidcError::InvalidPkceChallenge)?;
        let method = match self.code_challenge_method.as_deref() {
            Some("S256") => PkceMethod::S256,
            _ => return Err(OidcError::PkceRequired),
        };

        Ok(ValidatedAuthorizationRequest {
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scopes,
            state: self.state,
            nonce: self.nonce,
            max_age: self.max_age,
            response_mode,
            prompt,
            display,
            acr_values,
            ui_locales,
            claims_locales,
            login_hint: self.login_hint,
            code_challenge,
            code_challenge_method: method,
        })
    }
}

fn additional_scopes_for_supported_claims(
    claims: Option<&str>,
) -> Result<Vec<&'static str>, OidcError> {
    let Some(claims) = claims.map(str::trim).filter(|claims| !claims.is_empty()) else {
        return Ok(Vec::new());
    };
    let claims: Value =
        serde_json::from_str(claims).map_err(|_| OidcError::UnsupportedClaimsParameter)?;
    let claims = claims
        .as_object()
        .ok_or(OidcError::UnsupportedClaimsParameter)?;
    if claims.len() != 1 {
        return Err(OidcError::UnsupportedClaimsParameter);
    }

    let userinfo = claims
        .get("userinfo")
        .and_then(Value::as_object)
        .ok_or(OidcError::UnsupportedClaimsParameter)?;
    if userinfo.len() != 1 {
        return Err(OidcError::UnsupportedClaimsParameter);
    }

    let name = userinfo
        .get("name")
        .and_then(Value::as_object)
        .ok_or(OidcError::UnsupportedClaimsParameter)?;
    if name.len() == 1 && name.get("essential").and_then(Value::as_bool) == Some(true) {
        Ok(vec!["profile"])
    } else {
        Err(OidcError::UnsupportedClaimsParameter)
    }
}
