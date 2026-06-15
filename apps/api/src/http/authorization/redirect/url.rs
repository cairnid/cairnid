use cairn_authn::hash_token;
use cairn_oidc::AuthorizationRequest;

use super::super::super::urlencoded::percent_encode_minimal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) enum AuthorizeUrlPromptMode {
    Preserve,
    RemoveLogin,
    RemoveConsent,
}

pub(in crate::http) fn current_authorize_url(
    issuer: &str,
    request: &AuthorizationRequest,
    prompt_mode: AuthorizeUrlPromptMode,
) -> String {
    let mut params = vec![
        ("response_type", request.response_type.as_str()),
        ("client_id", request.client_id.as_str()),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("scope", request.scope.as_str()),
    ];
    if let Some(state) = request.state.as_deref() {
        params.push(("state", state));
    }
    if let Some(nonce) = request.nonce.as_deref() {
        params.push(("nonce", nonce));
    }
    if let Some(display) = request.display.as_deref() {
        params.push(("display", display));
    }
    if let Some(acr_values) = request.acr_values.as_deref() {
        params.push(("acr_values", acr_values));
    }
    if let Some(ui_locales) = request.ui_locales.as_deref() {
        params.push(("ui_locales", ui_locales));
    }
    if let Some(claims_locales) = request.claims_locales.as_deref() {
        params.push(("claims_locales", claims_locales));
    }
    let max_age = request.max_age.map(|max_age| max_age.to_string());
    if let Some(max_age) = max_age.as_deref() {
        params.push(("max_age", max_age));
    }
    if let Some(response_mode) = request.response_mode.as_deref() {
        params.push(("response_mode", response_mode));
    }
    let prompt = authorize_url_prompt(request.prompt.as_deref(), prompt_mode);
    if let Some(prompt) = prompt.as_deref() {
        params.push(("prompt", prompt));
    }
    if let Some(login_hint) = request.login_hint.as_deref() {
        params.push(("login_hint", login_hint));
    }
    if let Some(code_challenge) = request.code_challenge.as_deref() {
        params.push(("code_challenge", code_challenge));
    }
    if let Some(code_challenge_method) = request.code_challenge_method.as_deref() {
        params.push(("code_challenge_method", code_challenge_method));
    }

    let query = params
        .into_iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                percent_encode_minimal(name),
                percent_encode_minimal(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{}/oauth2/authorize?{query}", issuer.trim_end_matches('/'))
}

pub(in crate::http) fn authorization_request_hash(
    issuer: &str,
    request: &AuthorizationRequest,
) -> String {
    hash_token(&current_authorize_url(
        issuer,
        request,
        AuthorizeUrlPromptMode::Preserve,
    ))
}

fn authorize_url_prompt(
    prompt: Option<&str>,
    prompt_mode: AuthorizeUrlPromptMode,
) -> Option<String> {
    let prompt = prompt.map(str::trim).filter(|prompt| !prompt.is_empty())?;
    if matches!(prompt_mode, AuthorizeUrlPromptMode::Preserve) {
        return Some(prompt.to_owned());
    }

    let values = prompt
        .split_whitespace()
        .filter(|value| {
            !matches!(
                (prompt_mode, *value),
                (AuthorizeUrlPromptMode::RemoveLogin, "login")
                    | (AuthorizeUrlPromptMode::RemoveConsent, "consent")
            )
        })
        .collect::<Vec<_>>();

    if values.is_empty() {
        None
    } else {
        Some(values.join(" "))
    }
}
