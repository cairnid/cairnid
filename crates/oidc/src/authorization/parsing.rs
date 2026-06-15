use crate::OidcError;

use super::types::{AuthorizationDisplay, AuthorizationPrompt, AuthorizationResponseMode};

pub(super) fn optional_parameter_is_present(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

pub(super) fn parse_response_mode(
    response_mode: Option<&str>,
) -> Result<AuthorizationResponseMode, OidcError> {
    match response_mode.map(str::trim).filter(|mode| !mode.is_empty()) {
        None | Some("query") => Ok(AuthorizationResponseMode::Query),
        Some(_) => Err(OidcError::UnsupportedResponseMode),
    }
}

pub(super) fn parse_display(display: Option<&str>) -> Result<AuthorizationDisplay, OidcError> {
    match display.map(str::trim).filter(|display| !display.is_empty()) {
        None => Ok(AuthorizationDisplay::Default),
        Some("page") => Ok(AuthorizationDisplay::Page),
        Some("popup") => Ok(AuthorizationDisplay::Popup),
        Some("touch") => Ok(AuthorizationDisplay::Touch),
        Some("wap") => Ok(AuthorizationDisplay::Wap),
        Some(_) => Err(OidcError::InvalidDisplay),
    }
}

pub(super) fn parse_space_delimited_unique(value: Option<&str>) -> Vec<String> {
    let mut parsed = Vec::new();
    for value in value
        .unwrap_or_default()
        .split_whitespace()
        .filter(|value| !value.is_empty())
    {
        if !parsed.iter().any(|existing| existing == value) {
            parsed.push(value.to_owned());
        }
    }
    parsed
}

pub(super) fn parse_prompt(prompt: Option<&str>) -> Result<AuthorizationPrompt, OidcError> {
    let Some(prompt) = prompt.map(str::trim).filter(|prompt| !prompt.is_empty()) else {
        return Ok(AuthorizationPrompt::Default);
    };
    let values = prompt.split_whitespace().collect::<Vec<_>>();
    if values.contains(&"none") && values.len() > 1 {
        return Err(OidcError::InvalidPrompt);
    }
    if values.len()
        != values
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    {
        return Err(OidcError::InvalidPrompt);
    }

    if values
        .iter()
        .any(|value| !matches!(*value, "none" | "login" | "consent"))
    {
        return Err(OidcError::InvalidPrompt);
    }

    let has_login = values.contains(&"login");
    let has_consent = values.contains(&"consent");
    match (values.as_slice(), has_login, has_consent) {
        (["none"], _, _) => Ok(AuthorizationPrompt::None),
        (_, true, true) => Ok(AuthorizationPrompt::LoginConsent),
        (_, true, false) => Ok(AuthorizationPrompt::Login),
        (_, false, true) => Ok(AuthorizationPrompt::Consent),
        _ => Err(OidcError::InvalidPrompt),
    }
}
