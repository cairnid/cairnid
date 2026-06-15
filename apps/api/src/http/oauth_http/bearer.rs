use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::borrow::Cow;

use super::super::{OAUTH_QUERY_MAX_BYTES, urlencoded::parse_url_encoded_pairs};
use super::add_oauth_cache_headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) enum BearerTokenError {
    Missing,
    UnsupportedScheme,
    MultipleMethods,
    InvalidRequest,
}

pub(in crate::http) fn bearer_token(headers: &HeaderMap) -> Result<&str, BearerTokenError> {
    let mut authorization_headers = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw_header) = authorization_headers.next() else {
        return Err(BearerTokenError::Missing);
    };
    if authorization_headers.next().is_some() {
        return Err(BearerTokenError::InvalidRequest);
    }
    let raw_header = raw_header
        .to_str()
        .map_err(|_| BearerTokenError::InvalidRequest)?;
    let mut parts = raw_header.split_ascii_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(BearerTokenError::Missing);
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(BearerTokenError::UnsupportedScheme);
    }
    let Some(token) = parts.next() else {
        return Err(BearerTokenError::InvalidRequest);
    };
    if parts.next().is_some() || !is_bearer_token_value(token) {
        return Err(BearerTokenError::InvalidRequest);
    }

    Ok(token)
}

pub(in crate::http) fn bearer_token_from_sources<'a>(
    headers: &'a HeaderMap,
    form_access_token: Option<String>,
    raw_query: Option<&str>,
) -> Result<Cow<'a, str>, BearerTokenError> {
    if query_contains_bearer_token(raw_query)? {
        return Err(BearerTokenError::InvalidRequest);
    }
    let form_access_token = form_access_token.filter(|token| !token.is_empty());
    let header_token = bearer_token(headers);

    match (header_token, form_access_token) {
        (Ok(_), Some(_)) => Err(BearerTokenError::MultipleMethods),
        (Ok(token), None) => Ok(Cow::Borrowed(token)),
        (Err(BearerTokenError::Missing), Some(token)) => {
            if is_bearer_token_value(&token) {
                Ok(Cow::Owned(token))
            } else {
                Err(BearerTokenError::InvalidRequest)
            }
        }
        (Err(BearerTokenError::Missing), None) => Err(BearerTokenError::Missing),
        (Err(error), _) => Err(error),
    }
}

fn query_contains_bearer_token(raw_query: Option<&str>) -> Result<bool, BearerTokenError> {
    let Some(query) = raw_query else {
        return Ok(false);
    };
    if query.len() > OAUTH_QUERY_MAX_BYTES {
        return Err(BearerTokenError::InvalidRequest);
    }
    let pairs = parse_url_encoded_pairs(query).map_err(|_| BearerTokenError::InvalidRequest)?;
    Ok(pairs.iter().any(|(name, _)| name == "access_token"))
}

fn is_bearer_token_value(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'+'
                    | b'/'
                    | b'='
            )
        })
}

pub(in crate::http) fn bearer_challenge_response(
    status: StatusCode,
    error: Option<&str>,
    error_description: Option<&str>,
    scope: Option<&str>,
) -> Response {
    let mut response = status.into_response();
    add_oauth_cache_headers(response.headers_mut());
    let challenge = bearer_challenge_value(error, error_description, scope);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge)
            .expect("bearer challenge values are static visible ASCII"),
    );
    response
}

pub(in crate::http) fn bearer_token_error_response(error: BearerTokenError) -> Response {
    match error {
        BearerTokenError::Missing | BearerTokenError::UnsupportedScheme => {
            bearer_challenge_response(StatusCode::UNAUTHORIZED, None, None, None)
        }
        BearerTokenError::MultipleMethods => bearer_challenge_response(
            StatusCode::BAD_REQUEST,
            Some("invalid_request"),
            Some("multiple bearer token transport methods"),
            None,
        ),
        BearerTokenError::InvalidRequest => bearer_challenge_response(
            StatusCode::BAD_REQUEST,
            Some("invalid_request"),
            Some("invalid bearer token request"),
            None,
        ),
    }
}

pub(in crate::http) fn bearer_challenge_value(
    error: Option<&str>,
    error_description: Option<&str>,
    scope: Option<&str>,
) -> String {
    let mut challenge = "Bearer realm=\"cairn\"".to_owned();
    if let Some(error) = error {
        challenge.push_str(", error=\"");
        challenge.push_str(&bearer_challenge_param_value(error));
        challenge.push('"');
    }
    if let Some(error_description) = error_description {
        challenge.push_str(", error_description=\"");
        challenge.push_str(&bearer_challenge_param_value(error_description));
        challenge.push('"');
    }
    if let Some(scope) = scope {
        challenge.push_str(", scope=\"");
        challenge.push_str(&bearer_challenge_param_value(scope));
        challenge.push('"');
    }
    challenge
}

pub(in crate::http) fn bearer_challenge_param_value(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if is_bearer_challenge_param_character(character) {
                character
            } else {
                ' '
            }
        })
        .collect()
}

pub(in crate::http) fn is_bearer_challenge_param_character(character: char) -> bool {
    matches!(character as u32, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parser_accepts_strict_visible_token_syntax() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bEaReR abc.DEF_123-~+/="),
        );

        assert_eq!(bearer_token(&headers), Ok("abc.DEF_123-~+/="));
    }

    #[test]
    fn bearer_source_resolver_rejects_query_transport_and_mixed_methods() {
        let empty_headers = HeaderMap::new();
        assert_eq!(
            bearer_token_from_sources(&empty_headers, None, Some("access_token=query-token")),
            Err(BearerTokenError::InvalidRequest)
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        assert_eq!(
            bearer_token_from_sources(&headers, Some("form-token".to_owned()), None),
            Err(BearerTokenError::MultipleMethods)
        );
    }

    #[test]
    fn bearer_challenge_parameters_are_visible_ascii() {
        let sanitized = bearer_challenge_param_value("bad\n\"quoted\" cafe \\ value");

        assert!(sanitized.chars().all(|character| {
            matches!(character as u32, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
        }));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('"'));
    }
}
