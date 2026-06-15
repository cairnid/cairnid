use crate::config::ApiConfig;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use uuid::Uuid;

use super::ApiError;

pub(super) const SESSION_COOKIE: &str = "cairn_session";
pub(super) const CSRF_COOKIE: &str = "cairn_csrf";
pub(super) const CSRF_HEADER: &str = "x-cairn-csrf";

const CSRF_TOKEN_MIN_LEN: usize = 32;
const CSRF_TOKEN_MAX_LEN: usize = 128;

pub(super) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
}

pub(super) fn require_csrf(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(cookie_token) = cookie_value(headers, CSRF_COOKIE) else {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "missing CSRF cookie",
        ));
    };
    let Some(header_token) = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "missing CSRF header",
        ));
    };

    if !is_csrf_token_value(cookie_token) || !is_csrf_token_value(header_token) {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "invalid CSRF token",
        ));
    }

    if constant_time_eq(cookie_token.as_bytes(), header_token.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "invalid CSRF token",
        ))
    }
}

fn is_csrf_token_value(token: &str) -> bool {
    (CSRF_TOKEN_MIN_LEN..=CSRF_TOKEN_MAX_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

pub(super) fn set_session_cookie(
    headers: &mut HeaderMap,
    config: &ApiConfig,
    session_id: Uuid,
) -> Result<(), ApiError> {
    let secure = if config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}"
    );
    append_set_cookie(headers, value)
}

pub(super) fn set_csrf_cookie(
    headers: &mut HeaderMap,
    config: &ApiConfig,
    token: &str,
) -> Result<(), ApiError> {
    let secure = if config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let value =
        format!("{CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}");
    append_set_cookie(headers, value)
}

pub(super) fn clear_browser_session_cookies(
    headers: &mut HeaderMap,
    config: &ApiConfig,
) -> Result<(), ApiError> {
    clear_session_cookie(headers, config)?;
    clear_csrf_cookie(headers, config)?;
    Ok(())
}

fn clear_session_cookie(headers: &mut HeaderMap, config: &ApiConfig) -> Result<(), ApiError> {
    let secure = if config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let value = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    append_set_cookie(headers, value)
}

fn clear_csrf_cookie(headers: &mut HeaderMap, config: &ApiConfig) -> Result<(), ApiError> {
    let secure = if config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    let value = format!("{CSRF_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    append_set_cookie(headers, value)
}

fn append_set_cookie(headers: &mut HeaderMap, value: String) -> Result<(), ApiError> {
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value)
            .map_err(|_| ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "invalid cookie"))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CSRF_COOKIE, CSRF_HEADER, cookie_value, require_csrf};
    use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

    const VALID_CSRF_TOKEN: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";

    #[test]
    fn cookie_value_finds_named_cookie_in_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=value; cairn_csrf=token-value; session=ignored"),
        );

        assert_eq!(cookie_value(&headers, CSRF_COOKIE), Some("token-value"));
        assert_eq!(cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn csrf_requires_matching_cookie_and_header_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("cairn_csrf=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"),
        );
        headers.insert(
            HeaderName::from_static(CSRF_HEADER),
            HeaderValue::from_static(VALID_CSRF_TOKEN),
        );
        assert!(require_csrf(&headers).is_ok());

        headers.insert(
            HeaderName::from_static(CSRF_HEADER),
            HeaderValue::from_static("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefh"),
        );
        assert!(require_csrf(&headers).is_err());
    }
}
