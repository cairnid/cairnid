use axum::http::{HeaderMap, header};
use sha2::{Digest, Sha256};

use super::{AppState, scim_protocol::ScimError};

pub(super) fn require_scim_bearer(state: &AppState, headers: &HeaderMap) -> Result<(), ScimError> {
    require_scim_bearer_hashes(&state.config.scim.bearer_token_sha256_hashes, headers)
}

fn require_scim_bearer_hashes(
    expected_hashes: &[[u8; 32]],
    headers: &HeaderMap,
) -> Result<(), ScimError> {
    if expected_hashes.is_empty() {
        return Err(ScimError::unavailable(
            "SCIM bearer token is not configured",
        ));
    }

    let mut authorization_values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = authorization_values.next() else {
        return Err(ScimError::unauthorized("missing bearer token"));
    };
    if authorization_values.next().is_some() {
        return Err(ScimError::unauthorized(
            "multiple authorization headers are not allowed",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| ScimError::unauthorized("invalid bearer token"))?;
    let Some(token) = bearer_token_value(value) else {
        return Err(ScimError::unauthorized("invalid bearer token"));
    };

    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !scim_token_hash_matches(expected_hashes, &actual) {
        return Err(ScimError::unauthorized("invalid bearer token"));
    }

    Ok(())
}

fn bearer_token_value(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let split_at = trimmed.find(char::is_whitespace)?;
    let (scheme, token) = trimmed.split_at(split_at);
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    Some(token)
}

fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn scim_token_hash_matches(expected_hashes: &[[u8; 32]], actual_hash: &[u8; 32]) -> bool {
    let mut matched = false;
    for expected_hash in expected_hashes {
        matched |= constant_time_eq_32(expected_hash, actual_hash);
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, StatusCode};

    #[test]
    fn bearer_parser_is_case_insensitive_and_strict() {
        assert_eq!(
            bearer_token_value("Bearer scim-secret"),
            Some("scim-secret")
        );
        assert_eq!(
            bearer_token_value("bearer scim-secret"),
            Some("scim-secret")
        );
        assert_eq!(bearer_token_value("Bearer"), None);
        assert_eq!(bearer_token_value("Basic scim-secret"), None);
        assert_eq!(bearer_token_value("Bearer scim secret"), None);

        let left = [7_u8; 32];
        let mut right = [7_u8; 32];
        assert!(constant_time_eq_32(&left, &right));
        right[31] = 8;
        assert!(!constant_time_eq_32(&left, &right));
    }

    #[test]
    fn bearer_auth_uses_configured_sha256_hashes() {
        let expected_hashes = vec![
            Sha256::digest(b"scim-secret").into(),
            Sha256::digest(b"scim-secret-rotating").into(),
        ];
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer scim-secret"),
        );
        assert!(require_scim_bearer_hashes(&expected_hashes, &headers).is_ok());

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer scim-secret-rotating"),
        );
        assert!(require_scim_bearer_hashes(&expected_hashes, &headers).is_ok());

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-secret"),
        );
        let error =
            require_scim_bearer_hashes(&expected_hashes, &headers).expect_err("wrong token fails");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn bearer_auth_fails_closed_without_configured_hashes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer scim-secret"),
        );

        let error =
            require_scim_bearer_hashes(&[], &headers).expect_err("missing token hashes fail");
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
