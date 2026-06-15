use axum::http::{HeaderMap, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cairn_oidc::OAuthErrorBody;

use super::super::ApiError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct OAuthClientAuth {
    pub(in crate::http) client_id: Option<String>,
    pub(in crate::http) client_secret: Option<String>,
}

pub(in crate::http) fn oauth_client_auth_from_request(
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<OAuthClientAuth, ApiError> {
    if let Some(basic_auth) = oauth_basic_client_auth(headers)? {
        if body_client_id.is_some() || body_client_secret.is_some() {
            return Err(ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_request("multiple client authentication methods"),
            ));
        }
        return Ok(basic_auth);
    }

    Ok(OAuthClientAuth {
        client_id: body_client_id.map(ToOwned::to_owned),
        client_secret: body_client_secret.map(ToOwned::to_owned),
    })
}

fn oauth_basic_client_auth(headers: &HeaderMap) -> Result<Option<OAuthClientAuth>, ApiError> {
    let mut authorization_headers = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw_header) = authorization_headers.next() else {
        return Ok(None);
    };
    if authorization_headers.next().is_some() {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid Authorization header"),
        ));
    }
    let raw_header = raw_header.to_str().map_err(|_| {
        ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid Authorization header"),
        )
    })?;
    let Some((scheme, encoded)) = raw_header.split_once(' ') else {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid Authorization header"),
        ));
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("unsupported client authentication scheme"),
        ));
    }
    let decoded = BASE64_STANDARD.decode(encoded.trim()).map_err(|_| {
        ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid client authentication encoding"),
        )
    })?;
    let decoded = String::from_utf8(decoded).map_err(|_| {
        ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid client authentication encoding"),
        )
    })?;
    let Some((client_id, client_secret)) = decoded.split_once(':') else {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("invalid client authentication payload"),
        ));
    };

    Ok(Some(OAuthClientAuth {
        client_id: Some(form_url_decode_component(client_id)?),
        client_secret: Some(form_url_decode_component(client_secret)?),
    }))
}

fn form_url_decode_component(value: &str) -> Result<String, ApiError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(invalid_client_auth_encoding());
                }
                let high = hex_value(bytes[index + 1]).ok_or_else(invalid_client_auth_encoding)?;
                let low = hex_value(bytes[index + 2]).ok_or_else(invalid_client_auth_encoding)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|_| invalid_client_auth_encoding())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_client_auth_encoding() -> ApiError {
    ApiError::oauth(
        StatusCode::BAD_REQUEST,
        OAuthErrorBody::invalid_request("invalid client authentication encoding"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn basic_client_auth_decodes_form_encoded_credentials() {
        let encoded = BASE64_STANDARD.encode("client%20id:secret+value");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        let auth = oauth_client_auth_from_request(&headers, None, None).unwrap();

        assert_eq!(auth.client_id.as_deref(), Some("client id"));
        assert_eq!(auth.client_secret.as_deref(), Some("secret value"));
    }

    #[test]
    fn basic_client_auth_rejects_mixed_methods() {
        let encoded = BASE64_STANDARD.encode("client:secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        assert!(oauth_client_auth_from_request(&headers, Some("client"), None).is_err());
    }
}
