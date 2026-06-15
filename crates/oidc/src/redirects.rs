use crate::oauth_types::oauth_error_description;

pub fn append_authorization_response_params(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut target = format!(
        "{redirect_uri}{separator}code={code}&iss={}",
        percent_encode_minimal(issuer)
    );
    if let Some(state) = state {
        target.push_str("&state=");
        target.push_str(&percent_encode_minimal(state));
    }
    target
}

pub fn append_authorization_error_response_params(
    redirect_uri: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut target = format!(
        "{redirect_uri}{separator}error={}&iss={}",
        percent_encode_minimal(error),
        percent_encode_minimal(issuer)
    );
    if let Some(error_description) = error_description {
        target.push_str("&error_description=");
        target.push_str(&percent_encode_minimal(&oauth_error_description(
            error_description,
        )));
    }
    if let Some(state) = state {
        target.push_str("&state=");
        target.push_str(&percent_encode_minimal(state));
    }
    target
}

pub fn append_post_logout_redirect_params(
    post_logout_redirect_uri: &str,
    state: Option<&str>,
) -> String {
    let Some(state) = state else {
        return post_logout_redirect_uri.to_owned();
    };
    let separator = if post_logout_redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{post_logout_redirect_uri}{separator}state={}",
        percent_encode_minimal(state)
    )
}

fn percent_encode_minimal(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}
