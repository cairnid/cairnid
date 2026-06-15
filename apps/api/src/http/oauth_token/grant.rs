use url::Url;

pub(in crate::http) fn grant_type_is_valid(grant_type: &str) -> bool {
    is_oauth_grant_name(grant_type) || is_absolute_uri_reference(grant_type)
}

fn is_oauth_grant_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_'
            )
        })
}

fn is_absolute_uri_reference(value: &str) -> bool {
    value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        && Url::parse(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::grant_type_is_valid;

    #[test]
    fn grant_type_syntax_accepts_registered_names_and_extension_uris() {
        for valid in [
            "authorization_code",
            "client.credentials-1",
            "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "https://example.com/grants/custom",
        ] {
            assert!(grant_type_is_valid(valid), "{valid} should be valid");
        }

        for invalid in [
            "",
            " authorization_code",
            "authorization_code ",
            "authorization code",
            "grant\n",
            "cafe\u{301}",
        ] {
            assert!(!grant_type_is_valid(invalid), "{invalid:?} should fail");
        }
    }
}
