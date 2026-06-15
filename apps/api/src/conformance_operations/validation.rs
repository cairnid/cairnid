use std::{env, io};

pub(super) fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .map_err(|_| config_error_owned(format!("missing required environment variable {name}")))
}

pub(super) fn validate_conformance_issuer(issuer: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(issuer)
        .map_err(|error| config_error_owned(format!("invalid CAIRN_ISSUER: {error}")))?;
    if url.scheme() != "https" {
        return Err(config_error(
            "OpenID conformance requires CAIRN_ISSUER to be an externally reachable HTTPS origin",
        ));
    }
    let origin_only = url.username().is_empty()
        && url.password().is_none()
        && matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none();
    if !origin_only {
        return Err(config_error(
            "OpenID conformance requires CAIRN_ISSUER to be an HTTPS origin without credentials, path, query, or fragment",
        ));
    }
    Ok(())
}

pub(super) fn validate_conformance_alias(alias: &str) -> Result<(), Box<dyn std::error::Error>> {
    let valid = !alias.is_empty()
        && alias.len() <= 64
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(config_error(
            "CAIRN_CONFORMANCE_ALIAS must be 1..64 ASCII letters, numbers, '.', '-', or '_'",
        ))
    }
}

pub(super) fn validate_conformance_value(
    name: &'static str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !value.is_empty() && value.len() <= 512 {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "{name} must be non-empty and at most 512 bytes"
        )))
    }
}

pub(super) fn bounded_conformance_description(value: &str) -> String {
    let trimmed = value.trim();
    let description = if trimmed.is_empty() {
        "Cairn Identity OIDC static client certification"
    } else {
        trimmed
    };
    description.chars().take(160).collect()
}

pub(super) fn conformance_suite_base_url(
    value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = url::Url::parse(value).map_err(|error| {
        config_error_owned(format!("invalid CAIRN_CONFORMANCE_SUITE_BASE_URL: {error}"))
    })?;
    if url.scheme() != "https" {
        return Err(config_error(
            "CAIRN_CONFORMANCE_SUITE_BASE_URL must be an HTTPS base URL",
        ));
    }
    let valid_base = url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if !valid_base {
        return Err(config_error(
            "CAIRN_CONFORMANCE_SUITE_BASE_URL must not include credentials, query, or fragment",
        ));
    }
    let mut base = value.trim_end_matches('/').to_owned();
    base.push('/');
    Ok(base)
}

pub(super) fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

pub(super) fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}
