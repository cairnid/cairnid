use super::ConfigError;
use cairn_domain::Environment;
use url::Url;

pub(super) fn validate_origin_configuration(
    environment: Environment,
    issuer: &str,
    public_web_origin: &str,
) -> Result<(), ConfigError> {
    validate_public_origin(environment, "CAIRN_ISSUER", issuer)?;
    validate_public_origin(environment, "CAIRN_PUBLIC_WEB_ORIGIN", public_web_origin)
}

fn validate_public_origin(
    environment: Environment,
    variable: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let parsed = Url::parse(value)
        .map_err(|_| invalid_origin(variable, value, "must be an absolute URL"))?;
    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(invalid_origin(variable, value, "must include a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_origin(
            variable,
            value,
            "must not include credentials",
        ));
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_origin(
            variable,
            value,
            "must be an origin without path, query, or fragment",
        ));
    }

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if matches!(environment, Environment::Development) && is_loopback_host(&parsed) => {
            Ok(())
        }
        "http" => Err(invalid_origin(
            variable,
            value,
            "http is allowed only for localhost development origins",
        )),
        _ => Err(invalid_origin(variable, value, "must use http or https")),
    }
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    )
}

fn invalid_origin(variable: &'static str, value: &str, reason: &'static str) -> ConfigError {
    ConfigError::InvalidOrigin {
        variable,
        value: value.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_origins_must_use_https() {
        let issuer_error = validate_origin_configuration(
            Environment::Production,
            "http://id.example.com",
            "https://app.example.com",
        )
        .expect_err("production issuer must reject http");
        assert!(matches!(
            issuer_error,
            ConfigError::InvalidOrigin {
                variable: "CAIRN_ISSUER",
                reason: "http is allowed only for localhost development origins",
                ..
            }
        ));

        let web_origin_error = validate_origin_configuration(
            Environment::Production,
            "https://id.example.com",
            "http://localhost:5173",
        )
        .expect_err("production web origin must reject http localhost");
        assert!(matches!(
            web_origin_error,
            ConfigError::InvalidOrigin {
                variable: "CAIRN_PUBLIC_WEB_ORIGIN",
                reason: "http is allowed only for localhost development origins",
                ..
            }
        ));
    }

    #[test]
    fn production_origins_accept_https_origin_values() {
        assert!(
            validate_origin_configuration(
                Environment::Production,
                "https://id.example.com",
                "https://app.example.com"
            )
            .is_ok()
        );
    }

    #[test]
    fn development_origins_allow_localhost_http() {
        assert!(
            validate_origin_configuration(
                Environment::Development,
                "http://localhost:8080",
                "http://127.0.0.1:5173"
            )
            .is_ok()
        );
        assert!(
            validate_origin_configuration(
                Environment::Development,
                "http://[::1]:8080",
                "http://localhost:5173"
            )
            .is_ok()
        );
    }

    #[test]
    fn origins_reject_credentials_paths_queries_and_fragments() {
        for value in [
            "https://user:pass@id.example.com",
            "https://id.example.com/app",
            "https://id.example.com?debug=true",
            "https://id.example.com#fragment",
        ] {
            let error = validate_origin_configuration(
                Environment::Production,
                value,
                "https://app.example.com",
            )
            .expect_err("origin must be normalized");
            assert!(matches!(error, ConfigError::InvalidOrigin { .. }));
        }
    }
}
