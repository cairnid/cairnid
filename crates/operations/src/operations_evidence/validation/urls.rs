use super::path::value_at_path;
use serde_json::Value;

pub(in crate::operations_evidence) fn require_https_origin_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) => match url::Url::parse(actual) {
            Ok(url)
                if url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && matches!(url.path(), "" | "/")
                    && url.query().is_none()
                    && url.fragment().is_none() => {}
            Ok(_) => failures.push(format!("{field} must be an HTTPS origin")),
            Err(_) => failures.push(format!("{field} must be a valid HTTPS origin")),
        },
        None => failures.push(format!("{field} must be an HTTPS origin")),
    }
}

pub(in crate::operations_evidence) fn require_https_scim_smoke_base_url_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) => match url::Url::parse(actual) {
            Ok(url)
                if url.scheme() == "https"
                    && url.has_host()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none() => {}
            Ok(_) => failures.push(format!(
                "{field} must be an HTTPS SCIM smoke base URL without credentials, query, or fragment"
            )),
            Err(_) => failures.push(format!("{field} must be a valid HTTPS SCIM smoke base URL")),
        },
        None => failures.push(format!("{field} must be an HTTPS SCIM smoke base URL")),
    }
}

pub(in crate::operations_evidence) fn require_https_discovery_url_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    let field = path.join(".");
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) => match url::Url::parse(actual) {
            Ok(url)
                if url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/.well-known/openid-configuration"
                    && url.query().is_none()
                    && url.fragment().is_none() => {}
            Ok(_) => failures.push(format!(
                "{field} must be an HTTPS OpenID discovery URL without credentials, query, or fragment"
            )),
            Err(_) => failures.push(format!("{field} must be a valid HTTPS OpenID discovery URL")),
        },
        None => failures.push(format!("{field} must be an HTTPS OpenID discovery URL")),
    }
}

pub(in crate::operations_evidence) fn require_uri_array_for_suite_alias(
    value: &Value,
    prefix: &str,
    field: &'static str,
    suite_alias: &str,
    expected_suffix: &str,
    failures: &mut Vec<String>,
) {
    let Some(values) = value.get(field).and_then(Value::as_array) else {
        failures.push(format!("{prefix}.{field} must be an array"));
        return;
    };
    if values.is_empty() {
        failures.push(format!("{prefix}.{field} must not be empty"));
        return;
    }
    let expected_path_suffix = format!("/test/a/{suite_alias}{expected_suffix}");
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{prefix}.{field}[{index}]");
        match value.as_str() {
            Some(uri) => match url::Url::parse(uri) {
                Ok(url)
                    if url.scheme() == "https"
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.path().ends_with(&expected_path_suffix)
                        && url.query().is_none()
                        && url.fragment().is_none() => {}
                Ok(_) => failures.push(format!(
                    "{item_path} must be an HTTPS suite URL ending with {expected_path_suffix}"
                )),
                Err(_) => failures.push(format!("{item_path} must be a valid HTTPS URL")),
            },
            None => failures.push(format!("{item_path} must be a string")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::require_https_origin_at_path;
    use serde_json::json;

    #[test]
    fn https_origin_validation_rejects_paths_credentials_queries_and_fragments() {
        for origin in [
            "https://id.example.com/path",
            "https://user@id.example.com",
            "https://id.example.com?debug=true",
            "https://id.example.com#fragment",
            "http://id.example.com",
        ] {
            let value = json!({ "issuer": origin });
            let mut failures = Vec::new();

            require_https_origin_at_path(&value, &["issuer"], &mut failures);

            assert_eq!(failures, vec!["issuer must be an HTTPS origin"]);
        }
    }
}
