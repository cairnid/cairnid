use super::super::validation::{
    reject_non_empty_array, require_https_discovery_url_at_path, require_https_origin_at_path,
    require_non_empty_string_at_path, require_non_empty_string_at_path_dynamic,
    require_rfc3339_timestamp, require_string, require_string_array_contains_all,
    require_string_array_contains_all_from_value, require_string_array_contains_substrings,
    require_uri_array_for_suite_alias, value_at_path,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(in crate::operations_evidence) fn validate_openid_static_registration(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ready", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "generated_at",
        "OpenID static registration",
        checks,
        failures,
    );
    require_https_origin_at_path(value, &["issuer"], failures);
    require_non_empty_string_at_path(value, &["suite_alias"], failures);
    require_string_array_contains_all(
        value,
        &["certification_profiles"],
        &["Config OP", "Basic OP"],
        failures,
    );
    require_string_array_contains_substrings(
        value,
        &["run_plan_commands"],
        &[
            "oidcc-config-certification-test-plan",
            "oidcc-basic-certification-test-plan",
        ],
        failures,
    );
    require_string_array_contains_all(
        value,
        &["unsupported_v1_profiles"],
        &["Implicit OP", "Hybrid OP", "Dynamic OP", "Form Post OP"],
        failures,
    );

    let Some(clients) = value.get("static_clients").and_then(Value::as_array) else {
        failures.push("static_clients must contain primary and secondary clients".to_owned());
        return;
    };
    if clients.len() != 2 {
        failures.push(format!(
            "static_clients must contain exactly 2 clients, got {}",
            clients.len()
        ));
    }

    let suite_alias = value
        .get("suite_alias")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut roles = BTreeSet::new();
    for (index, client) in clients.iter().enumerate() {
        let path = format!("static_clients[{index}]");
        match client.get("role").and_then(Value::as_str) {
            Some("primary" | "secondary") => {
                roles.insert(
                    client
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
            }
            Some(role) => failures.push(format!(
                "{path}.role must be primary or secondary, got {role}"
            )),
            None => failures.push(format!("{path}.role must be primary or secondary")),
        }
        require_non_empty_string_at_path_dynamic(client, &path, &["client_id"], failures);
        require_uri_array_for_suite_alias(
            client,
            &path,
            "redirect_uris",
            suite_alias,
            "/callback",
            failures,
        );
        require_uri_array_for_suite_alias(
            client,
            &path,
            "post_logout_redirect_uris",
            suite_alias,
            "/post_logout_redirect",
            failures,
        );
        require_string_array_contains_all_from_value(
            client,
            &path,
            "response_types",
            &["code"],
            failures,
        );
        require_string_array_contains_all_from_value(
            client,
            &path,
            "grant_types",
            &["authorization_code", "refresh_token"],
            failures,
        );
        require_string_array_contains_all_from_value(
            client,
            &path,
            "token_endpoint_auth_methods",
            &["client_secret_basic", "client_secret_post"],
            failures,
        );
        require_string_array_contains_all_from_value(
            client,
            &path,
            "allowed_scopes",
            &["openid", "profile", "email", "groups", "offline_access"],
            failures,
        );
        require_string_array_contains_all_from_value(
            client,
            &path,
            "pkce_methods",
            &["S256"],
            failures,
        );
    }
    for role in ["primary", "secondary"] {
        if !roles.contains(role) {
            failures.push(format!("static_clients must include {role} client"));
        }
    }
    if failures.is_empty() {
        checks.push("OpenID static registration covers Config OP and Basic OP clients".to_owned());
    }
}

pub(in crate::operations_evidence) fn validate_openid_static_config(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "generated_at",
        "OpenID static config",
        checks,
        failures,
    );
    require_non_empty_string_at_path(value, &["alias"], failures);
    require_non_empty_string_at_path(value, &["description"], failures);
    require_https_discovery_url_at_path(value, &["server", "discoveryUrl"], failures);
    require_non_empty_string_at_path(value, &["client", "client_id"], failures);
    require_non_empty_string_at_path(value, &["client", "client_secret"], failures);
    require_non_empty_string_at_path(value, &["client2", "client_id"], failures);
    require_non_empty_string_at_path(value, &["client2", "client_secret"], failures);

    let client_id = value_at_path(value, &["client", "client_id"]).and_then(Value::as_str);
    let client2_id = value_at_path(value, &["client2", "client_id"]).and_then(Value::as_str);
    if let (Some(client_id), Some(client2_id)) = (client_id, client2_id) {
        if client_id == client2_id {
            failures.push("client.client_id and client2.client_id must be distinct".to_owned());
        } else {
            checks.push(
                "OpenID static config includes distinct primary and secondary clients".to_owned(),
            );
        }
    }
    if failures.is_empty() {
        checks.push("OpenID static config points at HTTPS discovery metadata".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::validate_openid_static_config;
    use serde_json::json;

    #[test]
    fn openid_static_config_rejects_duplicate_clients_and_http_discovery() {
        let value = json!({
            "generated_at": "2026-06-07T12:00:00Z",
            "alias": "cairn-basic-op",
            "description": "Cairn Identity Basic OP static client config",
            "server": {
                "discoveryUrl": "http://id.example.com/.well-known/openid-configuration"
            },
            "client": {
                "client_id": "oidf-client",
                "client_secret": "secret-one"
            },
            "client2": {
                "client_id": "oidf-client",
                "client_secret": "secret-two"
            }
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_openid_static_config(&value, &mut checks, &mut failures);

        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("server.discoveryUrl"))
        );
        assert!(failures.iter().any(|failure| {
            failure == "client.client_id and client2.client_id must be distinct"
        }));
    }
}
