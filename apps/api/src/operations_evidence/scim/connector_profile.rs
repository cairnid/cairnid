use super::super::validation::{
    reject_non_empty_array, require_https_origin_at_path, require_non_empty_array_at_path,
    require_object_array_contains_strings, require_rfc3339_timestamp, require_scim_mapping,
    require_string, require_string_array_contains_all, require_string_array_contains_substrings,
    require_string_at_path,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_scim_connector_profile(
    value: &Value,
    expected_profile: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "generated_at",
        "SCIM connector profile",
        checks,
        failures,
    );
    require_string(value, "status", "ready", failures);
    require_string(value, "profile", expected_profile, failures);
    require_string(
        value,
        "display_name",
        expected_scim_connector_display_name(expected_profile),
        failures,
    );
    require_https_origin_at_path(value, &["issuer"], failures);

    if let Some(issuer) = value.get("issuer").and_then(Value::as_str) {
        let issuer = issuer.trim_end_matches('/');
        require_string(
            value,
            "scim_base_url",
            &format!("{issuer}/scim/v2"),
            failures,
        );
        require_string(
            value,
            "service_provider_config_url",
            &format!("{issuer}/scim/v2/ServiceProviderConfig"),
            failures,
        );
    }

    require_string_at_path(value, &["authentication", "scheme"], "bearer", failures);
    require_string_at_path(
        value,
        &["authentication", "connector_header"],
        "Authorization: Bearer <raw-token>",
        failures,
    );
    require_string_at_path(
        value,
        &["authentication", "server_env"],
        "CAIRN_SCIM_BEARER_TOKEN_SHA256=<sha256(raw-token)>",
        failures,
    );
    require_string_at_path(
        value,
        &["authentication", "rotation_env"],
        "CAIRN_SCIM_BEARER_TOKEN_SHA256=<old-sha256>,<new-sha256>",
        failures,
    );

    require_object_array_contains_strings(
        value,
        &["connector_settings"],
        "name",
        expected_scim_connector_settings(expected_profile),
        failures,
    );
    require_scim_mapping(value, "User", "userName", failures);
    require_scim_mapping(value, "User", "emails[type eq \"work\"].value", failures);
    require_scim_mapping(value, "User", "externalId", failures);
    require_scim_mapping(value, "User", "active", failures);
    require_scim_mapping(value, "Group", "externalId", failures);
    require_scim_mapping(value, "Group", "members.value", failures);
    require_string_array_contains_substrings(
        value,
        &["supported_operations"],
        &[
            "ServiceProviderConfig",
            "User create",
            "Group create",
            "Bulk mutations",
            "Token rotation",
        ],
        failures,
    );
    require_string_array_contains_substrings(
        value,
        &["validation_checks"],
        &[
            "ServiceProviderConfig",
            "create and update a user",
            "create and update a group",
            "retired bearer tokens",
        ],
        failures,
    );
    require_string_array_contains_all(
        value,
        &["unsupported_v1_features"],
        &[
            "password synchronization",
            "nested group membership",
            "SCIM ETags",
            "SCIM cursor pagination",
            "Shared Signals Framework events",
        ],
        failures,
    );
    require_string_array_contains_substrings(
        value,
        &["smoke_commands"],
        &[
            "CAIRN_SCIM_SMOKE_BASE_URL",
            "CAIRN_SCIM_BEARER_TOKEN",
            "CAIRN_SCIM_SECONDARY_BEARER_TOKEN",
            "CAIRN_SCIM_REJECTED_BEARER_TOKEN",
            "cairn-api scim smoke",
        ],
        failures,
    );
    require_non_empty_array_at_path(value, &["operator_notes"], failures);

    if failures.is_empty() {
        checks.push(format!(
            "SCIM {expected_profile} connector profile covers token-free setup guidance"
        ));
    }
}

pub(in crate::operations_evidence) fn expected_scim_connector_display_name(
    profile: &str,
) -> &'static str {
    match profile {
        "generic" => "Generic SCIM 2.0",
        "okta" => "Okta SCIM 2.0",
        "entra" => "Microsoft Entra SCIM 2.0",
        _ => unreachable!("unsupported SCIM connector profile validator"),
    }
}

fn expected_scim_connector_settings(profile: &str) -> &'static [&'static str] {
    match profile {
        "generic" => &[
            "SCIM base URL",
            "Authentication",
            "Unique user key",
            "Stable user ID",
            "Stable group ID",
        ],
        "okta" => &[
            "Base URL",
            "Unique identifier field for users",
            "Authentication mode",
            "Supported provisioning actions",
        ],
        "entra" => &[
            "Tenant URL",
            "Secret Token",
            "Provisioning mode",
            "Target object actions",
        ],
        _ => unreachable!("unsupported SCIM connector profile validator"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        expected_scim_connector_display_name, expected_scim_connector_settings,
        validate_scim_connector_profile,
    };
    use serde_json::{Value, json};

    #[test]
    fn scim_connector_profile_accepts_generic_profile() {
        let value = scim_connector_profile("generic");
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_scim_connector_profile(&value, "generic", &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(checks.contains(
            &"SCIM generic connector profile covers token-free setup guidance".to_owned()
        ));
    }

    fn scim_connector_profile(profile: &str) -> Value {
        let settings = expected_scim_connector_settings(profile)
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>();
        json!({
            "generated_at": "2026-06-07T12:00:00Z",
            "status": "ready",
            "profile": profile,
            "display_name": expected_scim_connector_display_name(profile),
            "issuer": "https://id.example.com",
            "scim_base_url": "https://id.example.com/scim/v2",
            "service_provider_config_url": "https://id.example.com/scim/v2/ServiceProviderConfig",
            "authentication": {
                "scheme": "bearer",
                "connector_header": "Authorization: Bearer <raw-token>",
                "server_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<sha256(raw-token)>",
                "rotation_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<old-sha256>,<new-sha256>"
            },
            "connector_settings": settings,
            "recommended_mappings": [
                {
                    "resource": "User",
                    "scim_attribute": "userName",
                    "connector_attribute": "userName",
                    "note": "Map the external user identifier to SCIM userName."
                },
                {
                    "resource": "User",
                    "scim_attribute": "emails[type eq \"work\"].value",
                    "connector_attribute": "emails[primary eq true].value",
                    "note": "Use the primary work email as the account email."
                },
                {
                    "resource": "User",
                    "scim_attribute": "externalId",
                    "connector_attribute": "externalId",
                    "note": "Keep the connector object id stable."
                },
                {
                    "resource": "User",
                    "scim_attribute": "active",
                    "connector_attribute": "active",
                    "note": "Treat inactive users as suspended accounts."
                },
                {
                    "resource": "Group",
                    "scim_attribute": "externalId",
                    "connector_attribute": "externalId",
                    "note": "Keep group ids stable across provisioning runs."
                },
                {
                    "resource": "Group",
                    "scim_attribute": "members.value",
                    "connector_attribute": "members.value",
                    "note": "Preserve direct membership values."
                }
            ],
            "supported_operations": [
                "ServiceProviderConfig",
                "User create",
                "Group create",
                "Bulk mutations",
                "Token rotation"
            ],
            "validation_checks": [
                "ServiceProviderConfig",
                "create and update a user",
                "create and update a group",
                "retired bearer tokens"
            ],
            "unsupported_v1_features": [
                "password synchronization",
                "nested group membership",
                "SCIM ETags",
                "SCIM cursor pagination",
                "Shared Signals Framework events"
            ],
            "smoke_commands": [
                "CAIRN_SCIM_SMOKE_BASE_URL=https://id.example.com/scim/v2",
                "CAIRN_SCIM_BEARER_TOKEN=<raw-token>",
                "CAIRN_SCIM_SECONDARY_BEARER_TOKEN=<next-token>",
                "CAIRN_SCIM_REJECTED_BEARER_TOKEN=<retired-token>",
                "cairn-api scim smoke"
            ],
            "operator_notes": ["Use a dedicated app for production smoke checks."]
        })
    }
}
