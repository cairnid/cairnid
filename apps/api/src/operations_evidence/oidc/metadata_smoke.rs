use super::super::validation::{
    reject_non_empty_array, require_https_origin_at_path, require_non_empty_string_at_path_dynamic,
    require_rfc3339_timestamp, require_string, require_string_at_path,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(in crate::operations_evidence) const REQUIRED_OIDC_METADATA_SMOKE_CHECKS: &[&str] = &[
    "issuer_https_origin",
    "discovery_http_status",
    "discovery_issuer_matches",
    "discovery_endpoint_urls_match_issuer",
    "discovery_strict_code_flow",
    "discovery_refresh_and_client_credentials",
    "discovery_pkce_s256",
    "discovery_rs256",
    "discovery_request_objects_disabled",
    "discovery_rfc9207_iss_supported",
    "jwks_http_status",
    "jwks_rs256_public_key_material",
    "jwks_no_private_key_material",
];

pub(in crate::operations_evidence) fn validate_oidc_metadata_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_https_origin_at_path(value, &["issuer"], failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "OIDC metadata smoke",
        checks,
        failures,
    );

    let Some(checks_value) = value.get("checks").and_then(Value::as_array) else {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    };
    if checks_value.is_empty() {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    }

    let mut seen = BTreeSet::new();
    for (index, check) in checks_value.iter().enumerate() {
        let path = format!("checks[{index}]");
        match check.get("name").and_then(Value::as_str) {
            Some(name) if REQUIRED_OIDC_METADATA_SMOKE_CHECKS.contains(&name) => {
                seen.insert(name);
            }
            Some(name) => failures.push(format!(
                "{path}.name must be a required OIDC metadata smoke check, got {name}"
            )),
            None => failures.push(format!("{path}.name must be a required smoke check name")),
        }
        require_string_at_path(check, &["status"], "passed", failures);
        require_non_empty_string_at_path_dynamic(check, &path, &["detail"], failures);
    }

    for required_check in REQUIRED_OIDC_METADATA_SMOKE_CHECKS {
        if !seen.contains(required_check) {
            failures.push(format!("checks must include {required_check}"));
        }
    }

    if failures.is_empty() {
        checks.push("OIDC discovery and JWKS metadata passed deployed smoke".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_OIDC_METADATA_SMOKE_CHECKS, validate_oidc_metadata_smoke};
    use serde_json::json;

    #[test]
    fn oidc_metadata_smoke_accepts_required_checks() {
        let value = json!({
            "status": "ok",
            "issuer": "https://id.example.com",
            "completed_at": "2026-06-07T12:00:00Z",
            "failures": [],
            "errors": [],
            "checks": REQUIRED_OIDC_METADATA_SMOKE_CHECKS
                .iter()
                .map(|name| json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{name} passed")
                }))
                .collect::<Vec<_>>()
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_oidc_metadata_smoke(&value, &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(
            checks.contains(&"OIDC discovery and JWKS metadata passed deployed smoke".to_owned())
        );
    }
}
