use super::super::validation::{
    reject_forbidden_scim_connector_smoke_fields, reject_non_empty_array, require_bool,
    require_https_scim_smoke_base_url_at_path, require_non_empty_string_at_path,
    require_non_empty_string_at_path_dynamic, require_rfc3339_timestamp, require_string,
    require_string_at_path, require_uuid_array_exact_len, require_uuid_at_path,
};
use super::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, connector_profile::expected_scim_connector_display_name,
};
use serde_json::Value;
use std::collections::BTreeSet;

const SCIM_CONNECTOR_SMOKE_USER_ID_COUNT: usize = 2;

pub(in crate::operations_evidence) fn validate_scim_connector_smoke(
    value: &Value,
    expected_provider: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_forbidden_scim_connector_smoke_fields(value, "$", failures);
    require_string(value, "status", "ok", failures);
    require_string(value, "source", "external-scim-connector", failures);
    require_string(value, "provider", expected_provider, failures);
    require_string(
        value,
        "display_name",
        expected_scim_connector_display_name(expected_provider),
        failures,
    );
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_https_scim_smoke_base_url_at_path(value, &["scim_base_url"], failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "SCIM connector smoke",
        checks,
        failures,
    );
    require_non_empty_string_at_path(value, &["connector_application_id"], failures);
    require_non_empty_string_at_path(value, &["provisioning_job_id"], failures);
    require_bool(value, &["secondary_token_checked"], true, failures);
    require_bool(value, &["rejected_token_checked"], true, failures);

    let created_user_ids = require_uuid_array_exact_len(
        value,
        &["created_user_ids"],
        SCIM_CONNECTOR_SMOKE_USER_ID_COUNT,
        failures,
    );
    let deactivated_user_id = require_uuid_at_path(value, &["deactivated_user_id"], failures);
    if let (Some(created_user_ids), Some(deactivated_user_id)) =
        (&created_user_ids, deactivated_user_id)
    {
        if created_user_ids.contains(&deactivated_user_id) {
            checks.push("connector smoke deactivated a created user".to_owned());
        } else {
            failures.push(
                "deactivated_user_id must be one of the created_user_ids for cleanup evidence"
                    .to_owned(),
            );
        }
    }
    require_uuid_at_path(value, &["deleted_group_id"], failures);

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
            Some(name) if REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS.contains(&name) => {
                seen.insert(name);
            }
            Some(name) => failures.push(format!(
                "{path}.name must be a required SCIM connector smoke check, got {name}"
            )),
            None => failures.push(format!(
                "{path}.name must be a required connector smoke check name"
            )),
        }
        require_string_at_path(check, &["status"], "passed", failures);
        require_non_empty_string_at_path_dynamic(check, &path, &["detail"], failures);
    }

    for required_check in REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS {
        if !seen.contains(required_check) {
            failures.push(format!("checks must include {required_check}"));
        }
    }

    if failures.is_empty() {
        checks.push(format!(
            "SCIM {expected_provider} connector smoke covered required external provisioning flows"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, validate_scim_connector_smoke};
    use serde_json::json;

    const USER_ONE: &str = "01890d6f-109f-767a-96cb-2927626f45b1";
    const USER_TWO: &str = "01890d6f-109f-767a-96cb-2927626f45b2";
    const USER_OUTSIDE_SMOKE: &str = "01890d6f-109f-767a-96cb-2927626f45ff";
    const GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f45aa";

    #[test]
    fn scim_connector_smoke_rejects_secret_fields_and_foreign_deactivation() {
        let value = json!({
            "status": "ok",
            "source": "external-scim-connector",
            "provider": "okta",
            "display_name": "Okta SCIM 2.0",
            "scim_base_url": "https://id.example.com/scim/v2",
            "completed_at": "2026-06-07T12:00:00Z",
            "connector_application_id": "okta-app",
            "provisioning_job_id": "okta-job",
            "secondary_token_checked": true,
            "rejected_token_checked": true,
            "raw_token": "must-not-archive",
            "created_user_ids": [USER_ONE, USER_TWO],
            "deactivated_user_id": USER_OUTSIDE_SMOKE,
            "deleted_group_id": GROUP_ID,
            "checks": REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS
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

        validate_scim_connector_smoke(&value, "okta", &mut checks, &mut failures);

        assert!(failures.iter().any(|failure| {
            failure == "$.raw_token must not be present in token-free connector smoke evidence"
        }));
        assert!(failures.iter().any(|failure| {
            failure
                == "deactivated_user_id must be one of the created_user_ids for cleanup evidence"
        }));
    }
}
