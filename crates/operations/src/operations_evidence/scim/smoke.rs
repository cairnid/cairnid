use super::super::validation::{
    reject_non_empty_array, require_bool, require_https_scim_smoke_base_url_at_path,
    require_non_empty_string_at_path_dynamic, require_rfc3339_timestamp, require_string,
    require_string_at_path, require_uuid_array_exact_len, require_uuid_at_path,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(in crate::operations_evidence) const REQUIRED_SCIM_SMOKE_CHECKS: &[&str] = &[
    "secondary_token",
    "rejected_token",
    "service_provider_config",
    "schemas",
    "resource_types",
    "user_create",
    "user_filter",
    "user_search_request",
    "user_projection",
    "user_patch",
    "user_replace",
    "group_create",
    "group_filter",
    "group_search_request",
    "group_projection",
    "group_patch",
    "group_replace",
    "group_delete",
    "bulk_mutations",
    "user_delete",
    "user_soft_delete",
];

const SCIM_SMOKE_USER_ID_COUNT: usize = 3;

pub(in crate::operations_evidence) fn validate_scim_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_https_scim_smoke_base_url_at_path(value, &["base_url"], failures);
    require_rfc3339_timestamp(value, "completed_at", "SCIM smoke", checks, failures);
    require_bool(value, &["secondary_token_checked"], true, failures);
    require_bool(value, &["rejected_token_checked"], true, failures);
    let created_user_ids = require_uuid_array_exact_len(
        value,
        &["created_user_ids"],
        SCIM_SMOKE_USER_ID_COUNT,
        failures,
    );
    let soft_deleted_user_ids = require_uuid_array_exact_len(
        value,
        &["soft_deleted_user_ids"],
        SCIM_SMOKE_USER_ID_COUNT,
        failures,
    );
    if let (Some(created_user_ids), Some(soft_deleted_user_ids)) =
        (&created_user_ids, &soft_deleted_user_ids)
    {
        if created_user_ids != soft_deleted_user_ids {
            failures.push(
                "soft_deleted_user_ids must match created_user_ids for cleanup evidence".to_owned(),
            );
        } else {
            checks.push("SCIM smoke soft-deleted every created user".to_owned());
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
            Some(name) if REQUIRED_SCIM_SMOKE_CHECKS.contains(&name) => {
                seen.insert(name);
            }
            Some(name) => failures.push(format!(
                "{path}.name must be a required SCIM smoke check, got {name}"
            )),
            None => failures.push(format!("{path}.name must be a required smoke check name")),
        }
        require_string_at_path(check, &["status"], "passed", failures);
        require_non_empty_string_at_path_dynamic(check, &path, &["detail"], failures);
    }

    for required_check in REQUIRED_SCIM_SMOKE_CHECKS {
        if !seen.contains(required_check) {
            failures.push(format!("checks must include {required_check}"));
        }
    }

    if failures.is_empty() {
        checks.push("SCIM smoke covered required provisioning and token-rotation flows".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::validate_scim_smoke;
    use serde_json::json;

    const USER_ONE: &str = "01890d6f-109f-767a-96cb-2927626f45b1";
    const USER_TWO: &str = "01890d6f-109f-767a-96cb-2927626f45b2";
    const USER_THREE: &str = "01890d6f-109f-767a-96cb-2927626f45b3";
    const USER_OUTSIDE_SMOKE: &str = "01890d6f-109f-767a-96cb-2927626f45ff";
    const GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f45aa";

    #[test]
    fn scim_smoke_rejects_cleanup_mismatch_and_missing_required_checks() {
        let value = json!({
            "status": "ok",
            "base_url": "https://id.example.com/scim/v2",
            "completed_at": "2026-06-07T12:00:00Z",
            "secondary_token_checked": true,
            "rejected_token_checked": true,
            "created_user_ids": [USER_ONE, USER_TWO, USER_THREE],
            "soft_deleted_user_ids": [USER_ONE, USER_TWO, USER_OUTSIDE_SMOKE],
            "deleted_group_id": GROUP_ID,
            "checks": [
                {
                    "name": "service_provider_config",
                    "status": "passed",
                    "detail": "service provider config passed"
                }
            ]
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_scim_smoke(&value, &mut checks, &mut failures);

        assert!(failures.iter().any(|failure| {
            failure == "soft_deleted_user_ids must match created_user_ids for cleanup evidence"
        }));
        assert!(
            failures
                .iter()
                .any(|failure| failure == "checks must include user_create")
        );
    }
}
