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
const FORBIDDEN_SCIM_SMOKE_FIELDS: &[&str] = &[
    "authorization",
    "authorizationheader",
    "bearertoken",
    "cookie",
    "password",
    "rawbearertoken",
    "rawtoken",
    "secret",
    "secrettoken",
];

pub(in crate::operations_evidence) fn validate_scim_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_forbidden_scim_smoke_fields(value, "$", failures);
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

fn reject_forbidden_scim_smoke_fields(value: &Value, path: &str, failures: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized_key = normalized_json_field_name(key);
                let child_path = child_json_path(path, key);
                if FORBIDDEN_SCIM_SMOKE_FIELDS.contains(&normalized_key.as_str()) {
                    failures.push(format!(
                        "{child_path} must not be present in token-free SCIM smoke evidence"
                    ));
                }
                reject_forbidden_scim_smoke_fields(child, &child_path, failures);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_scim_smoke_fields(child, &format!("{path}[{index}]"), failures);
            }
        }
        _ => {}
    }
}

fn normalized_json_field_name(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn child_json_path(parent: &str, key: &str) -> String {
    if parent == "$" {
        format!("$.{key}")
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_SCIM_SMOKE_CHECKS, validate_scim_smoke};
    use serde_json::{Value, json};

    const GENERATOR_SCIM_SMOKE_CHECKS_SOURCE: &str =
        include_str!("../../../../../apps/api/src/scim_smoke/checks.rs");

    const USER_ONE: &str = "01890d6f-109f-767a-96cb-2927626f45b1";
    const USER_TWO: &str = "01890d6f-109f-767a-96cb-2927626f45b2";
    const USER_THREE: &str = "01890d6f-109f-767a-96cb-2927626f45b3";
    const USER_OUTSIDE_SMOKE: &str = "01890d6f-109f-767a-96cb-2927626f45ff";
    const GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f45aa";

    #[test]
    fn scim_smoke_required_checks_match_generator_names() {
        let generator_required_checks = generator_required_checks();

        assert_eq!(
            generator_required_checks.as_slice(),
            REQUIRED_SCIM_SMOKE_CHECKS
        );
    }

    #[test]
    fn scim_smoke_accepts_generator_shaped_report_without_secret_fields() {
        let generator_required_checks = generator_required_checks();
        let value = valid_scim_smoke(&generator_required_checks);
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_scim_smoke(&value, &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(
            checks
                .iter()
                .any(|check| check == "SCIM smoke soft-deleted every created user")
        );
        assert!(checks.iter().any(|check| {
            check == "SCIM smoke covered required provisioning and token-rotation flows"
        }));
    }

    #[test]
    fn scim_smoke_rejects_report_missing_generator_required_check() {
        let generator_required_checks = generator_required_checks();
        let missing_check = generator_required_checks[0];
        let remaining_checks = generator_required_checks
            .iter()
            .copied()
            .filter(|name| *name != missing_check)
            .collect::<Vec<_>>();
        let value = valid_scim_smoke(&remaining_checks);
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_scim_smoke(&value, &mut checks, &mut failures);

        assert!(
            failures
                .iter()
                .any(|failure| failure == &format!("checks must include {missing_check}")),
            "{failures:?}"
        );
    }

    #[test]
    fn scim_smoke_rejects_secret_shaped_fields() {
        let generator_required_checks = generator_required_checks();
        let mut value = valid_scim_smoke(&generator_required_checks);
        value["Authorization"] = json!("Bearer raw-token");
        value["checks"][0]["raw_bearer_token"] = json!("raw-token");
        value["nested"] = json!({
            "cookie": "session=value",
            "password": "raw-password",
            "secret": "raw-secret"
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_scim_smoke(&value, &mut checks, &mut failures);

        for expected in [
            "$.Authorization must not be present in token-free SCIM smoke evidence",
            "$.checks[0].raw_bearer_token must not be present in token-free SCIM smoke evidence",
            "$.nested.cookie must not be present in token-free SCIM smoke evidence",
            "$.nested.password must not be present in token-free SCIM smoke evidence",
            "$.nested.secret must not be present in token-free SCIM smoke evidence",
        ] {
            assert!(
                failures.iter().any(|failure| failure == expected),
                "{failures:?}"
            );
        }
    }

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

    fn generator_required_checks() -> Vec<&'static str> {
        GENERATOR_SCIM_SMOKE_CHECKS_SOURCE
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !line.starts_with("pub(in crate::scim_smoke) const CHECK_") {
                    return None;
                }
                let (_, value) = line.split_once("= \"")?;
                let (name, _) = value.split_once('"')?;
                Some(name)
            })
            .collect()
    }

    fn valid_scim_smoke(check_names: &[&str]) -> Value {
        json!({
            "status": "ok",
            "base_url": "https://id.example.com/scim/v2",
            "completed_at": "2026-06-07T12:00:00Z",
            "secondary_token_checked": true,
            "rejected_token_checked": true,
            "created_user_ids": [USER_ONE, USER_TWO, USER_THREE],
            "soft_deleted_user_ids": [USER_ONE, USER_TWO, USER_THREE],
            "deleted_group_id": GROUP_ID,
            "checks": check_names
                .iter()
                .map(|name| {
                    json!({
                        "name": name,
                        "status": "passed",
                        "detail": format!("{name} passed during built-in SCIM smoke")
                    })
                })
                .collect::<Vec<_>>()
        })
    }
}
