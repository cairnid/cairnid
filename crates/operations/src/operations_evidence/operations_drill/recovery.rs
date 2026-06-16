use super::super::validation::{
    reject_non_empty_array, require_bool_at_path, require_non_empty_string_at_path,
    require_rfc3339_timestamp, require_string, require_string_at_path, require_uuid_at_path,
    validate_optional_membership_role, validate_user_status_field,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_break_glass_admin_recovery(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "granted", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "break-glass recovery",
        checks,
        failures,
    );
    require_uuid_at_path(value, &["organization_id"], failures);
    require_uuid_at_path(value, &["user_id"], failures);
    require_non_empty_string_at_path(value, &["user_email"], failures);
    require_uuid_at_path(value, &["admin_group_id"], failures);
    require_bool_at_path(value, &["admin_group_created"], failures);
    validate_user_status_field(value, &["user_status_before"], failures);
    require_string_at_path(value, &["user_status_after"], "active", failures);
    validate_optional_membership_role(value, &["membership_role_before"], failures);
    require_string_at_path(value, &["membership_role_after"], "owner", failures);
    require_uuid_at_path(value, &["audit_event_id"], failures);

    checks.push("break-glass recovery grants active owner access".to_owned());
    checks.push("break-glass recovery includes audit event evidence".to_owned());
}

#[cfg(test)]
mod tests {
    use super::validate_break_glass_admin_recovery;
    use serde_json::json;

    const USER_ID: &str = "01890d6f-109f-767a-96cb-2927626f4501";
    const GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f4502";
    const EVENT_ID: &str = "01890d6f-109f-767a-96cb-2927626f4503";

    #[test]
    fn break_glass_recovery_rejects_invalid_access_receipt() {
        let value = json!({
            "status": "ok",
            "organization_id": "not-a-uuid",
            "user_id": USER_ID,
            "user_email": "",
            "user_status_before": "deleted",
            "user_status_after": "suspended",
            "admin_group_id": GROUP_ID,
            "admin_group_created": true,
            "membership_role_before": "viewer",
            "membership_role_after": "member",
            "audit_event_id": EVENT_ID,
            "completed_at": "not-a-timestamp"
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_break_glass_admin_recovery(&value, &mut checks, &mut failures);

        assert!(
            failures
                .iter()
                .any(|failure| failure == "status must be granted, got ok")
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure == "organization_id must be a UUID")
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("membership_role_after"))
        );
    }
}
