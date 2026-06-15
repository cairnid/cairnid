use super::super::validation::{
    reject_non_empty_array, require_bool_at_path, require_non_empty_string_at_path,
    require_rfc3339_timestamp, require_rfc3339_timestamp_at_path, require_string,
    require_u64_at_path, require_uuid_at_path, validate_optional_filter_string,
    validate_optional_filter_timestamp, validate_optional_uuid, value_at_path,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_audit_export_archive(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "audit export/archive",
        checks,
        failures,
    );
    require_uuid_at_path(value, &["organization_id"], failures);
    require_non_empty_string_at_path(value, &["output_path"], failures);

    let rows_exported = require_u64_at_path(value, &["rows_exported"], failures);
    let bytes_written = require_u64_at_path(value, &["bytes_written"], failures);
    let limit = require_u64_at_path(value, &["limit"], failures);
    let export_max_rows = require_u64_at_path(value, &["export_max_rows"], failures);

    if let Some(output_path) = value_at_path(value, &["output_path"]).and_then(Value::as_str)
        && output_path == "-"
    {
        failures.push("output_path must be a create-only archive file path".to_owned());
    }
    if let (Some(rows_exported), Some(limit)) = (rows_exported, limit) {
        if rows_exported <= limit {
            checks.push("audit export row count is within the requested limit".to_owned());
        } else {
            failures.push(format!(
                "rows_exported must be less than or equal to limit, got {rows_exported} > {limit}"
            ));
        }
    }
    if let (Some(limit), Some(export_max_rows)) = (limit, export_max_rows) {
        if limit >= 1 && limit <= export_max_rows {
            checks.push("audit export limit is within the configured ceiling".to_owned());
        } else {
            failures.push(format!(
                "limit must be between 1 and export_max_rows, got {limit} with ceiling {export_max_rows}"
            ));
        }
    }
    if let (Some(rows_exported), Some(bytes_written)) = (rows_exported, bytes_written)
        && rows_exported > 0
        && bytes_written == 0
    {
        failures.push("bytes_written must be greater than zero when rows are exported".to_owned());
    }

    let has_more = require_bool_at_path(value, &["has_more"], failures);
    let next_after_created_at = value_at_path(value, &["next_after_created_at"]);
    let next_after_id = value_at_path(value, &["next_after_id"]);
    if has_more == Some(true) {
        require_rfc3339_timestamp_at_path(
            value,
            &["next_after_created_at"],
            "next_after_created_at",
            failures,
        );
        require_uuid_at_path(value, &["next_after_id"], failures);
    } else if next_after_created_at.is_some_and(|value| !value.is_null())
        || next_after_id.is_some_and(|value| !value.is_null())
    {
        failures
            .push("next cursor fields must be null or absent when has_more is false".to_owned());
    }

    let Some(filters) = value_at_path(value, &["filters"]) else {
        failures.push("filters must be present".to_owned());
        return;
    };
    if !filters.is_object() {
        failures.push("filters must be an object".to_owned());
        return;
    }
    validate_optional_filter_string(value, &["filters", "action_prefix"], failures);
    validate_optional_filter_string(value, &["filters", "target_prefix"], failures);
    validate_optional_uuid(value, &["filters", "actor_id"], failures);
    validate_optional_filter_timestamp(value, &["filters", "created_from"], failures);
    validate_optional_filter_timestamp(value, &["filters", "created_to"], failures);
    match value_at_path(value, &["filters", "actor_kind"]) {
        Some(Value::Null) | None => {}
        Some(Value::String(kind)) if matches!(kind.as_str(), "user" | "client" | "system") => {}
        Some(Value::String(kind)) => failures.push(format!(
            "filters.actor_kind must be user, client, or system, got {kind}"
        )),
        Some(_) => failures.push("filters.actor_kind must be a string or null".to_owned()),
    }
}

pub(in crate::operations_evidence) fn validate_audit_retention_purge(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "audit retention purge",
        checks,
        failures,
    );
    require_uuid_at_path(value, &["organization_id"], failures);
    require_rfc3339_timestamp_at_path(value, &["cutoff"], "cutoff", failures);

    let retention_days = require_u64_at_path(value, &["retention_days"], failures);
    let batch_size = require_u64_at_path(value, &["batch_size"], failures);
    let deleted = require_u64_at_path(value, &["deleted"], failures);

    if let Some(retention_days) = retention_days {
        if (30..=3650).contains(&retention_days) {
            checks.push("audit retention window is within configured bounds".to_owned());
        } else {
            failures.push(format!(
                "retention_days must be between 30 and 3650, got {retention_days}"
            ));
        }
    }
    if let Some(batch_size) = batch_size {
        if (1..=50_000).contains(&batch_size) {
            checks.push("audit purge batch size is within configured bounds".to_owned());
        } else {
            failures.push(format!(
                "batch_size must be between 1 and 50000, got {batch_size}"
            ));
        }
    }
    if let (Some(deleted), Some(batch_size)) = (deleted, batch_size) {
        if deleted <= batch_size {
            checks.push("audit purge deleted count is within batch size".to_owned());
        } else {
            failures.push(format!(
                "deleted must be less than or equal to batch_size, got {deleted} > {batch_size}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_audit_export_archive, validate_audit_retention_purge};
    use serde_json::json;

    const ORG_ID: &str = "01890d6f-109f-767a-96cb-2927626f4500";
    const USER_ID: &str = "01890d6f-109f-767a-96cb-2927626f4501";
    const EVENT_ID: &str = "01890d6f-109f-767a-96cb-2927626f4503";

    #[test]
    fn audit_export_archive_accepts_cursor_when_more_rows_exist() {
        let value = json!({
            "status": "ok",
            "organization_id": ORG_ID,
            "completed_at": "2026-06-07T12:00:00Z",
            "output_path": "release-evidence/audit.ndjson",
            "rows_exported": 100,
            "bytes_written": 4096,
            "limit": 100,
            "export_max_rows": 500,
            "has_more": true,
            "next_after_created_at": "2026-06-07T11:00:00Z",
            "next_after_id": EVENT_ID,
            "filters": {
                "action_prefix": "admin.",
                "target_prefix": null,
                "actor_id": USER_ID,
                "actor_kind": "user",
                "created_from": "2026-06-01T00:00:00Z",
                "created_to": null
            }
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_audit_export_archive(&value, &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(
            checks.contains(&"audit export row count is within the requested limit".to_owned())
        );
        assert!(checks.contains(&"audit export limit is within the configured ceiling".to_owned()));
    }

    #[test]
    fn audit_retention_purge_rejects_unsafe_retention_bounds() {
        let value = json!({
            "status": "ok",
            "organization_id": ORG_ID,
            "completed_at": "2026-06-07T12:00:00Z",
            "cutoff": "2026-01-01T00:00:00Z",
            "retention_days": 7,
            "batch_size": 60000,
            "deleted": 70000
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_audit_retention_purge(&value, &mut checks, &mut failures);

        assert!(
            failures
                .iter()
                .any(|failure| failure == "retention_days must be between 30 and 3650, got 7")
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure == "batch_size must be between 1 and 50000, got 60000")
        );
        assert!(failures.iter().any(|failure| {
            failure == "deleted must be less than or equal to batch_size, got 70000 > 60000"
        }));
    }
}
