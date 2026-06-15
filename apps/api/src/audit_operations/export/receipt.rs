use cairn_domain::OrganizationId;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub(in crate::audit_operations) struct AuditExportReceipt {
    pub(super) status: &'static str,
    pub(super) organization_id: OrganizationId,
    pub(super) output_path: String,
    pub(super) rows_exported: usize,
    pub(super) bytes_written: u64,
    pub(super) limit: i64,
    pub(super) export_max_rows: i64,
    pub(super) has_more: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) next_after_created_at: Option<OffsetDateTime>,
    pub(super) next_after_id: Option<Uuid>,
    pub(super) filters: AuditExportReceiptFilter,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) completed_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct AuditExportReceiptFilter {
    pub(super) action_prefix: Option<String>,
    pub(super) target_prefix: Option<String>,
    pub(super) actor_kind: Option<&'static str>,
    pub(super) actor_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) created_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) created_to: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::{AuditExportReceipt, AuditExportReceiptFilter};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    #[test]
    fn audit_export_receipt_serializes_evidence_timestamps_as_rfc3339() {
        let timestamp = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let receipt = AuditExportReceipt {
            status: "ok",
            organization_id: Uuid::new_v4(),
            output_path: "audit.ndjson".to_owned(),
            rows_exported: 0,
            bytes_written: 0,
            limit: 100,
            export_max_rows: 1000,
            has_more: true,
            next_after_created_at: Some(timestamp),
            next_after_id: Some(Uuid::new_v4()),
            filters: AuditExportReceiptFilter {
                action_prefix: Some("admin.".to_owned()),
                target_prefix: None,
                actor_kind: Some("system"),
                actor_id: None,
                created_from: Some(timestamp),
                created_to: None,
            },
            completed_at: timestamp,
        };

        let value = serde_json::to_value(receipt).expect("receipt json");

        assert_eq!(value["status"], "ok");
        assert_eq!(value["completed_at"], "1970-01-02T00:00:00Z");
        assert_eq!(value["next_after_created_at"], "1970-01-02T00:00:00Z");
        assert_eq!(value["filters"]["created_from"], "1970-01-02T00:00:00Z");
    }
}
