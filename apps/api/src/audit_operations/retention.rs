use crate::config::ApiConfig;
use cairn_database::Database;
use cairn_domain::OrganizationId;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

pub(super) async fn purge_expired_audit_events(
    database: &Database,
    config: &ApiConfig,
    organization_id: OrganizationId,
    now: OffsetDateTime,
) -> Result<AuditRetentionPurgeReport, Box<dyn std::error::Error>> {
    let cutoff = audit_retention_cutoff(now, config.audit.retention_days);
    let deleted = database
        .delete_audit_events_before(organization_id, cutoff, config.audit.purge_batch_size)
        .await?;
    Ok(AuditRetentionPurgeReport {
        status: "ok",
        organization_id,
        retention_days: config.audit.retention_days,
        cutoff,
        batch_size: config.audit.purge_batch_size,
        deleted,
        completed_at: now,
    })
}

fn audit_retention_cutoff(now: OffsetDateTime, retention_days: i64) -> OffsetDateTime {
    now - Duration::days(retention_days)
}

#[derive(Debug, Serialize)]
pub(super) struct AuditRetentionPurgeReport {
    status: &'static str,
    organization_id: OrganizationId,
    retention_days: i64,
    #[serde(with = "time::serde::rfc3339")]
    cutoff: OffsetDateTime,
    batch_size: i64,
    deleted: i64,
    #[serde(with = "time::serde::rfc3339")]
    completed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::{AuditRetentionPurgeReport, audit_retention_cutoff};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    #[test]
    fn audit_retention_cutoff_uses_configured_day_window() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp");

        assert_eq!(audit_retention_cutoff(now, 365), now - Duration::days(365));
    }

    #[test]
    fn audit_retention_purge_report_serializes_evidence_timestamps_as_rfc3339() {
        let cutoff = OffsetDateTime::UNIX_EPOCH + Duration::days(5);
        let completed_at = OffsetDateTime::UNIX_EPOCH + Duration::days(6);
        let report = AuditRetentionPurgeReport {
            status: "ok",
            organization_id: Uuid::new_v4(),
            retention_days: 365,
            cutoff,
            batch_size: 1000,
            deleted: 12,
            completed_at,
        };

        let value = serde_json::to_value(report).expect("audit retention purge report json");

        assert_eq!(value["status"], "ok");
        assert_eq!(value["cutoff"], "1970-01-06T00:00:00Z");
        assert_eq!(value["completed_at"], "1970-01-07T00:00:00Z");
    }
}
