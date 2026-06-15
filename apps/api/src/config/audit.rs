use super::{AuditOperationsConfig, ConfigError, optional_i64};

pub(super) fn audit_operations_from_env() -> Result<AuditOperationsConfig, ConfigError> {
    Ok(AuditOperationsConfig {
        retention_days: optional_i64("CAIRN_AUDIT_RETENTION_DAYS", 365)?.clamp(30, 3650),
        purge_batch_size: optional_i64("CAIRN_AUDIT_PURGE_BATCH_SIZE", 1000)?.clamp(1, 50_000),
        export_max_rows: optional_i64("CAIRN_AUDIT_EXPORT_MAX_ROWS", 10_000)?.clamp(1, 50_000),
    })
}
