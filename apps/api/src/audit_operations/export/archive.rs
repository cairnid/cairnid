use super::{
    options::AuditExportOptions,
    receipt::{AuditExportReceipt, AuditExportReceiptFilter},
};
use cairn_database::{Database, ListCursor};
use cairn_domain::{AuditActorKind, AuditEvent, OrganizationId};
use std::{fs::OpenOptions, io::Write, path::Path};
use time::OffsetDateTime;

pub(in crate::audit_operations) async fn export_audit_events_ndjson(
    database: &Database,
    organization_id: OrganizationId,
    export_max_rows: i64,
    options: AuditExportOptions,
    completed_at: OffsetDateTime,
) -> Result<AuditExportReceipt, Box<dyn std::error::Error>> {
    let export_max_rows = export_max_rows.clamp(1, 50_000);
    let fetch_limit = options.limit.saturating_add(1).min(export_max_rows + 1);
    let mut events = database
        .list_audit_events_page_filtered(
            organization_id,
            &options.filter,
            options.after,
            fetch_limit,
        )
        .await?;
    let limit = usize::try_from(options.limit).unwrap_or(usize::MAX);
    let has_more = events.len() > limit;
    if has_more {
        events.truncate(limit);
    }
    let next_after = has_more
        .then(|| {
            events
                .last()
                .map(|event| ListCursor::new(event.created_at, event.id))
        })
        .flatten();
    let bytes_written = write_audit_export_ndjson_file(&options.output_path, &events)?;

    Ok(AuditExportReceipt {
        status: "ok",
        organization_id,
        output_path: options.output_path.to_string_lossy().into_owned(),
        rows_exported: events.len(),
        bytes_written,
        limit: options.limit,
        export_max_rows,
        has_more,
        next_after_created_at: next_after.map(|cursor| cursor.created_at),
        next_after_id: next_after.map(|cursor| cursor.tie_breaker_id),
        filters: AuditExportReceiptFilter {
            action_prefix: options.filter.action_prefix,
            target_prefix: options.filter.target_prefix,
            actor_kind: options.filter.actor_kind.map(audit_export_actor_kind_name),
            actor_id: options.filter.actor_id,
            created_from: options.filter.created_from,
            created_to: options.filter.created_to,
        },
        completed_at,
    })
}

fn audit_export_actor_kind_name(kind: AuditActorKind) -> &'static str {
    match kind {
        AuditActorKind::User => "user",
        AuditActorKind::Client => "client",
        AuditActorKind::System => "system",
    }
}

fn write_audit_export_ndjson_file(
    path: &Path,
    events: &[AuditEvent],
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    for event in events {
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    file.sync_all()?;
    Ok(file.metadata()?.len())
}

#[cfg(test)]
mod tests {
    use super::write_audit_export_ndjson_file;
    use cairn_domain::{AuditActorKind, AuditEvent};
    use serde_json::Value;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn audit_export_ndjson_writer_is_create_only_and_line_delimited() {
        let path =
            std::env::temp_dir().join(format!("cairn-audit-export-{}.ndjson", Uuid::new_v4()));
        let organization_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let event = AuditEvent {
            id: event_id,
            organization_id,
            actor_kind: AuditActorKind::System,
            actor_id: None,
            action: "audit.export.test".to_owned(),
            target: "audit".to_owned(),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({ "safe": true }),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };

        let bytes = write_audit_export_ndjson_file(&path, std::slice::from_ref(&event))
            .expect("write audit export");
        assert!(bytes > 0);
        let body = std::fs::read_to_string(&path).expect("read audit export");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let exported = serde_json::from_str::<Value>(lines[0]).expect("json line");
        assert_eq!(exported["id"], event_id.to_string());
        assert_eq!(exported["organization_id"], organization_id.to_string());

        let overwrite = write_audit_export_ndjson_file(&path, &[event])
            .expect_err("export should not overwrite existing archive files");
        assert_eq!(
            overwrite
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        let _ = std::fs::remove_file(path);
    }
}
