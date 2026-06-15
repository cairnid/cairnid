use super::super::{config_error, config_error_owned};
use cairn_database::{AuditEventListFilter, ListCursor};
use cairn_domain::AuditActorKind;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_EXPORT_DEFAULT_LIMIT: i64 = 1000;
const AUDIT_EXPORT_USAGE: &str = "usage: cairn-api audit export-ndjson <output-path> [--limit <rows>] [--action <prefix>] [--target <prefix>] [--actor-kind <user|client|system>] [--actor-id <uuid>] [--from <rfc3339>] [--to <rfc3339>] [--after-created-at <rfc3339> --after-id <uuid>]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::audit_operations) struct AuditExportOptions {
    pub(super) output_path: PathBuf,
    pub(super) limit: i64,
    pub(super) after: Option<ListCursor>,
    pub(super) filter: AuditEventListFilter,
}

pub(in crate::audit_operations) fn audit_export_options(
    args: &[String],
    export_max_rows: i64,
) -> Result<AuditExportOptions, Box<dyn std::error::Error>> {
    let Some(output_path) = args.first() else {
        return Err(config_error(AUDIT_EXPORT_USAGE));
    };
    if output_path.trim().is_empty() || output_path == "-" {
        return Err(config_error(
            "audit export output path must be a file path, not stdout",
        ));
    }

    let export_max_rows = export_max_rows.clamp(1, 50_000);
    let mut limit = None;
    let mut action_prefix = None;
    let mut target_prefix = None;
    let mut actor_kind = None;
    let mut actor_id = None;
    let mut created_from = None;
    let mut created_to = None;
    let mut after_created_at = None;
    let mut after_id = None;
    let mut index = 1;

    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--limit" if limit.is_some() => {
                return Err(config_error("duplicate audit export --limit"));
            }
            "--action" if action_prefix.is_some() => {
                return Err(config_error("duplicate audit export --action"));
            }
            "--target" if target_prefix.is_some() => {
                return Err(config_error("duplicate audit export --target"));
            }
            "--actor-kind" if actor_kind.is_some() => {
                return Err(config_error("duplicate audit export --actor-kind"));
            }
            "--actor-id" if actor_id.is_some() => {
                return Err(config_error("duplicate audit export --actor-id"));
            }
            "--from" if created_from.is_some() => {
                return Err(config_error("duplicate audit export --from"));
            }
            "--to" if created_to.is_some() => {
                return Err(config_error("duplicate audit export --to"));
            }
            "--after-created-at" if after_created_at.is_some() => {
                return Err(config_error("duplicate audit export --after-created-at"));
            }
            "--after-id" if after_id.is_some() => {
                return Err(config_error("duplicate audit export --after-id"));
            }
            "--limit" => {
                let value = next_audit_export_arg(args, &mut index, "--limit")?;
                let parsed = value
                    .parse::<i64>()
                    .map_err(|_| config_error("invalid audit export --limit"))?;
                if parsed < 1 || parsed > export_max_rows {
                    return Err(config_error("audit export --limit out of range"));
                }
                limit = Some(parsed);
            }
            "--action" => {
                action_prefix = audit_export_prefix(
                    next_audit_export_arg(args, &mut index, "--action")?,
                    "audit export --action too large",
                )?;
            }
            "--target" => {
                target_prefix = audit_export_prefix(
                    next_audit_export_arg(args, &mut index, "--target")?,
                    "audit export --target too large",
                )?;
            }
            "--actor-kind" => {
                actor_kind = Some(audit_export_actor_kind(next_audit_export_arg(
                    args,
                    &mut index,
                    "--actor-kind",
                )?)?);
            }
            "--actor-id" => {
                let value = next_audit_export_arg(args, &mut index, "--actor-id")?;
                actor_id = Some(
                    Uuid::parse_str(value.trim())
                        .map_err(|_| config_error("invalid audit export --actor-id"))?,
                );
            }
            "--from" => {
                created_from = Some(audit_export_timestamp(next_audit_export_arg(
                    args, &mut index, "--from",
                )?)?);
            }
            "--to" => {
                created_to = Some(audit_export_timestamp(next_audit_export_arg(
                    args, &mut index, "--to",
                )?)?);
            }
            "--after-created-at" => {
                after_created_at = Some(audit_export_timestamp(next_audit_export_arg(
                    args,
                    &mut index,
                    "--after-created-at",
                )?)?);
            }
            "--after-id" => {
                let value = next_audit_export_arg(args, &mut index, "--after-id")?;
                after_id = Some(
                    Uuid::parse_str(value.trim())
                        .map_err(|_| config_error("invalid audit export --after-id"))?,
                );
            }
            _ => return Err(config_error("unsupported audit export argument")),
        }
    }

    if let (Some(from), Some(to)) = (created_from, created_to)
        && from >= to
    {
        return Err(config_error("audit export time range invalid"));
    }
    let after = match (after_created_at, after_id) {
        (Some(created_at), Some(id)) => Some(ListCursor::new(created_at, id)),
        (None, None) => None,
        _ => {
            return Err(config_error(
                "audit export cursor requires both --after-created-at and --after-id",
            ));
        }
    };

    Ok(AuditExportOptions {
        output_path: PathBuf::from(output_path),
        limit: limit.unwrap_or(AUDIT_EXPORT_DEFAULT_LIMIT.min(export_max_rows)),
        after,
        filter: AuditEventListFilter {
            action_prefix,
            target_prefix,
            actor_kind,
            actor_id,
            created_from,
            created_to,
        },
    })
}

fn next_audit_export_arg<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &'static str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let Some(value) = args.get(*index) else {
        return Err(config_error_owned(format!("missing value for {flag}")));
    };
    *index += 1;
    Ok(value)
}

fn audit_export_prefix(
    value: &str,
    too_large_message: &'static str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    if trimmed.len() > 128 {
        return Err(config_error(too_large_message));
    }
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_ascii_lowercase()))
    }
}

fn audit_export_actor_kind(value: &str) -> Result<AuditActorKind, Box<dyn std::error::Error>> {
    match value.trim() {
        "user" => Ok(AuditActorKind::User),
        "client" => Ok(AuditActorKind::Client),
        "system" => Ok(AuditActorKind::System),
        _ => Err(config_error("invalid audit export --actor-kind")),
    }
}

fn audit_export_timestamp(value: &str) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc3339)
        .map_err(|_| config_error("invalid audit export timestamp"))
}

#[cfg(test)]
mod tests {
    use super::{AUDIT_EXPORT_DEFAULT_LIMIT, audit_export_options};
    use cairn_domain::AuditActorKind;
    use uuid::Uuid;

    #[test]
    fn audit_export_options_enforce_bounds_filters_and_cursor_pair() {
        let after_id = Uuid::new_v4();
        let args = vec![
            "audit.ndjson".to_owned(),
            "--limit".to_owned(),
            "25".to_owned(),
            "--action".to_owned(),
            "Admin.User".to_owned(),
            "--target".to_owned(),
            "user".to_owned(),
            "--actor-kind".to_owned(),
            "system".to_owned(),
            "--actor-id".to_owned(),
            after_id.to_string(),
            "--from".to_owned(),
            "2026-01-01T00:00:00Z".to_owned(),
            "--to".to_owned(),
            "2026-02-01T00:00:00Z".to_owned(),
            "--after-created-at".to_owned(),
            "2026-01-15T00:00:00Z".to_owned(),
            "--after-id".to_owned(),
            after_id.to_string(),
        ];

        let options = audit_export_options(&args, 100).expect("valid audit export options");

        assert_eq!(options.output_path.to_string_lossy(), "audit.ndjson");
        assert_eq!(options.limit, 25);
        assert_eq!(options.filter.action_prefix.as_deref(), Some("admin.user"));
        assert_eq!(options.filter.target_prefix.as_deref(), Some("user"));
        assert_eq!(options.filter.actor_kind, Some(AuditActorKind::System));
        assert_eq!(options.filter.actor_id, Some(after_id));
        assert!(options.filter.created_from.is_some());
        assert!(options.filter.created_to.is_some());
        assert_eq!(options.after.expect("cursor").tie_breaker_id, after_id);

        let default_options = audit_export_options(&["audit.ndjson".to_owned()], 10_000)
            .expect("default audit export options");
        assert_eq!(default_options.limit, AUDIT_EXPORT_DEFAULT_LIMIT);

        let too_large = audit_export_options(
            &[
                "audit.ndjson".to_owned(),
                "--limit".to_owned(),
                "101".to_owned(),
            ],
            100,
        )
        .expect_err("limit above configured maximum should fail");
        assert!(too_large.to_string().contains("out of range"));

        let half_cursor = audit_export_options(
            &[
                "audit.ndjson".to_owned(),
                "--after-id".to_owned(),
                Uuid::new_v4().to_string(),
            ],
            100,
        )
        .expect_err("cursor must include timestamp and id");
        assert!(half_cursor.to_string().contains("requires both"));
    }
}
