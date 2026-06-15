use crate::config::ApiConfig;
use cairn_audit::AuditEventBuilder;
use cairn_database::{BreakGlassAdminRecovery, Database};
use cairn_domain::{
    Group, GroupId, MembershipRole, OrganizationId, UserId, UserStatus, normalize_email,
};
use serde::Serialize;
use serde_json::json;
use std::{env, io};
use time::OffsetDateTime;

const ADMINISTRATORS_GROUP_SLUG: &str = "administrators";
const ADMINISTRATORS_GROUP_DISPLAY_NAME: &str = "Administrators";
const BREAK_GLASS_CONFIRMATION: &str = "grant-admin-owner";

pub(crate) async fn run_admin_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("break-glass-owner") => {
            let Some(email) = args.get(1) else {
                return Err(config_error(
                    "usage: cairn-api admin break-glass-owner <user-email>",
                ));
            };
            if !break_glass_confirmation_is_valid(
                env::var("CAIRN_BREAK_GLASS_CONFIRM").ok().as_deref(),
            ) {
                return Err(config_error(
                    "set CAIRN_BREAK_GLASS_CONFIRM=grant-admin-owner to acknowledge admin-auth bypass",
                ));
            }

            let config = ApiConfig::from_env()?;
            let email = normalize_email(email.to_owned())?;
            let database = Database::connect(&config.database_url).await?;
            database.migrate().await?;
            let organization = database
                .get_organization_by_slug(&config.default_org_slug)
                .await?
                .ok_or_else(|| {
                    config_error_owned(format!(
                        "organization {} does not exist",
                        config.default_org_slug
                    ))
                })?;
            let user = database
                .find_user_by_email(organization.id, &email)
                .await?
                .ok_or_else(|| {
                    config_error_owned(format!(
                        "user {email} does not exist in organization {}",
                        config.default_org_slug
                    ))
                })?
                .user;
            let now = OffsetDateTime::now_utc();
            let admin_group = break_glass_admin_group(organization.id, now);
            let audit_event = AuditEventBuilder::system(
                organization.id,
                "operator.break_glass_owner_granted",
                user.id.to_string(),
            )
            .metadata(json!({
                "command": "cairn-api admin break-glass-owner",
                "requested_email": email,
                "default_org_slug": config.default_org_slug
            }))
            .build();
            let recovery = database
                .break_glass_grant_admin_owner(
                    organization.id,
                    user.id,
                    &admin_group,
                    now,
                    &audit_event,
                )
                .await?
                .ok_or_else(|| {
                    config_error_owned(format!(
                        "user {email} no longer exists in organization {}",
                        config.default_org_slug
                    ))
                })?;

            println!(
                "{}",
                serde_json::to_string_pretty(&break_glass_owner_report(
                    recovery,
                    audit_event.id,
                    now
                ))?
            );
            Ok(())
        }
        _ => Err(config_error(
            "usage: cairn-api admin break-glass-owner <user-email>",
        )),
    }
}

fn break_glass_confirmation_is_valid(value: Option<&str>) -> bool {
    value == Some(BREAK_GLASS_CONFIRMATION)
}

fn break_glass_admin_group(organization_id: OrganizationId, created_at: OffsetDateTime) -> Group {
    Group {
        id: uuid::Uuid::new_v4(),
        organization_id,
        slug: ADMINISTRATORS_GROUP_SLUG.to_owned(),
        scim_external_id: None,
        display_name: ADMINISTRATORS_GROUP_DISPLAY_NAME.to_owned(),
        created_at,
    }
}

fn break_glass_owner_report(
    recovery: BreakGlassAdminRecovery,
    audit_event_id: uuid::Uuid,
    completed_at: OffsetDateTime,
) -> BreakGlassOwnerReport {
    BreakGlassOwnerReport {
        status: "granted",
        organization_id: recovery.organization_id,
        user_id: recovery.user_id,
        user_email: recovery.user_email,
        user_status_before: recovery.user_status_before,
        user_status_after: recovery.user_status_after,
        admin_group_id: recovery.admin_group_id,
        admin_group_created: recovery.admin_group_created,
        membership_role_before: recovery.membership_role_before,
        membership_role_after: recovery.membership_role_after,
        audit_event_id,
        completed_at,
    }
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[derive(Debug, Serialize)]
struct BreakGlassOwnerReport {
    status: &'static str,
    organization_id: OrganizationId,
    user_id: UserId,
    user_email: String,
    user_status_before: UserStatus,
    user_status_after: UserStatus,
    admin_group_id: GroupId,
    admin_group_created: bool,
    membership_role_before: Option<MembershipRole>,
    membership_role_after: MembershipRole,
    audit_event_id: uuid::Uuid,
    #[serde(with = "time::serde::rfc3339")]
    completed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::{
        BreakGlassOwnerReport, break_glass_admin_group, break_glass_confirmation_is_valid,
    };
    use cairn_domain::{MembershipRole, UserStatus};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    #[test]
    fn break_glass_owner_report_serializes_evidence_timestamp_as_rfc3339() {
        let completed_at = OffsetDateTime::UNIX_EPOCH + Duration::days(7);
        let report = BreakGlassOwnerReport {
            status: "granted",
            organization_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            user_email: "ops@example.com".to_owned(),
            user_status_before: UserStatus::Suspended,
            user_status_after: UserStatus::Active,
            admin_group_id: Uuid::new_v4(),
            admin_group_created: false,
            membership_role_before: Some(MembershipRole::Member),
            membership_role_after: MembershipRole::Owner,
            audit_event_id: Uuid::new_v4(),
            completed_at,
        };

        let value = serde_json::to_value(report).expect("break-glass owner report json");

        assert_eq!(value["status"], "granted");
        assert_eq!(value["user_status_after"], "active");
        assert_eq!(value["membership_role_after"], "owner");
        assert_eq!(value["completed_at"], "1970-01-08T00:00:00Z");
    }

    #[test]
    fn break_glass_confirmation_requires_exact_operator_acknowledgement() {
        assert!(break_glass_confirmation_is_valid(Some("grant-admin-owner")));
        assert!(!break_glass_confirmation_is_valid(None));
        assert!(!break_glass_confirmation_is_valid(Some(
            "Grant Admin Owner"
        )));
        assert!(!break_glass_confirmation_is_valid(Some(
            "grant-admin-owner "
        )));
    }

    #[test]
    fn break_glass_admin_group_uses_reserved_administrators_identity() {
        let organization_id = Uuid::new_v4();
        let created_at = OffsetDateTime::UNIX_EPOCH + Duration::days(1);

        let group = break_glass_admin_group(organization_id, created_at);

        assert_eq!(group.organization_id, organization_id);
        assert_eq!(group.slug, "administrators");
        assert_eq!(group.display_name, "Administrators");
        assert_eq!(group.scim_external_id, None);
        assert_eq!(group.created_at, created_at);
    }
}
