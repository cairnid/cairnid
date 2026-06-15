use cairn_database::ScimGroupMember;
use cairn_domain::{Group, User, UserStatus};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    AppState,
    scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA, scim_location, scim_timestamp},
};

pub(super) fn scim_user_resource(state: &AppState, user: &User) -> Value {
    let mut resource = json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id.to_string(),
        "userName": user.email,
        "displayName": user.display_name,
        "name": {
            "formatted": user.display_name
        },
        "active": user.status == UserStatus::Active,
        "emails": [{
            "value": user.email,
            "type": "work",
            "primary": true
        }],
        "meta": {
            "resourceType": "User",
            "created": scim_timestamp(user.created_at),
            "lastModified": scim_timestamp(user.updated_at),
            "location": scim_location(state, &format!("Users/{}", user.id))
        }
    });
    if let Some(external_id) = &user.scim_external_id {
        resource["externalId"] = json!(external_id);
    }
    resource
}

pub(super) fn scim_group_resource(
    state: &AppState,
    group: &Group,
    members: &[ScimGroupMember],
) -> Value {
    let mut resource = json!({
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": group.id.to_string(),
        "displayName": group.display_name,
        "members": members
            .iter()
            .map(|member| {
                json!({
                    "value": member.user_id.to_string(),
                    "$ref": scim_location(state, &format!("Users/{}", member.user_id)),
                    "display": member.display_name,
                    "type": "User"
                })
            })
            .collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "created": scim_timestamp(group.created_at),
            "lastModified": scim_timestamp(group.created_at),
            "location": scim_location(state, &format!("Groups/{}", group.id))
        }
    });
    if let Some(external_id) = &group.scim_external_id {
        resource["externalId"] = json!(external_id);
    }
    resource
}

pub(super) fn scim_group_members_by_group(
    members: Vec<ScimGroupMember>,
) -> HashMap<Uuid, Vec<ScimGroupMember>> {
    let mut members_by_group: HashMap<Uuid, Vec<ScimGroupMember>> = HashMap::new();
    for member in members {
        members_by_group
            .entry(member.group_id)
            .or_default()
            .push(member);
    }
    members_by_group
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
    };
    use cairn_database::Database;
    use cairn_domain::MembershipRole;
    use time::OffsetDateTime;

    fn resource_state() -> AppState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
            .expect("lazy pool");
        AppState {
            database: Database::from_pool(pool),
            organization_id: Uuid::new_v4(),
            config: ApiConfig {
                environment: cairn_domain::Environment::Development,
                bind: "127.0.0.1:8080".to_owned(),
                issuer: "https://id.example.com/".to_owned(),
                public_web_origin: "http://localhost:5173".to_owned(),
                database_url: "postgres://cairn:cairn@localhost:5432/cairn_identity".to_owned(),
                default_org_slug: "default".to_owned(),
                scim: ScimConfig {
                    bearer_token_sha256_hashes: Vec::new(),
                },
                audit: AuditOperationsConfig {
                    retention_days: 365,
                    purge_batch_size: 1000,
                    export_max_rows: 10_000,
                },
                email_delivery: EmailDeliveryConfig {
                    provider: EmailProviderConfig::Stdout,
                    batch_size: 10,
                    max_attempts: 5,
                    retry_seconds: 300,
                    sending_timeout_seconds: 900,
                },
                request_identity: crate::config::RequestIdentityConfig {
                    trusted_proxy_ips: Vec::new(),
                },
                bootstrap_setup_secret_hash: None,
                signing: None,
                key_encryption_key: None,
            },
        }
    }

    #[tokio::test]
    async fn user_resource_uses_standard_shape_and_location() {
        let state = resource_state();
        let mut user = User::new(state.organization_id, "user@example.com", "User Example")
            .expect("valid user");
        user.scim_external_id = Some("hr-123".to_owned());

        let resource = scim_user_resource(&state, &user);

        assert_eq!(resource["schemas"], json!([SCIM_USER_SCHEMA]));
        assert_eq!(resource["id"], json!(user.id.to_string()));
        assert_eq!(resource["userName"], json!("user@example.com"));
        assert_eq!(resource["externalId"], json!("hr-123"));
        assert_eq!(resource["active"], json!(true));
        assert_eq!(resource["emails"][0]["primary"], json!(true));
        assert_eq!(
            resource["meta"]["location"],
            json!(format!("https://id.example.com/scim/v2/Users/{}", user.id))
        );
    }

    #[tokio::test]
    async fn group_resource_uses_member_refs_and_grouped_member_index() {
        let state = resource_state();
        let now = OffsetDateTime::now_utc();
        let group = Group {
            id: Uuid::new_v4(),
            organization_id: state.organization_id,
            slug: "engineering".to_owned(),
            scim_external_id: Some("group-123".to_owned()),
            display_name: "Engineering".to_owned(),
            created_at: now,
        };
        let user_id = Uuid::new_v4();
        let member = ScimGroupMember {
            group_id: group.id,
            user_id,
            email: "user@example.com".to_owned(),
            display_name: "User Example".to_owned(),
            role: MembershipRole::Member,
            created_at: now,
        };

        let grouped = scim_group_members_by_group(vec![member.clone()]);
        assert_eq!(grouped.get(&group.id).expect("group members").len(), 1);

        let resource = scim_group_resource(&state, &group, &[member]);

        assert_eq!(resource["schemas"], json!([SCIM_GROUP_SCHEMA]));
        assert_eq!(resource["id"], json!(group.id.to_string()));
        assert_eq!(resource["displayName"], json!("Engineering"));
        assert_eq!(resource["externalId"], json!("group-123"));
        assert_eq!(resource["members"][0]["value"], json!(user_id.to_string()));
        assert_eq!(
            resource["members"][0]["$ref"],
            json!(format!("https://id.example.com/scim/v2/Users/{user_id}"))
        );
        assert_eq!(
            resource["meta"]["location"],
            json!(format!(
                "https://id.example.com/scim/v2/Groups/{}",
                group.id
            ))
        );
    }
}
