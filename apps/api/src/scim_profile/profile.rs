use time::OffsetDateTime;

use super::{
    kind::ScimConnectorProfileKind,
    types::{
        ScimConnectorAuthentication, ScimConnectorMapping, ScimConnectorProfileError,
        ScimConnectorProfileReport, ScimConnectorSetting,
    },
    validation::normalized_https_origin,
};

pub fn scim_connector_profile(
    profile: &str,
    issuer: &str,
) -> Result<ScimConnectorProfileReport, ScimConnectorProfileError> {
    let kind = ScimConnectorProfileKind::parse(profile)?;
    let issuer = normalized_https_origin(issuer)?;
    let scim_base_url = format!("{issuer}/scim/v2");

    Ok(ScimConnectorProfileReport {
        generated_at: OffsetDateTime::now_utc(),
        status: "ready",
        profile: kind.key(),
        display_name: kind.display_name(),
        issuer: issuer.clone(),
        scim_base_url: scim_base_url.clone(),
        service_provider_config_url: format!("{scim_base_url}/ServiceProviderConfig"),
        authentication: ScimConnectorAuthentication {
            scheme: "bearer",
            connector_header: "Authorization: Bearer <raw-token>",
            server_env: "CAIRN_SCIM_BEARER_TOKEN_SHA256=<sha256(raw-token)>",
            rotation_env: "CAIRN_SCIM_BEARER_TOKEN_SHA256=<old-sha256>,<new-sha256>",
        },
        connector_settings: connector_settings(kind, &scim_base_url),
        recommended_mappings: recommended_mappings(kind),
        supported_operations: vec![
            "ServiceProviderConfig, Schemas, and ResourceTypes discovery",
            "User create, list, SearchRequest, get, full replace, bounded PATCH, and soft deprovision",
            "Group create, list, SearchRequest, get, full replace, bounded PATCH, and delete",
            "Built-in smoke covers bounded Bulk mutations with same-request bulkId references",
            "Token rotation with up to four active SHA-256 token hashes",
        ],
        validation_checks: vec![
            format!("{scim_base_url}/ServiceProviderConfig returns application/scim+json"),
            "connector can create and update a user with userName, emails[type eq \"work\"].value, displayName, externalId, and active".to_owned(),
            "connector can create and update a group with displayName, externalId, and User members".to_owned(),
            "connector deactivation maps to active=false or DELETE /Users/{id} and leaves audit history intact".to_owned(),
            "retired bearer tokens receive 401 Unauthorized after the rotation window closes".to_owned(),
        ],
        unsupported_v1_features: vec![
            "password synchronization",
            "nested group membership",
            "SCIM change-password operation",
            "SCIM ETags",
            "SCIM cursor pagination",
            "Shared Signals Framework events",
        ],
        smoke_commands: vec![
            "$env:CAIRN_SCIM_SMOKE_BASE_URL=\"https://id.example.com\"".to_owned(),
            "$env:CAIRN_SCIM_BEARER_TOKEN=\"<raw-token>\"".to_owned(),
            "$env:CAIRN_SCIM_SECONDARY_BEARER_TOKEN=\"<old-or-new-token-during-rotation>\""
                .to_owned(),
            "$env:CAIRN_SCIM_REJECTED_BEARER_TOKEN=\"<old-or-invalid-token>\"".to_owned(),
            "cairn-api scim smoke".to_owned(),
        ],
        operator_notes: vec![
            "Do not store the raw connector token in application environment variables; store only its SHA-256 digest.",
            "Use stable directory object IDs for externalId so retries and renames remain idempotent.",
            "Map SCIM Group members to User resources returned by Cairn; nested Group members are rejected.",
            "Run the built-in smoke command before external connector smokes and after every token rotation.",
            "External Okta and Microsoft Entra connector-smoke summaries should record only provider-emitted operations; built-in scim-smoke.json carries Bulk proof.",
        ],
    })
}

fn connector_settings(
    kind: ScimConnectorProfileKind,
    scim_base_url: &str,
) -> Vec<ScimConnectorSetting> {
    match kind {
        ScimConnectorProfileKind::Generic => vec![
            setting(
                "SCIM base URL",
                scim_base_url,
                "Use this as the service root for Users, Groups, Bulk, and discovery endpoints.",
            ),
            setting(
                "Authentication",
                "Bearer token",
                "Send the raw token as an Authorization bearer token.",
            ),
            setting(
                "Unique user key",
                "userName",
                "Use the primary login email for exact user lookups.",
            ),
            setting(
                "Stable user ID",
                "externalId",
                "Use the directory immutable user ID for idempotent updates.",
            ),
            setting(
                "Stable group ID",
                "externalId",
                "Use the directory immutable group ID for idempotent updates.",
            ),
        ],
        ScimConnectorProfileKind::Okta => vec![
            setting(
                "Base URL",
                scim_base_url,
                "Okta calls this the SCIM connector base URL.",
            ),
            setting(
                "Unique identifier field for users",
                "userName",
                "Use exact userName matching for imports and assignment reconciliation.",
            ),
            setting(
                "Authentication mode",
                "HTTP Header",
                "Configure the Authorization bearer token header.",
            ),
            setting(
                "Supported provisioning actions",
                "Create Users, Update User Attributes, Deactivate Users, Push Groups",
                "Enable user lifecycle and group push after the built-in smoke passes.",
            ),
        ],
        ScimConnectorProfileKind::Entra => vec![
            setting(
                "Tenant URL",
                scim_base_url,
                "Use this value in the Entra application provisioning settings.",
            ),
            setting(
                "Secret Token",
                "<raw-token>",
                "Paste only into Entra; Cairn stores the matching SHA-256 digest.",
            ),
            setting(
                "Provisioning mode",
                "Automatic",
                "Run test connection first, then scope assignments deliberately.",
            ),
            setting(
                "Target object actions",
                "Create, Update, Delete",
                "Delete maps to soft user deprovisioning for User resources.",
            ),
        ],
    }
}

fn recommended_mappings(kind: ScimConnectorProfileKind) -> Vec<ScimConnectorMapping> {
    let user_email_source = match kind {
        ScimConnectorProfileKind::Generic => "primary email",
        ScimConnectorProfileKind::Okta => "user.email",
        ScimConnectorProfileKind::Entra => "userPrincipalName or mail",
    };
    let user_id_source = match kind {
        ScimConnectorProfileKind::Generic => "directory immutable user ID",
        ScimConnectorProfileKind::Okta => "user.id",
        ScimConnectorProfileKind::Entra => "objectId",
    };
    let group_id_source = match kind {
        ScimConnectorProfileKind::Generic => "directory immutable group ID",
        ScimConnectorProfileKind::Okta => "group.id",
        ScimConnectorProfileKind::Entra => "objectId",
    };

    vec![
        mapping(
            "User",
            user_email_source,
            "userName",
            "Required login identifier; exact filters are supported.",
        ),
        mapping(
            "User",
            user_email_source,
            "emails[type eq \"work\"].value",
            "Primary work email is stored as the account email.",
        ),
        mapping(
            "User",
            "display name",
            "displayName",
            "Optional user-facing name.",
        ),
        mapping(
            "User",
            user_id_source,
            "externalId",
            "Recommended immutable reconciliation key.",
        ),
        mapping(
            "User",
            "assignment or account enabled state",
            "active",
            "false and DELETE both suspend the user and revoke runtime credentials.",
        ),
        mapping(
            "Group",
            "group name",
            "displayName",
            "Required tenant-unique group display name.",
        ),
        mapping(
            "Group",
            group_id_source,
            "externalId",
            "Recommended immutable reconciliation key.",
        ),
        mapping(
            "Group",
            "assigned User resources",
            "members.value",
            "Members must reference Cairn User resource IDs returned by SCIM.",
        ),
    ]
}

fn setting(
    name: &'static str,
    value: impl Into<String>,
    note: &'static str,
) -> ScimConnectorSetting {
    ScimConnectorSetting {
        name,
        value: value.into(),
        note,
    }
}

fn mapping(
    resource: &'static str,
    connector_attribute: &'static str,
    scim_attribute: &'static str,
    note: &'static str,
) -> ScimConnectorMapping {
    ScimConnectorMapping {
        resource,
        connector_attribute,
        scim_attribute,
        note,
    }
}
