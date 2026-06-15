use crate::config::{
    ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig, ScimConfig,
};
use cairn_database::Database;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    super::{
        AppState,
        scim_protocol::{
            SCIM_GROUP_SCHEMA, SCIM_RESOURCE_TYPE_SCHEMA, SCIM_SCHEMA_SCHEMA, SCIM_USER_SCHEMA,
        },
    },
    scim_group_resource_type, scim_group_schema_resource, scim_user_resource_type,
    scim_user_schema_resource,
};

fn metadata_state() -> AppState {
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
async fn resource_types_use_stable_schema_ids_and_locations() {
    let state = metadata_state();

    let user = scim_user_resource_type(&state);
    assert_eq!(user["schemas"], json!([SCIM_RESOURCE_TYPE_SCHEMA]));
    assert_eq!(user["id"], json!("User"));
    assert_eq!(user["schema"], json!(SCIM_USER_SCHEMA));
    assert_eq!(
        user["meta"]["location"],
        json!("https://id.example.com/scim/v2/ResourceTypes/User")
    );

    let group = scim_group_resource_type(&state);
    assert_eq!(group["schemas"], json!([SCIM_RESOURCE_TYPE_SCHEMA]));
    assert_eq!(group["id"], json!("Group"));
    assert_eq!(group["schema"], json!(SCIM_GROUP_SCHEMA));
    assert_eq!(
        group["meta"]["location"],
        json!("https://id.example.com/scim/v2/ResourceTypes/Group")
    );
}

#[tokio::test]
async fn schema_resources_advertise_supported_attributes() {
    let state = metadata_state();

    let user = scim_user_schema_resource(&state);
    assert_eq!(user["schemas"], json!([SCIM_SCHEMA_SCHEMA]));
    assert_eq!(user["id"], json!(SCIM_USER_SCHEMA));
    assert!(schema_has_attribute(&user, "userName"));
    assert!(schema_has_attribute(&user, "emails"));
    assert_eq!(
        user["meta"]["location"],
        json!(format!(
            "https://id.example.com/scim/v2/Schemas/{SCIM_USER_SCHEMA}"
        ))
    );

    let group = scim_group_schema_resource(&state);
    assert_eq!(group["schemas"], json!([SCIM_SCHEMA_SCHEMA]));
    assert_eq!(group["id"], json!(SCIM_GROUP_SCHEMA));
    assert!(schema_has_attribute(&group, "displayName"));
    assert!(schema_has_attribute(&group, "members"));
    assert_eq!(
        group["meta"]["location"],
        json!(format!(
            "https://id.example.com/scim/v2/Schemas/{SCIM_GROUP_SCHEMA}"
        ))
    );
}

fn schema_has_attribute(schema: &Value, attribute_name: &str) -> bool {
    schema["attributes"].as_array().is_some_and(|attributes| {
        attributes.iter().any(|attribute| {
            attribute["name"]
                .as_str()
                .is_some_and(|name| name == attribute_name)
        })
    })
}
