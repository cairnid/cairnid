use cairn_domain::OrganizationId;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub(crate) struct RestoreDrillReport {
    pub(super) status: &'static str,
    pub(super) organization_slug: String,
    pub(super) organization_id: Option<OrganizationId>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) completed_at: OffsetDateTime,
    pub(super) database: RestoreDrillDatabaseReport,
    pub(super) signing: RestoreDrillSigningReport,
    pub(super) checks: Vec<String>,
    pub(crate) failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct RestoreDrillDatabaseReport {
    pub(super) reachable: bool,
    pub(super) applied_migrations: i64,
    pub(super) migrations_present: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct RestoreDrillSigningReport {
    pub(super) legacy_env_configured: bool,
    pub(super) key_encryption_key_configured: bool,
    pub(super) active_database_kid: Option<String>,
    pub(super) active_jwks_count: usize,
    pub(super) active_database_key_decryptable: bool,
    pub(super) signing_source_available: bool,
}
