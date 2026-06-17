#![forbid(unsafe_code)]

mod account_tokens;
mod audit;
mod auth_sessions;
mod codec;
mod consent_grants;
mod email_outbox;
mod groups;
mod mfa;
mod oauth_tokens;
mod oidc_clients;
mod organizations;
mod rate_limit;
mod repository_helpers;
mod rows;
mod signing_keys;
mod types;
mod users;

pub use self::rows::{
    AccessTokenRecord, EmailOutboxDeliveryToken, RateLimitBucket,
    ReencryptedEmailOutboxDeliveryToken, UserWithPassword,
};
pub use self::types::{
    AuditEventListFilter, AuthSessionCreationInput, BreakGlassAdminRecovery, BrowserSessionSummary,
    ConsentAuthorizationConsumption, ConsentGrantListFilter, ConsentGrantRevocation,
    ConsentGrantSummary, EmailOutboxQueueSummary, LifecycleEmailEvidenceMessage, ListCursor,
    MembershipMutationOutcome, OidcClientDetailsMutation, OidcClientDetailsMutationOutcome,
    OidcClientDetailsUpdate, OidcClientListFilter, OidcClientStatusMutation,
    OidcClientStatusMutationOutcome, PasswordChangeInput, PasswordChangeMutation,
    PasswordChangeOutcome, PasswordRecoveryInput, PasswordRecoveryMutation,
    PasswordRecoveryOutcome, ScimGroupListFilter, ScimGroupMember, ScimGroupMutationOutcome,
    ScimGroupReplaceInput, ScimUserListFilter, ScimUserUpdateInput, ScimUserUpdateOutcome,
    SessionRequestContext, SigningKeyLifecycleSummary, UserConsentGrantSummary, UserListFilter,
    UserStatusMutationOutcome,
};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("record not found")]
    NotFound,
    #[error("stored enum value is invalid: {0}")]
    InvalidEnum(String),
}

#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self, DatabaseError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), DatabaseError> {
        sqlx::migrate!("../../infra/migrations")
            .run(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn applied_migration_count(&self) -> Result<i64, DatabaseError> {
        match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&self.pool)
            .await
        {
            Ok(count) => Ok(count),
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42P01") => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn health_check(&self) -> Result<(), DatabaseError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
