use cairn_domain::Organization;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitBucket {
    pub key: String,
    pub purpose: String,
    pub attempts: i64,
    pub window_start: OffsetDateTime,
    pub blocked_until: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

impl RateLimitBucket {
    pub fn is_blocked(&self, now: OffsetDateTime) -> bool {
        self.blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct OrganizationRow {
    pub(crate) id: Uuid,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) created_at: OffsetDateTime,
}

impl From<OrganizationRow> for Organization {
    fn from(row: OrganizationRow) -> Self {
        Self {
            id: row.id,
            slug: row.slug,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct RateLimitBucketRow {
    pub(crate) key: String,
    pub(crate) purpose: String,
    pub(crate) attempts: i64,
    pub(crate) window_start: OffsetDateTime,
    pub(crate) blocked_until: Option<OffsetDateTime>,
    pub(crate) updated_at: OffsetDateTime,
}

impl From<RateLimitBucketRow> for RateLimitBucket {
    fn from(row: RateLimitBucketRow) -> Self {
        Self {
            key: row.key,
            purpose: row.purpose,
            attempts: row.attempts,
            window_start: row.window_start,
            blocked_until: row.blocked_until,
            updated_at: row.updated_at,
        }
    }
}
