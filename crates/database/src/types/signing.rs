use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, sqlx::FromRow)]
pub struct SigningKeyLifecycleSummary {
    pub total: i64,
    pub active: i64,
    pub active_with_private_material: i64,
    pub unretired: i64,
    pub retired: i64,
    pub rollover: i64,
    pub encrypted_private_material: i64,
    pub active_created_at: Option<OffsetDateTime>,
    pub oldest_unretired_created_at: Option<OffsetDateTime>,
    pub newest_retired_at: Option<OffsetDateTime>,
}
