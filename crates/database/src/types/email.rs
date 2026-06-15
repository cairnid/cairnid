use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, sqlx::FromRow)]
pub struct EmailOutboxQueueSummary {
    pub queued: i64,
    pub retry: i64,
    pub retry_due: i64,
    pub sending: i64,
    pub stale_sending: i64,
    pub failed: i64,
    pub sent: i64,
    pub unfinished: i64,
    pub oldest_unfinished_at: Option<OffsetDateTime>,
    pub next_retry_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LifecycleEmailEvidenceMessage {
    pub kind: String,
    pub template: String,
    pub action_url_present: bool,
    pub provider_message_id: Option<String>,
    pub sent_at: OffsetDateTime,
}
