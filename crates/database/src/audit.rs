use super::codec::audit_actor_kind_to_str;
use super::repository_helpers::prefix_search_pattern;
use super::rows::AuditEventRow;
use super::{AuditEventListFilter, Database, DatabaseError, ListCursor};
use cairn_domain::{AuditEvent, OrganizationId, UserId};
use sqlx::types::Json;
use time::OffsetDateTime;

impl Database {
    pub async fn insert_audit_event(&self, event: &AuditEvent) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, organization_id, actor_kind, actor_id, action, target,
                ip_address, user_agent, metadata, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(event.id)
        .bind(event.organization_id)
        .bind(audit_actor_kind_to_str(event.actor_kind))
        .bind(event.actor_id)
        .bind(&event.action)
        .bind(&event.target)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(Json(&event.metadata))
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        organization_id: OrganizationId,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DatabaseError> {
        self.list_audit_events_page(organization_id, None, limit)
            .await
    }

    pub async fn list_audit_events_page(
        &self,
        organization_id: OrganizationId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DatabaseError> {
        self.list_audit_events_page_filtered(
            organization_id,
            &AuditEventListFilter::default(),
            after,
            limit,
        )
        .await
    }

    pub async fn list_audit_events_page_filtered(
        &self,
        organization_id: OrganizationId,
        filter: &AuditEventListFilter,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DatabaseError> {
        let action_pattern = prefix_search_pattern(filter.action_prefix.as_deref());
        let target_pattern = prefix_search_pattern(filter.target_prefix.as_deref());
        let actor_kind = filter.actor_kind.map(audit_actor_kind_to_str);
        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT id, organization_id, actor_kind, actor_id, action, target,
                   ip_address, user_agent, metadata, created_at
            FROM audit_events
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
              AND ($4::text IS NULL OR lower(action) LIKE $4)
              AND ($5::text IS NULL OR lower(target) LIKE $5)
              AND ($6::text IS NULL OR actor_kind = $6)
              AND ($7::uuid IS NULL OR actor_id = $7)
              AND ($8::timestamptz IS NULL OR created_at >= $8)
              AND ($9::timestamptz IS NULL OR created_at < $9)
            ORDER BY created_at DESC, id DESC
            LIMIT $10
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(action_pattern)
        .bind(target_pattern)
        .bind(actor_kind)
        .bind(filter.actor_id)
        .bind(filter.created_from)
        .bind(filter.created_to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(AuditEventRow::try_into_event)
            .collect()
    }

    pub async fn list_user_security_events_page(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DatabaseError> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT id, organization_id, actor_kind, actor_id, action, target,
                   ip_address, user_agent, metadata, created_at
            FROM audit_events
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
              AND (
                  target = $4
                  OR (actor_kind = 'user' AND actor_id = $5)
                  OR metadata->>'subject_user_id' = $4
                  OR metadata->>'user_id' = $4
              )
            ORDER BY created_at DESC, id DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(&user_id_text)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(AuditEventRow::try_into_event)
            .collect()
    }

    pub async fn delete_audit_events_before(
        &self,
        organization_id: OrganizationId,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<i64, DatabaseError> {
        if limit <= 0 {
            return Ok(0);
        }

        let result = sqlx::query(
            r#"
            WITH expired AS (
                SELECT id
                FROM audit_events
                WHERE organization_id = $1
                  AND created_at < $2
                ORDER BY created_at ASC, id ASC
                LIMIT $3
            )
            DELETE FROM audit_events
            WHERE id IN (SELECT id FROM expired)
            "#,
        )
        .bind(organization_id)
        .bind(before)
        .bind(limit)
        .execute(&self.pool)
        .await?;

        Ok(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
    }
}
