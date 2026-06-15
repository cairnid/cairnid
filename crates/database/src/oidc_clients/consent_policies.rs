use crate::codec::consent_grant_mode_to_str;
use crate::rows::ConsentPolicyTemplateRow;
use crate::{Database, DatabaseError, ListCursor};
use cairn_domain::{ConsentPolicyTemplate, ConsentPolicyTemplateId, OrganizationId};

impl Database {
    pub async fn create_consent_policy_template(
        &self,
        template: &ConsentPolicyTemplate,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO consent_policy_templates (
                id, organization_id, slug, name, grant_mode, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(template.id)
        .bind(template.organization_id)
        .bind(&template.slug)
        .bind(&template.name)
        .bind(consent_grant_mode_to_str(template.grant_mode))
        .bind(template.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_consent_policy_template(
        &self,
        organization_id: OrganizationId,
        id: ConsentPolicyTemplateId,
    ) -> Result<Option<ConsentPolicyTemplate>, DatabaseError> {
        let row = sqlx::query_as::<_, ConsentPolicyTemplateRow>(
            r#"
            SELECT id, organization_id, slug, name, grant_mode, created_at
            FROM consent_policy_templates
            WHERE organization_id = $1 AND id = $2
            "#,
        )
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(ConsentPolicyTemplateRow::try_into_template)
            .transpose()
    }

    pub async fn list_consent_policy_templates(
        &self,
        organization_id: OrganizationId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<ConsentPolicyTemplate>, DatabaseError> {
        let rows = sqlx::query_as::<_, ConsentPolicyTemplateRow>(
            r#"
            SELECT id, organization_id, slug, name, grant_mode, created_at
            FROM consent_policy_templates
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(ConsentPolicyTemplateRow::try_into_template)
            .collect()
    }
}
