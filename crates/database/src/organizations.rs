use super::rows::OrganizationRow;
use super::{Database, DatabaseError};
use cairn_domain::Organization;

impl Database {
    pub async fn create_organization(
        &self,
        organization: &Organization,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO organizations (id, slug, display_name, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (slug) DO NOTHING
            "#,
        )
        .bind(organization.id)
        .bind(&organization.slug)
        .bind(&organization.display_name)
        .bind(organization.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, DatabaseError> {
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"
            SELECT id, slug, display_name, created_at
            FROM organizations
            WHERE slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }
}
