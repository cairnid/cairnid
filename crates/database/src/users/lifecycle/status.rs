use crate::codec::user_status_to_str;
use crate::rows::UserRow;
use crate::{
    Database, DatabaseError, UserStatusMutationOutcome,
    users::lifecycle::{
        credentials::revoke_user_runtime_credentials,
        ownership::deactivation_would_remove_last_owner, records::locked_user_for_update,
    },
};
use cairn_domain::{OrganizationId, UserId, UserStatus};
use time::OffsetDateTime;

impl Database {
    pub async fn update_user_status(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        status: UserStatus,
        protected_owner_group_slug: &str,
        at: OffsetDateTime,
    ) -> Result<UserStatusMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(existing_user) = locked_user_for_update(&mut tx, organization_id, user_id).await?
        else {
            return Ok(UserStatusMutationOutcome::NotFound);
        };

        if deactivation_would_remove_last_owner(
            &mut tx,
            organization_id,
            user_id,
            existing_user.status,
            status,
            protected_owner_group_slug,
        )
        .await?
        {
            return Ok(UserStatusMutationOutcome::WouldDeactivateLastOwner);
        }

        let updated_row = sqlx::query_as::<_, UserRow>(
            r#"
            UPDATE users
            SET status = $1, updated_at = $2
            WHERE organization_id = $3 AND id = $4
            RETURNING id, organization_id, email, scim_external_id, email_verified, display_name,
                      password_hash, status, created_at, updated_at, last_login_at
            "#,
        )
        .bind(user_status_to_str(status))
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        if status != UserStatus::Active {
            revoke_user_runtime_credentials(&mut tx, organization_id, user_id, at).await?;
        }

        tx.commit().await?;
        Ok(UserStatusMutationOutcome::Applied(
            updated_row.try_into_user()?,
        ))
    }
}
