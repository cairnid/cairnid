use crate::codec::user_status_to_str;
use crate::rows::UserRow;
use crate::{
    Database, DatabaseError, ScimUserUpdateInput, ScimUserUpdateOutcome,
    users::lifecycle::{
        credentials::revoke_user_runtime_credentials,
        ownership::deactivation_would_remove_last_owner,
        records::{locked_user_for_update, user_email_is_taken, user_scim_external_id_is_taken},
    },
};
use cairn_domain::UserStatus;

impl Database {
    pub async fn update_user_from_scim(
        &self,
        input: ScimUserUpdateInput<'_>,
    ) -> Result<ScimUserUpdateOutcome, DatabaseError> {
        let ScimUserUpdateInput {
            organization_id,
            user_id,
            email,
            scim_external_id,
            email_verified: _,
            display_name,
            status,
            protected_owner_group_slug,
            at,
        } = input;

        let mut tx = self.pool.begin().await?;
        let Some(existing_user) = locked_user_for_update(&mut tx, organization_id, user_id).await?
        else {
            return Ok(ScimUserUpdateOutcome::NotFound);
        };

        if user_email_is_taken(&mut tx, organization_id, user_id, email).await? {
            return Ok(ScimUserUpdateOutcome::EmailAlreadyExists);
        }

        if let Some(external_id) = scim_external_id
            && user_scim_external_id_is_taken(&mut tx, organization_id, user_id, external_id)
                .await?
        {
            return Ok(ScimUserUpdateOutcome::ExternalIdAlreadyExists);
        }

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
            return Ok(ScimUserUpdateOutcome::WouldDeactivateLastOwner);
        }

        let email_changed = existing_user.email != email;
        let effective_email_verified = !email_changed && existing_user.email_verified;

        let updated_row = sqlx::query_as::<_, UserRow>(
            r#"
            UPDATE users
            SET email = $1,
                scim_external_id = $2,
                email_verified = $3,
                display_name = $4,
                status = $5,
                updated_at = $6
            WHERE organization_id = $7 AND id = $8
            RETURNING id, organization_id, email, scim_external_id, email_verified, display_name,
                      password_hash, status, created_at, updated_at, last_login_at
            "#,
        )
        .bind(email)
        .bind(scim_external_id)
        .bind(effective_email_verified)
        .bind(display_name)
        .bind(user_status_to_str(status))
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        if email_changed {
            sqlx::query(
                r#"
                UPDATE account_tokens
                SET consumed_at = COALESCE(consumed_at, $1)
                WHERE organization_id = $2
                  AND user_id = $3
                  AND consumed_at IS NULL
                  AND expires_at > $1
                "#,
            )
            .bind(at)
            .bind(organization_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        if status != UserStatus::Active {
            revoke_user_runtime_credentials(&mut tx, organization_id, user_id, at).await?;
        }

        tx.commit().await?;
        Ok(ScimUserUpdateOutcome::Applied(updated_row.try_into_user()?))
    }
}
