use crate::{DatabaseError, codec::user_status_from_str};
use cairn_domain::User;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserWithPassword {
    pub user: User,
    pub password_hash: Option<String>,
}

impl UserWithPassword {
    pub(crate) fn try_from_row(row: UserRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            user: row.clone().try_into_user()?,
            password_hash: row.password_hash,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct UserRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) email: String,
    pub(crate) scim_external_id: Option<String>,
    pub(crate) email_verified: bool,
    pub(crate) display_name: String,
    pub(crate) password_hash: Option<String>,
    pub(crate) status: String,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
    pub(crate) last_login_at: Option<OffsetDateTime>,
}

impl UserRow {
    pub(crate) fn try_into_user(self) -> Result<User, DatabaseError> {
        Ok(User {
            id: self.id,
            organization_id: self.organization_id,
            email: self.email,
            scim_external_id: self.scim_external_id,
            email_verified: self.email_verified,
            display_name: self.display_name,
            status: user_status_from_str(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}
