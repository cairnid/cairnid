use crate::{DomainError, OrganizationId, UserId, checked_string, normalize_email};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Suspended,
    Locked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub organization_id: OrganizationId,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_external_id: Option<String>,
    pub email_verified: bool,
    pub display_name: String,
    pub status: UserStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

impl User {
    pub fn new(
        organization_id: OrganizationId,
        email: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let email = normalize_email(email.into())?;
        let display_name = checked_string("display_name", display_name.into(), 160)?;
        let now = OffsetDateTime::now_utc();

        Ok(Self {
            id: Uuid::new_v4(),
            organization_id,
            email,
            scim_external_id: None,
            email_verified: false,
            display_name,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        })
    }
}
