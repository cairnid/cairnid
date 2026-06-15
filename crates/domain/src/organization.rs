use crate::{DomainError, OrganizationId, checked_string};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Development,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id: OrganizationId,
    pub slug: String,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl Organization {
    pub fn new(
        slug: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let slug = checked_string("slug", slug.into(), 80)?;
        let display_name = checked_string("display_name", display_name.into(), 160)?;

        Ok(Self {
            id: Uuid::new_v4(),
            slug,
            display_name,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}
