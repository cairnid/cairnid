use crate::{GroupId, OrganizationId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: GroupId,
    pub organization_id: OrganizationId,
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_external_id: Option<String>,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Member,
    Owner,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub group_id: GroupId,
    pub role: MembershipRole,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
