use crate::{DatabaseError, ScimGroupMember, codec::membership_role_from_str};
use cairn_domain::{Group, Membership};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct GroupRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) slug: String,
    pub(crate) scim_external_id: Option<String>,
    pub(crate) display_name: String,
    pub(crate) created_at: OffsetDateTime,
}

impl From<GroupRow> for Group {
    fn from(row: GroupRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            slug: row.slug,
            scim_external_id: row.scim_external_id,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct MembershipRow {
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) group_id: Uuid,
    pub(crate) role: String,
    pub(crate) created_at: OffsetDateTime,
}

impl MembershipRow {
    pub(crate) fn try_into_membership(self) -> Result<Membership, DatabaseError> {
        Ok(Membership {
            organization_id: self.organization_id,
            user_id: self.user_id,
            group_id: self.group_id,
            role: membership_role_from_str(&self.role)?,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ScimGroupMemberRow {
    pub(crate) group_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
    pub(crate) created_at: OffsetDateTime,
}

impl ScimGroupMemberRow {
    pub(crate) fn try_into_member(self) -> Result<ScimGroupMember, DatabaseError> {
        Ok(ScimGroupMember {
            group_id: self.group_id,
            user_id: self.user_id,
            email: self.email,
            display_name: self.display_name,
            role: membership_role_from_str(&self.role)?,
            created_at: self.created_at,
        })
    }
}
