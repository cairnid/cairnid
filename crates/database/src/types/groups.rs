use cairn_domain::{Group, GroupId, MembershipRole, OrganizationId, UserId};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipMutationOutcome {
    Applied,
    NotFound,
    WouldRemoveLastOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimGroupMutationOutcome {
    Applied(Group),
    NotFound,
    SlugAlreadyExists,
    ExternalIdAlreadyExists,
    MemberNotFound,
    WouldModifyProtectedGroup,
}

#[derive(Debug, Clone)]
pub struct ScimGroupReplaceInput<'a> {
    pub organization_id: OrganizationId,
    pub group_id: GroupId,
    pub display_name: &'a str,
    pub scim_external_id: Option<&'a str>,
    pub member_user_ids: &'a [UserId],
    pub protected_group_slug: &'a str,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimGroupMember {
    pub group_id: GroupId,
    pub user_id: UserId,
    pub email: String,
    pub display_name: String,
    pub role: MembershipRole,
    pub created_at: OffsetDateTime,
}
