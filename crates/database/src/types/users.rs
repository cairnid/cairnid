use cairn_domain::{GroupId, MembershipRole, OrganizationId, User, UserId, UserStatus};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStatusMutationOutcome {
    Applied(User),
    NotFound,
    WouldDeactivateLastOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimUserUpdateOutcome {
    Applied(User),
    NotFound,
    WouldDeactivateLastOwner,
    EmailAlreadyExists,
    ExternalIdAlreadyExists,
}

#[derive(Debug, Clone)]
pub struct ScimUserUpdateInput<'a> {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub email: &'a str,
    pub scim_external_id: Option<&'a str>,
    pub email_verified: bool,
    pub display_name: &'a str,
    pub status: UserStatus,
    pub protected_owner_group_slug: &'a str,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassAdminRecovery {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub user_email: String,
    pub user_status_before: UserStatus,
    pub user_status_after: UserStatus,
    pub admin_group_id: GroupId,
    pub admin_group_created: bool,
    pub membership_role_before: Option<MembershipRole>,
    pub membership_role_after: MembershipRole,
}
