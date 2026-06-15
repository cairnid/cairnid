use cairn_domain::Group;
use uuid::Uuid;

use super::super::super::{AppState, scim_protocol::ScimError};

pub(in crate::http) async fn scim_get_tenant_group(
    state: &AppState,
    group_id: Uuid,
) -> Result<Group, ScimError> {
    state
        .database
        .get_group(state.organization_id, group_id)
        .await?
        .ok_or_else(|| ScimError::not_found("SCIM group not found"))
}
