use cairn_domain::User;
use uuid::Uuid;

use super::super::super::{AppState, scim_protocol::ScimError};

pub(in crate::http) async fn scim_get_tenant_user(
    state: &AppState,
    user_id: Uuid,
) -> Result<User, ScimError> {
    let user = state
        .database
        .get_user_with_password(state.organization_id, user_id)
        .await?
        .ok_or_else(|| ScimError::not_found("SCIM user not found"))?
        .user;
    Ok(user)
}
