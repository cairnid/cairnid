use cairn_domain::{AccountToken, AccountTokenKind};
use time::OffsetDateTime;

use super::super::{AppState, api_response::ApiError};

pub(in crate::http) async fn valid_account_token(
    state: &AppState,
    token_hash: &str,
    kind: AccountTokenKind,
) -> Result<AccountToken, ApiError> {
    let token = state
        .database
        .get_account_token_by_hash(token_hash, kind)
        .await?
        .ok_or_else(|| ApiError::bad_request("invalid account token"))?;

    if token.organization_id != state.organization_id
        || token.consumed_at.is_some()
        || token.expires_at <= OffsetDateTime::now_utc()
    {
        return Err(ApiError::bad_request(
            "account token expired or already used",
        ));
    }

    Ok(token)
}
