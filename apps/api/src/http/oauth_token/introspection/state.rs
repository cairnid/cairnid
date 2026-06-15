use cairn_database::AccessTokenRecord;
use cairn_domain::{OidcClient, RefreshToken};
use time::OffsetDateTime;

pub(in crate::http) fn access_token_active_for_client(
    token: &AccessTokenRecord,
    client: &OidcClient,
    now: OffsetDateTime,
) -> bool {
    token.organization_id == client.organization_id
        && token.client_id == client.id
        && token.revoked_at.is_none()
        && token.expires_at > now
}

pub(in crate::http) fn refresh_token_active_for_client(
    token: &RefreshToken,
    client: &OidcClient,
    now: OffsetDateTime,
) -> bool {
    token.organization_id == client.organization_id
        && token.client_id == client.id
        && token.rotated_at.is_none()
        && token.revoked_at.is_none()
        && token.expires_at > now
}
