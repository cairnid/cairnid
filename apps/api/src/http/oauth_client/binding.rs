use axum::http::StatusCode;
use cairn_domain::{OidcClient, OrganizationId};
use cairn_oidc::OAuthErrorBody;
use uuid::Uuid;

use super::super::ApiError;

pub(in crate::http) fn require_client_bound_to_stored_grant(
    client: &OidcClient,
    organization_id: Uuid,
    client_id: Uuid,
) -> Result<(), ApiError> {
    if client.organization_id != organization_id || client.id != client_id {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("client does not match token grant"),
        ));
    }

    Ok(())
}

pub(in crate::http) fn require_oauth_client_organization(
    client: &OidcClient,
    organization_id: OrganizationId,
) -> Result<(), ApiError> {
    if client.organization_id != organization_id {
        return Err(ApiError::oauth(
            StatusCode::UNAUTHORIZED,
            OAuthErrorBody::invalid_client(),
        ));
    }

    Ok(())
}

pub(in crate::http) fn require_stored_token_organization(
    token_organization_id: OrganizationId,
    organization_id: OrganizationId,
) -> Result<(), ApiError> {
    if token_organization_id != organization_id {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("token does not belong to this issuer"),
        ));
    }

    Ok(())
}

pub(in crate::http) fn bearer_token_matches_organization(
    token_organization_id: OrganizationId,
    organization_id: OrganizationId,
) -> bool {
    token_organization_id == organization_id
}
