mod authentication;
mod binding;
mod policy;

pub(super) use authentication::{authenticate_oauth_client, authenticated_client_from_request};
pub(super) use binding::{
    bearer_token_matches_organization, require_client_bound_to_stored_grant,
    require_oauth_client_organization, require_stored_token_organization,
};
pub(super) use policy::{
    oidc_client_is_active, require_confidential_client_credentials_client,
    require_oauth_client_active, require_token_endpoint_grant,
};

#[cfg(test)]
mod tests;
