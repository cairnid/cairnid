mod clients;
mod consent_grants;
mod consent_policies;
mod types;

pub(super) use self::{
    clients::{
        create_client, get_client, list_clients, rotate_client_secret, update_client,
        update_client_status,
    },
    consent_grants::{list_client_consent_grants, revoke_client_consent_grant},
    consent_policies::{create_consent_policy_template, list_consent_policy_templates},
    types::AdminConsentGrantRevocationResponse,
};

#[cfg(test)]
pub(super) use self::types::validate_allowed_client_scopes;
