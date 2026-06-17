use cairn_domain::{ConsentPolicyTemplateId, OidcClient, RedirectUri};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcClientStatusMutationOutcome {
    Applied(Box<OidcClientStatusMutation>),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClientStatusMutation {
    pub client: OidcClient,
    pub authorization_codes_invalidated: u64,
    pub access_tokens_revoked: u64,
    pub refresh_tokens_revoked: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClientDetailsUpdate {
    pub name: String,
    pub redirect_uris: Vec<RedirectUri>,
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    pub allowed_scopes: Vec<String>,
    pub consent_policy_template_id: Option<ConsentPolicyTemplateId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcClientDetailsMutationOutcome {
    Applied(Box<OidcClientDetailsMutation>),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClientDetailsMutation {
    pub client: OidcClient,
    pub changed_fields: Vec<String>,
    pub authorization_codes_invalidated: u64,
    pub access_tokens_revoked: u64,
    pub refresh_tokens_revoked: u64,
}
