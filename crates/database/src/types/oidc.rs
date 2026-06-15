use cairn_domain::OidcClient;

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
