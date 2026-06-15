#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

impl TokenTypeHint {
    pub(super) fn parse(token_type_hint: Option<&str>) -> Option<Self> {
        match token_type_hint {
            Some("access_token") => Some(Self::AccessToken),
            Some("refresh_token") => Some(Self::RefreshToken),
            _ => None,
        }
    }
}

pub(in crate::http) fn token_type_hint_lookup_order(
    token_type_hint: Option<&str>,
) -> [TokenTypeHint; 2] {
    match TokenTypeHint::parse(token_type_hint) {
        Some(TokenTypeHint::RefreshToken) => {
            [TokenTypeHint::RefreshToken, TokenTypeHint::AccessToken]
        }
        Some(TokenTypeHint::AccessToken) | None => {
            [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
        }
    }
}
