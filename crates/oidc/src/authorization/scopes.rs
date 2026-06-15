use crate::OidcError;

pub fn parse_scopes(scope: &str) -> Result<Vec<String>, OidcError> {
    let mut scopes = Vec::new();
    for scope in scope.split(' ') {
        if !scope_token_is_valid(scope) {
            return Err(OidcError::InvalidScope);
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.to_owned());
        }
    }
    Ok(scopes)
}

pub fn scope_token_is_valid(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}
