use cairn_authn::verify_pkce;
use cairn_domain::PkceMethod;

use crate::OidcError;

pub fn verify_authorization_code_pkce(
    verifier: &str,
    expected_challenge: &str,
    method: PkceMethod,
) -> Result<(), OidcError> {
    verify_pkce(verifier, expected_challenge, method).map_err(|_| OidcError::PkceVerificationFailed)
}
