use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{Jwk, PublicKeyUse},
};
use serde_json::Value;

use crate::OidcError;

pub(crate) fn rsa_public_jwk(key_id: &str, private_key_pem: &str) -> Result<Value, OidcError> {
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|_| OidcError::InvalidSigningKey)?;
    let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)
        .map_err(|_| OidcError::InvalidSigningKey)?;
    jwk.common.key_id = Some(key_id.to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    serde_json::to_value(jwk).map_err(|_| OidcError::InvalidSigningKey)
}
