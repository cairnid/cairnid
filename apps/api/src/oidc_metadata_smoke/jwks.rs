use serde_json::Value;

use super::{
    types::{OidcMetadataSmokeCheck, OidcMetadataSmokeError},
    validation::require_object,
};

pub(super) fn validate_jwks_metadata(
    jwks: &Value,
) -> Result<Vec<OidcMetadataSmokeCheck>, OidcMetadataSmokeError> {
    require_object(jwks, "jwks")?;
    let keys = jwks.get("keys").and_then(Value::as_array).ok_or_else(|| {
        OidcMetadataSmokeError::InvalidJwks("keys must be a non-empty array".to_owned())
    })?;
    if keys.is_empty() {
        return Err(OidcMetadataSmokeError::InvalidJwks(
            "keys must be a non-empty array".to_owned(),
        ));
    }

    let mut rs256_public_key_found = false;
    for (index, key) in keys.iter().enumerate() {
        require_object(key, "jwks.keys[]")?;
        reject_private_jwk_material(index, key)?;

        let kty = key.get("kty").and_then(Value::as_str);
        let kid = key.get("kid").and_then(Value::as_str);
        let modulus = key.get("n").and_then(Value::as_str);
        let exponent = key.get("e").and_then(Value::as_str);
        if kty == Some("RSA")
            && kid.is_some_and(|kid| !kid.is_empty())
            && modulus.is_some_and(|modulus| !modulus.is_empty())
            && exponent.is_some_and(|exponent| !exponent.is_empty())
            && optional_jwk_field_is(key, "use", "sig")?
            && optional_jwk_field_is(key, "alg", "RS256")?
        {
            rs256_public_key_found = true;
        }
    }

    if !rs256_public_key_found {
        return Err(OidcMetadataSmokeError::InvalidJwks(
            "keys must include at least one public RSA signing key for RS256".to_owned(),
        ));
    }

    Ok(vec![
        OidcMetadataSmokeCheck {
            name: "jwks_rs256_public_key_material",
            status: "passed",
            detail: "JWKS includes at least one public RSA signing key usable for RS256".to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "jwks_no_private_key_material",
            status: "passed",
            detail: "JWKS did not expose private RSA parameters".to_owned(),
        },
    ])
}

fn reject_private_jwk_material(index: usize, key: &Value) -> Result<(), OidcMetadataSmokeError> {
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        if key.get(field).is_some() {
            return Err(OidcMetadataSmokeError::InvalidJwks(format!(
                "keys[{index}] must not expose private JWK field {field}"
            )));
        }
    }
    Ok(())
}

fn optional_jwk_field_is(
    key: &Value,
    field: &'static str,
    expected: &'static str,
) -> Result<bool, OidcMetadataSmokeError> {
    match key.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(true),
        None => Ok(true),
        Some(_) => Ok(false),
    }
}
