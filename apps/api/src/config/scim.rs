use super::{ConfigError, SCIM_BEARER_TOKEN_HASH_MAX_VALUES, ScimConfig};

pub(super) fn scim_config_from_env() -> Result<ScimConfig, ConfigError> {
    let bearer_token_sha256_hashes = std::env::var("CAIRN_SCIM_BEARER_TOKEN_SHA256")
        .ok()
        .map(|value| {
            parse_sha256_hex_list(
                "CAIRN_SCIM_BEARER_TOKEN_SHA256",
                &value,
                SCIM_BEARER_TOKEN_HASH_MAX_VALUES,
            )
        })
        .transpose()?
        .unwrap_or_default();
    Ok(ScimConfig {
        bearer_token_sha256_hashes,
    })
}

fn parse_sha256_hex_list(
    variable: &'static str,
    value: &str,
    max_values: usize,
) -> Result<Vec<[u8; 32]>, ConfigError> {
    let mut hashes = Vec::new();
    for raw_hash in value.split(',') {
        let hash = parse_sha256_hex(variable, raw_hash)?;
        if hashes.iter().any(|existing| existing == &hash) {
            return Err(ConfigError::DuplicateTokenHash { variable });
        }
        hashes.push(hash);
    }

    if hashes.len() > max_values {
        return Err(ConfigError::TooManyTokenHashes {
            variable,
            max: max_values,
        });
    }
    Ok(hashes)
}

fn parse_sha256_hex(variable: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let value = value.trim();
    if value.len() != 64 {
        return Err(ConfigError::InvalidTokenHash { variable });
    }

    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(ConfigError::InvalidTokenHash { variable })?;
        let low = hex_nibble(chunk[1]).ok_or(ConfigError::InvalidTokenHash { variable })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_token_hash_requires_sha256_hex() {
        let parsed = parse_sha256_hex(
            "CAIRN_SCIM_BEARER_TOKEN_SHA256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("valid sha256 hex");
        assert_eq!(parsed[0], 0xe3);
        assert_eq!(parsed[31], 0x55);

        assert!(matches!(
            parse_sha256_hex("CAIRN_SCIM_BEARER_TOKEN_SHA256", "not-hex"),
            Err(ConfigError::InvalidTokenHash { .. })
        ));
        assert!(matches!(
            parse_sha256_hex(
                "CAIRN_SCIM_BEARER_TOKEN_SHA256",
                "x3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            Err(ConfigError::InvalidTokenHash { .. })
        ));
    }

    #[test]
    fn scim_token_hash_list_is_bounded_and_unique() {
        let parsed = parse_sha256_hex_list(
            "CAIRN_SCIM_BEARER_TOKEN_SHA256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, C78009FDBF7D03E74AD8D61FAD69BF64F05FAFC8922C72252FF403770DD2E9D1 ",
            4,
        )
        .expect("valid rotation hash set");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0][0], 0xe3);
        assert_eq!(parsed[1][31], 0xd1);

        assert!(matches!(
            parse_sha256_hex_list(
                "CAIRN_SCIM_BEARER_TOKEN_SHA256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                4
            ),
            Err(ConfigError::DuplicateTokenHash { .. })
        ));
        assert!(matches!(
            parse_sha256_hex_list(
                "CAIRN_SCIM_BEARER_TOKEN_SHA256",
                "0000000000000000000000000000000000000000000000000000000000000000,1111111111111111111111111111111111111111111111111111111111111111",
                1
            ),
            Err(ConfigError::TooManyTokenHashes { max: 1, .. })
        ));
    }
}
