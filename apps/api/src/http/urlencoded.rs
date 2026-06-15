#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UrlEncodedParseError;

pub(super) fn parse_url_encoded_pairs(
    input: &str,
) -> Result<Vec<(String, String)>, UrlEncodedParseError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    input
        .split('&')
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((decode_component(name)?, decode_component(value)?))
        })
        .collect()
}

pub(super) fn percent_encode_minimal(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn decode_component(value: &str) -> Result<String, UrlEncodedParseError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(UrlEncodedParseError);
                }
                let high = hex_nibble(bytes[index + 1]).ok_or(UrlEncodedParseError)?;
                let low = hex_nibble(bytes[index + 2]).ok_or(UrlEncodedParseError)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            value => {
                decoded.push(value);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|_| UrlEncodedParseError)
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
    use super::{parse_url_encoded_pairs, percent_encode_minimal};

    #[test]
    fn parser_decodes_pairs_plus_spaces_and_empty_values() {
        assert_eq!(
            parse_url_encoded_pairs("scope=openid+profile&state=a%2Bb&prompt").unwrap(),
            vec![
                ("scope".to_owned(), "openid profile".to_owned()),
                ("state".to_owned(), "a+b".to_owned()),
                ("prompt".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn parser_rejects_bad_percent_encoding_and_invalid_utf8() {
        assert!(parse_url_encoded_pairs("state=%").is_err());
        assert!(parse_url_encoded_pairs("state=%GG").is_err());
        assert!(parse_url_encoded_pairs("state=%FF").is_err());
    }

    #[test]
    fn minimal_percent_encoder_preserves_unreserved_ascii() {
        assert_eq!(percent_encode_minimal("abc-._~ AZ+/"), "abc-._~%20AZ%2B%2F");
    }
}
