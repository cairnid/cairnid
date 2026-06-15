use cairn_database::{ScimGroupListFilter, ScimUserListFilter};

use super::super::scim_protocol::ScimError;

pub(in crate::http::scim_query) fn scim_user_filter(
    value: &str,
) -> Result<ScimUserListFilter, ScimError> {
    let mut filter = ScimUserListFilter::default();
    for condition in split_scim_and_conditions(value)? {
        let (attribute, raw_value) = scim_eq_condition(condition)?;
        match attribute.to_ascii_lowercase().as_str() {
            "username" => {
                if filter.user_name_eq.is_some() {
                    return Err(ScimError::invalid_filter("duplicate userName filter"));
                }
                filter.user_name_eq = Some(cairn_domain::normalize_email(scim_filter_string(
                    raw_value,
                )?)?);
            }
            "externalid" => {
                if filter.external_id_eq.is_some() {
                    return Err(ScimError::invalid_filter("duplicate externalId filter"));
                }
                let external_id = scim_filter_string(raw_value)?;
                filter.external_id_eq =
                    optional_filter_string("externalId", Some(&external_id), 256)?;
            }
            "active" => {
                if filter.active_eq.is_some() {
                    return Err(ScimError::invalid_filter("duplicate active filter"));
                }
                filter.active_eq = Some(match raw_value.trim() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(ScimError::invalid_filter("active filter must be boolean")),
                });
            }
            _ => {
                return Err(ScimError::invalid_filter(
                    "unsupported SCIM filter attribute",
                ));
            }
        }
    }
    Ok(filter)
}

pub(in crate::http::scim_query) fn scim_group_filter(
    value: &str,
) -> Result<ScimGroupListFilter, ScimError> {
    let mut filter = ScimGroupListFilter::default();
    for condition in split_scim_and_conditions(value)? {
        let (attribute, raw_value) = scim_eq_condition(condition)?;
        match attribute.to_ascii_lowercase().as_str() {
            "displayname" => {
                if filter.display_name_eq.is_some() {
                    return Err(ScimError::invalid_filter("duplicate displayName filter"));
                }
                let display_name = scim_filter_string(raw_value)?;
                filter.display_name_eq =
                    optional_filter_string("displayName", Some(&display_name), 160)?
                        .ok_or_else(|| {
                            ScimError::invalid_filter("displayName filter cannot be empty")
                        })?
                        .into();
            }
            "externalid" => {
                if filter.external_id_eq.is_some() {
                    return Err(ScimError::invalid_filter("duplicate externalId filter"));
                }
                let external_id = scim_filter_string(raw_value)?;
                filter.external_id_eq =
                    optional_filter_string("externalId", Some(&external_id), 256)?
                        .ok_or_else(|| {
                            ScimError::invalid_filter("externalId filter cannot be empty")
                        })?
                        .into();
            }
            _ => {
                return Err(ScimError::invalid_filter(
                    "unsupported SCIM filter attribute",
                ));
            }
        }
    }
    Ok(filter)
}

fn optional_filter_string(
    field: &'static str,
    value: Option<&str>,
    max_len: usize,
) -> Result<Option<String>, ScimError> {
    value
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            if trimmed.chars().count() > max_len {
                return Err(ScimError::invalid_value(format!(
                    "{field} exceeds maximum length"
                )));
            }
            Ok(Some(trimmed.to_owned()))
        })
        .transpose()
        .map(Option::flatten)
}

fn split_scim_and_conditions(value: &str) -> Result<Vec<&str>, ScimError> {
    let mut conditions = Vec::new();
    let mut start = 0;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match byte {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            _ if !in_string && ascii_keyword_at(bytes, index, b" and ") => {
                let condition = value[start..index].trim();
                if condition.is_empty() {
                    return Err(ScimError::invalid_filter("empty SCIM filter condition"));
                }
                conditions.push(condition);
                index += b" and ".len();
                start = index;
                continue;
            }
            _ => {}
        }
        index += 1;
    }

    if in_string {
        return Err(ScimError::invalid_filter("unterminated SCIM filter string"));
    }
    let condition = value[start..].trim();
    if condition.is_empty() {
        return Err(ScimError::invalid_filter("empty SCIM filter condition"));
    }
    conditions.push(condition);
    Ok(conditions)
}

fn ascii_keyword_at(bytes: &[u8], index: usize, keyword: &[u8]) -> bool {
    bytes
        .get(index..index + keyword.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(keyword))
}

pub(in crate::http) fn scim_eq_condition(condition: &str) -> Result<(&str, &str), ScimError> {
    let trimmed = condition.trim();
    let Some(first_space) = trimmed.find(char::is_whitespace) else {
        return Err(ScimError::invalid_filter("SCIM filter must use eq"));
    };
    let attribute = trimmed[..first_space].trim();
    let remaining = trimmed[first_space..].trim_start();
    let Some(second_space) = remaining.find(char::is_whitespace) else {
        return Err(ScimError::invalid_filter("SCIM filter must use eq"));
    };
    let operator = &remaining[..second_space];
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(ScimError::invalid_filter("only eq filters are supported"));
    }
    let raw_value = remaining[second_space..].trim_start();
    if attribute.is_empty() || raw_value.is_empty() {
        return Err(ScimError::invalid_filter(
            "SCIM filter must include attribute and value",
        ));
    }
    Ok((attribute, raw_value))
}

pub(in crate::http) fn scim_filter_string(value: &str) -> Result<String, ScimError> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return Err(ScimError::invalid_filter(
            "SCIM string filter value must be quoted",
        ));
    }
    let mut output = String::new();
    let mut escaped = false;
    for character in value[1..value.len() - 1].chars() {
        if escaped {
            match character {
                '"' | '\\' => output.push(character),
                _ => return Err(ScimError::invalid_filter("unsupported SCIM string escape")),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    if escaped {
        return Err(ScimError::invalid_filter("unterminated SCIM string escape"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_string_parser_handles_escapes_and_rejects_bad_strings() {
        assert_eq!(
            scim_filter_string(r#""quoted \"value\"""#).expect("valid escaped string"),
            "quoted \"value\""
        );
        assert_eq!(
            scim_filter_string(r#""escaped \\ value""#).expect("valid slash escape"),
            "escaped \\ value"
        );
        assert_eq!(
            scim_filter_string(r#""bad \n value""#)
                .expect_err("unsupported escape")
                .scim_type,
            Some("invalidFilter")
        );
        assert_eq!(
            split_scim_and_conditions(r#"displayName eq "A and B" and externalId eq "x""#)
                .expect("quoted and does not split"),
            vec![r#"displayName eq "A and B""#, r#"externalId eq "x""#]
        );
    }
}
