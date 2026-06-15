use axum::http::{HeaderMap, header};

pub(super) const OAUTH_FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
pub(super) const SCIM_CONTENT_TYPE: &str = "application/scim+json";

pub(super) fn request_has_urlencoded_content_type(headers: &HeaderMap) -> bool {
    request_media_type(headers)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case(OAUTH_FORM_CONTENT_TYPE))
}

pub(super) fn request_has_scim_content_type(headers: &HeaderMap) -> bool {
    request_media_type(headers).is_some_and(|media_type| {
        media_type.eq_ignore_ascii_case(SCIM_CONTENT_TYPE)
            || media_type.eq_ignore_ascii_case("application/json")
    })
}

pub(super) fn request_has_json_content_type(headers: &HeaderMap) -> bool {
    request_media_type(headers).is_some_and(is_json_media_type)
}

fn request_media_type(headers: &HeaderMap) -> Option<&str> {
    let content_type = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    Some(
        content_type
            .split_once(';')
            .map_or(content_type, |(media_type, _)| media_type)
            .trim(),
    )
}

fn is_json_media_type(media_type: &str) -> bool {
    if media_type.eq_ignore_ascii_case("application/json") {
        return true;
    }

    let lower = media_type.to_ascii_lowercase();
    lower
        .strip_prefix("application/")
        .is_some_and(|subtype| subtype.ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use super::{
        OAUTH_FORM_CONTENT_TYPE, SCIM_CONTENT_TYPE, request_has_json_content_type,
        request_has_scim_content_type, request_has_urlencoded_content_type,
    };
    use axum::http::{HeaderMap, HeaderValue, header};

    #[test]
    fn urlencoded_content_type_accepts_parameters_and_case_variants() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/X-WWW-Form-Urlencoded; charset=utf-8"),
        );

        assert!(request_has_urlencoded_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!request_has_urlencoded_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(OAUTH_FORM_CONTENT_TYPE),
        );
        assert!(request_has_urlencoded_content_type(&headers));
    }

    #[test]
    fn scim_content_type_accepts_scim_and_json_media_types() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SCIM_CONTENT_TYPE),
        );
        assert!(request_has_scim_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(request_has_scim_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.example+json"),
        );
        assert!(!request_has_scim_content_type(&headers));
    }

    #[test]
    fn json_content_type_accepts_application_json_and_suffixes() {
        let mut headers = HeaderMap::new();
        assert!(!request_has_json_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(request_has_json_content_type(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        assert!(request_has_json_content_type(&headers));

        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/json"));
        assert!(!request_has_json_content_type(&headers));
    }
}
