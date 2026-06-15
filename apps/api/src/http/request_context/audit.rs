use axum::http::{HeaderMap, header};

use super::network::{RequestIdentity, header_first_value};

const AUDIT_REQUEST_CONTEXT_MAX_LEN: usize = 512;

pub(in crate::http) fn audit_request_context(
    headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
    audit_request_context_for_identity(&RequestIdentity::without_peer(), headers)
}

pub(in crate::http) fn audit_request_context_for_identity(
    identity: &RequestIdentity,
    headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
    (audit_ip_address(identity), audit_user_agent(headers))
}

fn audit_ip_address(identity: &RequestIdentity) -> Option<String> {
    identity
        .audit_ip_address()
        .map(|identifier| truncate_audit_request_context_value(&identifier))
}

fn audit_user_agent(headers: &HeaderMap) -> Option<String> {
    header_first_value(headers, header::USER_AGENT.as_str())
        .map(truncate_audit_request_context_value)
}

fn truncate_audit_request_context_value(value: &str) -> String {
    value.chars().take(AUDIT_REQUEST_CONTEXT_MAX_LEN).collect()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

    use super::{
        AUDIT_REQUEST_CONTEXT_MAX_LEN, audit_request_context, audit_request_context_for_identity,
    };
    use crate::http::request_context::network::RequestIdentity;

    #[test]
    fn audit_request_context_records_resolved_client_and_bounded_user_agent() {
        let long_user_agent = "Cairn-Test/".to_owned() + &"a".repeat(AUDIT_REQUEST_CONTEXT_MAX_LEN);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&long_user_agent).expect("valid user agent"),
        );
        let identity = RequestIdentity {
            source_ip: Some("203.0.113.20".parse().unwrap()),
        };

        let (ip_address, user_agent) = audit_request_context_for_identity(&identity, &headers);

        assert_eq!(ip_address.as_deref(), Some("203.0.113.20"));
        let user_agent = user_agent.expect("user agent");
        assert_eq!(user_agent.chars().count(), AUDIT_REQUEST_CONTEXT_MAX_LEN);
        assert!(long_user_agent.starts_with(&user_agent));
    }

    #[test]
    fn audit_request_context_omits_unknown_network_identifier() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Cairn-Test/1.0"),
        );

        let (ip_address, user_agent) = audit_request_context(&headers);

        assert!(ip_address.is_none());
        assert_eq!(user_agent.as_deref(), Some("Cairn-Test/1.0"));
    }

    #[test]
    fn audit_request_context_does_not_trust_forwarded_headers_without_identity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.20, 10.0.0.1"),
        );

        let (ip_address, _) = audit_request_context(&headers);

        assert!(ip_address.is_none());
    }
}
