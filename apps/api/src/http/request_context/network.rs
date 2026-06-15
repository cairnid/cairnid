use axum::{
    extract::{FromRequestParts, connect_info::ConnectInfo},
    http::{HeaderMap, request::Parts},
};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use crate::{config::RequestIdentityConfig, http::AppState};

const UNKNOWN_NETWORK_IDENTIFIER: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct RequestIdentity {
    pub(in crate::http::request_context) source_ip: Option<IpAddr>,
}

impl RequestIdentity {
    pub(in crate::http) fn network_identifier(&self) -> String {
        self.source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| UNKNOWN_NETWORK_IDENTIFIER.to_owned())
    }

    pub(in crate::http) fn audit_ip_address(&self) -> Option<String> {
        self.source_ip.map(|ip| ip.to_string())
    }

    fn from_parts(
        config: &RequestIdentityConfig,
        headers: &HeaderMap,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        let source_ip = source_ip(config, headers, peer_addr);

        Self { source_ip }
    }

    pub(in crate::http::request_context) fn without_peer() -> Self {
        Self { source_ip: None }
    }
}

impl FromRequestParts<AppState> for RequestIdentity {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer_addr = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|connect_info| connect_info.0);

        Ok(Self::from_parts(
            &state.config.request_identity,
            &parts.headers,
            peer_addr,
        ))
    }
}

pub(in crate::http::request_context) fn header_first_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn source_ip(
    config: &RequestIdentityConfig,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
) -> Option<IpAddr> {
    let peer_ip = peer_addr.map(|addr| addr.ip())?;
    if config.trusted_proxy_ips.contains(&peer_ip) {
        Some(forwarded_ip(headers).unwrap_or(peer_ip))
    } else {
        Some(peer_ip)
    }
}

fn forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    header_first_value(headers, "x-forwarded-for")
        .and_then(first_forwarded_for_ip)
        .or_else(|| header_first_value(headers, "x-real-ip").and_then(parse_ip))
}

fn first_forwarded_for_ip(value: &str) -> Option<IpAddr> {
    value.split(',').next().and_then(parse_ip)
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    use super::{RequestIdentity, source_ip};
    use crate::config::RequestIdentityConfig;

    #[test]
    fn direct_peer_ip_ignores_client_controlled_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.10, 10.0.0.1"),
        );
        headers.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("198.51.100.4"),
        );
        let config = RequestIdentityConfig {
            trusted_proxy_ips: Vec::new(),
        };

        let ip = source_ip(&config, &headers, Some(([192, 0, 2, 10], 443).into()));

        assert_eq!(ip, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_peer_uses_first_forwarded_for_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.10, 10.0.0.1"),
        );
        headers.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("198.51.100.4"),
        );
        let config = RequestIdentityConfig {
            trusted_proxy_ips: vec!["10.0.0.1".parse().unwrap()],
        };

        let ip = source_ip(&config, &headers, Some(([10, 0, 0, 1], 443).into()));

        assert_eq!(ip, Some("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_peer_falls_back_to_real_ip_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("198.51.100.4"),
        );
        let config = RequestIdentityConfig {
            trusted_proxy_ips: vec!["10.0.0.1".parse().unwrap()],
        };

        let ip = source_ip(&config, &headers, Some(([10, 0, 0, 1], 443).into()));

        assert_eq!(ip, Some("198.51.100.4".parse().unwrap()));
    }

    #[test]
    fn forwarded_headers_are_ignored_without_peer_identity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.10"),
        );
        let config = RequestIdentityConfig {
            trusted_proxy_ips: vec!["10.0.0.1".parse().unwrap()],
        };

        assert_eq!(source_ip(&config, &headers, None), None);
        assert_eq!(
            RequestIdentity::without_peer().network_identifier(),
            "unknown"
        );
    }
}
