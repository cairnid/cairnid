use crate::DomainError;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

pub fn normalize_email(email: String) -> Result<String, DomainError> {
    let email = checked_string("email", email.trim().to_ascii_lowercase(), 320)?;
    let has_single_at = email.matches('@').count() == 1;
    let has_domain_dot = email
        .split('@')
        .nth(1)
        .is_some_and(|domain| domain.contains('.'));

    if has_single_at && has_domain_dot {
        Ok(email)
    } else {
        Err(DomainError::InvalidEmail)
    }
}

pub fn checked_string(
    field: &'static str,
    value: String,
    max: usize,
) -> Result<String, DomainError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(DomainError::EmptyField { field });
    }
    if value.len() > max {
        return Err(DomainError::FieldTooLong { field, max });
    }
    Ok(value)
}

pub(crate) fn is_https_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };

    url.scheme() == "https"
        && has_authority_without_credentials(&url)
        && url.fragment().is_none()
        && !url.cannot_be_a_base()
}

pub(crate) fn is_localhost_http_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };

    let is_loopback_host = match url.host() {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(address)) => address == Ipv6Addr::LOCALHOST,
        _ => false,
    };

    url.scheme() == "http"
        && has_authority_without_credentials(&url)
        && url.fragment().is_none()
        && !url.cannot_be_a_base()
        && url.port().is_some()
        && is_loopback_host
}

fn has_authority_without_credentials(url: &Url) -> bool {
    url.host().is_some() && url.username().is_empty() && url.password().is_none()
}
