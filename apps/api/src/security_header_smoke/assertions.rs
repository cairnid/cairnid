use reqwest::{
    Client, Url,
    header::{self, HeaderMap},
};

use super::{
    resources::security_header_resource_url,
    targets::SecurityHeaderTarget,
    types::{SecurityHeaderSmokeCheck, SecurityHeaderSmokeError},
};

const PERMISSIONS_POLICY_REQUIRED_PARTS: &[&str] = &[
    "camera=()",
    "microphone=()",
    "geolocation=()",
    "payment=()",
    "usb=()",
];

pub(super) async fn check_security_headers(
    client: &Client,
    base_url: &Url,
    target: &SecurityHeaderTarget,
) -> Result<SecurityHeaderSmokeCheck, SecurityHeaderSmokeError> {
    let url = security_header_resource_url(base_url, target.path)?;
    let response = client
        .get(url)
        .header(header::ACCEPT, "application/json,text/html;q=0.9,*/*;q=0.1")
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    if status != target.expected_status {
        return Err(SecurityHeaderSmokeError::UnexpectedStatus {
            service: target.service,
            path: target.path,
            expected: target.expected_status.as_u16(),
            actual: status.as_u16(),
        });
    }

    require_header_contains(
        &headers,
        target,
        "content-security-policy",
        target.csp_contains,
    )?;
    require_header_contains(
        &headers,
        target,
        "strict-transport-security",
        "max-age=63072000",
    )?;
    require_header_contains(
        &headers,
        target,
        "strict-transport-security",
        "includeSubDomains",
    )?;
    require_header_eq(&headers, target, "x-content-type-options", "nosniff")?;
    require_header_eq(&headers, target, "x-frame-options", "DENY")?;
    require_header_eq(&headers, target, "referrer-policy", "no-referrer")?;
    require_header_eq(
        &headers,
        target,
        "cross-origin-opener-policy",
        "same-origin",
    )?;
    for required_part in PERMISSIONS_POLICY_REQUIRED_PARTS {
        require_header_contains(&headers, target, "permissions-policy", required_part)?;
    }
    if let Some(expected_no_store) = target.cache_control_no_store {
        let cache_control = header_value(&headers, "cache-control");
        let actual_no_store = cache_control
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("no-store"));
        if actual_no_store != expected_no_store {
            return Err(SecurityHeaderSmokeError::UnexpectedHeader {
                service: target.service,
                path: target.path,
                header_name: "cache-control",
                expected: if expected_no_store {
                    "no-store"
                } else {
                    "not no-store"
                },
                actual: cache_control.unwrap_or_else(|| "<missing>".to_owned()),
            });
        }
    }

    Ok(SecurityHeaderSmokeCheck {
        service: target.service,
        path: target.path,
        status: "passed",
        status_code: status.as_u16(),
        content_security_policy: true,
        strict_transport_security: true,
        x_content_type_options_nosniff: true,
        x_frame_options_deny: true,
        referrer_policy_no_referrer: true,
        permissions_policy_restrictive: true,
        cross_origin_opener_policy_same_origin: true,
        cache_control_no_store: target.cache_control_no_store,
        detail: "required security headers were present on deployed response".to_owned(),
    })
}

fn require_header_eq(
    headers: &HeaderMap,
    target: &SecurityHeaderTarget,
    header_name: &'static str,
    expected: &'static str,
) -> Result<(), SecurityHeaderSmokeError> {
    let actual = header_value(headers, header_name).unwrap_or_else(|| "<missing>".to_owned());
    if actual != expected {
        return Err(SecurityHeaderSmokeError::UnexpectedHeader {
            service: target.service,
            path: target.path,
            header_name,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_header_contains(
    headers: &HeaderMap,
    target: &SecurityHeaderTarget,
    header_name: &'static str,
    expected: &'static str,
) -> Result<(), SecurityHeaderSmokeError> {
    let actual = header_value(headers, header_name).unwrap_or_else(|| "<missing>".to_owned());
    if !actual.contains(expected) {
        return Err(SecurityHeaderSmokeError::UnexpectedHeader {
            service: target.service,
            path: target.path,
            header_name,
            expected,
            actual,
        });
    }
    Ok(())
}

fn header_value(headers: &HeaderMap, header_name: &'static str) -> Option<String> {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
