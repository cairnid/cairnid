use serde_json::Value;

mod browser_origin;
mod security_headers;

#[cfg(test)]
mod tests;

pub(super) fn validate_browser_origin_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    browser_origin::validate(value, checks, failures);
}

pub(super) fn validate_security_headers_smoke(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    security_headers::validate(value, checks, failures);
}
