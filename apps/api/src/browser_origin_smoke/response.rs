use reqwest::{
    Client, Method, StatusCode, Url,
    header::{self, HeaderMap},
};
use serde_json::Value;

use super::{
    resources::browser_origin_resource_url, routes::BrowserOriginMutationRoute,
    types::BrowserOriginSmokeError,
};

pub(super) async fn assert_rejected(
    client: &Client,
    base_url: &Url,
    route: &BrowserOriginMutationRoute,
    signal: &'static str,
    signal_value: &str,
) -> Result<StatusCode, BrowserOriginSmokeError> {
    let url = browser_origin_resource_url(base_url, route.path)?;
    let method = route
        .method
        .parse::<Method>()
        .map_err(|error| BrowserOriginSmokeError::InvalidInput(error.to_string()))?;
    let mut request = client
        .request(method, url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body("{}");
    request = match signal {
        "Origin" => request.header(header::ORIGIN, signal_value),
        "Referer" => request.header(header::REFERER, signal_value),
        _ => {
            return Err(BrowserOriginSmokeError::InvalidInput(
                "unsupported browser-origin signal".to_owned(),
            ));
        }
    };

    let response = request.send().await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = truncate_error_body(response.text().await?);
    if status != StatusCode::FORBIDDEN {
        return Err(BrowserOriginSmokeError::UnexpectedStatus {
            route_name: route.name,
            signal,
            actual: status.as_u16(),
            body,
        });
    }
    require_header(&headers, route.name, signal, "cache-control", "no-store")?;
    require_header(&headers, route.name, signal, "pragma", "no-cache")?;
    require_header(
        &headers,
        route.name,
        signal,
        "x-content-type-options",
        "nosniff",
    )?;
    let value = serde_json::from_str::<Value>(&body).ok();
    if value
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
        != Some("invalid request origin")
    {
        return Err(BrowserOriginSmokeError::UnexpectedBody {
            route_name: route.name,
            signal,
        });
    }

    Ok(status)
}

fn require_header(
    headers: &HeaderMap,
    route_name: &'static str,
    signal: &'static str,
    header_name: &'static str,
    expected: &'static str,
) -> Result<(), BrowserOriginSmokeError> {
    let actual = headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>");
    if actual != expected {
        return Err(BrowserOriginSmokeError::UnexpectedHeader {
            route_name,
            signal,
            header_name,
            expected,
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn truncate_error_body(value: String) -> String {
    value.chars().take(1024).collect()
}
