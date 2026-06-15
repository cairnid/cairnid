use reqwest::{Client, Method, StatusCode, Url, header};
use serde_json::Value;

use super::{
    SCIM_CONTENT_TYPE, ScimSmokeError,
    helpers::{scim_resource_url, truncate_error_body},
};

pub(super) async fn scim_request(
    client: &Client,
    base_url: &Url,
    request: ScimHttpRequest<'_>,
) -> Result<Value, ScimSmokeError> {
    let mut url = scim_resource_url(base_url, request.path)?;
    {
        let mut query_pairs = url.query_pairs_mut();
        for (name, value) in request.query {
            query_pairs.append_pair(name, value);
        }
    }

    let mut builder = client
        .request(request.method.clone(), url.clone())
        .bearer_auth(request.bearer_token)
        .header(header::ACCEPT, SCIM_CONTENT_TYPE);
    if let Some(body) = request.body {
        builder = builder
            .header(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)
            .json(&body);
    }

    let response = builder.send().await?;
    let status = response.status();
    if status != request.expected_status {
        let body = response
            .text()
            .await
            .map(truncate_error_body)
            .unwrap_or_else(|error| format!("failed to read response body: {error}"));
        return Err(ScimSmokeError::UnexpectedStatus {
            method: request.method.to_string(),
            url: url.to_string(),
            expected: request.expected_status.as_u16(),
            actual: status.as_u16(),
            body,
        });
    }
    if status == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let media_type = content_type
        .split_once(';')
        .map_or(content_type.as_str(), |(media_type, _)| media_type)
        .trim();
    if !media_type.eq_ignore_ascii_case(SCIM_CONTENT_TYPE) {
        return Err(ScimSmokeError::UnexpectedContentType {
            method: request.method.to_string(),
            url: url.to_string(),
            actual: if content_type.is_empty() {
                "<missing>".to_owned()
            } else {
                content_type
            },
        });
    }

    Ok(response.json::<Value>().await?)
}

pub(super) struct ScimHttpRequest<'a> {
    pub(super) bearer_token: &'a str,
    pub(super) method: Method,
    pub(super) path: &'a str,
    pub(super) query: &'a [(&'a str, &'a str)],
    pub(super) body: Option<Value>,
    pub(super) expected_status: StatusCode,
}
