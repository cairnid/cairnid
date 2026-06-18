use reqwest::{Method, StatusCode};
use serde_json::Value;

use super::super::{
    REQUIRED_SCIM_SMOKE_CHECKS, ScimSmokeCheck, ScimSmokeError,
    http::{ScimHttpRequest, scim_request},
};
use super::ScimSmokeRun;

impl ScimSmokeRun {
    pub(in crate::scim_smoke) async fn request_ok(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, ScimSmokeError> {
        self.request(
            &self.bearer_token,
            method,
            path,
            query,
            body,
            StatusCode::OK,
        )
        .await
    }

    pub(in crate::scim_smoke) async fn request(
        &self,
        bearer_token: &str,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
        expected_status: StatusCode,
    ) -> Result<Value, ScimSmokeError> {
        scim_request(
            &self.client,
            &self.base_url,
            ScimHttpRequest {
                bearer_token,
                method,
                path,
                query,
                body,
                expected_status,
            },
        )
        .await
    }

    pub(in crate::scim_smoke) fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        debug_assert!(
            REQUIRED_SCIM_SMOKE_CHECKS.contains(&name),
            "unknown SCIM smoke check name: {name}"
        );
        self.checks.push(ScimSmokeCheck {
            name,
            status: "passed",
            detail: detail.into(),
        });
    }
}
