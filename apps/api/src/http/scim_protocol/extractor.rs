use axum::{
    Json,
    extract::{FromRequest, Request},
};
use serde::de::DeserializeOwned;

use super::{constants::SCIM_JSON_BODY_MAX_BYTES, error::ScimError};
use crate::http::{
    content_type::request_has_scim_content_type, request_body::bounded_request_body,
};

pub(in crate::http) struct ScimJson<T>(pub(in crate::http) T);

impl<S, T> FromRequest<S> for ScimJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ScimError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !request_has_scim_content_type(request.headers()) {
            return Err(ScimError::invalid_value(
                "content type must be application/scim+json",
            ));
        }
        let body = bounded_request_body(request, SCIM_JSON_BODY_MAX_BYTES)
            .await
            .map_err(|_| ScimError::invalid_value("SCIM body too large"))?;
        let Json(payload) = Json::<T>::from_bytes(&body)
            .map_err(|_| ScimError::invalid_value("invalid SCIM JSON body"))?;
        Ok(Self(payload))
    }
}
