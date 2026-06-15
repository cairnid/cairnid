use axum::{
    body::{Bytes, to_bytes},
    extract::Request,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestBodyError {
    TooLarge,
}

pub(super) async fn bounded_request_body(
    request: Request,
    max_bytes: usize,
) -> Result<Bytes, RequestBodyError> {
    let limit = max_bytes.checked_add(1).ok_or(RequestBodyError::TooLarge)?;
    let body = to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| RequestBodyError::TooLarge)?;
    if body.len() > max_bytes {
        return Err(RequestBodyError::TooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{RequestBodyError, bounded_request_body};
    use axum::{body::Body, http::Request};

    #[tokio::test]
    async fn bounded_request_body_accepts_exact_limit() {
        let request = Request::builder()
            .body(Body::from("1234"))
            .expect("request");

        let body = bounded_request_body(request, 4).await.expect("body");
        assert_eq!(&body[..], b"1234");
    }

    #[tokio::test]
    async fn bounded_request_body_rejects_above_limit() {
        let request = Request::builder()
            .body(Body::from("12345"))
            .expect("request");

        let error = bounded_request_body(request, 4)
            .await
            .expect_err("oversized body");
        assert_eq!(error, RequestBodyError::TooLarge);
    }
}
