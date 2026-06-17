use axum::{
    Json,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use cairn_database::ListCursor;
use cairn_domain::AuditEvent;

use super::{
    ADMIN_AUDIT_EXPORT_DEFAULT_LIMIT, ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, admin_audit_event_list_query, list_page},
    api_response::ApiError,
    session_auth::require_admin_session,
};

pub(super) async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<AuditEvent>>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let query = admin_audit_event_list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
    )?;
    let events = state
        .database
        .list_audit_events_page_filtered(
            state.organization_id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?;
    Ok(Json(audit_event_page(events, query.page.limit)))
}

pub(super) async fn export_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    require_admin_session(&state, &headers).await?;
    let export_max_rows = state.config.audit.export_max_rows;
    let query = admin_audit_event_list_query(
        raw_query.as_deref(),
        ADMIN_AUDIT_EXPORT_DEFAULT_LIMIT.min(export_max_rows),
        export_max_rows,
    )?;
    let events = state
        .database
        .list_audit_events_page_filtered(
            state.organization_id,
            &query.filter,
            query.page.cursor,
            query.page.fetch_limit(),
        )
        .await?;
    audit_export_response(audit_event_page(events, query.page.limit))
}

fn audit_event_page(events: Vec<AuditEvent>, limit: i64) -> ListPage<AuditEvent> {
    list_page(events, limit, |event| {
        ListCursor::new(event.created_at, event.id)
    })
}

fn audit_export_response(page: ListPage<AuditEvent>) -> Result<Response, ApiError> {
    let mut response = audit_export_body(&page.items)?.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"cairn-audit-events.ndjson\""),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("x-cairn-next-cursor"),
    );
    if let Some(next_cursor) = page.next_cursor {
        let next_cursor = HeaderValue::from_str(&next_cursor).map_err(|error| {
            tracing::error!(%error, "failed to encode audit event export cursor header");
            ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "audit export failed")
        })?;
        headers.insert(HeaderName::from_static("x-cairn-next-cursor"), next_cursor);
    }
    Ok(response)
}

fn audit_export_body(events: &[AuditEvent]) -> Result<String, ApiError> {
    let mut body = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|error| {
            tracing::error!(%error, "failed to serialize audit event export row");
            ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "audit export failed")
        })?;
        body.push_str(&line);
        body.push('\n');
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_domain::AuditActorKind;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn audit_export_body_serializes_one_json_object_per_line() {
        let organization_id = Uuid::new_v4();
        let first = test_audit_event(organization_id, "session.logged_in");
        let second = test_audit_event(organization_id, "session.logged_out");

        let body = audit_export_body(&[first.clone(), second.clone()]).unwrap();
        let lines = body.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        assert!(body.ends_with('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(lines[0]).unwrap()["id"],
            json!(first.id)
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(lines[1]).unwrap()["id"],
            json!(second.id)
        );
    }

    #[tokio::test]
    async fn audit_export_response_sets_download_headers_and_next_cursor() {
        let next_cursor = "cursor-value".to_owned();
        let page = ListPage {
            items: vec![test_audit_event(Uuid::new_v4(), "admin.user_created")],
            next_cursor: Some(next_cursor.clone()),
        };

        let response = audit_export_response(page).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-ndjson"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"cairn-audit-events.ndjson\""
        );
        assert_eq!(
            response
                .headers()
                .get(HeaderName::from_static("x-cairn-next-cursor"))
                .unwrap(),
            &next_cursor
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert_eq!(body.lines().count(), 1);
    }

    fn test_audit_event(organization_id: Uuid, action: &str) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            organization_id,
            actor_kind: AuditActorKind::User,
            actor_id: Some(Uuid::new_v4()),
            action: action.to_owned(),
            target: Uuid::new_v4().to_string(),
            ip_address: Some("203.0.113.10".to_owned()),
            user_agent: Some("Cairn-Test/1.0".to_owned()),
            metadata: json!({ "source": "test" }),
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
