use super::{
    ScimSmokeCheck, ScimSmokeError, ScimSmokeInputs, ScimSmokeReport,
    helpers::{non_empty_secret, scim_smoke_base_url},
};
use reqwest::{Client, Url};
use std::{env, time::Duration as StdDuration};
use time::OffsetDateTime;
use uuid::Uuid;

mod cleanup;
mod metadata;
mod requests;
mod tokens;

use self::tokens::validate_rotation_tokens;

const SCIM_SMOKE_TIMEOUT: StdDuration = StdDuration::from_secs(20);

pub async fn run_scim_smoke_from_env() -> Result<ScimSmokeReport, ScimSmokeError> {
    let base_url = env::var("CAIRN_SCIM_SMOKE_BASE_URL")
        .or_else(|_| env::var("CAIRN_ISSUER"))
        .map_err(|_| ScimSmokeError::MissingEnv("CAIRN_SCIM_SMOKE_BASE_URL or CAIRN_ISSUER"))?;
    let bearer_token = env::var("CAIRN_SCIM_BEARER_TOKEN")
        .map_err(|_| ScimSmokeError::MissingEnv("CAIRN_SCIM_BEARER_TOKEN"))?;
    let secondary_bearer_token = env::var("CAIRN_SCIM_SECONDARY_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let rejected_bearer_token = env::var("CAIRN_SCIM_REJECTED_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    run_scim_smoke(ScimSmokeInputs {
        base_url,
        bearer_token,
        secondary_bearer_token,
        rejected_bearer_token,
    })
    .await
}

pub async fn run_scim_smoke(inputs: ScimSmokeInputs) -> Result<ScimSmokeReport, ScimSmokeError> {
    let base_url = scim_smoke_base_url(&inputs.base_url)?;
    let bearer_token = non_empty_secret("CAIRN_SCIM_BEARER_TOKEN", inputs.bearer_token)?;
    let secondary_bearer_token = inputs
        .secondary_bearer_token
        .map(|token| non_empty_secret("CAIRN_SCIM_SECONDARY_BEARER_TOKEN", token))
        .transpose()?;
    let rejected_bearer_token = inputs
        .rejected_bearer_token
        .map(|token| non_empty_secret("CAIRN_SCIM_REJECTED_BEARER_TOKEN", token))
        .transpose()?;
    validate_rotation_tokens(
        &bearer_token,
        &secondary_bearer_token,
        &rejected_bearer_token,
    )?;

    let client = Client::builder()
        .timeout(SCIM_SMOKE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut smoke = ScimSmokeRun {
        client,
        base_url,
        bearer_token,
        secondary_bearer_token,
        rejected_bearer_token,
        checks: Vec::new(),
        created_user_ids: Vec::new(),
        created_group_id: None,
    };

    let result = smoke.run().await;
    if result.is_err() {
        smoke.cleanup_after_failure().await;
    }
    result
}

pub(super) struct ScimSmokeRun {
    pub(super) client: Client,
    pub(super) base_url: Url,
    pub(super) bearer_token: String,
    pub(super) secondary_bearer_token: Option<String>,
    pub(super) rejected_bearer_token: Option<String>,
    pub(super) checks: Vec<ScimSmokeCheck>,
    pub(super) created_user_ids: Vec<Uuid>,
    pub(super) created_group_id: Option<Uuid>,
}

impl ScimSmokeRun {
    async fn run(&mut self) -> Result<ScimSmokeReport, ScimSmokeError> {
        self.check_secondary_token_if_configured().await?;
        self.check_rejected_token_if_configured().await?;
        self.check_metadata().await?;

        let suffix = Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..8];
        let user_one_email = format!("scim-smoke-{suffix}@example.invalid");
        let user_two_email = format!("scim-smoke-{suffix}-2@example.invalid");
        let bulk_user_email = format!("scim-smoke-{suffix}-bulk@example.invalid");
        let user_one_external_id = format!("scim-smoke-user-{suffix}");
        let user_two_external_id = format!("scim-smoke-user-{suffix}-2");
        let bulk_user_external_id = format!("scim-smoke-user-{suffix}-bulk");
        let group_external_id = format!("scim-smoke-group-{suffix}");
        let bulk_group_external_id = format!("scim-smoke-group-{suffix}-bulk");

        let user_one_id = self
            .create_user(
                &user_one_email,
                &user_one_external_id,
                &format!("SCIM Smoke User {short_suffix}"),
            )
            .await?;
        let user_two_id = self
            .create_user(
                &user_two_email,
                &user_two_external_id,
                &format!("SCIM Smoke User {short_suffix} Two"),
            )
            .await?;
        self.check_user_filter(&user_one_email, user_one_id).await?;
        self.check_user_search_request(&user_one_email, user_one_id)
            .await?;
        self.check_user_projection(user_one_id, &user_one_email)
            .await?;
        self.patch_user_display_name(user_one_id, "SCIM Smoke User Patched")
            .await?;
        self.replace_user(
            user_one_id,
            &user_one_email,
            &format!("{user_one_external_id}-replaced"),
            "SCIM Smoke User Replaced",
        )
        .await?;

        let group_id = self
            .create_group(
                &format!("SCIM Smoke Group {short_suffix}"),
                &group_external_id,
                user_one_id,
            )
            .await?;
        self.check_group_filter(&format!("SCIM Smoke Group {short_suffix}"), group_id)
            .await?;
        self.check_group_search_request(&format!("SCIM Smoke Group {short_suffix}"), group_id)
            .await?;
        self.check_group_projection(group_id, user_one_id).await?;
        self.patch_group_members(group_id, user_one_id, user_two_id)
            .await?;
        self.replace_group(
            group_id,
            "SCIM Smoke Group Replaced",
            &format!("{group_external_id}-replaced"),
            user_one_id,
        )
        .await?;
        self.delete_group(group_id).await?;

        let bulk_user_id = self
            .check_bulk_mutations(
                &bulk_user_email,
                &bulk_user_external_id,
                &format!("SCIM Smoke Bulk User {short_suffix}"),
                &format!("SCIM Smoke Bulk Group {short_suffix}"),
                &bulk_group_external_id,
            )
            .await?;

        self.delete_user(user_one_id).await?;
        self.delete_user(user_two_id).await?;
        self.check_user_soft_deleted(user_one_id).await?;
        self.check_user_soft_deleted(user_two_id).await?;
        self.check_user_soft_deleted(bulk_user_id).await?;

        Ok(ScimSmokeReport {
            status: "ok",
            base_url: self.base_url.as_str().trim_end_matches('/').to_owned(),
            completed_at: OffsetDateTime::now_utc(),
            secondary_token_checked: self.secondary_bearer_token.is_some(),
            rejected_token_checked: self.rejected_bearer_token.is_some(),
            created_user_ids: vec![user_one_id, user_two_id, bulk_user_id],
            soft_deleted_user_ids: vec![user_one_id, user_two_id, bulk_user_id],
            deleted_group_id: group_id,
            checks: std::mem::take(&mut self.checks),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ScimSmokeInputs, run_scim_smoke};
    use crate::scim_smoke::{
        REQUIRED_SCIM_SMOKE_CHECKS, SCIM_BULK_RESPONSE_SCHEMA, SCIM_CONTENT_TYPE,
        SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA,
    };
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, StatusCode, Uri, header},
        response::{IntoResponse, Response},
    };
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };
    use tokio::net::TcpListener;

    const PRIMARY_TOKEN: &str = "primary-scim-smoke-token";
    const SECONDARY_TOKEN: &str = "secondary-scim-smoke-token";
    const REJECTED_TOKEN: &str = "rejected-scim-smoke-token";

    const USER_ONE_ID: &str = "01890d6f-109f-767a-96cb-2927626f45b1";
    const USER_TWO_ID: &str = "01890d6f-109f-767a-96cb-2927626f45b2";
    const BULK_USER_ID: &str = "01890d6f-109f-767a-96cb-2927626f45b3";
    const GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f45aa";
    const BULK_GROUP_ID: &str = "01890d6f-109f-767a-96cb-2927626f45ab";

    #[tokio::test]
    async fn smoke_run_proves_token_rotation_and_emits_token_free_evidence() {
        let fixture = ScimSmokeFixture::spawn().await;

        let report = run_scim_smoke(ScimSmokeInputs {
            base_url: fixture.base_url.clone(),
            bearer_token: PRIMARY_TOKEN.to_owned(),
            secondary_bearer_token: Some(SECONDARY_TOKEN.to_owned()),
            rejected_bearer_token: Some(REJECTED_TOKEN.to_owned()),
        })
        .await
        .expect("SCIM smoke against local fixture");

        assert_eq!(report.status, "ok");
        assert_eq!(report.base_url, fixture.base_url);
        assert!(report.secondary_token_checked);
        assert!(report.rejected_token_checked);

        let seen_checks = report
            .checks
            .iter()
            .map(|check| check.name)
            .collect::<BTreeSet<_>>();
        for required_check in REQUIRED_SCIM_SMOKE_CHECKS {
            assert!(
                seen_checks.contains(required_check),
                "missing required smoke check {required_check}"
            );
        }

        let serialized = serde_json::to_string(&report).expect("serialize SCIM smoke report");
        for forbidden in [
            PRIMARY_TOKEN,
            SECONDARY_TOKEN,
            REJECTED_TOKEN,
            "Authorization",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "SCIM smoke evidence leaked {forbidden}"
            );
        }

        let state = fixture.state.lock().expect("fixture state");
        assert!(
            state.primary_requests > 20,
            "primary token did not drive the SCIM smoke flow"
        );
        assert_eq!(state.secondary_requests, 1);
        assert_eq!(state.rejected_requests, 1);
    }

    struct ScimSmokeFixture {
        base_url: String,
        state: Arc<Mutex<FixtureState>>,
    }

    impl ScimSmokeFixture {
        async fn spawn() -> Self {
            let state = Arc::new(Mutex::new(FixtureState::default()));
            let app = Router::new()
                .fallback(scim_fixture_handler)
                .with_state(state.clone());
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind SCIM fixture");
            let base_url = format!(
                "http://{}",
                listener.local_addr().expect("fixture local address")
            );
            state.lock().expect("fixture state").base_url = base_url.clone();

            tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("serve SCIM smoke fixture");
            });

            Self { base_url, state }
        }
    }

    async fn scim_fixture_handler(
        State(state): State<Arc<Mutex<FixtureState>>>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let body = if body.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&body).expect("SCIM fixture JSON body"))
        };
        state
            .lock()
            .expect("fixture state")
            .handle(method, uri, headers, body)
    }

    #[derive(Default)]
    struct FixtureState {
        base_url: String,
        users: BTreeMap<String, FixtureUser>,
        groups: BTreeMap<String, FixtureGroup>,
        next_user_index: usize,
        primary_requests: usize,
        secondary_requests: usize,
        rejected_requests: usize,
    }

    impl FixtureState {
        fn handle(
            &mut self,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Option<Value>,
        ) -> Response {
            let path = uri.path();
            match self.authenticate(&headers) {
                FixtureToken::Primary => self.handle_primary(method, path, body),
                FixtureToken::Secondary
                    if method == Method::GET && path == "/scim/v2/ServiceProviderConfig" =>
                {
                    self.service_provider_config()
                }
                FixtureToken::Secondary => {
                    scim_error(StatusCode::FORBIDDEN, "secondary token is read-only")
                }
                FixtureToken::Rejected => {
                    scim_error(StatusCode::UNAUTHORIZED, "bearer token rejected")
                }
            }
        }

        fn authenticate(&mut self, headers: &HeaderMap) -> FixtureToken {
            match headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) if value.strip_prefix("Bearer ") == Some(PRIMARY_TOKEN) => {
                    self.primary_requests += 1;
                    FixtureToken::Primary
                }
                Some(value) if value.strip_prefix("Bearer ") == Some(SECONDARY_TOKEN) => {
                    self.secondary_requests += 1;
                    FixtureToken::Secondary
                }
                _ => {
                    self.rejected_requests += 1;
                    FixtureToken::Rejected
                }
            }
        }

        fn handle_primary(&mut self, method: Method, path: &str, body: Option<Value>) -> Response {
            match (method, path) {
                (Method::GET, "/scim/v2/ServiceProviderConfig") => self.service_provider_config(),
                (Method::GET, "/scim/v2/Schemas") => scim_json(
                    StatusCode::OK,
                    json!({
                        "Resources": [
                            { "id": SCIM_USER_SCHEMA },
                            { "id": SCIM_GROUP_SCHEMA }
                        ]
                    }),
                ),
                (Method::GET, "/scim/v2/ResourceTypes") => scim_json(
                    StatusCode::OK,
                    json!({
                        "Resources": [
                            { "id": "User" },
                            { "id": "Group" }
                        ]
                    }),
                ),
                (Method::POST, "/scim/v2/Users") => {
                    self.create_user(body.expect("create user body"))
                }
                (Method::GET, "/scim/v2/Users") => self.list_first_user(),
                (Method::POST, "/scim/v2/Users/.search") => self.list_first_user(),
                (Method::POST, "/scim/v2/Groups") => {
                    self.create_group(body.expect("create group body"))
                }
                (Method::GET, "/scim/v2/Groups") => self.list_first_group(),
                (Method::POST, "/scim/v2/Groups/.search") => self.list_first_group(),
                (Method::POST, "/scim/v2/Bulk") => self.handle_bulk(body.expect("bulk body")),
                (method, path) if path.starts_with("/scim/v2/Users/") => {
                    self.handle_user_resource(method, resource_id_from_path(path), body)
                }
                (method, path) if path.starts_with("/scim/v2/Groups/") => {
                    self.handle_group_resource(method, resource_id_from_path(path), body)
                }
                (method, path) => scim_error(
                    StatusCode::NOT_FOUND,
                    &format!("unexpected SCIM fixture request {method} {path}"),
                ),
            }
        }

        fn service_provider_config(&self) -> Response {
            scim_json(
                StatusCode::OK,
                json!({
                    "patch": { "supported": true },
                    "filter": { "supported": true },
                    "bulk": { "supported": true }
                }),
            )
        }

        fn create_user(&mut self, body: Value) -> Response {
            let id = match self.next_user_index {
                0 => USER_ONE_ID,
                1 => USER_TWO_ID,
                _ => panic!("unexpected direct SCIM user create"),
            };
            self.next_user_index += 1;
            let user = FixtureUser {
                id: id.to_owned(),
                user_name: required_string(&body, "userName"),
                external_id: required_string(&body, "externalId"),
                display_name: required_string(&body, "displayName"),
                active: required_bool(&body, "active"),
            };
            self.users.insert(id.to_owned(), user.clone());
            scim_json(StatusCode::CREATED, user.full_resource(&self.base_url))
        }

        fn list_first_user(&self) -> Response {
            scim_json(StatusCode::OK, list_response(USER_ONE_ID))
        }

        fn handle_user_resource(
            &mut self,
            method: Method,
            user_id: &str,
            body: Option<Value>,
        ) -> Response {
            match method {
                Method::GET => {
                    let user = self.users.get(user_id).expect("fixture user");
                    if user_id == USER_ONE_ID && user.active {
                        scim_json(StatusCode::OK, user.projected_resource(&self.base_url))
                    } else {
                        scim_json(StatusCode::OK, user.full_resource(&self.base_url))
                    }
                }
                Method::PATCH => {
                    let body = body.expect("patch user body");
                    let user = self.users.get_mut(user_id).expect("fixture user");
                    user.display_name = required_string(&body["Operations"][0], "value");
                    scim_json(StatusCode::OK, user.full_resource(&self.base_url))
                }
                Method::PUT => {
                    let body = body.expect("replace user body");
                    let user = self.users.get_mut(user_id).expect("fixture user");
                    user.external_id = required_string(&body, "externalId");
                    user.display_name = required_string(&body, "displayName");
                    user.active = required_bool(&body, "active");
                    scim_json(StatusCode::OK, user.full_resource(&self.base_url))
                }
                Method::DELETE => {
                    self.users.get_mut(user_id).expect("fixture user").active = false;
                    StatusCode::NO_CONTENT.into_response()
                }
                _ => scim_error(StatusCode::METHOD_NOT_ALLOWED, "unsupported user method"),
            }
        }

        fn create_group(&mut self, body: Value) -> Response {
            let member_id = required_string(&body["members"][0], "value");
            let group = FixtureGroup {
                id: GROUP_ID.to_owned(),
                display_name: required_string(&body, "displayName"),
                external_id: required_string(&body, "externalId"),
                member_ids: vec![member_id],
            };
            self.groups.insert(GROUP_ID.to_owned(), group.clone());
            scim_json(StatusCode::CREATED, group.full_resource())
        }

        fn list_first_group(&self) -> Response {
            scim_json(StatusCode::OK, list_response(GROUP_ID))
        }

        fn handle_group_resource(
            &mut self,
            method: Method,
            group_id: &str,
            body: Option<Value>,
        ) -> Response {
            match method {
                Method::GET => {
                    let group = self.groups.get(group_id).expect("fixture group");
                    scim_json(StatusCode::OK, group.projected_resource())
                }
                Method::PATCH => {
                    let body = body.expect("patch group body");
                    let group = self.groups.get_mut(group_id).expect("fixture group");
                    group.member_ids =
                        vec![required_string(&body["Operations"][0]["value"][0], "")];
                    scim_json(StatusCode::OK, group.full_resource())
                }
                Method::PUT => {
                    let body = body.expect("replace group body");
                    let group = self.groups.get_mut(group_id).expect("fixture group");
                    group.display_name = required_string(&body, "displayName");
                    group.external_id = required_string(&body, "externalId");
                    group.member_ids = vec![required_string(&body["members"][0], "value")];
                    scim_json(StatusCode::OK, group.full_resource())
                }
                Method::DELETE => {
                    self.groups.remove(group_id).expect("fixture group");
                    StatusCode::NO_CONTENT.into_response()
                }
                _ => scim_error(StatusCode::METHOD_NOT_ALLOWED, "unsupported group method"),
            }
        }

        fn handle_bulk(&mut self, body: Value) -> Response {
            let operations = body["Operations"]
                .as_array()
                .expect("bulk operations in fixture");
            if operations.len() == 3
                && operations[0].get("method").and_then(Value::as_str) == Some("POST")
            {
                self.create_bulk_resources(&operations[0]["data"], &operations[1]["data"])
            } else {
                self.cleanup_bulk_resources()
            }
        }

        fn create_bulk_resources(&mut self, group_body: &Value, user_body: &Value) -> Response {
            let user = FixtureUser {
                id: BULK_USER_ID.to_owned(),
                user_name: required_string(user_body, "userName"),
                external_id: required_string(user_body, "externalId"),
                display_name: "SCIM Smoke Bulk User Patched".to_owned(),
                active: required_bool(user_body, "active"),
            };
            self.users.insert(BULK_USER_ID.to_owned(), user.clone());

            let group = FixtureGroup {
                id: BULK_GROUP_ID.to_owned(),
                display_name: required_string(group_body, "displayName"),
                external_id: required_string(group_body, "externalId"),
                member_ids: vec![BULK_USER_ID.to_owned()],
            };
            self.groups.insert(BULK_GROUP_ID.to_owned(), group.clone());

            scim_json(
                StatusCode::OK,
                json!({
                    "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
                    "Operations": [
                        {
                            "method": "POST",
                            "bulkId": "bulk-group",
                            "status": "201",
                            "response": group.full_resource()
                        },
                        {
                            "method": "POST",
                            "bulkId": "bulk-user",
                            "status": "201",
                            "response": user.full_resource(&self.base_url)
                        },
                        {
                            "method": "PATCH",
                            "status": "200",
                            "response": user.full_resource(&self.base_url)
                        }
                    ]
                }),
            )
        }

        fn cleanup_bulk_resources(&mut self) -> Response {
            let user = self.users.get_mut(BULK_USER_ID).expect("bulk fixture user");
            user.active = false;
            let user_resource = user.full_resource(&self.base_url);
            self.groups
                .remove(BULK_GROUP_ID)
                .expect("bulk fixture group");

            scim_json(
                StatusCode::OK,
                json!({
                    "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
                    "Operations": [
                        {
                            "method": "PATCH",
                            "status": "200",
                            "response": user_resource
                        },
                        {
                            "method": "DELETE",
                            "status": "204"
                        },
                        {
                            "method": "DELETE",
                            "status": "204"
                        }
                    ]
                }),
            )
        }
    }

    enum FixtureToken {
        Primary,
        Secondary,
        Rejected,
    }

    #[derive(Clone)]
    struct FixtureUser {
        id: String,
        user_name: String,
        external_id: String,
        display_name: String,
        active: bool,
    }

    impl FixtureUser {
        fn full_resource(&self, base_url: &str) -> Value {
            json!({
                "schemas": [SCIM_USER_SCHEMA],
                "id": self.id,
                "userName": self.user_name,
                "externalId": self.external_id,
                "displayName": self.display_name,
                "active": self.active,
                "emails": [{
                    "value": self.user_name,
                    "type": "work",
                    "primary": true
                }],
                "meta": {
                    "resourceType": "User",
                    "location": format!("{base_url}/scim/v2/Users/{}", self.id)
                }
            })
        }

        fn projected_resource(&self, base_url: &str) -> Value {
            json!({
                "schemas": [SCIM_USER_SCHEMA],
                "id": self.id,
                "userName": self.user_name,
                "emails": [{
                    "value": self.user_name
                }],
                "meta": {
                    "location": format!("{base_url}/scim/v2/Users/{}", self.id)
                }
            })
        }
    }

    #[derive(Clone)]
    struct FixtureGroup {
        id: String,
        display_name: String,
        external_id: String,
        member_ids: Vec<String>,
    }

    impl FixtureGroup {
        fn full_resource(&self) -> Value {
            json!({
                "schemas": [SCIM_GROUP_SCHEMA],
                "id": self.id,
                "displayName": self.display_name,
                "externalId": self.external_id,
                "members": self.member_ids
                    .iter()
                    .map(|id| json!({ "value": id, "type": "User" }))
                    .collect::<Vec<_>>()
            })
        }

        fn projected_resource(&self) -> Value {
            json!({
                "schemas": [SCIM_GROUP_SCHEMA],
                "id": self.id,
                "members": self.member_ids
                    .iter()
                    .map(|id| json!({ "value": id }))
                    .collect::<Vec<_>>()
            })
        }
    }

    fn list_response(id: &str) -> Value {
        json!({
            "Resources": [{ "id": id }],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 1
        })
    }

    fn resource_id_from_path(path: &str) -> &str {
        path.rsplit('/').next().expect("resource id in path")
    }

    fn required_string(value: &Value, field: &str) -> String {
        let target = if field.is_empty() {
            value
        } else {
            &value[field]
        };
        target
            .as_str()
            .unwrap_or_else(|| panic!("fixture string field {field}"))
            .to_owned()
    }

    fn required_bool(value: &Value, field: &str) -> bool {
        value[field]
            .as_bool()
            .unwrap_or_else(|| panic!("fixture bool field {field}"))
    }

    fn scim_json(status: StatusCode, value: Value) -> Response {
        (
            status,
            [(header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
            value.to_string(),
        )
            .into_response()
    }

    fn scim_error(status: StatusCode, detail: &str) -> Response {
        scim_json(
            status,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": status.as_u16().to_string(),
                "detail": detail
            }),
        )
    }
}
