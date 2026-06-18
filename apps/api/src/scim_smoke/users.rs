use reqwest::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use super::{
    CHECK_USER_CREATE, CHECK_USER_DELETE, CHECK_USER_FILTER, CHECK_USER_PATCH,
    CHECK_USER_PROJECTION, CHECK_USER_REPLACE, CHECK_USER_SEARCH_REQUEST, CHECK_USER_SOFT_DELETE,
    SCIM_PATCH_OP_SCHEMA, SCIM_SEARCH_REQUEST_SCHEMA, SCIM_USER_SCHEMA, ScimSmokeError,
    ScimSmokeRun,
    helpers::{
        expect_bool, expect_list_response_id, expect_missing, expect_str, resource_id,
        scim_resource_url,
    },
};

impl ScimSmokeRun {
    pub(super) async fn create_user(
        &mut self,
        email: &str,
        external_id: &str,
        display_name: &str,
    ) -> Result<Uuid, ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "userName": email,
            "externalId": external_id,
            "displayName": display_name,
            "active": true,
            "emails": [{
                "value": email,
                "type": "work",
                "primary": true
            }]
        });
        let resource = self
            .request(
                &self.bearer_token,
                Method::POST,
                "Users",
                &[],
                Some(body),
                StatusCode::CREATED,
            )
            .await?;
        expect_str(&resource, "/userName", email)?;
        expect_str(&resource, "/externalId", external_id)?;
        expect_bool(&resource, "/active", true)?;
        let user_id = resource_id(&resource)?;
        self.created_user_ids.push(user_id);
        self.pass(CHECK_USER_CREATE, format!("created SCIM user {user_id}"));
        Ok(user_id)
    }

    pub(super) async fn check_user_filter(
        &mut self,
        email: &str,
        user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let filter = format!("userName eq \"{email}\"");
        let response = self
            .request_ok(Method::GET, "Users", &[("filter", filter.as_str())], None)
            .await?;
        expect_list_response_id(&response, &user_id.to_string())?;
        self.pass(
            CHECK_USER_FILTER,
            format!("exact userName filter returned SCIM user {user_id}"),
        );
        Ok(())
    }

    pub(super) async fn check_user_search_request(
        &mut self,
        email: &str,
        user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "filter": format!("userName eq \"{email}\""),
            "startIndex": 1,
            "count": 1,
            "attributes": ["userName", "emails.value"]
        });
        let response = self
            .request_ok(Method::POST, "Users/.search", &[], Some(body))
            .await?;
        expect_list_response_id(&response, &user_id.to_string())?;
        self.pass(
            CHECK_USER_SEARCH_REQUEST,
            format!("SearchRequest userName filter returned SCIM user {user_id}"),
        );
        Ok(())
    }

    pub(super) async fn check_user_projection(
        &mut self,
        user_id: Uuid,
        email: &str,
    ) -> Result<(), ScimSmokeError> {
        let resource = self
            .request_ok(
                Method::GET,
                &format!("Users/{user_id}"),
                &[("attributes", "userName,emails.value,meta.location")],
                None,
            )
            .await?;
        expect_str(&resource, "/id", &user_id.to_string())?;
        expect_str(&resource, "/userName", email)?;
        expect_str(&resource, "/emails/0/value", email)?;
        let expected_location = scim_resource_url(&self.base_url, &format!("Users/{user_id}"))?;
        expect_str(&resource, "/meta/location", expected_location.as_str())?;
        expect_missing(&resource, "/displayName")?;
        expect_missing(&resource, "/externalId")?;
        expect_missing(&resource, "/active")?;
        self.pass(
            CHECK_USER_PROJECTION,
            format!("SCIM user {user_id} returned only requested attributes"),
        );
        Ok(())
    }

    pub(super) async fn patch_user_display_name(
        &mut self,
        user_id: Uuid,
        display_name: &str,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_PATCH_OP_SCHEMA],
            "Operations": [{
                "op": "replace",
                "path": "displayName",
                "value": display_name
            }]
        });
        let resource = self
            .request_ok(Method::PATCH, &format!("Users/{user_id}"), &[], Some(body))
            .await?;
        expect_str(&resource, "/displayName", display_name)?;
        self.pass(CHECK_USER_PATCH, format!("patched SCIM user {user_id}"));
        Ok(())
    }

    pub(super) async fn replace_user(
        &mut self,
        user_id: Uuid,
        email: &str,
        external_id: &str,
        display_name: &str,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "userName": email,
            "externalId": external_id,
            "displayName": display_name,
            "active": true,
            "emails": [{
                "value": email,
                "type": "work",
                "primary": true
            }]
        });
        let resource = self
            .request_ok(Method::PUT, &format!("Users/{user_id}"), &[], Some(body))
            .await?;
        expect_str(&resource, "/externalId", external_id)?;
        expect_str(&resource, "/displayName", display_name)?;
        expect_bool(&resource, "/active", true)?;
        self.pass(
            CHECK_USER_REPLACE,
            format!("fully replaced SCIM user {user_id}"),
        );
        Ok(())
    }

    pub(super) async fn delete_user(&mut self, user_id: Uuid) -> Result<(), ScimSmokeError> {
        self.request(
            &self.bearer_token,
            Method::DELETE,
            &format!("Users/{user_id}"),
            &[],
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
        self.pass(
            CHECK_USER_DELETE,
            format!("soft-deleted SCIM user {user_id}"),
        );
        Ok(())
    }

    pub(super) async fn check_user_soft_deleted(
        &mut self,
        user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let resource = self
            .request_ok(Method::GET, &format!("Users/{user_id}"), &[], None)
            .await?;
        expect_bool(&resource, "/active", false)?;
        self.pass(
            CHECK_USER_SOFT_DELETE,
            format!("SCIM user {user_id} is inactive after DELETE"),
        );
        Ok(())
    }
}
