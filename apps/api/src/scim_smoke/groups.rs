use reqwest::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use super::{
    CHECK_GROUP_CREATE, CHECK_GROUP_DELETE, CHECK_GROUP_FILTER, CHECK_GROUP_PATCH,
    CHECK_GROUP_PROJECTION, CHECK_GROUP_REPLACE, CHECK_GROUP_SEARCH_REQUEST, SCIM_GROUP_SCHEMA,
    SCIM_PATCH_OP_SCHEMA, SCIM_SEARCH_REQUEST_SCHEMA, ScimSmokeError, ScimSmokeRun,
    helpers::{
        expect_list_response_id, expect_member_set, expect_missing, expect_str, resource_id,
    },
};

impl ScimSmokeRun {
    pub(super) async fn create_group(
        &mut self,
        display_name: &str,
        external_id: &str,
        user_id: Uuid,
    ) -> Result<Uuid, ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": display_name,
            "externalId": external_id,
            "members": [{
                "value": user_id.to_string(),
                "type": "User"
            }]
        });
        let resource = self
            .request(
                &self.bearer_token,
                Method::POST,
                "Groups",
                &[],
                Some(body),
                StatusCode::CREATED,
            )
            .await?;
        expect_str(&resource, "/displayName", display_name)?;
        expect_str(&resource, "/externalId", external_id)?;
        expect_member_set(&resource, &[user_id])?;
        let group_id = resource_id(&resource)?;
        self.created_group_id = Some(group_id);
        self.pass(CHECK_GROUP_CREATE, format!("created SCIM group {group_id}"));
        Ok(group_id)
    }

    pub(super) async fn check_group_filter(
        &mut self,
        display_name: &str,
        group_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let filter = format!("displayName eq \"{display_name}\"");
        let response = self
            .request_ok(Method::GET, "Groups", &[("filter", filter.as_str())], None)
            .await?;
        expect_list_response_id(&response, &group_id.to_string())?;
        self.pass(
            CHECK_GROUP_FILTER,
            format!("exact displayName filter returned SCIM group {group_id}"),
        );
        Ok(())
    }

    pub(super) async fn check_group_search_request(
        &mut self,
        display_name: &str,
        group_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_SEARCH_REQUEST_SCHEMA],
            "filter": format!("displayName eq \"{display_name}\""),
            "startIndex": 1,
            "count": 1,
            "attributes": ["displayName", "members.value"]
        });
        let response = self
            .request_ok(Method::POST, "Groups/.search", &[], Some(body))
            .await?;
        expect_list_response_id(&response, &group_id.to_string())?;
        self.pass(
            CHECK_GROUP_SEARCH_REQUEST,
            format!("SearchRequest displayName filter returned SCIM group {group_id}"),
        );
        Ok(())
    }

    pub(super) async fn check_group_projection(
        &mut self,
        group_id: Uuid,
        member_user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let resource = self
            .request_ok(
                Method::GET,
                &format!("Groups/{group_id}"),
                &[("excludedAttributes", "members.display,members.type,meta")],
                None,
            )
            .await?;
        expect_str(&resource, "/id", &group_id.to_string())?;
        expect_str(&resource, "/members/0/value", &member_user_id.to_string())?;
        expect_missing(&resource, "/members/0/display")?;
        expect_missing(&resource, "/members/0/type")?;
        expect_missing(&resource, "/meta")?;
        self.pass(
            CHECK_GROUP_PROJECTION,
            format!("SCIM group {group_id} excluded selected default attributes"),
        );
        Ok(())
    }

    pub(super) async fn patch_group_members(
        &mut self,
        group_id: Uuid,
        removed_user_id: Uuid,
        added_user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_PATCH_OP_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members.value",
                    "value": [added_user_id.to_string()]
                },
                {
                    "op": "remove",
                    "path": format!("members[value eq \"{removed_user_id}\"].value")
                }
            ]
        });
        let resource = self
            .request_ok(
                Method::PATCH,
                &format!("Groups/{group_id}"),
                &[],
                Some(body),
            )
            .await?;
        expect_member_set(&resource, &[added_user_id])?;
        self.pass(
            CHECK_GROUP_PATCH,
            format!("patched SCIM group {group_id} membership set with member value paths"),
        );
        Ok(())
    }

    pub(super) async fn replace_group(
        &mut self,
        group_id: Uuid,
        display_name: &str,
        external_id: &str,
        user_id: Uuid,
    ) -> Result<(), ScimSmokeError> {
        let body = json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": display_name,
            "externalId": external_id,
            "members": [{
                "value": user_id.to_string(),
                "type": "User"
            }]
        });
        let resource = self
            .request_ok(Method::PUT, &format!("Groups/{group_id}"), &[], Some(body))
            .await?;
        expect_str(&resource, "/displayName", display_name)?;
        expect_str(&resource, "/externalId", external_id)?;
        expect_member_set(&resource, &[user_id])?;
        self.pass(
            CHECK_GROUP_REPLACE,
            format!("fully replaced SCIM group {group_id}"),
        );
        Ok(())
    }

    pub(super) async fn delete_group(&mut self, group_id: Uuid) -> Result<(), ScimSmokeError> {
        self.request(
            &self.bearer_token,
            Method::DELETE,
            &format!("Groups/{group_id}"),
            &[],
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
        self.created_group_id = None;
        self.pass(CHECK_GROUP_DELETE, format!("deleted SCIM group {group_id}"));
        Ok(())
    }
}
