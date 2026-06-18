use reqwest::Method;
use serde_json::json;
use uuid::Uuid;

use super::{
    CHECK_BULK_MUTATIONS, SCIM_BULK_REQUEST_SCHEMA, SCIM_BULK_RESPONSE_SCHEMA, SCIM_GROUP_SCHEMA,
    SCIM_PATCH_OP_SCHEMA, SCIM_USER_SCHEMA, ScimSmokeError, ScimSmokeRun,
    helpers::{
        expect_bool, expect_bulk_operation, expect_bulk_response, expect_member_set, expect_str,
        resource_id,
    },
};

impl ScimSmokeRun {
    pub(super) async fn check_bulk_mutations(
        &mut self,
        email: &str,
        external_id: &str,
        display_name: &str,
        group_display_name: &str,
        group_external_id: &str,
    ) -> Result<Uuid, ScimSmokeError> {
        let create_body = json!({
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "failOnErrors": 1,
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "bulk-group",
                    "path": "/Groups",
                    "data": {
                        "schemas": [SCIM_GROUP_SCHEMA],
                        "displayName": group_display_name,
                        "externalId": group_external_id,
                        "members": [{
                            "value": "bulkId:bulk-user",
                            "type": "User"
                        }]
                    }
                },
                {
                    "method": "POST",
                    "bulkId": "bulk-user",
                    "path": "/Users",
                    "data": {
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
                    }
                },
                {
                    "method": "PATCH",
                    "path": "/Users/bulkId:bulk-user",
                    "data": {
                        "schemas": [SCIM_PATCH_OP_SCHEMA],
                        "Operations": [{
                            "op": "replace",
                            "path": "displayName",
                            "value": "SCIM Smoke Bulk User Patched"
                        }]
                    }
                }
            ]
        });
        let create_response = self
            .request_ok(Method::POST, "Bulk", &[], Some(create_body))
            .await?;
        expect_str(&create_response, "/schemas/0", SCIM_BULK_RESPONSE_SCHEMA)?;

        let user_operation = expect_bulk_operation(&create_response, 1, "201")?;
        expect_str(user_operation, "/bulkId", "bulk-user")?;
        let user_resource = expect_bulk_response(user_operation)?;
        expect_str(user_resource, "/userName", email)?;
        expect_str(user_resource, "/externalId", external_id)?;
        expect_bool(user_resource, "/active", true)?;
        let user_id = resource_id(user_resource)?;
        self.created_user_ids.push(user_id);

        let group_operation = expect_bulk_operation(&create_response, 0, "201")?;
        expect_str(group_operation, "/bulkId", "bulk-group")?;
        let group_resource = expect_bulk_response(group_operation)?;
        expect_str(group_resource, "/displayName", group_display_name)?;
        expect_str(group_resource, "/externalId", group_external_id)?;
        expect_member_set(group_resource, &[user_id])?;
        let group_id = resource_id(group_resource)?;
        self.created_group_id = Some(group_id);

        let patch_operation = expect_bulk_operation(&create_response, 2, "200")?;
        let patched_user = expect_bulk_response(patch_operation)?;
        expect_str(patched_user, "/displayName", "SCIM Smoke Bulk User Patched")?;

        let cleanup_body = json!({
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "failOnErrors": 1,
            "Operations": [
                {
                    "method": "PATCH",
                    "path": format!("/Users/{user_id}"),
                    "data": {
                        "schemas": [SCIM_PATCH_OP_SCHEMA],
                        "Operations": [{
                            "op": "replace",
                            "path": "active",
                            "value": false
                        }]
                    }
                },
                {
                    "method": "DELETE",
                    "path": format!("/Groups/{group_id}")
                },
                {
                    "method": "DELETE",
                    "path": format!("/Users/{user_id}")
                }
            ]
        });
        let cleanup_response = self
            .request_ok(Method::POST, "Bulk", &[], Some(cleanup_body))
            .await?;
        expect_str(&cleanup_response, "/schemas/0", SCIM_BULK_RESPONSE_SCHEMA)?;
        let patch_operation = expect_bulk_operation(&cleanup_response, 0, "200")?;
        let patched_user = expect_bulk_response(patch_operation)?;
        expect_bool(patched_user, "/active", false)?;
        expect_bulk_operation(&cleanup_response, 1, "204")?;
        expect_bulk_operation(&cleanup_response, 2, "204")?;
        self.created_group_id = None;

        self.pass(
            CHECK_BULK_MUTATIONS,
            format!(
                "created, patched, and cleaned up SCIM Bulk user {user_id} and group {group_id} with forward bulkId references"
            ),
        );
        Ok(user_id)
    }
}
