use reqwest::Method;

use super::super::{
    CHECK_RESOURCE_TYPES, CHECK_SCHEMAS, CHECK_SERVICE_PROVIDER_CONFIG, SCIM_GROUP_SCHEMA,
    SCIM_USER_SCHEMA, ScimSmokeError,
    helpers::{expect_bool, expect_list_response_id},
};
use super::ScimSmokeRun;

impl ScimSmokeRun {
    pub(super) async fn check_metadata(&mut self) -> Result<(), ScimSmokeError> {
        let service_provider_config = self
            .request_ok(Method::GET, "ServiceProviderConfig", &[], None)
            .await?;
        expect_bool(&service_provider_config, "/patch/supported", true)?;
        expect_bool(&service_provider_config, "/filter/supported", true)?;
        expect_bool(&service_provider_config, "/bulk/supported", true)?;
        self.pass(
            CHECK_SERVICE_PROVIDER_CONFIG,
            "ServiceProviderConfig advertises bounded PATCH, Bulk, and filter support",
        );

        let schemas = self.request_ok(Method::GET, "Schemas", &[], None).await?;
        expect_list_response_id(&schemas, SCIM_USER_SCHEMA)?;
        expect_list_response_id(&schemas, SCIM_GROUP_SCHEMA)?;
        self.pass(CHECK_SCHEMAS, "Schemas includes User and Group resources");

        let resource_types = self
            .request_ok(Method::GET, "ResourceTypes", &[], None)
            .await?;
        expect_list_response_id(&resource_types, "User")?;
        expect_list_response_id(&resource_types, "Group")?;
        self.pass(
            CHECK_RESOURCE_TYPES,
            "ResourceTypes includes User and Group resource types",
        );
        Ok(())
    }
}
