use super::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, scim_connector_profile, scim_connector_smoke_template,
    types::ScimConnectorProfileError,
};
use time::OffsetDateTime;

#[test]
fn scim_connector_profile_reports_generic_shape() {
    let report = scim_connector_profile("generic", "https://id.example.com/")
        .expect("valid generic profile");
    let json = serde_json::to_value(&report).expect("serializable profile");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["status"], "ready");
    assert_eq!(json["profile"], "generic");
    assert_eq!(json["issuer"], "https://id.example.com");
    assert_eq!(json["scim_base_url"], "https://id.example.com/scim/v2");
    assert_eq!(
        json["service_provider_config_url"],
        "https://id.example.com/scim/v2/ServiceProviderConfig"
    );
    assert_eq!(
        json["authentication"]["connector_header"],
        "Authorization: Bearer <raw-token>"
    );
    assert!(
        json["smoke_commands"]
            .as_array()
            .expect("smoke commands")
            .iter()
            .any(|command| command
                .as_str()
                .is_some_and(|command| command.contains("CAIRN_SCIM_SECONDARY_BEARER_TOKEN")))
    );
    assert!(
        report
            .recommended_mappings
            .iter()
            .any(|mapping| mapping.scim_attribute == "members.value")
    );
}

#[test]
fn scim_connector_profile_reports_provider_specific_settings() {
    let okta =
        scim_connector_profile("okta", "https://id.example.com").expect("valid okta profile");
    assert_eq!(okta.profile, "okta");
    assert!(okta.connector_settings.iter().any(|setting| {
        setting.name == "Unique identifier field for users" && setting.value == "userName"
    }));
    assert!(okta.recommended_mappings.iter().any(|mapping| {
        mapping.resource == "User"
            && mapping.connector_attribute == "user.id"
            && mapping.scim_attribute == "externalId"
    }));

    let entra =
        scim_connector_profile("azure-ad", "https://id.example.com").expect("valid entra alias");
    assert_eq!(entra.profile, "entra");
    assert!(
        entra
            .connector_settings
            .iter()
            .any(|setting| setting.name == "Tenant URL")
    );
    assert!(entra.recommended_mappings.iter().any(|mapping| {
        mapping.resource == "User"
            && mapping.connector_attribute == "objectId"
            && mapping.scim_attribute == "externalId"
    }));
}

#[test]
fn scim_connector_profile_rejects_unsafe_inputs() {
    let unknown = scim_connector_profile("custom", "https://id.example.com")
        .expect_err("unknown profile should fail");
    assert!(matches!(
        unknown,
        ScimConnectorProfileError::UnknownProfile(_)
    ));

    let non_https = scim_connector_profile("generic", "http://id.example.com")
        .expect_err("connector profile requires HTTPS");
    assert!(matches!(
        non_https,
        ScimConnectorProfileError::NonHttpsIssuer
    ));

    let with_path = scim_connector_profile("generic", "https://id.example.com/scim/v2")
        .expect_err("connector profile requires origin");
    assert!(matches!(
        with_path,
        ScimConnectorProfileError::NonOriginIssuer
    ));

    let with_credentials = scim_connector_profile("generic", "https://ops@id.example.com")
        .expect_err("connector profile rejects credentials");
    assert!(matches!(
        with_credentials,
        ScimConnectorProfileError::NonOriginIssuer
    ));
}

#[test]
fn scim_connector_smoke_template_reports_provider_shape_without_secrets() {
    let report = scim_connector_smoke_template("okta", "https://id.example.com")
        .expect("valid okta template");
    let json = serde_json::to_value(&report).expect("serializable template");
    let generated_at = json["generated_at"]
        .as_str()
        .expect("generated_at is serialized");
    OffsetDateTime::parse(generated_at, &time::format_description::well_known::Rfc3339)
        .expect("generated_at is RFC3339");

    assert_eq!(json["status"], "template");
    assert_eq!(json["source"], "external-scim-connector");
    assert_eq!(json["provider"], "okta");
    assert_eq!(json["display_name"], "Okta SCIM 2.0");
    assert_eq!(json["scim_base_url"], "https://id.example.com/scim/v2");
    assert_eq!(json["secondary_token_checked"], false);
    assert_eq!(json["rejected_token_checked"], false);
    assert_eq!(
        json["checks"].as_array().expect("checks").len(),
        REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS.len()
    );
    assert!(
        json["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .any(|check| check["name"] == "bulk_forward_reference" && check["status"] == "pending")
    );
    assert!(
        json["forbidden_fields"]
            .as_array()
            .expect("forbidden fields")
            .iter()
            .any(|field| field == "raw_token")
    );

    let serialized = serde_json::to_string(&report).expect("serialize template");
    assert!(!serialized.contains("Authorization: Bearer"));
    assert!(!serialized.contains("<raw-token>"));
    assert!(!serialized.contains("secret-value"));
}

#[test]
fn scim_connector_smoke_template_accepts_entra_alias_and_rejects_unsupported_inputs() {
    let entra = scim_connector_smoke_template("azuread", "https://id.example.com")
        .expect("valid entra alias");
    assert_eq!(entra.provider, "entra");
    assert_eq!(entra.display_name, "Microsoft Entra SCIM 2.0");

    let generic = scim_connector_smoke_template("generic", "https://id.example.com")
        .expect_err("generic templates are not supported");
    assert!(matches!(
        generic,
        ScimConnectorProfileError::UnsupportedSmokeTemplateProfile
    ));

    let non_https = scim_connector_smoke_template("okta", "http://id.example.com")
        .expect_err("template requires HTTPS issuer");
    assert!(matches!(
        non_https,
        ScimConnectorProfileError::NonHttpsIssuer
    ));
}
