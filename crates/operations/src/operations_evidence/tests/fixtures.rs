use super::super::oidc::REQUIRED_OIDC_METADATA_SMOKE_CHECKS;
use super::super::scim::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, REQUIRED_SCIM_SMOKE_CHECKS,
    expected_scim_connector_display_name,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn temp_evidence_dir(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("cairn-release-evidence-{name}-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp evidence dir");
    root
}

pub(super) fn release_evidence_now() -> OffsetDateTime {
    OffsetDateTime::parse(
        "2026-06-07T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("valid release evidence timestamp")
}

pub(super) fn write_json(root: &Path, file_name: &str, value: Value) {
    fs::write(
        root.join(file_name),
        serde_json::to_string_pretty(&value).expect("serialize evidence"),
    )
    .expect("write evidence");
}

pub(super) fn production_preflight() -> Value {
    json!({
        "status": "ok",
        "environment": "production",
        "failures": [],
        "database": {
            "reachable": true,
            "applied_migrations": 12
        },
        "signing": {
            "database_active_kid": "rs256-active",
            "active_jwks_count": 2,
            "database_active_key_decryptable": true,
            "lifecycle": {
                "active_key_count": 1
            }
        },
        "email_delivery": {
            "production_ready": true,
            "queue": {
                "failed": 0
            }
        },
        "openid_conformance": {
            "issuer_https_origin_ready": true,
            "static_client_environment_ready": true
        }
    })
}

pub(super) fn dependency_policy_check() -> Value {
    json!({
        "status": "ok",
        "completed_at": "2026-06-07T12:00:00Z",
        "workspace": {
            "cargo_lock_present": true,
            "bun_lock_present": true,
            "package_json_present": true,
            "deny_toml_present": true,
            "cargo_audit_config_present": true,
            "dependency_docs_present": true
        },
        "checks": [
            {
                "name": "cargo_deny",
                "command": "cargo deny check",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 81,
                "stderr_bytes": 0,
                "tool_version": "cargo-deny 0.19.8"
            },
            {
                "name": "cargo_audit",
                "command": "cargo audit",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 128,
                "stderr_bytes": 0,
                "tool_version": "cargo-audit 0.22.2"
            },
            {
                "name": "bun_audit",
                "command": "bun run audit",
                "status": "passed",
                "exit_code": 0,
                "stdout_bytes": 19,
                "stderr_bytes": 0,
                "tool_version": "1.3.4"
            }
        ],
        "failures": []
    })
}

pub(super) fn openid_static_registration_report() -> Value {
    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "status": "ready",
        "issuer": "https://id.example.com",
        "suite_alias": "cairn-basic-op",
        "certification_profiles": ["Config OP", "Basic OP"],
        "run_plan_commands": [
            "scripts/run-test-plan.py oidcc-config-certification-test-plan cairn-oidcc-static.json",
            "scripts/run-test-plan.py oidcc-basic-certification-test-plan cairn-oidcc-static.json"
        ],
        "static_clients": [
            openid_static_client_registration("primary", "oidf-client"),
            openid_static_client_registration("secondary", "oidf-client-2")
        ],
        "unsupported_v1_profiles": [
            "Implicit OP",
            "Hybrid OP",
            "Dynamic OP",
            "Form Post OP"
        ]
    })
}

fn openid_static_client_registration(role: &str, client_id: &str) -> Value {
    json!({
        "role": role,
        "client_id": client_id,
        "redirect_uris": [
            "https://www.certification.openid.net/test/a/cairn-basic-op/callback"
        ],
        "post_logout_redirect_uris": [
            "https://www.certification.openid.net/test/a/cairn-basic-op/post_logout_redirect"
        ],
        "response_types": ["code"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods": ["client_secret_basic", "client_secret_post"],
        "allowed_scopes": ["openid", "profile", "email", "groups", "offline_access"],
        "pkce_methods": ["S256"]
    })
}

pub(super) fn openid_static_config() -> Value {
    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "alias": "cairn-basic-op",
        "description": "Cairn Identity OIDC static client certification",
        "server": {
            "discoveryUrl": "https://id.example.com/.well-known/openid-configuration"
        },
        "client": {
            "client_id": "oidf-client",
            "client_secret": "primary-secret"
        },
        "client2": {
            "client_id": "oidf-client-2",
            "client_secret": "secondary-secret"
        }
    })
}

pub(super) fn openid_conformance_summary(
    profile: &str,
    plan_name: &str,
    result_url: &str,
) -> Value {
    json!({
        "source": "openid-conformance-suite",
        "certification_profile": profile,
        "plan_name": plan_name,
        "status": "FINISHED",
        "result": "PASSED",
        "completed_at": "2026-06-07T12:00:00Z",
        "published_result_url": result_url
    })
}

pub(super) fn openid_conformance_plan_export(plan_name: &str, result: &str) -> Value {
    json!({
        "exportedAt": "2026-06-07T12:00:00Z",
        "exportedFrom": "https://www.certification.openid.net/",
        "exportedVersion": "5.1.24",
        "planInfo": {
            "planName": plan_name,
            "modules": [
                {
                    "testModule": "oidcc-server",
                    "instances": ["test-inst-001"]
                },
                {
                    "testModule": "oidcc-server-rotate-keys",
                    "instances": ["test-inst-002"]
                }
            ]
        },
        "testLogExports": [
            openid_conformance_test_export("test-inst-001", "oidcc-server", result),
            openid_conformance_test_export("test-inst-002", "oidcc-server-rotate-keys", "WARNING")
        ]
    })
}

fn openid_conformance_test_export(test_id: &str, test_module_name: &str, result: &str) -> Value {
    json!({
        "testId": test_id,
        "testModuleName": test_module_name,
        "export": {
            "exportedAt": "2026-06-07T12:00:00Z",
            "exportedFrom": "https://www.certification.openid.net/",
            "exportedVersion": "5.1.24",
            "testInfo": {
                "testId": test_id,
                "testName": test_module_name,
                "status": "FINISHED",
                "result": result
            },
            "results": [
                {
                    "result": "SUCCESS",
                    "msg": "Test completed"
                }
            ]
        }
    })
}

pub(super) fn scim_connector_profile(profile: &str) -> Value {
    let display_name = match profile {
        "generic" => "Generic SCIM 2.0",
        "okta" => "Okta SCIM 2.0",
        "entra" => "Microsoft Entra SCIM 2.0",
        _ => panic!("unsupported test SCIM connector profile"),
    };
    let connector_settings = match profile {
        "generic" => json!([
            {"name": "SCIM base URL", "value": "https://id.example.com/scim/v2", "note": "service root"},
            {"name": "Authentication", "value": "Bearer token", "note": "authorization header"},
            {"name": "Unique user key", "value": "userName", "note": "exact lookups"},
            {"name": "Stable user ID", "value": "externalId", "note": "immutable user ID"},
            {"name": "Stable group ID", "value": "externalId", "note": "immutable group ID"}
        ]),
        "okta" => json!([
            {"name": "Base URL", "value": "https://id.example.com/scim/v2", "note": "Okta connector base URL"},
            {"name": "Unique identifier field for users", "value": "userName", "note": "assignment reconciliation"},
            {"name": "Authentication mode", "value": "HTTP Header", "note": "bearer token header"},
            {"name": "Supported provisioning actions", "value": "Create Users, Update User Attributes, Deactivate Users, Push Groups", "note": "lifecycle and group push"}
        ]),
        "entra" => json!([
            {"name": "Tenant URL", "value": "https://id.example.com/scim/v2", "note": "directory application provisioning"},
            {"name": "Secret Token", "value": "<raw-token>", "note": "raw token is configured only in Entra"},
            {"name": "Provisioning mode", "value": "Automatic", "note": "test connection first"},
            {"name": "Target object actions", "value": "Create, Update, Delete", "note": "delete maps to soft deprovisioning"}
        ]),
        _ => unreachable!("unsupported test SCIM connector profile"),
    };

    json!({
        "generated_at": "2026-06-07T12:00:00Z",
        "status": "ready",
        "profile": profile,
        "display_name": display_name,
        "issuer": "https://id.example.com",
        "scim_base_url": "https://id.example.com/scim/v2",
        "service_provider_config_url": "https://id.example.com/scim/v2/ServiceProviderConfig",
        "authentication": {
            "scheme": "bearer",
            "connector_header": "Authorization: Bearer <raw-token>",
            "server_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<sha256(raw-token)>",
            "rotation_env": "CAIRN_SCIM_BEARER_TOKEN_SHA256=<old-sha256>,<new-sha256>"
        },
        "connector_settings": connector_settings,
        "recommended_mappings": [
            {"resource": "User", "connector_attribute": "primary email", "scim_attribute": "userName", "note": "Required login identifier"},
            {"resource": "User", "connector_attribute": "primary email", "scim_attribute": "emails[type eq \"work\"].value", "note": "Primary work email"},
            {"resource": "User", "connector_attribute": "display name", "scim_attribute": "displayName", "note": "Optional display name"},
            {"resource": "User", "connector_attribute": "directory immutable user ID", "scim_attribute": "externalId", "note": "Recommended immutable key"},
            {"resource": "User", "connector_attribute": "assignment state", "scim_attribute": "active", "note": "false suspends users"},
            {"resource": "Group", "connector_attribute": "group name", "scim_attribute": "displayName", "note": "Group display name"},
            {"resource": "Group", "connector_attribute": "directory immutable group ID", "scim_attribute": "externalId", "note": "Recommended immutable key"},
            {"resource": "Group", "connector_attribute": "assigned User resources", "scim_attribute": "members.value", "note": "Cairn User resource IDs"}
        ],
        "supported_operations": [
            "ServiceProviderConfig, Schemas, and ResourceTypes discovery",
            "User create, list, SearchRequest, get, full replace, bounded PATCH, and soft deprovision",
            "Group create, list, SearchRequest, get, full replace, bounded PATCH, and delete",
            "Bounded Bulk mutations with same-request bulkId references",
            "Token rotation with up to four active SHA-256 token hashes"
        ],
        "validation_checks": [
            "https://id.example.com/scim/v2/ServiceProviderConfig returns application/scim+json",
            "connector can create and update a user with userName, emails[type eq \"work\"].value, displayName, externalId, and active",
            "connector can create and update a group with displayName, externalId, and User members",
            "connector deactivation maps to active=false or DELETE /Users/{id} and leaves audit history intact",
            "retired bearer tokens receive 401 Unauthorized after the rotation window closes"
        ],
        "unsupported_v1_features": [
            "password synchronization",
            "nested group membership",
            "SCIM change-password operation",
            "SCIM ETags",
            "SCIM cursor pagination",
            "Shared Signals Framework events"
        ],
        "smoke_commands": [
            "$env:CAIRN_SCIM_SMOKE_BASE_URL=\"https://id.example.com\"",
            "$env:CAIRN_SCIM_BEARER_TOKEN=\"<raw-token>\"",
            "$env:CAIRN_SCIM_SECONDARY_BEARER_TOKEN=\"<old-or-new-token-during-rotation>\"",
            "$env:CAIRN_SCIM_REJECTED_BEARER_TOKEN=\"<old-or-invalid-token>\"",
            "cairn-api scim smoke"
        ],
        "operator_notes": [
            "Do not store the raw connector token in application environment variables; store only its SHA-256 digest.",
            "Use stable directory object IDs for externalId so retries and renames remain idempotent.",
            "Map SCIM Group members to User resources returned by Cairn; nested Group members are rejected."
        ]
    })
}

pub(super) fn audit_export_receipt() -> Value {
    json!({
        "status": "ok",
        "organization_id": Uuid::new_v4(),
        "output_path": "evidence/cairn-audit-events.ndjson",
        "rows_exported": 2,
        "bytes_written": 256,
        "limit": 100,
        "export_max_rows": 1000,
        "has_more": true,
        "next_after_created_at": "2026-06-07T12:00:00Z",
        "next_after_id": Uuid::new_v4(),
        "filters": {
            "action_prefix": "admin.",
            "target_prefix": null,
            "actor_kind": "system",
            "actor_id": null,
            "created_from": "2026-01-01T00:00:00Z",
            "created_to": null
        },
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

pub(super) fn break_glass_admin_recovery_receipt() -> Value {
    json!({
        "status": "granted",
        "organization_id": Uuid::new_v4(),
        "user_id": Uuid::new_v4(),
        "user_email": "ops@example.com",
        "user_status_before": "suspended",
        "user_status_after": "active",
        "admin_group_id": Uuid::new_v4(),
        "admin_group_created": true,
        "membership_role_before": null,
        "membership_role_after": "owner",
        "audit_event_id": Uuid::new_v4(),
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

pub(super) fn scim_smoke() -> Value {
    let created_user_ids = vec![
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
    ];
    json!({
        "status": "ok",
        "base_url": "https://id.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "secondary_token_checked": true,
        "rejected_token_checked": true,
        "created_user_ids": created_user_ids.clone(),
        "soft_deleted_user_ids": created_user_ids,
        "deleted_group_id": Uuid::new_v4(),
        "checks": REQUIRED_SCIM_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

pub(super) fn scim_connector_smoke(provider: &str) -> Value {
    let first_user_id = Uuid::new_v4();
    let second_user_id = Uuid::new_v4();
    json!({
        "status": "ok",
        "source": "external-scim-connector",
        "provider": provider,
        "display_name": expected_scim_connector_display_name(provider),
        "scim_base_url": "https://id.example.com/scim/v2",
        "completed_at": "2026-06-07T12:00:00Z",
        "connector_application_id": format!("{provider}-application-id"),
        "provisioning_job_id": format!("{provider}-provisioning-job-id"),
        "secondary_token_checked": true,
        "rejected_token_checked": true,
        "created_user_ids": [
            first_user_id,
            second_user_id
        ],
        "deactivated_user_id": first_user_id,
        "deleted_group_id": Uuid::new_v4(),
        "checks": REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{provider} {name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

pub(super) fn oidc_metadata_smoke() -> Value {
    json!({
        "status": "ok",
        "issuer": "https://id.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "checks": REQUIRED_OIDC_METADATA_SMOKE_CHECKS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "status": "passed",
                    "detail": format!("{name} passed")
                })
            })
            .collect::<Vec<_>>()
    })
}

pub(super) fn browser_origin_smoke() -> Value {
    json!({
        "status": "ok",
        "base_url": "https://id.example.com",
        "hostile_origin": "https://browser-origin-smoke.invalid",
        "completed_at": "2026-06-07T12:00:00Z",
        "routes_checked": 2,
        "checks": [
            {
                "name": "logout",
                "method": "POST",
                "path": "/api/v1/session/logout",
                "status": "passed",
                "origin_status": 403,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            },
            {
                "name": "admin user create",
                "method": "POST",
                "path": "/api/v1/users",
                "status": "passed",
                "origin_status": 403,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            }
        ]
    })
}

pub(super) fn security_headers_smoke() -> Value {
    json!({
        "status": "ok",
        "api_base_url": "https://id.example.com",
        "web_base_url": "https://app.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "checks": [
            security_headers_smoke_check("api", "/healthz", Value::Null),
            security_headers_smoke_check("api", "/.well-known/openid-configuration", Value::Null),
            security_headers_smoke_check("web", "/healthz", json!(true)),
            security_headers_smoke_check("web", "/login", Value::Null)
        ]
    })
}

fn security_headers_smoke_check(service: &str, path: &str, cache_control_no_store: Value) -> Value {
    json!({
        "service": service,
        "path": path,
        "status": "passed",
        "status_code": 200,
        "content_security_policy": true,
        "strict_transport_security": true,
        "x_content_type_options_nosniff": true,
        "x_frame_options_deny": true,
        "referrer_policy_no_referrer": true,
        "permissions_policy_restrictive": true,
        "cross_origin_opener_policy_same_origin": true,
        "cache_control_no_store": cache_control_no_store
    })
}

pub(super) fn key_encryption_rotation_receipt() -> Value {
    json!({
        "status": "rotated",
        "signing_keys": 1,
        "email_delivery_tokens": 0,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

pub(super) fn lifecycle_email_smoke_receipt() -> Value {
    json!({
        "status": "completed",
        "provider": "command",
        "completed_at": "2026-06-07T12:00:00Z",
        "messages": [
            lifecycle_email_message("invitation", true),
            lifecycle_email_message("email_verification", true),
            lifecycle_email_message("password_recovery", true),
            lifecycle_email_message("password_recovered_notification", false),
            lifecycle_email_message("password_changed_notification", false),
            lifecycle_email_message("new_login_notification", false)
        ]
    })
}

fn lifecycle_email_message(kind: &str, action_url_present: bool) -> Value {
    json!({
        "kind": kind,
        "template": lifecycle_email_template(kind),
        "status": "sent",
        "action_url_present": action_url_present,
        "provider_message_id": format!("provider-{kind}")
    })
}

fn lifecycle_email_template(kind: &str) -> &str {
    match kind {
        "invitation" => "account_invitation",
        _ => kind,
    }
}

pub(super) fn signing_key_rotation_receipt() -> Value {
    json!({
        "status": "rotated",
        "active_kid": "rs256-active",
        "active": true,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}

pub(super) fn audit_retention_purge_receipt() -> Value {
    json!({
        "status": "ok",
        "organization_id": Uuid::new_v4(),
        "retention_days": 365,
        "cutoff": "2025-06-07T12:00:00Z",
        "batch_size": 1000,
        "deleted": 0,
        "completed_at": "2026-06-07T12:00:00Z"
    })
}
