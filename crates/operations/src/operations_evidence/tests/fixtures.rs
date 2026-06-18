use super::super::oidc::REQUIRED_OIDC_METADATA_SMOKE_CHECKS;
use super::super::scim::{
    REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS, REQUIRED_SCIM_SMOKE_CHECKS,
    expected_scim_connector_display_name,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use uuid::Uuid;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

pub(super) const RELEASE_ASSET_TAG: &str = "v0.1.0-rc.1";
pub(super) const RELEASE_ASSET_SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(super) const RELEASE_ASSET_RELEASE_URL: &str =
    "https://github.com/cairnid/cairnid/releases/tag/v0.1.0-rc.1";
pub(super) const RELEASE_ASSET_RUN_URL: &str =
    "https://github.com/cairnid/cairnid/actions/runs/123456789";
const CLI_COMPLETION_FILES: &[(&str, &str, &str)] = &[
    ("completions/cairnid.bash", "shell-completion", "bash"),
    ("completions/_cairnid", "shell-completion", "zsh"),
    ("completions/cairnid.fish", "shell-completion", "fish"),
    ("completions/cairnid.ps1", "shell-completion", "powershell"),
    ("completions/cairnid.elv", "shell-completion", "elvish"),
];
const CLI_MANPAGE_FILES: &[&str] = &[
    "man/man1/cairnid.1",
    "man/man1/cairnid-completions.1",
    "man/man1/cairnid-evidence.1",
    "man/man1/cairnid-evidence-plan.1",
    "man/man1/cairnid-evidence-manifest.1",
    "man/man1/cairnid-evidence-init.1",
    "man/man1/cairnid-evidence-status.1",
    "man/man1/cairnid-evidence-check.1",
    "man/man1/cairnid-release-assets.1",
    "man/man1/cairnid-release-assets-verify.1",
    "man/man1/cairnid-manpage.1",
    "man/man1/cairnid-manpages.1",
];

pub(super) struct FakeReleaseAssets {
    pub(super) root: PathBuf,
    pub(super) tag: &'static str,
    pub(super) source_commit: &'static str,
    pub(super) release_url: &'static str,
    pub(super) run_url: &'static str,
}

pub(super) fn temp_evidence_dir(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("cairn-release-evidence-{name}-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create temp evidence dir");
    root
}

pub(super) fn fake_release_assets_dir(name: &str) -> FakeReleaseAssets {
    let root = std::env::temp_dir().join(format!("cairn-release-assets-{name}-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create fake release assets dir");

    let targets = [
        ("x86_64-unknown-linux-gnu", "linux", "tar.gz"),
        ("x86_64-pc-windows-msvc", "windows", "zip"),
    ];
    let binaries = [
        ("cairnid", "apps/cli", "operator CLI"),
        ("cairnid-mcp", "apps/mcp", "stdio MCP server"),
    ];

    let mut manifest_assets = Vec::new();
    let mut checksums = BTreeMap::new();
    for (binary, package, description) in binaries {
        for (target, os, archive_format) in targets {
            let stem = format!("{binary}-{RELEASE_ASSET_TAG}-{target}");
            let archive_name = format!("{stem}.{archive_format}");
            let sbom_name = format!("{stem}.sbom.cdx.json");

            let archive_path = root.join(&archive_name);
            write_release_archive(
                &archive_path,
                archive_format,
                &stem,
                binary,
                target,
                package,
            );
            let archive_hash = sha256_file(&archive_path);
            checksums.insert(archive_name.clone(), archive_hash.clone());

            let sbom_path = root.join(&sbom_name);
            fs::write(
                &sbom_path,
                serde_json::to_string_pretty(&json!({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "name": binary,
                            "version": RELEASE_ASSET_TAG
                        }
                    },
                    "components": []
                }))
                .expect("serialize fake SBOM"),
            )
            .expect("write SBOM");
            let sbom_hash = sha256_file(&sbom_path);
            checksums.insert(sbom_name.clone(), sbom_hash.clone());

            let mut archive_asset = json!({
                "name": archive_name,
                "kind": "archive",
                "binary": binary,
                "description": description,
                "target": target,
                "os": os,
                "arch": "x86_64",
                "archive_format": archive_format,
                "sha256": archive_hash,
                "size_bytes": archive_path.metadata().expect("archive metadata").len(),
                "sbom": sbom_name
            });
            if package == "apps/cli" {
                archive_asset["auxiliary_files"] = json!(cli_auxiliary_manifest_entries(&stem));
            }
            manifest_assets.push(archive_asset);
            manifest_assets.push(json!({
                "name": sbom_name,
                "kind": "sbom",
                "binary": binary,
                "format": "CycloneDX JSON",
                "target": target,
                "os": os,
                "arch": "x86_64",
                "sha256": sbom_hash,
                "size_bytes": sbom_path.metadata().expect("SBOM metadata").len(),
                "subject": archive_name
            }));
        }
    }

    let manifest = json!({
        "schema_version": 1,
        "project": "cairnid",
        "tag": RELEASE_ASSET_TAG,
        "version": "0.1.0-rc.1",
        "release_type": "release-candidate",
        "draft": true,
        "prerelease": true,
        "generated_at": "2026-06-07T12:00:00Z",
        "source": {
            "repository": "cairnid/cairnid",
            "commit": RELEASE_ASSET_SOURCE_COMMIT,
            "ref": "refs/tags/v0.1.0-rc.1",
            "workflow": "Release",
            "workflow_ref": "cairnid/cairnid/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1",
            "run_id": "123456789",
            "run_attempt": "1",
            "run_url": RELEASE_ASSET_RUN_URL,
            "validated_ci_run_url": "https://github.com/cairnid/cairnid/actions/runs/123456700"
        },
        "distribution": {
            "release_workflow": ".github/workflows/release.yml",
            "crates_io": false,
            "homebrew": false,
            "msi": false,
            "macos": false,
            "containers": false
        },
        "checksums": {
            "algorithm": "SHA-256",
            "file": "SHA256SUMS.txt",
            "note": "GitHub also exposes release asset digest metadata after upload."
        },
        "provenance": {
            "github_artifact_attestations": true,
            "action": "actions/attest@v4",
            "key_material": "GitHub Actions OIDC and Sigstore; no long-lived signing key"
        },
        "sbom": {
            "generator": "cargo-cyclonedx",
            "generator_version": "0.5.8",
            "format": "CycloneDX JSON",
            "spec_version": "1.5"
        },
        "tools": {
            "rustc": "rustc 1.94.0",
            "cargo": "cargo 1.94.0",
            "cargo_cyclonedx": "cargo-cyclonedx 0.5.8"
        },
        "assets": manifest_assets
    });
    let manifest_path = root.join("release-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize manifest") + "\n",
    )
    .expect("write manifest");
    checksums.insert(
        "release-manifest.json".to_owned(),
        sha256_file(&manifest_path),
    );

    let checksum_text = checksums
        .iter()
        .map(|(file_name, hash)| format!("{hash}  {file_name}\n"))
        .collect::<String>();
    fs::write(root.join("SHA256SUMS.txt"), checksum_text).expect("write checksums");

    FakeReleaseAssets {
        root,
        tag: RELEASE_ASSET_TAG,
        source_commit: RELEASE_ASSET_SOURCE_COMMIT,
        release_url: RELEASE_ASSET_RELEASE_URL,
        run_url: RELEASE_ASSET_RUN_URL,
    }
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

fn write_release_archive(
    path: &Path,
    archive_format: &str,
    stem: &str,
    binary: &str,
    target: &str,
    package: &str,
) {
    let members = release_archive_members(stem, binary, target, package);
    match archive_format {
        "zip" => write_zip_archive(path, &members),
        "tar.gz" => write_tar_gz_archive(path, &members),
        other => panic!("unsupported archive format {other}"),
    }
}

fn release_archive_members(
    stem: &str,
    binary: &str,
    target: &str,
    package: &str,
) -> Vec<(String, Vec<u8>)> {
    let binary_name = if target == "x86_64-pc-windows-msvc" {
        format!("{binary}.exe")
    } else {
        binary.to_owned()
    };
    let mut members = vec![
        (
            format!("{stem}/{binary_name}"),
            format!("fake binary for {binary} {target}\n").into_bytes(),
        ),
        (format!("{stem}/LICENSE"), b"Apache-2.0\n".to_vec()),
        (format!("{stem}/README.md"), b"# CairnID\n".to_vec()),
    ];
    if package == "apps/cli" {
        members.extend(cli_auxiliary_archive_members(stem));
    }
    members
}

fn cli_auxiliary_manifest_entries(stem: &str) -> Vec<Value> {
    CLI_COMPLETION_FILES
        .iter()
        .map(|(path, kind, shell)| {
            json!({"path": format!("{stem}/{path}"), "kind": kind, "shell": shell})
        })
        .chain(CLI_MANPAGE_FILES.iter().map(|path| {
            json!({"path": format!("{stem}/{path}"), "kind": "manpage", "section": "1"})
        }))
        .collect()
}

fn cli_auxiliary_archive_members(stem: &str) -> Vec<(String, Vec<u8>)> {
    CLI_COMPLETION_FILES
        .iter()
        .map(|(path, _kind, shell)| {
            let content = match *shell {
                "bash" => b"complete -F _cairnid cairnid\n".to_vec(),
                "zsh" => b"#compdef cairnid\n".to_vec(),
                "fish" => b"complete -c cairnid\n".to_vec(),
                "powershell" => {
                    b"Register-ArgumentCompleter -Native -CommandName cairnid\n".to_vec()
                }
                "elvish" => b"edit:completion:arg-completer[cairnid] = {|@words| }\n".to_vec(),
                other => panic!("unsupported shell {other}"),
            };
            (format!("{stem}/{path}"), content)
        })
        .chain(CLI_MANPAGE_FILES.iter().map(|path| {
            let page = path
                .strip_prefix("man/man1/")
                .expect("manpage path prefix")
                .trim_end_matches(".1")
                .to_ascii_uppercase();
            (
                format!("{stem}/{path}"),
                format!(".TH {page} 1\n").into_bytes(),
            )
        }))
        .collect()
}

fn write_zip_archive(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = File::create(path).expect("create zip archive");
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, content) in members {
        archive
            .start_file(name, options)
            .expect("start zip archive member");
        archive
            .write_all(content)
            .expect("write zip archive member");
    }
    archive.finish().expect("finish zip archive");
}

fn write_tar_gz_archive(path: &Path, members: &[(String, Vec<u8>)]) {
    let file = File::create(path).expect("create tar.gz archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, content) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, content.as_slice())
            .expect("append tar archive member");
    }
    let encoder = archive.into_inner().expect("finish tar archive");
    encoder.finish().expect("finish gzip archive");
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file for sha256");
    format!("{:x}", Sha256::digest(bytes))
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

pub(super) fn release_assets_verification() -> Value {
    let tag = "v0.1.0-rc.1";
    json!({
        "status": "ok",
        "completed_at": "2026-06-07T12:00:00Z",
        "release_tag": tag,
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "release_url": "https://github.com/cairnid/cairnid/releases/tag/v0.1.0-rc.1",
        "run_url": "https://github.com/cairnid/cairnid/actions/runs/123456789",
        "checksums": {
            "file_name": "SHA256SUMS.txt",
            "algorithm": "SHA-256",
            "present": true,
            "verified": true
        },
        "release_manifest": {
            "file_name": "release-manifest.json",
            "present": true,
            "sha256_verified": true
        },
        "attestations": {
            "signer_workflow": "cairnid/cairnid/.github/workflows/release.yml",
            "source_ref": "refs/tags/v0.1.0-rc.1",
            "provenance_verified": true,
            "sbom_attestations_verified": true
        },
        "archives": [
            release_archive("cairnid", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
            release_archive("cairnid", tag, "x86_64-pc-windows-msvc", "zip"),
            release_archive("cairnid-mcp", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
            release_archive("cairnid-mcp", tag, "x86_64-pc-windows-msvc", "zip")
        ],
        "sboms": [
            release_sbom("cairnid", tag, "x86_64-unknown-linux-gnu"),
            release_sbom("cairnid", tag, "x86_64-pc-windows-msvc"),
            release_sbom("cairnid-mcp", tag, "x86_64-unknown-linux-gnu"),
            release_sbom("cairnid-mcp", tag, "x86_64-pc-windows-msvc")
        ],
        "failures": []
    })
}

fn release_archive(binary: &str, tag: &str, target: &str, archive_format: &str) -> Value {
    json!({
        "file_name": format!("{binary}-{tag}-{target}.{archive_format}"),
        "binary": binary,
        "target": target,
        "archive_format": archive_format,
        "present": true,
        "sha256": "a".repeat(64),
        "sha256_verified": true,
        "manifest_entry_present": true,
        "github_attestation_verified": true,
        "sbom_file_name": format!("{binary}-{tag}-{target}.sbom.cdx.json"),
        "sbom_attestation_verified": true
    })
}

fn release_sbom(binary: &str, tag: &str, target: &str) -> Value {
    json!({
        "file_name": format!("{binary}-{tag}-{target}.sbom.cdx.json"),
        "binary": binary,
        "target": target,
        "format": "CycloneDX JSON",
        "present": true,
        "sha256": "b".repeat(64),
        "sha256_verified": true,
        "manifest_entry_present": true,
        "github_attestation_verified": true
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
            "Built-in smoke covers bounded Bulk mutations with same-request bulkId references",
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
