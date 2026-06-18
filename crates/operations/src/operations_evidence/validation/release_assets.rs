use serde_json::Value;
use url::Url;

use crate::operations_evidence::release_assets::{
    EXPECTED_RELEASE_ASSETS, ExpectedReleaseAsset, archive_file_name, sbom_file_name,
};

use super::{
    require_bool, require_empty_array, require_rfc3339_timestamp, require_string, value_at_path,
};

pub(in crate::operations_evidence) fn validate_release_assets_verification(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    require_empty_array(value, "failures", failures);
    require_rfc3339_timestamp(value, "completed_at", "release assets", checks, failures);

    let raw_release_tag = value.get("release_tag").and_then(Value::as_str);
    let release_tag = validate_release_tag(value, failures);
    validate_source_commit(value, failures);
    validate_release_or_run_url(value, release_tag, failures);
    validate_checksums(value, failures);
    validate_release_manifest(value, failures);
    validate_attestations(value, release_tag, failures);

    if let Some(release_tag) = raw_release_tag {
        validate_release_archives(value, release_tag, failures);
        validate_release_sboms(value, release_tag, failures);
    }

    if failures.is_empty() {
        checks.push("public CLI/MCP release assets verified".to_owned());
    }
}

fn validate_release_tag<'a>(value: &'a Value, failures: &mut Vec<String>) -> Option<&'a str> {
    let Some(tag) = value.get("release_tag").and_then(Value::as_str) else {
        failures.push("release_tag must be a public release tag".to_owned());
        return None;
    };
    if release_tag_is_valid(tag) {
        Some(tag)
    } else {
        failures.push(
            "release_tag must match vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N".to_owned(),
        );
        None
    }
}

fn release_tag_is_valid(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let (version, rc) = match version.split_once("-rc.") {
        Some((version, rc)) => (version, Some(rc)),
        None => (version, None),
    };
    let version_parts = version.split('.').collect::<Vec<_>>();
    version_parts.len() == 3
        && version_parts.iter().all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
        && rc.is_none_or(|rc| {
            !rc.is_empty() && rc.chars().all(|character| character.is_ascii_digit())
        })
}

fn validate_source_commit(value: &Value, failures: &mut Vec<String>) {
    match value.get("source_commit").and_then(Value::as_str) {
        Some(commit)
            if commit.len() == 40
                && commit
                    .chars()
                    .all(|character| character.is_ascii_hexdigit()) => {}
        Some(_) => failures.push("source_commit must be a 40-character git commit SHA".to_owned()),
        None => failures.push("source_commit must be a 40-character git commit SHA".to_owned()),
    }
}

fn validate_release_or_run_url(
    value: &Value,
    release_tag: Option<&str>,
    failures: &mut Vec<String>,
) {
    let release_url = value.get("release_url").and_then(Value::as_str);
    let run_url = value.get("run_url").and_then(Value::as_str);
    if release_url.is_none_or(str::is_empty) && run_url.is_none_or(str::is_empty) {
        failures.push("release_url or run_url must be present".to_owned());
        return;
    }

    if let Some(release_url) = release_url
        && !release_url.is_empty()
    {
        validate_github_url(
            release_url,
            "release_url",
            release_tag.map(|tag| format!("/cairnid/cairnid/releases/tag/{tag}")),
            "/cairnid/cairnid/releases/tag/",
            failures,
        );
    }
    if let Some(run_url) = run_url
        && !run_url.is_empty()
    {
        validate_github_url(
            run_url,
            "run_url",
            None,
            "/cairnid/cairnid/actions/runs/",
            failures,
        );
    }
}

fn validate_github_url(
    value: &str,
    field: &'static str,
    exact_path: Option<String>,
    path_prefix: &'static str,
    failures: &mut Vec<String>,
) {
    match Url::parse(value) {
        Ok(url) => {
            let path_matches = exact_path.as_ref().map_or_else(
                || url.path().starts_with(path_prefix),
                |path| url.path() == path,
            );
            if !(url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && path_matches)
            {
                failures.push(format!(
                    "{field} must be a GitHub HTTPS URL under {path_prefix} without credentials, query, or fragment"
                ));
            }
        }
        Err(_) => failures.push(format!("{field} must be a valid GitHub HTTPS URL")),
    }
}

fn validate_checksums(value: &Value, failures: &mut Vec<String>) {
    require_string_at_path_dynamic(
        value,
        "checksums.file_name",
        &["checksums", "file_name"],
        "SHA256SUMS.txt",
        failures,
    );
    require_string_at_path_dynamic(
        value,
        "checksums.algorithm",
        &["checksums", "algorithm"],
        "SHA-256",
        failures,
    );
    require_bool(value, &["checksums", "present"], true, failures);
    require_bool(value, &["checksums", "verified"], true, failures);
}

fn validate_release_manifest(value: &Value, failures: &mut Vec<String>) {
    require_string_at_path_dynamic(
        value,
        "release_manifest.file_name",
        &["release_manifest", "file_name"],
        "release-manifest.json",
        failures,
    );
    require_bool(value, &["release_manifest", "present"], true, failures);
    require_bool(
        value,
        &["release_manifest", "sha256_verified"],
        true,
        failures,
    );
}

fn validate_attestations(value: &Value, release_tag: Option<&str>, failures: &mut Vec<String>) {
    require_string_at_path_dynamic(
        value,
        "attestations.signer_workflow",
        &["attestations", "signer_workflow"],
        "cairnid/cairnid/.github/workflows/release.yml",
        failures,
    );
    if let Some(release_tag) = release_tag {
        require_string_at_path_dynamic(
            value,
            "attestations.source_ref",
            &["attestations", "source_ref"],
            &format!("refs/tags/{release_tag}"),
            failures,
        );
    }
    require_bool(
        value,
        &["attestations", "provenance_verified"],
        true,
        failures,
    );
    require_bool(
        value,
        &["attestations", "sbom_attestations_verified"],
        true,
        failures,
    );
}

fn validate_release_archives(value: &Value, release_tag: &str, failures: &mut Vec<String>) {
    let Some(archives) = value.get("archives").and_then(Value::as_array) else {
        failures.push("archives must be an array".to_owned());
        return;
    };
    if archives.len() != EXPECTED_RELEASE_ASSETS.len() {
        failures.push(format!(
            "archives must contain exactly {} public CLI/MCP archives",
            EXPECTED_RELEASE_ASSETS.len()
        ));
    }

    for expected in EXPECTED_RELEASE_ASSETS {
        let Some(asset) = find_asset(archives, *expected) else {
            failures.push(format!(
                "archives must include {} for {}",
                expected.binary, expected.target
            ));
            continue;
        };
        let prefix = format!("archives[{}:{}]", expected.binary, expected.target);
        validate_archive_asset(asset, expected, release_tag, &prefix, failures);
    }
}

fn validate_release_sboms(value: &Value, release_tag: &str, failures: &mut Vec<String>) {
    let Some(sboms) = value.get("sboms").and_then(Value::as_array) else {
        failures.push("sboms must be an array".to_owned());
        return;
    };
    if sboms.len() != EXPECTED_RELEASE_ASSETS.len() {
        failures.push(format!(
            "sboms must contain exactly {} CycloneDX SBOMs",
            EXPECTED_RELEASE_ASSETS.len()
        ));
    }

    for expected in EXPECTED_RELEASE_ASSETS {
        let Some(asset) = find_asset(sboms, *expected) else {
            failures.push(format!(
                "sboms must include {} for {}",
                expected.binary, expected.target
            ));
            continue;
        };
        let prefix = format!("sboms[{}:{}]", expected.binary, expected.target);
        validate_sbom_asset(asset, expected, release_tag, &prefix, failures);
    }
}

fn find_asset(assets: &[Value], expected: ExpectedReleaseAsset) -> Option<&Value> {
    assets.iter().find(|asset| {
        asset.get("binary").and_then(Value::as_str) == Some(expected.binary)
            && asset.get("target").and_then(Value::as_str) == Some(expected.target)
    })
}

fn validate_archive_asset(
    asset: &Value,
    expected: &ExpectedReleaseAsset,
    release_tag: &str,
    prefix: &str,
    failures: &mut Vec<String>,
) {
    let expected_archive = archive_file_name(expected, release_tag);
    let expected_sbom = sbom_file_name(expected, release_tag);
    require_asset_string(asset, prefix, "file_name", &expected_archive, failures);
    require_asset_string(asset, prefix, "binary", expected.binary, failures);
    require_asset_string(asset, prefix, "target", expected.target, failures);
    require_asset_string(
        asset,
        prefix,
        "archive_format",
        expected.archive_format,
        failures,
    );
    require_asset_string(asset, prefix, "sbom_file_name", &expected_sbom, failures);
    require_asset_bool(asset, prefix, "present", true, failures);
    require_asset_bool(asset, prefix, "sha256_verified", true, failures);
    require_asset_bool(asset, prefix, "manifest_entry_present", true, failures);
    require_asset_bool(asset, prefix, "github_attestation_verified", true, failures);
    require_asset_bool(asset, prefix, "sbom_attestation_verified", true, failures);
    require_asset_sha256(asset, prefix, failures);
}

fn validate_sbom_asset(
    asset: &Value,
    expected: &ExpectedReleaseAsset,
    release_tag: &str,
    prefix: &str,
    failures: &mut Vec<String>,
) {
    let expected_sbom = sbom_file_name(expected, release_tag);
    require_asset_string(asset, prefix, "file_name", &expected_sbom, failures);
    require_asset_string(asset, prefix, "binary", expected.binary, failures);
    require_asset_string(asset, prefix, "target", expected.target, failures);
    require_asset_string(asset, prefix, "format", "CycloneDX JSON", failures);
    require_asset_bool(asset, prefix, "present", true, failures);
    require_asset_bool(asset, prefix, "sha256_verified", true, failures);
    require_asset_bool(asset, prefix, "manifest_entry_present", true, failures);
    require_asset_bool(asset, prefix, "github_attestation_verified", true, failures);
    require_asset_sha256(asset, prefix, failures);
}

fn require_asset_string(
    value: &Value,
    prefix: &str,
    field: &'static str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    match value.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{prefix}.{field} must be {expected}, got {actual}")),
        None => failures.push(format!("{prefix}.{field} must be {expected}")),
    }
}

fn require_asset_bool(
    value: &Value,
    prefix: &str,
    field: &'static str,
    expected: bool,
    failures: &mut Vec<String>,
) {
    match value.get(field).and_then(Value::as_bool) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{prefix}.{field} must be {expected}, got {actual}")),
        None => failures.push(format!("{prefix}.{field} must be {expected}")),
    }
}

fn require_asset_sha256(value: &Value, prefix: &str, failures: &mut Vec<String>) {
    match value.get("sha256").and_then(Value::as_str) {
        Some(hash)
            if hash.len() == 64 && hash.chars().all(|character| character.is_ascii_hexdigit()) => {}
        Some(_) => failures.push(format!(
            "{prefix}.sha256 must be a 64-character SHA-256 hex digest"
        )),
        None => failures.push(format!(
            "{prefix}.sha256 must be a 64-character SHA-256 hex digest"
        )),
    }
}

fn require_string_at_path_dynamic(
    value: &Value,
    prefix: &str,
    path: &[&'static str],
    expected: &str,
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{prefix} must be {expected}, got {actual}")),
        None => failures.push(format!("{prefix} must be {expected}")),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_release_assets_verification;
    use serde_json::{Value, json};

    #[test]
    fn release_assets_verification_accepts_complete_receipt() {
        let value = release_assets_verification();
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_release_assets_verification(&value, &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(checks.contains(&"public CLI/MCP release assets verified".to_owned()));
    }

    #[test]
    fn release_assets_verification_rejects_missing_archive_and_unverified_attestation() {
        let mut value = release_assets_verification();
        value["archives"]
            .as_array_mut()
            .expect("archives array")
            .pop();
        value["attestations"]["provenance_verified"] = json!(false);
        value["release_tag"] = json!("v0.1");
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_release_assets_verification(&value, &mut checks, &mut failures);

        assert!(checks.contains(&"release assets completion timestamp is valid".to_owned()));
        assert!(
            failures
                .iter()
                .any(|failure| { failure.contains("release_tag must match vMAJOR.MINOR.PATCH") })
        );
        assert!(
            failures.iter().any(|failure| {
                failure.contains("attestations.provenance_verified must be true")
            })
        );
        assert!(failures.iter().any(|failure| {
            failure.contains("archives must contain exactly 4 public CLI/MCP archives")
        }));
    }

    fn release_assets_verification() -> Value {
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
                archive("cairnid", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
                archive("cairnid", tag, "x86_64-pc-windows-msvc", "zip"),
                archive("cairnid-mcp", tag, "x86_64-unknown-linux-gnu", "tar.gz"),
                archive("cairnid-mcp", tag, "x86_64-pc-windows-msvc", "zip")
            ],
            "sboms": [
                sbom("cairnid", tag, "x86_64-unknown-linux-gnu"),
                sbom("cairnid", tag, "x86_64-pc-windows-msvc"),
                sbom("cairnid-mcp", tag, "x86_64-unknown-linux-gnu"),
                sbom("cairnid-mcp", tag, "x86_64-pc-windows-msvc")
            ],
            "failures": []
        })
    }

    fn archive(binary: &str, tag: &str, target: &str, archive_format: &str) -> Value {
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

    fn sbom(binary: &str, tag: &str, target: &str) -> Value {
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
}
