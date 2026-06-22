use super::validation::validate_release_assets_verification;
use flate2::bufread::GzDecoder;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use url::Url;
use zip::ZipArchive;

pub(in crate::operations_evidence) const CHECKSUM_FILE_NAME: &str = "SHA256SUMS.txt";
pub(in crate::operations_evidence) const RELEASE_MANIFEST_FILE_NAME: &str = "release-manifest.json";
pub(in crate::operations_evidence) const SIGNER_WORKFLOW: &str =
    "cairnid/cairnid/.github/workflows/release.yml";
pub(in crate::operations_evidence) const PUBLIC_RELEASE_URL_REQUIRED_FAILURE: &str = "release_url must be present for public release evidence; workflow run URLs are workflow-local validation only";
pub(in crate::operations_evidence) const GITHUB_RELEASE_IMMUTABILITY_REQUIRED_FAILURE: &str = "--github-release-immutability-enabled-before-publish must be supplied for published release evidence after confirming GitHub release immutability was enabled before publication";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliAuxiliaryFile {
    path: &'static str,
    kind: &'static str,
    shell: Option<&'static str>,
    section: Option<&'static str>,
}

const CLI_AUXILIARY_FILES: &[CliAuxiliaryFile] = &[
    CliAuxiliaryFile {
        path: "completions/cairnid.bash",
        kind: "shell-completion",
        shell: Some("bash"),
        section: None,
    },
    CliAuxiliaryFile {
        path: "completions/_cairnid",
        kind: "shell-completion",
        shell: Some("zsh"),
        section: None,
    },
    CliAuxiliaryFile {
        path: "completions/cairnid.fish",
        kind: "shell-completion",
        shell: Some("fish"),
        section: None,
    },
    CliAuxiliaryFile {
        path: "completions/cairnid.ps1",
        kind: "shell-completion",
        shell: Some("powershell"),
        section: None,
    },
    CliAuxiliaryFile {
        path: "completions/cairnid.elv",
        kind: "shell-completion",
        shell: Some("elvish"),
        section: None,
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-completions.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence-plan.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence-manifest.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence-init.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence-status.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-evidence-check.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-release-assets.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-release-assets-verify.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-manpage.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
    CliAuxiliaryFile {
        path: "man/man1/cairnid-manpages.1",
        kind: "manpage",
        shell: None,
        section: Some("1"),
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::operations_evidence) struct ExpectedReleaseAsset {
    pub(in crate::operations_evidence) binary: &'static str,
    pub(in crate::operations_evidence) target: &'static str,
    pub(in crate::operations_evidence) archive_format: &'static str,
}

pub(in crate::operations_evidence) const EXPECTED_RELEASE_ASSETS: &[ExpectedReleaseAsset] = &[
    ExpectedReleaseAsset {
        binary: "cairnid",
        target: "x86_64-unknown-linux-gnu",
        archive_format: "tar.gz",
    },
    ExpectedReleaseAsset {
        binary: "cairnid",
        target: "x86_64-pc-windows-msvc",
        archive_format: "zip",
    },
    ExpectedReleaseAsset {
        binary: "cairnid-mcp",
        target: "x86_64-unknown-linux-gnu",
        archive_format: "tar.gz",
    },
    ExpectedReleaseAsset {
        binary: "cairnid-mcp",
        target: "x86_64-pc-windows-msvc",
        archive_format: "zip",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAssetsVerificationOptions {
    pub release_dir: PathBuf,
    pub release_tag: String,
    pub source_commit: String,
    pub release_url: Option<String>,
    pub run_url: Option<String>,
    pub provenance_attestations_verified: bool,
    pub sbom_attestations_verified: bool,
    pub github_release_immutability_enabled_before_publish: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseAssetsVerificationReceipt {
    pub status: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub release_tag: String,
    pub source_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_url: Option<String>,
    pub github_release_immutability_enabled_before_publish: bool,
    pub checksums: ReleaseAssetChecksumsReceipt,
    pub release_manifest: ReleaseAssetManifestReceipt,
    pub attestations: ReleaseAssetAttestationsReceipt,
    pub archives: Vec<ReleaseArchiveReceipt>,
    pub sboms: Vec<ReleaseSbomReceipt>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseAssetChecksumsReceipt {
    pub file_name: &'static str,
    pub algorithm: &'static str,
    pub present: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseAssetManifestReceipt {
    pub file_name: &'static str,
    pub present: bool,
    pub sha256_verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseAssetAttestationsReceipt {
    pub signer_workflow: &'static str,
    pub source_ref: String,
    pub provenance_verified: bool,
    pub sbom_attestations_verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseArchiveReceipt {
    pub file_name: String,
    pub binary: &'static str,
    pub target: &'static str,
    pub archive_format: &'static str,
    pub present: bool,
    pub sha256: String,
    pub sha256_verified: bool,
    pub manifest_entry_present: bool,
    pub github_attestation_verified: bool,
    pub sbom_file_name: String,
    pub sbom_attestation_verified: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReleaseSbomReceipt {
    pub file_name: String,
    pub binary: &'static str,
    pub target: &'static str,
    pub format: &'static str,
    pub present: bool,
    pub sha256: String,
    pub sha256_verified: bool,
    pub manifest_entry_present: bool,
    pub github_attestation_verified: bool,
}

#[derive(Debug)]
pub enum ReleaseAssetsVerificationError {
    NotDirectory,
    Io(std::io::Error),
    Json(serde_json::Error),
    VerificationFailed(Vec<String>),
}

impl ReleaseAssetsVerificationError {
    pub fn failures(&self) -> Option<&[String]> {
        match self {
            Self::VerificationFailed(failures) => Some(failures),
            Self::NotDirectory | Self::Io(_) | Self::Json(_) => None,
        }
    }
}

impl fmt::Display for ReleaseAssetsVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDirectory => formatter.write_str("release assets path is not a directory"),
            Self::Io(error) => write!(formatter, "release assets filesystem error: {error}"),
            Self::Json(error) => write!(
                formatter,
                "release assets JSON serialization error: {error}"
            ),
            Self::VerificationFailed(failures) if failures.is_empty() => {
                formatter.write_str("release assets verification failed")
            }
            Self::VerificationFailed(failures) => {
                write!(
                    formatter,
                    "release assets verification failed: {}",
                    failures.join("; ")
                )
            }
        }
    }
}

impl Error for ReleaseAssetsVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::NotDirectory | Self::VerificationFailed(_) => None,
        }
    }
}

pub fn release_assets_verification_receipt(
    options: &ReleaseAssetsVerificationOptions,
    completed_at: OffsetDateTime,
) -> Result<ReleaseAssetsVerificationReceipt, ReleaseAssetsVerificationError> {
    let receipt = release_assets_verification_report(options, completed_at)?;
    if receipt.status == "ok" && receipt.failures.is_empty() {
        Ok(receipt)
    } else {
        Err(ReleaseAssetsVerificationError::VerificationFailed(
            receipt.failures,
        ))
    }
}

pub fn release_assets_verification_report(
    options: &ReleaseAssetsVerificationOptions,
    completed_at: OffsetDateTime,
) -> Result<ReleaseAssetsVerificationReceipt, ReleaseAssetsVerificationError> {
    if !options.release_dir.is_dir() {
        return Err(ReleaseAssetsVerificationError::NotDirectory);
    }

    let mut failures = Vec::new();
    validate_attestation_confirmations(options, &mut failures);
    validate_github_release_immutability_confirmation(options, &mut failures);
    validate_public_release_url_option(options, &mut failures);

    let checksum_entries = read_checksums(&options.release_dir, &mut failures)?;
    let manifest = read_json_file(
        &options.release_dir,
        RELEASE_MANIFEST_FILE_NAME,
        &mut failures,
    )?;

    let release_manifest_sha256 = verify_file_sha256(
        &options.release_dir,
        RELEASE_MANIFEST_FILE_NAME,
        &checksum_entries,
        &mut failures,
    )?;
    if release_manifest_sha256.is_none() {
        failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME} must be covered by {CHECKSUM_FILE_NAME}"
        ));
    }

    validate_manifest_metadata(manifest.as_ref(), options, &mut failures);

    let verification_context = ReleaseAssetVerificationContext {
        release_dir: &options.release_dir,
        checksum_entries: &checksum_entries,
        manifest: manifest.as_ref(),
    };
    let mut archives = Vec::new();
    let mut sboms = Vec::new();
    for expected in EXPECTED_RELEASE_ASSETS {
        let archive_file_name = archive_file_name(expected, &options.release_tag);
        let sbom_file_name = sbom_file_name(expected, &options.release_tag);

        if let Some(archive_hash) = verify_release_asset(
            &verification_context,
            &archive_file_name,
            ManifestAssetExpectation {
                expected_kind: "archive",
                expected,
                linked_file_name: Some(&sbom_file_name),
            },
            &mut failures,
        )? {
            validate_archive_structure(
                &options.release_dir,
                &archive_file_name,
                expected,
                &options.release_tag,
                &mut failures,
            );
            archives.push(ReleaseArchiveReceipt {
                file_name: archive_file_name.clone(),
                binary: expected.binary,
                target: expected.target,
                archive_format: expected.archive_format,
                present: true,
                sha256: archive_hash,
                sha256_verified: true,
                manifest_entry_present: true,
                github_attestation_verified: options.provenance_attestations_verified,
                sbom_file_name: sbom_file_name.clone(),
                sbom_attestation_verified: options.sbom_attestations_verified,
            });
        }

        if let Some(sbom_hash) = verify_release_asset(
            &verification_context,
            &sbom_file_name,
            ManifestAssetExpectation {
                expected_kind: "sbom",
                expected,
                linked_file_name: Some(&archive_file_name),
            },
            &mut failures,
        )? {
            validate_sbom_format(&options.release_dir, &sbom_file_name, &mut failures)?;
            sboms.push(ReleaseSbomReceipt {
                file_name: sbom_file_name,
                binary: expected.binary,
                target: expected.target,
                format: "CycloneDX JSON",
                present: true,
                sha256: sbom_hash,
                sha256_verified: true,
                manifest_entry_present: true,
                github_attestation_verified: options.provenance_attestations_verified,
            });
        }
    }

    let mut receipt = ReleaseAssetsVerificationReceipt {
        status: if failures.is_empty() { "ok" } else { "failed" },
        completed_at,
        release_tag: options.release_tag.clone(),
        source_commit: options.source_commit.clone(),
        release_url: safe_public_github_url(&options.release_url, "/cairnid/cairnid/releases/tag/"),
        run_url: safe_public_github_url(&options.run_url, "/cairnid/cairnid/actions/runs/"),
        github_release_immutability_enabled_before_publish: options.release_url.is_some()
            && options.github_release_immutability_enabled_before_publish,
        checksums: ReleaseAssetChecksumsReceipt {
            file_name: CHECKSUM_FILE_NAME,
            algorithm: "SHA-256",
            present: options.release_dir.join(CHECKSUM_FILE_NAME).is_file(),
            verified: !failures
                .iter()
                .any(|failure| failure.starts_with(CHECKSUM_FILE_NAME)),
        },
        release_manifest: ReleaseAssetManifestReceipt {
            file_name: RELEASE_MANIFEST_FILE_NAME,
            present: options
                .release_dir
                .join(RELEASE_MANIFEST_FILE_NAME)
                .is_file(),
            sha256_verified: release_manifest_sha256.is_some(),
        },
        attestations: ReleaseAssetAttestationsReceipt {
            signer_workflow: SIGNER_WORKFLOW,
            source_ref: format!("refs/tags/{}", options.release_tag),
            provenance_verified: options.provenance_attestations_verified,
            sbom_attestations_verified: options.sbom_attestations_verified,
        },
        archives,
        sboms,
        failures,
    };

    if receipt.failures.is_empty() {
        let mut contract_checks = Vec::new();
        let mut contract_failures = Vec::new();
        let value = serde_json::to_value(&receipt).map_err(ReleaseAssetsVerificationError::Json)?;
        validate_release_assets_verification(&value, &mut contract_checks, &mut contract_failures);
        if !contract_failures.is_empty() {
            receipt.status = "failed";
            receipt.failures = contract_failures;
        }
    }

    Ok(receipt)
}

pub(in crate::operations_evidence) fn archive_file_name(
    expected: &ExpectedReleaseAsset,
    release_tag: &str,
) -> String {
    format!(
        "{}-{release_tag}-{}.{}",
        expected.binary, expected.target, expected.archive_format
    )
}

pub(in crate::operations_evidence) fn sbom_file_name(
    expected: &ExpectedReleaseAsset,
    release_tag: &str,
) -> String {
    format!(
        "{}-{release_tag}-{}.sbom.cdx.json",
        expected.binary, expected.target
    )
}

fn validate_attestation_confirmations(
    options: &ReleaseAssetsVerificationOptions,
    failures: &mut Vec<String>,
) {
    if !options.provenance_attestations_verified {
        failures.push(
            "--provenance-attestations-verified must be supplied after external provenance attestation verification"
                .to_owned(),
        );
    }
    if !options.sbom_attestations_verified {
        failures.push(
            "--sbom-attestations-verified must be supplied after external SBOM attestation verification"
                .to_owned(),
        );
    }
}

fn validate_github_release_immutability_confirmation(
    options: &ReleaseAssetsVerificationOptions,
    failures: &mut Vec<String>,
) {
    if options.release_url.is_some() && !options.github_release_immutability_enabled_before_publish
    {
        failures.push(GITHUB_RELEASE_IMMUTABILITY_REQUIRED_FAILURE.to_owned());
    }
}

fn validate_public_release_url_option(
    options: &ReleaseAssetsVerificationOptions,
    failures: &mut Vec<String>,
) {
    let Some(release_url) = non_empty_option(&options.release_url) else {
        failures.push(PUBLIC_RELEASE_URL_REQUIRED_FAILURE.to_owned());
        return;
    };
    let expected_path = format!("/cairnid/cairnid/releases/tag/{}", options.release_tag);
    match Url::parse(&release_url) {
        Ok(url) => {
            if !(url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == expected_path)
            {
                failures.push(
                    "release_url must be a GitHub HTTPS URL under /cairnid/cairnid/releases/tag/ without credentials, query, or fragment"
                        .to_owned(),
                );
            }
        }
        Err(_) => failures.push("release_url must be a valid GitHub HTTPS URL".to_owned()),
    }
}

fn read_checksums(
    release_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<BTreeMap<String, String>, ReleaseAssetsVerificationError> {
    let path = release_dir.join(CHECKSUM_FILE_NAME);
    if !path.is_file() {
        failures.push(format!("{CHECKSUM_FILE_NAME} must be present"));
        return Ok(BTreeMap::new());
    }

    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            failures.push(format!(
                "{CHECKSUM_FILE_NAME} could not be read: {}",
                safe_io_error(&error)
            ));
            return Ok(BTreeMap::new());
        }
    };
    let mut entries = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let digest = parts.next();
        let file_name = parts.next();
        if digest.is_none()
            || file_name.is_none()
            || parts.next().is_some()
            || !digest.is_some_and(is_sha256_hex)
        {
            failures.push(format!(
                "{CHECKSUM_FILE_NAME} line {} must contain a SHA-256 digest and file name",
                index + 1
            ));
            continue;
        }
        let file_name = file_name
            .expect("checked file name")
            .trim_start_matches('*');
        if entries
            .insert(
                file_name.to_owned(),
                digest.expect("checked digest").to_ascii_lowercase(),
            )
            .is_some()
        {
            failures.push(format!(
                "{CHECKSUM_FILE_NAME} contains duplicate entry for {file_name}"
            ));
        }
    }

    if entries.is_empty() {
        failures.push(format!(
            "{CHECKSUM_FILE_NAME} must contain release asset checksums"
        ));
    }
    Ok(entries)
}

fn read_json_file(
    release_dir: &Path,
    file_name: &str,
    failures: &mut Vec<String>,
) -> Result<Option<Value>, ReleaseAssetsVerificationError> {
    let path = release_dir.join(file_name);
    if !path.is_file() {
        failures.push(format!("{file_name} must be present"));
        return Ok(None);
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!(
                "{file_name} could not be read: {}",
                safe_io_error(&error)
            ));
            return Ok(None);
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            failures.push(format!("{file_name} must contain valid JSON"));
            Ok(None)
        }
    }
}

fn verify_file_sha256(
    release_dir: &Path,
    file_name: &str,
    checksum_entries: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) -> Result<Option<String>, ReleaseAssetsVerificationError> {
    let path = release_dir.join(file_name);
    if !path.is_file() {
        return Ok(None);
    }
    let Some(expected_hash) = checksum_entries.get(file_name) else {
        failures.push(format!("{CHECKSUM_FILE_NAME} is missing {file_name}"));
        return Ok(None);
    };
    let actual_hash = match sha256_file(&path) {
        Ok(hash) => hash,
        Err(error) => {
            failures.push(format!(
                "{file_name} could not be read for SHA-256: {}",
                safe_io_error(&error)
            ));
            return Ok(None);
        }
    };
    if actual_hash != *expected_hash {
        failures.push(format!(
            "{CHECKSUM_FILE_NAME} hash mismatch for {file_name}"
        ));
        return Ok(None);
    }
    Ok(Some(actual_hash))
}

struct ReleaseAssetVerificationContext<'a> {
    release_dir: &'a Path,
    checksum_entries: &'a BTreeMap<String, String>,
    manifest: Option<&'a Value>,
}

struct ManifestAssetExpectation<'a> {
    expected_kind: &'static str,
    expected: &'a ExpectedReleaseAsset,
    linked_file_name: Option<&'a str>,
}

fn verify_release_asset(
    context: &ReleaseAssetVerificationContext<'_>,
    file_name: &str,
    expectation: ManifestAssetExpectation<'_>,
    failures: &mut Vec<String>,
) -> Result<Option<String>, ReleaseAssetsVerificationError> {
    let path = context.release_dir.join(file_name);
    if !path.is_file() {
        failures.push(format!("missing release asset {file_name}"));
        return Ok(None);
    }
    let Some(hash) = verify_file_sha256(
        context.release_dir,
        file_name,
        context.checksum_entries,
        failures,
    )?
    else {
        return Ok(None);
    };

    if let Some(manifest) = context.manifest {
        match find_manifest_asset(manifest, file_name) {
            Some(asset) => validate_manifest_asset(
                asset,
                file_name,
                expectation.expected_kind,
                expectation.expected,
                expectation.linked_file_name,
                &hash,
                failures,
            ),
            None => failures.push(format!(
                "{RELEASE_MANIFEST_FILE_NAME} is missing {file_name}"
            )),
        }
    }

    Ok(Some(hash))
}

fn validate_manifest_metadata(
    manifest: Option<&Value>,
    options: &ReleaseAssetsVerificationOptions,
    failures: &mut Vec<String>,
) {
    let Some(manifest) = manifest else {
        return;
    };

    require_manifest_string(manifest, &["project"], "cairnid", failures);
    require_manifest_string(manifest, &["tag"], &options.release_tag, failures);
    require_manifest_string(
        manifest,
        &["source", "repository"],
        "cairnid/cairnid",
        failures,
    );
    require_manifest_string(
        manifest,
        &["source", "commit"],
        &options.source_commit,
        failures,
    );
    require_manifest_string(
        manifest,
        &["source", "ref"],
        &format!("refs/tags/{}", options.release_tag),
        failures,
    );
    if let Some(run_url) = non_empty_option(&options.run_url) {
        require_manifest_string(manifest, &["source", "run_url"], &run_url, failures);
    }
    require_manifest_string(
        manifest,
        &["distribution", "release_workflow"],
        ".github/workflows/release.yml",
        failures,
    );
    for flag in ["crates_io", "homebrew", "msi", "macos", "containers"] {
        require_manifest_bool_false(manifest, &["distribution", flag], failures);
    }
    require_manifest_string(manifest, &["checksums", "algorithm"], "SHA-256", failures);
    require_manifest_string(
        manifest,
        &["checksums", "file"],
        CHECKSUM_FILE_NAME,
        failures,
    );

    if let Some(assets) = manifest.get("assets").and_then(Value::as_array) {
        let archive_count = assets
            .iter()
            .filter(|asset| asset.get("kind").and_then(Value::as_str) == Some("archive"))
            .count();
        let sbom_count = assets
            .iter()
            .filter(|asset| asset.get("kind").and_then(Value::as_str) == Some("sbom"))
            .count();
        if archive_count != EXPECTED_RELEASE_ASSETS.len()
            || sbom_count != EXPECTED_RELEASE_ASSETS.len()
        {
            failures.push(format!(
                "{RELEASE_MANIFEST_FILE_NAME} assets must describe exactly 4 archives and 4 SBOMs"
            ));
        }
    } else {
        failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME}.assets must be an array"
        ));
    }
}

fn find_manifest_asset<'a>(manifest: &'a Value, file_name: &str) -> Option<&'a Value> {
    manifest
        .get("assets")
        .and_then(Value::as_array)?
        .iter()
        .find(|asset| asset.get("name").and_then(Value::as_str) == Some(file_name))
}

fn validate_manifest_asset(
    asset: &Value,
    file_name: &str,
    expected_kind: &str,
    expected: &ExpectedReleaseAsset,
    linked_file_name: Option<&str>,
    actual_hash: &str,
    failures: &mut Vec<String>,
) {
    require_manifest_asset_string(asset, file_name, "kind", expected_kind, failures);
    require_manifest_asset_string(asset, file_name, "binary", expected.binary, failures);
    require_manifest_asset_string(asset, file_name, "target", expected.target, failures);
    require_manifest_asset_string(asset, file_name, "sha256", actual_hash, failures);
    match expected_kind {
        "archive" => {
            require_manifest_asset_string(
                asset,
                file_name,
                "archive_format",
                expected.archive_format,
                failures,
            );
            if let Some(sbom_file_name) = linked_file_name {
                require_manifest_asset_string(asset, file_name, "sbom", sbom_file_name, failures);
            }
            validate_manifest_auxiliary_files(asset, file_name, expected, failures);
        }
        "sbom" => {
            require_manifest_asset_string(asset, file_name, "format", "CycloneDX JSON", failures);
            if let Some(subject_file_name) = linked_file_name {
                require_manifest_asset_string(
                    asset,
                    file_name,
                    "subject",
                    subject_file_name,
                    failures,
                );
            }
        }
        _ => {}
    }
}

fn validate_manifest_auxiliary_files(
    asset: &Value,
    file_name: &str,
    expected: &ExpectedReleaseAsset,
    failures: &mut Vec<String>,
) {
    let auxiliary_files = asset.get("auxiliary_files");
    if expected.binary != "cairnid" {
        if auxiliary_files.is_some() {
            failures.push(format!(
                "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.auxiliary_files must not be present for cairnid-mcp archives"
            ));
        }
        return;
    }

    let stem = archive_stem(
        expected,
        asset.get("name").and_then(Value::as_str),
        file_name,
    );
    let expected_paths = cli_auxiliary_member_paths(&stem);
    let Some(entries) = auxiliary_files.and_then(Value::as_array) else {
        failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.auxiliary_files must list CLI completions and manpages"
        ));
        return;
    };

    let actual_paths = entries
        .iter()
        .filter_map(|entry| entry.get("path").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if actual_paths != expected_paths {
        failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.auxiliary_files must match the CLI archive member metadata"
        ));
        return;
    }

    for (entry, expected) in entries.iter().zip(CLI_AUXILIARY_FILES) {
        require_manifest_asset_string(entry, file_name, "kind", expected.kind, failures);
        match expected.shell {
            Some(shell) => require_manifest_asset_string(entry, file_name, "shell", shell, failures),
            None if entry.get("shell").is_some() => failures.push(format!(
                "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.auxiliary_files shell must not be present for {}",
                expected.path
            )),
            None => {}
        }
        match expected.section {
            Some(section) => {
                require_manifest_asset_string(entry, file_name, "section", section, failures)
            }
            None if entry.get("section").is_some() => failures.push(format!(
                "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.auxiliary_files section must not be present for {}",
                expected.path
            )),
            None => {}
        }
    }
}

fn archive_stem(
    expected: &ExpectedReleaseAsset,
    manifest_name: Option<&str>,
    file_name: &str,
) -> String {
    let suffix = format!(".{}", expected.archive_format);
    manifest_name
        .unwrap_or(file_name)
        .strip_suffix(&suffix)
        .unwrap_or(file_name)
        .to_owned()
}

fn validate_archive_structure(
    release_dir: &Path,
    file_name: &str,
    expected: &ExpectedReleaseAsset,
    release_tag: &str,
    failures: &mut Vec<String>,
) {
    match archive_member_names(&release_dir.join(file_name), expected.archive_format) {
        Ok(members) => {
            validate_archive_member_paths(file_name, &members, failures);
            let stem = format!("{}-{release_tag}-{}", expected.binary, expected.target);
            let missing = expected_archive_members(expected, &stem)
                .into_iter()
                .filter(|member| !members.contains(member))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                failures.push(format!(
                    "{file_name} is missing required archive members: {}",
                    missing.join(", ")
                ));
            }

            if expected.binary == "cairnid-mcp" {
                let forbidden = cli_auxiliary_member_paths(&stem)
                    .into_iter()
                    .filter(|member| members.contains(member))
                    .collect::<Vec<_>>();
                if !forbidden.is_empty() {
                    failures.push(format!(
                        "{file_name} contains CLI-only archive members: {}",
                        forbidden.join(", ")
                    ));
                }
            }
        }
        Err(error) => failures.push(format!(
            "{file_name} archive structure could not be read: {error}"
        )),
    }
}

fn expected_archive_members(expected: &ExpectedReleaseAsset, stem: &str) -> Vec<String> {
    let binary_member = if expected.target == "x86_64-pc-windows-msvc" {
        format!("{stem}/{}.exe", expected.binary)
    } else {
        format!("{stem}/{}", expected.binary)
    };
    let mut members = vec![
        binary_member,
        format!("{stem}/LICENSE"),
        format!("{stem}/README.md"),
    ];
    if expected.binary == "cairnid" {
        members.extend(cli_auxiliary_member_paths(stem));
    }
    members
}

fn cli_auxiliary_member_paths(stem: &str) -> Vec<String> {
    CLI_AUXILIARY_FILES
        .iter()
        .map(|file| format!("{stem}/{}", file.path))
        .collect()
}

fn archive_member_names(path: &Path, archive_format: &str) -> Result<BTreeSet<String>, String> {
    match archive_format {
        "zip" => zip_member_names(path),
        "tar.gz" => tar_gz_member_names(path),
        other => Err(format!("unsupported archive format {other}")),
    }
}

fn zip_member_names(path: &Path) -> Result<BTreeSet<String>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let archive = ZipArchive::new(file).map_err(|error| error.to_string())?;
    Ok(archive
        .file_names()
        .map(normalize_archive_member_name)
        .collect())
}

fn tar_gz_member_names(path: &Path) -> Result<BTreeSet<String>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let reader = BufReader::new(file);
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let mut members = BTreeSet::new();
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path().map_err(|error| error.to_string())?;
        members.insert(normalize_archive_member_name(&path.to_string_lossy()));
    }
    Ok(members)
}

fn normalize_archive_member_name(name: &str) -> String {
    name.replace('\\', "/").trim_start_matches("./").to_owned()
}

fn validate_archive_member_paths(
    file_name: &str,
    members: &BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    for member in members {
        let normalized = member.trim_end_matches('/');
        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized
                .split('/')
                .any(|segment| segment == ".." || segment.is_empty())
        {
            failures.push(format!(
                "{file_name} contains unsafe archive member path {member}"
            ));
        }
    }
}

fn validate_sbom_format(
    release_dir: &Path,
    file_name: &str,
    failures: &mut Vec<String>,
) -> Result<(), ReleaseAssetsVerificationError> {
    let Some(sbom) = read_json_file(release_dir, file_name, failures)? else {
        return Ok(());
    };
    if sbom.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        failures.push(format!("{file_name} must be a CycloneDX JSON SBOM"));
    }
    Ok(())
}

fn require_manifest_string(
    value: &Value,
    path: &[&str],
    expected: &str,
    failures: &mut Vec<String>,
) {
    match string_at_path(value, path) {
        Some(actual) if actual == expected => {}
        Some(_) => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME}.{} must be {expected}",
            path.join(".")
        )),
        None => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME}.{} must be {expected}",
            path.join(".")
        )),
    }
}

fn require_manifest_bool_false(value: &Value, path: &[&str], failures: &mut Vec<String>) {
    match value_at_path(value, path).and_then(Value::as_bool) {
        Some(false) => {}
        Some(true) => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME}.{} must be false",
            path.join(".")
        )),
        None => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME}.{} must be false",
            path.join(".")
        )),
    }
}

fn require_manifest_asset_string(
    asset: &Value,
    file_name: &str,
    field: &'static str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    match asset.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(_) => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.{field} must be {expected}"
        )),
        None => failures.push(format!(
            "{RELEASE_MANIFEST_FILE_NAME} asset {file_name}.{field} must be {expected}"
        )),
    }
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at_path(value, path).and_then(Value::as_str)
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn safe_public_github_url(value: &Option<String>, path_prefix: &str) -> Option<String> {
    let value = value.as_ref()?.trim();
    if value.is_empty() {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with(path_prefix)
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn non_empty_option(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()
}

fn safe_io_error(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "not found",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        std::io::ErrorKind::InvalidData => "invalid data",
        std::io::ErrorKind::UnexpectedEof => "unexpected EOF",
        _ => "I/O error",
    }
}
