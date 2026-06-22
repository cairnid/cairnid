use super::super::{ReleaseEvidenceManifest, ReleaseEvidenceManifestArtifact};

pub(super) fn release_evidence_readme(manifest: &ReleaseEvidenceManifest) -> String {
    let mut readme = String::new();
    readme.push_str("# Cairn Identity Release Evidence\n\n");
    readme.push_str(
        "This directory is for first-public-RC and public-release evidence. Keep it access-controlled. ",
    );
    readme.push_str(
        "The generated `.gitignore` keeps evidence artifacts out of source control by default.\n\n",
    );
    readme.push_str(
        "One required artifact, `cairn-oidcc-static.json`, contains OIDC client secrets. ",
    );
    readme.push_str(
        "Provider receipts and drill reports can also reveal operational posture, so store the directory with the same care as deployment records.\n\n",
    );
    readme.push_str("## Workflow\n\n");
    readme.push_str("1. Produce each artifact with the command in the checklist.\n");
    readme.push_str("2. Capture restore, signing-key rotation, KEK rotation, break-glass, audit export, and audit purge drill evidence from production-like or restored Postgres databases.\n");
    readme.push_str(
        "3. Keep state-changing drills on an approved production-like or restored database only.\n",
    );
    readme.push_str("4. Use local rehearsal only with disposable or restored databases; local rehearsal receipts are not release-ready evidence.\n");
    readme.push_str("5. Run `cairnid evidence check <evidence-dir>` before the first public RC and each public release.\n");
    readme.push_str("6. Do not commit the evidence artifacts.\n");
    readme.push_str("7. Do not add screenshots, raw provider exports, logs, or extra files to this directory.\n\n");
    push_high_risk_review(&mut readme, manifest);
    readme.push_str("## Required Artifacts\n\n");
    readme.push_str("| Release Gate | File | Command | Secrets | Production-like Env | Mutates | External Provider |\n");
    readme.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for artifact in &manifest.artifacts {
        readme.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} | {} |\n",
            artifact.release_gate,
            artifact.file_name,
            artifact.command,
            yes_no(artifact.contains_secrets),
            yes_no(artifact.requires_production_like_environment),
            yes_no(artifact.writes_application_state),
            yes_no(artifact.touches_external_provider)
        ));
    }
    readme.push_str("\n## Notes\n\n");
    for note in &manifest.notes {
        readme.push_str("- ");
        readme.push_str(note);
        readme.push('\n');
    }
    readme
}

fn push_high_risk_review(readme: &mut String, manifest: &ReleaseEvidenceManifest) {
    readme.push_str("## High-Risk Review\n\n");
    readme.push_str(
        "This scaffold is an operator checklist only. It does not produce artifacts, prove release approval, or claim production readiness. ",
    );
    readme.push_str(
        "Before running any command, review every `yes` flag in the table and confirm the exact target environment, provider, and approval path outside this directory.\n\n",
    );
    readme.push_str("### Secret-Containing Artifacts\n\n");
    readme.push_str(
        "Files listed here can contain or derive from secrets. Keep them access-controlled, do not commit them, and do not paste them into issue, PR, ticket, chat, or provider support systems.\n\n",
    );
    push_artifact_group(
        readme,
        manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.contains_secrets),
    );
    readme.push_str("### Production-Like Environment Artifacts\n\n");
    readme.push_str(
        "Files listed here must come from the required production-like HTTPS deployment, external suite, connector, provider, or approved restored/drill Postgres target. Local rehearsal receipts are not release-ready evidence.\n\n",
    );
    push_artifact_group(
        readme,
        manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.requires_production_like_environment),
    );
    readme.push_str("### State-Changing Artifacts\n\n");
    readme.push_str(
        "Files listed here can write application, tenant, provider, or drill-database state. Confirm the target, backup/restore posture, and operator approval before running them.\n\n",
    );
    push_artifact_group(
        readme,
        manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.writes_application_state),
    );
    readme.push_str("### External-Provider Artifacts\n\n");
    readme.push_str(
        "Files listed here require action against systems outside CairnID. Save only the normalized JSON receipt expected by `cairnid evidence check`; do not archive raw provider exports, debug logs, request headers, cookies, bearer tokens, client secrets, screenshots, or copied stdout/stderr.\n\n",
    );
    push_artifact_group(
        readme,
        manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.touches_external_provider),
    );
    readme.push_str("### Example Gate Checks\n\n");
    readme.push_str(
        "- `cairn-oidcc-static.json`: secret-containing static OpenID config for the target issuer; keep it access-controlled and never commit or paste it.\n",
    );
    readme.push_str(
        "- `lifecycle-email-smoke.json`: state-changing plus external-provider email evidence; use controlled recipients and keep lifecycle URLs, tokens, provider credentials, provider logs, and screenshots out of the saved JSON.\n",
    );
    readme.push_str(
        "- `signing-key-rotation-drill.json`: state-changing key-operations drill evidence; confirm `DATABASE_URL` points at the approved production-like or restored Postgres drill database before running the rotation command.\n",
    );
    readme.push_str(
        "- `release-assets-verification.json`: external-provider release-asset evidence; capture it only after a published GitHub Release exists, assets are downloaded, and provenance plus SBOM attestation checks have passed. Workflow-run and rehearsal receipts are not final release evidence.\n\n",
    );
}

fn push_artifact_group<'a, I>(readme: &mut String, artifacts: I)
where
    I: IntoIterator<Item = &'a ReleaseEvidenceManifestArtifact>,
{
    let mut found = false;
    for artifact in artifacts {
        found = true;
        readme.push_str(&format!(
            "- `{}` ({}) - `{}`\n",
            artifact.file_name, artifact.release_gate, artifact.command
        ));
    }
    if !found {
        readme.push_str("- None.\n");
    }
    readme.push('\n');
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
