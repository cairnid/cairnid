# Release Gates

Cairn Identity has not published a first public RC. A release can be recommended for production use only after every required gate below has current evidence from the required environment for that gate.

## RC Compatibility And Support Matrix

This matrix defines the first-RC support boundary. It is not a production-readiness claim; entries remain blocked until the required evidence below is current and the release is published.

| Area | RC support status | Supported scope/version | Tested runtime/platform | Public artifact/install path | Required evidence | Explicitly unsupported |
| --- | --- | --- | --- | --- | --- | --- |
| Release status | Pre-beta; no first public RC has been published. | First-RC compatibility target only; production recommendation waits for every required gate. | Current CI and local release-gate commands only. | None until maintainers publish a reviewed GitHub Release. | Every required gate below, plus no current blocker. | Production readiness, OpenID Certification claims, supported production releases. |
| OIDC/OAuth | First-RC target; not OpenID Certified. | Config OP and Basic OP target. Browser and OpenID conformance path is Authorization Code + PKCE with query response mode and `S256`; token endpoint also supports `authorization_code`, `refresh_token`, and configured confidential-client `client_credentials`. | `cairn-oidc` tests, API token/metadata tests, deployed metadata smoke, and external OIDF suite evidence. | API endpoint from a reviewed source/container deployment; no standalone OIDC service artifact. | `oidc-metadata-smoke.json`, static registration/config artifacts, `openid-config-op-result.json`, `openid-basic-op-result.json`. | Implicit, hybrid, resource-owner password grant, dynamic registration, `response_mode=form_post`, request objects through `request` or `request_uri`, and general claims-parameter support. |
| SCIM | Optional v1 subset; disabled unless `CAIRN_SCIM_BEARER_TOKEN_SHA256` is configured. | SCIM 2.0 User and Group subset, ServiceProviderConfig/Schemas/ResourceTypes, exact filters/SearchRequest, bounded PATCH, bounded Bulk, bearer-token hash rotation. | `cairn-api scim` tests, built-in SCIM smoke, and external Okta/Entra connector summaries. | `/scim/v2/*` on the deployed API; connector profiles from `cairn-api scim connector-profile`. | `scim-generic-connector-profile.json`, `scim-okta-connector-profile.json`, `scim-entra-connector-profile.json`, `scim-smoke.json`, `scim-okta-connector-smoke.json`, `scim-entra-connector-smoke.json`. | Sort, changePassword, ETags, cursor pagination, Shared Signals/security events, password synchronization, nested groups, broad multi-valued PATCH semantics, certified directory templates. |
| MCP | Local read-only stdio server for release-evidence inspection. | `cairnid-mcp` tools: `evidence_plan`, `evidence_manifest`, `evidence_status`, `evidence_check`, constrained by an allowlisted evidence root. | Windows CI `cargo test`/clippy, Linux/Windows distribution smoke, and local stdio validation. | `cairnid-mcp` Linux x86_64 and Windows x86_64 archives after a published GitHub Release; until then use Cargo from source. | MCP Windows behavior gate, stdio smoke, release-assets verification for the published archive. | Remote/network MCP hosting, write-capable evidence tools, unconstrained filesystem access, raw artifact/log/secret exposure. |
| cairnid CLI | Operator release-evidence CLI; first public install path pending. | `cairnid evidence plan`, `manifest`, `init`, `status`, and `check`; CLI archives include generated completions and `cairnid.1` manpage. | Windows CI `cargo test -p cairnid --locked`, Linux/Windows distribution smokes, Rust stable 1.94+. | `cairnid` Linux x86_64 and Windows x86_64 archives after a published GitHub Release; until then use Cargo from source. | CLI Windows lifecycle proof, release-assets verification, final `cairnid evidence check`. | Package-manager distribution, unattended install scripts, production support before a published release. |
| API runtime | Source/container-build target for RC evidence; no production support window yet. | Rust stable 1.94+ workspace, Axum API, OIDC/OAuth, SCIM, admin/session, operations commands. | Ubuntu CI with native dependencies; Windows GNU toolchain for local Rust verification where MSVC is unavailable; root Dockerfile Debian runtime smoke. | Reviewed source checkout or locally built API image; no public API binary or container image. | Rust quality gates, operations preflight, deployed HTTPS smokes, restore/key/audit/email evidence. | Published API server binary, public container image, registry digest, non-HTTPS production issuer posture, production SLA. |
| Web runtime | SvelteKit web UI tested with Bun tooling and Node 24 adapter-node runtime. | Bun 1.3.4 package manager/scripts; Node 24 for CI and Dockerfile build/runtime; Bun remains in the runtime image for healthcheck. | CI web job with Bun 1.3.4 and Node 24; `apps/web/Dockerfile` uses `node:24-bookworm-slim` and `oven/bun:1.3.4`. | Reviewed source checkout or locally built web image; no public site/runtime artifact. | `bun run check`, `bun run test`, `bun run build`, `bun run test:e2e`, web image smoke. | Other Node major versions as a tested runtime, published web image, static/site runtime distribution. |
| Database | Postgres-backed only. | Postgres 17 migrations and runtime schema. | `postgres:17-alpine` in CI service and local Compose. | Operator-provided Postgres; no managed database package. | Postgres 17 migration tests, operations preflight, restore drill. | MySQL, SQLite, untested Postgres major versions, production database support without restore evidence. |
| Local Compose/containers | Local Compose and CI image smoke only. | `infra/docker-compose.yml` starts Postgres 17, API, and web; Dockerfiles build API and web images. | CI validates Compose config, builds both images, smokes API key generation, Bun version, and web `/healthz`. | Source checkout Compose/Dockerfiles; operators build locally. | Containers gate, deployment smoke, preflight, release evidence. | Published images, registry policy/digests, Helm/Kubernetes package, production orchestration support; Kubernetes is custom until a package exists. |
| Public release artifacts | Pending first published GitHub Release. | Tag-driven release builds `cairnid` and `cairnid-mcp` archives for Linux x86_64 and Windows x86_64, plus CycloneDX SBOMs, `SHA256SUMS.txt`, `release-manifest.json`, and GitHub artifact attestations. | `.github/workflows/release.yml` requires a valid tag, source commit reachable from `origin/main`, successful CI for the tagged commit, release-mode build, package validation, and attestations. | Draft-reviewed GitHub Release after maintainers publish it. | `release-assets-verification.json` proving archives, SBOMs, checksums, manifest, provenance, and SBOM attestations. | crates.io, Homebrew, MSI, macOS/notarized binaries, Authenticode-signed Windows binaries, container images, site/runtime artifacts, install scripts. |
| Security/support window | No supported production releases yet. | Security fixes target `main` until versioned releases exist; private vulnerability reporting is in scope. | Best-effort triage targets in `SECURITY.md`; no contractual SLA. | `SECURITY.md` and `SUPPORT.md`; no LTS branch or support package. | Release gates closed, published version, security advisory/release-note process when a public release exists. | LTS, backports, production support window, paid/contractual SLA. |
| Future/out-of-scope product features | Not part of first-RC support. | Roadmap-only areas after the hardened core. | No release evidence for first RC. | None. | Future roadmap/release-gate updates before any support claim. | SAML, LDAP/Active Directory integration, upstream identity brokering, reverse-proxy auth mode, device trust/shared signals, Helm/Kubernetes package, certified directory templates. |

## Required Gates

| Gate | Evidence | Status |
| --- | --- | --- |
| Source hygiene | `bun run check:public-surface` passes | CI-gated |
| Dependency policy | `dependency-policy-check.json` from `cairn-api operations dependency-policy-evidence`; proves `cargo deny check`, `cargo audit`, and `bun run audit` without archived command output | CI-gated locally; release receipt required |
| Rust quality | `cargo fmt`, `cargo check`, `cargo test`, and `cargo clippy -D warnings` pass | CI-gated |
| CLI Windows lifecycle proof | `cargo test -p cairnid --locked` passes on Windows, including binary-level release-evidence manifest, init, incomplete status/check, and failure-redaction coverage | CI-gated |
| MCP stdio and Windows behavior | `cargo test -p cairnid-mcp --locked` and `cargo clippy -p cairnid-mcp --locked --all-targets -- -D warnings` pass on Windows, including stdio initialize, `tools/list`, and sanitized `tools/call` coverage | CI-gated |
| CLI/MCP public release assets | `release-assets-verification.json`; proves tag, source commit, release URL or workflow run URL, CLI and MCP archives, SHA-256 verification, CycloneDX SBOM presence, `release-manifest.json`, and GitHub provenance plus SBOM attestation verification | Tag-gated; first RC pending |
| Frontend quality | `bun run check`, `bun run test`, `bun run build`, and `bun run test:e2e` pass | CI-gated |
| Docs export | `bun run docs:site -- --out <temp-dir>` completes without committing generated output | CI-gated |
| Database migrations | Postgres 17 migration tests pass against a disposable database | CI-gated |
| Containers | Compose validates, API image builds, web image builds, and image-level smoke checks pass; no container images are published by the release workflow | CI-gated smoke only |
| Operations preflight | `operations-preflight.json` from `cairn-api operations preflight`; proves production mode, migrations, signing/JWKS, email readiness, queue health, HTTPS issuer posture, static OpenID env readiness, and SCIM posture | Pending external evidence |
| Static OpenID artifacts | `openid-static-registration.json` and `cairn-oidcc-static.json` generated from the target issuer and static clients | Pending external evidence |
| Deployed OIDC metadata | `oidc-metadata-smoke.json` from `cairn-api operations oidc-metadata-smoke` passes against the HTTPS API origin | Pending external evidence |
| OpenID conformance | `openid-config-op-result.json` and `openid-basic-op-result.json` pass using generated static registration/config artifacts | Pending external evidence |
| Browser origin defense | `browser-origin-smoke.json` from `cairn-api operations browser-origin-smoke` passes against the HTTPS API origin | Pending external evidence |
| Security headers | `security-headers-smoke.json` from `cairn-api operations security-headers-smoke` passes against HTTPS API and web origins | Pending external evidence |
| SCIM provisioning | `scim-generic-connector-profile.json`, `scim-okta-connector-profile.json`, `scim-entra-connector-profile.json`, `scim-smoke.json`, `scim-okta-connector-smoke.json`, and `scim-entra-connector-smoke.json` pass | Pending external evidence |
| Email delivery | `email-provider-smoke.json` and `lifecycle-email-smoke.json` pass through the configured command provider | Pending external evidence |
| Restore drill | `restore-drill.json` from `cairn-api operations restore-check` passes against a restored database | Pending external evidence |
| Key operations | `signing-key-rotation-drill.json` and `kek-rotation-drill.json` pass evidence validation | Pending external evidence |
| Emergency access | `break-glass-admin-recovery-drill.json` passes and records audit evidence | Pending external evidence |
| Audit operations | `audit-export-archive-drill.json` and `audit-retention-purge-drill.json` pass evidence validation | Pending external evidence |
| Final release evidence | `cairnid evidence check <evidence-dir>` passes with fresh artifacts, current manifest, release-gate ownership metadata, and no unexpected files | Pending external evidence |

## Evidence Workflow

Until the first tagged RC is published, run the current CLI from a local checkout with `cargo run -p cairnid --locked -- <args>` or build it locally with `cargo build -p cairnid --locked` and run the resulting binary from `target`.

```powershell
cargo run -p cairnid --locked -- evidence plan
cargo run -p cairnid --locked -- evidence init <evidence-dir>
cargo run -p cairnid --locked -- evidence status --evidence-dir <evidence-dir>
cargo run -p cairnid --locked -- evidence check --evidence-dir <evidence-dir>
```

`cairnid evidence plan` confirms that required environment variable names are present without printing values. `cairnid evidence init` creates the guarded evidence directory. `cairnid evidence status` shows missing or failed artifacts while evidence is being collected. `cairnid evidence check` is the final local release gate.

The CLI evidence JSON reports carry root `schema_version="cairnid.evidence.v1"` for machine-readable contract stability. Additive fields can appear under the same version, but removing or renaming fields, changing field meanings, changing stable status values, weakening redaction expectations, or changing count/failure semantics requires a new schema version. Artifact entries in plan, manifest, status/check, next-action, and generated README output include `release_gate` ownership labels so operators can map each artifact back to this gate table.

Stable `cairnid evidence` exit codes:

- `0`: success.
- `1`: unexpected internal error.
- `2`: clap usage or parse error before runtime execution.
- `3`: the command printed JSON, but the release evidence set or capture environment is incomplete.
- `4`: operator input, path, or scaffold error, such as an evidence path that is not a directory or an existing scaffold without `--force`.

Do not commit release evidence directories. They can include operational context and must stay in controlled storage.

## CLI and MCP Release Assets

Pushing a tag that matches `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N` starts `.github/workflows/release.yml`. The workflow validates the tag with an exact regex, rejects tags that are not reachable from `origin/main`, and requires a successful completed `CI` run for the exact tagged commit before release artifacts are built. It then builds release-mode `cairnid` and `cairnid-mcp` binaries for:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

For each tag, the workflow creates a draft GitHub Release containing:

- Versioned archives for each binary and target. Each `cairnid` CLI archive also contains generated Bash, Zsh, Fish, PowerShell, and Elvish completions under `completions/`, plus `man/man1/cairnid.1`; `cairnid-mcp` archives do not contain these CLI-only files.
- CycloneDX JSON SBOMs generated with `cargo-cyclonedx`.
- `SHA256SUMS.txt`.
- `release-manifest.json` with source commit, workflow run, target, archive, SBOM, CLI archive auxiliary-file paths, and SHA-256 metadata.
- GitHub artifact attestations created with `actions/attest@v4`, GitHub Actions OIDC, and Sigstore, without long-lived signing keys.

Maintainers must review and publish the draft before the assets are public. RC tags are marked as prereleases and are not marked latest. No public crates.io packages, Homebrew formulae, MSI installers, macOS notarized binaries, signed Windows binaries, container images, install scripts, or site/runtime release artifacts exist yet.

CI distribution smoke artifacts are different. The regular CI workflow uploads short-lived Actions artifacts named `*-ci-rehearsal-*` to prove release-mode binaries can build and smoke-test before a tag exists. Those CI artifacts are not public release assets, are not attached to a GitHub Release, and are not the install path for users.

Container checks are also different from public release assets. CI validates Compose configuration, builds the API and web images, and runs image-level smoke checks, but no workflow currently pushes images to a registry or records public container digests. Container publication requires a separate registry policy and workflow before it can be documented as a release artifact.

### User verification after a release is published

These are local user verification commands. They do not create release evidence by themselves. `v0.1.0-rc.1` is a future example tag; replace it with an actual published GitHub Release tag after maintainers publish the release.

```powershell
$tag = "v0.1.0-rc.1"
$repo = "cairnid/cairnid"
$target = "x86_64-pc-windows-msvc"
$dir = "cairnid-release-$tag"
$sourceRef = "refs/tags/$tag"

gh release download $tag --repo $repo --dir $dir
Set-Location $dir

$archives = @("cairnid-$tag-$target.zip", "cairnid-mcp-$tag-$target.zip")
$sboms = @("cairnid-$tag-$target.sbom.cdx.json", "cairnid-mcp-$tag-$target.sbom.cdx.json")
$expected = @{}
Get-Content .\SHA256SUMS.txt | ForEach-Object {
    if ($_ -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
        $expected[$Matches[2]] = $Matches[1].ToLowerInvariant()
    }
}
foreach ($file in $archives + $sboms + @("release-manifest.json")) {
    if (-not $expected.ContainsKey($file)) { throw "SHA256SUMS.txt is missing $file" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$file]) { throw "SHA-256 mismatch for $file" }
}

$manifest = Get-Content .\release-manifest.json -Raw | ConvertFrom-Json
foreach ($field in @("crates_io", "homebrew", "msi", "macos", "containers")) {
    if ($manifest.distribution.$field -ne $false) { throw "unexpected distribution channel: $field" }
}
$manifestAssets = @{}
foreach ($asset in $manifest.assets) { $manifestAssets[$asset.name] = $asset }
foreach ($file in $archives + $sboms) {
    if (-not $manifestAssets.ContainsKey($file)) { throw "release-manifest.json is missing $file" }
    if ($manifestAssets[$file].sha256.ToLowerInvariant() -ne $expected[$file]) {
        throw "manifest SHA-256 mismatch for $file"
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Read-ZipMembers([string]$path) {
    $zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $path).ProviderPath)
    try { $zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") } } finally { $zip.Dispose() }
}
$cliStem = "cairnid-$tag-$target"
$mcpStem = "cairnid-mcp-$tag-$target"
$cliMembers = @(Read-ZipMembers $archives[0])
$mcpMembers = @(Read-ZipMembers $archives[1])
$cliRequired = @(
    "$cliStem/cairnid.exe",
    "$cliStem/LICENSE",
    "$cliStem/README.md",
    "$cliStem/completions/cairnid.bash",
    "$cliStem/completions/_cairnid",
    "$cliStem/completions/cairnid.fish",
    "$cliStem/completions/cairnid.ps1",
    "$cliStem/completions/cairnid.elv",
    "$cliStem/man/man1/cairnid.1"
)
foreach ($member in $cliRequired) {
    if ($member -notin $cliMembers) { throw "CLI archive is missing $member" }
}
foreach ($member in @("$mcpStem/cairnid-mcp.exe", "$mcpStem/LICENSE", "$mcpStem/README.md")) {
    if ($member -notin $mcpMembers) { throw "MCP archive is missing $member" }
}
$mcpForbidden = $mcpMembers | Where-Object {
    $_ -like "$mcpStem/completions/*" -or $_ -eq "$mcpStem/man/man1/cairnid.1"
}
if ($mcpForbidden) { throw "MCP archive contains CLI-only files: $mcpForbidden" }

foreach ($asset in $archives + $sboms + @("release-manifest.json", "SHA256SUMS.txt")) {
    gh attestation verify ".\$asset" --repo $repo --signer-workflow "$repo/.github/workflows/release.yml" --source-ref $sourceRef
}
foreach ($archive in $archives) {
    gh attestation verify ".\$archive" --repo $repo --signer-workflow "$repo/.github/workflows/release.yml" --source-ref $sourceRef --predicate-type https://cyclonedx.org/bom
}
```

```bash
tag="v0.1.0-rc.1"
repo="cairnid/cairnid"
target="x86_64-unknown-linux-gnu"
dir="cairnid-release-$tag"
source_ref="refs/tags/$tag"

gh release download "$tag" --repo "$repo" --dir "$dir"
cd "$dir"

sha256sum -c SHA256SUMS.txt --ignore-missing

TAG="$tag" TARGET="$target" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

tag = os.environ["TAG"]
target = os.environ["TARGET"]
archives = [
    f"cairnid-{tag}-{target}.tar.gz",
    f"cairnid-mcp-{tag}-{target}.tar.gz",
]
sboms = [
    f"cairnid-{tag}-{target}.sbom.cdx.json",
    f"cairnid-mcp-{tag}-{target}.sbom.cdx.json",
]
expected = {}
for line in Path("SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
    digest, name = line.split(maxsplit=1)
    expected[name.lstrip("*")] = digest.lower()

for name in archives + sboms + ["release-manifest.json"]:
    if name not in expected:
        raise SystemExit(f"SHA256SUMS.txt is missing {name}")
    actual = hashlib.sha256(Path(name).read_bytes()).hexdigest()
    if actual != expected[name]:
        raise SystemExit(f"SHA-256 mismatch for {name}")

manifest = json.loads(Path("release-manifest.json").read_text(encoding="utf-8"))
for field in ["crates_io", "homebrew", "msi", "macos", "containers"]:
    if manifest["distribution"].get(field) is not False:
        raise SystemExit(f"unexpected distribution channel: {field}")

assets = {asset["name"]: asset for asset in manifest["assets"]}
for name in archives + sboms:
    asset = assets.get(name)
    if asset is None:
        raise SystemExit(f"release-manifest.json is missing {name}")
    if asset["sha256"].lower() != expected[name]:
        raise SystemExit(f"manifest SHA-256 mismatch for {name}")
PY

cli_stem="cairnid-$tag-$target"
mcp_stem="cairnid-mcp-$tag-$target"
cli_archive="$cli_stem.tar.gz"
mcp_archive="$mcp_stem.tar.gz"
for member in \
  "$cli_stem/cairnid" \
  "$cli_stem/LICENSE" \
  "$cli_stem/README.md" \
  "$cli_stem/completions/cairnid.bash" \
  "$cli_stem/completions/_cairnid" \
  "$cli_stem/completions/cairnid.fish" \
  "$cli_stem/completions/cairnid.ps1" \
  "$cli_stem/completions/cairnid.elv" \
  "$cli_stem/man/man1/cairnid.1"; do
    tar -tzf "$cli_archive" "$member" >/dev/null
done
for member in "$mcp_stem/cairnid-mcp" "$mcp_stem/LICENSE" "$mcp_stem/README.md"; do
    tar -tzf "$mcp_archive" "$member" >/dev/null
done
if tar -tzf "$mcp_archive" | grep -E "/(completions/|man/man1/cairnid\.1$)"; then
    echo "MCP archive contains CLI-only files" >&2
    exit 1
fi

assets=(
  "cairnid-$tag-$target.tar.gz"
  "cairnid-mcp-$tag-$target.tar.gz"
  "cairnid-$tag-$target.sbom.cdx.json"
  "cairnid-mcp-$tag-$target.sbom.cdx.json"
  "release-manifest.json"
  "SHA256SUMS.txt"
)
for asset in "${assets[@]}"; do
    gh attestation verify "./$asset" --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml" --source-ref "$source_ref"
done
for archive in "cairnid-$tag-$target.tar.gz" "cairnid-mcp-$tag-$target.tar.gz"; do
    gh attestation verify "./$archive" --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml" --source-ref "$source_ref" --predicate-type https://cyclonedx.org/bom
done
```

The default `gh attestation verify` command checks the SLSA provenance predicate. The command with `--predicate-type https://cyclonedx.org/bom` checks the SBOM attestation for each archive. Run the same pattern for every published target that the user installs or records in evidence.

For release evidence, do not paste command output into the receipt. Save a normalized, token-free `release-assets-verification.json` after all four archives and four SBOMs are verified. The receipt fields belong in the release-evidence directory and must record `status="ok"`, `completed_at`, `release_tag`, `source_commit`, `release_url` or `run_url`, `checksums.file_name="SHA256SUMS.txt"`, `checksums.algorithm="SHA-256"`, `checksums.present=true`, `checksums.verified=true`, `release_manifest.file_name="release-manifest.json"`, `release_manifest.present=true`, `release_manifest.sha256_verified=true`, `attestations.signer_workflow="cairnid/cairnid/.github/workflows/release.yml"`, `attestations.source_ref="refs/tags/<tag>"`, `attestations.provenance_verified=true`, `attestations.sbom_attestations_verified=true`, exactly four `archives` entries, exactly four `sboms` entries, each asset `sha256`, `present=true`, `sha256_verified=true`, `manifest_entry_present=true`, and the required GitHub attestation booleans. Do not include GitHub tokens, request headers, cookies, raw attestation payloads, debug logs, or copied stdout/stderr.

## Current Blockers

- No first public RC tag has been pushed and published.
- No `release-assets-verification.json` can be captured until a first public RC GitHub Release exists and its assets are verified.
- No current `dependency-policy-check.json` release receipt has been captured for a release-evidence directory.
- No current `operations-preflight.json` has been captured from the target production-like deployment.
- No current static OpenID artifacts, `openid-static-registration.json` and `cairn-oidcc-static.json`, have been captured from the target issuer/static clients.
- No container image publishing workflow or registry policy exists; CI container checks are smoke evidence only.
- No published OpenID Foundation conformance result.
- No deployed HTTPS metadata/JWKS smoke receipt.
- No deployed browser-origin or security-header smoke receipt.
- No command-provider `email-provider-smoke.json` or `lifecycle-email-smoke.json` receipt.
- No production-like restore, signing-key rotation, KEK rotation, break-glass, audit export, or audit purge drill receipt.
- No SCIM connector profile artifacts, built-in `scim-smoke.json`, or external Okta and Entra SCIM connector summaries.
- Repository or organization release immutability must be enabled before publishing the first public RC if the release should lock assets and tags after publication.
