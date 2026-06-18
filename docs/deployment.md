# Deployment

## Local Docker Compose

```powershell
cargo run -p cairn-api -- signing-key generate-kek
$env:CAIRN_KEY_ENCRYPTION_KEY="<paste generated value>"
docker compose -f infra/docker-compose.yml up --build
```

Services:

- `postgres`: Postgres 17.
- `api`: Axum API on `http://localhost:8080`.
- `web`: SvelteKit UI on `http://localhost:5173`.

The API runs embedded SQLx migrations on startup.

The repository includes a root `.dockerignore` so generated Rust targets, Bun dependencies, SvelteKit output, test artifacts, local env files, and editor metadata are not sent to Docker builds.

## API Container

### Current Container Status

The repository contains Dockerfiles and Compose configuration, and CI validates that the API and web images build and pass image-level smoke checks. The current release workflow does not publish container images or registry digests. Operators should build images from the reviewed source checkout until a separate container publishing workflow and registry policy are added.

The root `Dockerfile` builds `cairn-api` with CMake, NASM, pkg-config, and Linux OpenSSL development headers for AWS-LC, OpenSSL key generation, and `webauthn-rs`. The runtime stage ships a slim Debian image with CA certificates and `libssl3`.

The API image healthcheck runs `cairn-api healthcheck`, which performs an HTTP GET against the local `/healthz` endpoint and requires the JSON status payload to be `ok`. Because `/healthz` performs a database health check, container health probes cover both HTTP serving and Postgres reachability after startup migrations.

Set these explicitly for deployed API containers:

- `DATABASE_URL`: Postgres connection string.
- `CAIRN_ISSUER`: public API/OIDC origin.
- `CAIRN_PUBLIC_WEB_ORIGIN`: public web origin used for lifecycle action links.
- `CAIRN_KEY_ENCRYPTION_KEY`: generate with `cairn-api signing-key generate-kek`; required by Local Docker Compose, encrypted database-backed signing-key generation and rotation, and production account lifecycle email outbox delivery.
- `CAIRN_ENV=production` for production deployments.
- `RUST_LOG=cairn_api=info,cairn_oidc=info,tower_http=info`

Production-only bootstrap and email variables:

- `CAIRN_BOOTSTRAP_SETUP_SECRET`: required when `CAIRN_ENV=production`; the first administrator bootstrap request must submit this operator-held setup secret.
- `CAIRN_EMAIL_PROVIDER=command`: required before production lifecycle email delivery.
- `CAIRN_EMAIL_COMMAND_PATH`: executable that receives rendered email JSON on stdin and exits `0` after provider acceptance.

Optional/defaulted variables:

- `CAIRN_EMAIL_BATCH_SIZE`: default `10`, clamped to `1..100`.
- `CAIRN_EMAIL_MAX_ATTEMPTS`: default `5`, clamped to `1..20`.
- `CAIRN_EMAIL_RETRY_SECONDS`: default `300`, clamped to `1..86400`.
- `CAIRN_EMAIL_SENDING_TIMEOUT_SECONDS`: default `900`, clamped to `30..86400`; stale `sending` rows older than this can be reclaimed.
- `CAIRN_TRUSTED_PROXY_IPS`: optional comma-separated exact IP addresses for direct reverse proxy or CDN peers. Leave unset unless the direct peer is trusted to set forwarded IP headers. When the peer matches, the first `X-Forwarded-For` IP, falling back to `X-Real-IP`, becomes the audit and rate-limit client identity; otherwise the socket peer IP is used.
- `CAIRN_SCIM_BEARER_TOKEN_SHA256`: optional 64-character SHA-256 hex digest of the raw SCIM bearer token; accepts up to four comma-separated hashes during rotation; required only when SCIM provisioning is enabled.

`CAIRN_ISSUER` and `CAIRN_PUBLIC_WEB_ORIGIN` must be absolute origins, not full paths. Production accepts HTTPS only. Development may use HTTP only for `localhost`, `127.0.0.1`, or `[::1]`.

Legacy static signing material can be supplied as a bootstrap/import fallback:

- `CAIRN_SIGNING_KEY_ID`
- `CAIRN_SIGNING_PRIVATE_KEY_PEM`
- `CAIRN_SIGNING_PUBLIC_JWK`

Operational signing-key commands:

```powershell
cairn-api signing-key generate-kek
cairn-api signing-key ensure
cairn-api signing-key rotate
cairn-api signing-key list
cairn-api signing-key retire <kid>
```

Operational readiness preflight:

```powershell
cairn-api operations preflight
```

Run preflight after deployment migrations, after signing-key or KEK maintenance, before enabling lifecycle email delivery, before OpenID conformance evidence capture, and after SCIM token rotation. It emits a JSON report and fails if migrations are absent, signing material is unusable, JWKS does not expose the active database key, more than one unretired database signing key is active, production lifecycle email delivery is missing the command provider, command path, or KEK required for encrypted action links, or failed outbox rows are present. The report also includes signing-key lifecycle counts, active key age, a 90-day rotation recommendation, operator signing-key command hints, email worker batch/retry/reclaim and redacted queue-health posture without printing provider credentials, recipients, subjects, errors, or message bodies, OpenID conformance issuer/static-client environment posture without printing client secrets, and SCIM enabled/rotation-window posture without printing bearer tokens or hashes.

Release evidence scaffold and check:

Until a tagged RC is published, run `cairnid` through Cargo in a local checkout or build the local binary first:

```powershell
cargo run -p cairnid --locked -- evidence plan
cargo run -p cairnid --locked -- evidence init <evidence-dir>
cargo run -p cairnid --locked -- evidence status --evidence-dir <evidence-dir>
cargo run -p cairnid --locked -- evidence check --evidence-dir <evidence-dir>
```

Run the plan first to confirm required capture environment variable names are present without printing values. Run the initializer before collecting artifacts so the directory has the generated manifest, checklist README, and `.gitignore` guard for secret-bearing evidence. Run the status command during collection to get counts and next artifact commands, then run the checker after production-like deployed OIDC metadata, OIDF, SCIM, email, restore, key-rotation, break-glass, and audit drill evidence has been collected. It validates scaffold integrity, strict directory inventory, required artifact names, freshness, forbidden secret-bearing field names in token-free artifacts, and passing status without printing secrets, with failure text redacting obvious secret-looking values; the full artifact contract is documented in [operations.md](operations.md).

Tagged CLI/MCP release archives:

The public binary distribution path is `.github/workflows/release.yml`, not CI artifacts. A pushed tag matching `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N` must be reachable from `origin/main` and must have a successful completed `CI` run for the exact tagged commit. The workflow then builds release-mode `cairnid` and `cairnid-mcp` archives for Linux x86_64 and Windows x86_64, generates CycloneDX JSON SBOMs, writes `SHA256SUMS.txt` and `release-manifest.json`, and creates GitHub artifact attestations with `actions/attest@v4` using GitHub Actions OIDC. The workflow creates a draft GitHub Release; maintainers publish it only after review. RC tags are prereleases and are not marked latest.

The regular CI workflow's `*-ci-rehearsal-*` Actions artifacts are build/smoke proof only. They expire, are not attached to a GitHub Release, and should not be documented as installable public release assets.

After a release draft is published, install by downloading the matching archive from the GitHub Release. Verify the archive before use:

```powershell
gh release download v0.1.0-rc.1 --repo cairnid/cairnid --dir cairnid-release
cd cairnid-release
gh attestation verify .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip --repo cairnid/cairnid --signer-workflow cairnid/cairnid/.github/workflows/release.yml --source-ref refs/tags/v0.1.0-rc.1
gh attestation verify .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip --repo cairnid/cairnid --signer-workflow cairnid/cairnid/.github/workflows/release.yml --source-ref refs/tags/v0.1.0-rc.1 --predicate-type https://cyclonedx.org/bom
Get-FileHash .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

The first attestation command verifies default SLSA provenance for the archive. The second verifies the CycloneDX SBOM attestation for the same archive. Compare the hash with `SHA256SUMS.txt`, `release-manifest.json`, and GitHub's release asset digest. On Linux, verify with `sha256sum -c SHA256SUMS.txt --ignore-missing` and the same `gh attestation verify` commands against `./cairnid-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz`.

This first distribution slice intentionally does not publish crates.io packages, Homebrew formulae, MSI installers, macOS notarized assets, Authenticode signatures, containers, or site/runtime artifacts.

OpenID conformance preparation:

```powershell
cairn-api conformance oidcc-static-registration > openid-static-registration.json
cairn-api conformance oidcc-static-config > cairn-oidcc-static.json
```

Use these against a production-like HTTPS issuer to prepare Config OP and Basic OP suite runs. `cairn-api operations preflight` reports missing `CAIRN_CONFORMANCE_*` variables and whether the issuer is suitable for the suite before the artifact commands are run. The full profile setup is documented in [openid-conformance.md](openid-conformance.md).

CI validates `cairnid evidence` tooling with placeholder environment values. Linux CI proves `cairnid evidence plan` does not print values, `cairnid evidence init` writes the expected scaffold, and `cairnid evidence status` reports next actions for an incomplete evidence directory. Windows CI runs `cargo test -p cairnid --locked` for the CLI binary contract, including manifest, init, incomplete status/check, and common failure-redaction coverage.

CI also generates the dependency-policy evidence receipt after pinned `cargo-deny`, `cargo-audit`, and Bun audit checks pass. Container checks validate the Compose file, build both production images, run `cairn-api signing-key generate-kek` inside the API image, run `bun --version` inside the web image, and boot the web image long enough to run its `/healthz` probe. Docker Compose waits for Postgres health before starting the API and waits for API health before starting the web service. The image smokes verify Dockerfile buildability and runtime entrypoint dependencies without requiring a live database or external provider. These checks stop at smoke coverage and create no image tags, registry entries, or digests.

Operational email delivery command:

```powershell
cairn-api email-outbox deliver-once
```

Run it from a scheduler or worker with the same `DATABASE_URL`, `CAIRN_PUBLIC_WEB_ORIGIN`, `CAIRN_KEY_ENCRYPTION_KEY`, and email provider variables as the API service. Confirm the `email_delivery` block in `cairn-api operations preflight` before enabling the job.

Before enabling the scheduled worker, validate the configured provider executable without touching the database:

```powershell
cairn-api email-outbox smoke-provider ops@example.com
```

The smoke command sends a synthetic `provider_smoke` payload to the configured command provider and exits non-zero if provider credentials, network access, or receipt handling fail.

Backup, restore, signing-key rotation, and KEK handling are covered in [operations.md](operations.md).

SCIM provisioning is optional and disabled unless `CAIRN_SCIM_BEARER_TOKEN_SHA256` is set. Generate a high-entropy raw bearer token, store only its SHA-256 hex digest in the API environment, and configure the raw token in the directory provisioning client. During rotation, deploy a comma-separated old/new hash set, move connectors to the new raw token, then remove the retired hash. Setup and smoke tests are covered in [scim.md](scim.md).

Run `cairn-api scim smoke` against the deployed API after setting `CAIRN_SCIM_BEARER_TOKEN`; set `CAIRN_SCIM_SECONDARY_BEARER_TOKEN` during the overlap window and `CAIRN_SCIM_REJECTED_BEARER_TOKEN` after retiring an old token when validating rotation.

Operational KEK re-encryption command:

```powershell
cairn-api key-encryption rotate
```

Run this only during KEK rotation maintenance with `CAIRN_OLD_KEY_ENCRYPTION_KEY` and `CAIRN_NEW_KEY_ENCRYPTION_KEY` set.

## Web Container

`apps/web/Dockerfile` installs dependencies with Bun, builds the SvelteKit app through the Node runtime required by Vite, and runs the adapter-node server with Node. The runtime image still includes Bun for the healthcheck script. The Docker `HEALTHCHECK` runs `bun scripts/healthcheck.ts`, which probes `http://127.0.0.1:${PORT}/healthz` and requires a `200` response with `status="ok"`.

Runtime variables:

- `HOST=0.0.0.0`
- `PORT=3000`
- `PUBLIC_CAIRN_API_ORIGIN=https://id.example.com`

## Windows Build Notes

The workspace requires Rust stable 1.94 or newer. `sqlx 0.9` sets the current dependency floor. `webauthn-rs` depends on OpenSSL, and the AWS-LC JWT backend depends on CMake and NASM. On Windows without Visual Studio Build Tools, use:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal --component rustfmt --component clippy
```

Install MSYS2 packages:

```powershell
C:\msys64\usr\bin\bash.exe -lc "pacman -Sy --needed --noconfirm mingw-w64-x86_64-binutils mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-pkgconf mingw-w64-x86_64-cmake mingw-w64-x86_64-nasm pkgconf openssl-devel nasm"
```

Then run checks with MSYS2 paths:

```powershell
$env:PATH="C:\msys64\mingw64\bin;C:\msys64\usr\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:OPENSSL_DIR="C:\msys64\mingw64"
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

The real Postgres migration smoke intentionally uses `CAIRN_DATABASE_TEST_URL`, not the application `DATABASE_URL`, so it can be pointed at a disposable database:

```powershell
$env:CAIRN_DATABASE_TEST_URL="postgres://cairn:cairn@localhost:5432/cairn_identity_test"
cargo +stable-x86_64-pc-windows-gnu test -p cairn-database --test postgres_migrations --locked
```
