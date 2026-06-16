# Operations Runbook

This runbook covers the current production operations surface for Cairn Identity: backups, restores, key-encryption-key handling, signing-key rotation, break-glass admin recovery, audit retention/export, and lifecycle email delivery jobs.

## Runtime Configuration And Secrets

Set these for deployed API runtimes. Local development has localhost defaults for the two origin variables, but production operators should set them explicitly.

- `DATABASE_URL`: required Postgres connection string.
- `CAIRN_ISSUER`: public API/OIDC origin. Production must be HTTPS with no path, query, fragment, or credentials.
- `CAIRN_PUBLIC_WEB_ORIGIN`: public web origin used for lifecycle action links. Production must be HTTPS with no path, query, fragment, or credentials.
- `CAIRN_KEY_ENCRYPTION_KEY`: base64url-no-padding 32-byte AES-256-GCM key. It is required by Local Docker Compose, database-backed signing-key generation and rotation, and production lifecycle action-link encryption.

Generate a KEK:

```powershell
cairn-api signing-key generate-kek
```

Store the generated value in the platform secret store. Do not commit it, print it in deployment logs, or rotate it without first backing up the database.

## Production Bootstrap And Email Requirements

- `CAIRN_ENV=production`: set for production deployments so production origin, cookie, bootstrap, and email-provider rules apply.
- `CAIRN_BOOTSTRAP_SETUP_SECRET`: random operator-held setup secret required for first administrator bootstrap when `CAIRN_ENV=production`.
- `CAIRN_EMAIL_PROVIDER=command`: required before production lifecycle email delivery is marked ready. The provider defaults to `stdout` in development and `disabled` in production; `stdout` is rejected in production.
- `CAIRN_EMAIL_COMMAND_PATH`: required when `CAIRN_EMAIL_PROVIDER=command`; points to the executable that sends rendered email payloads.

## Optional And Defaulted Operations Settings

- `CAIRN_DEFAULT_ORG_SLUG`: defaults to `default`. Operator commands such as break-glass admin recovery, audit export, audit purge, and restore checks use this slug to resolve the organization.
- `CAIRN_AUDIT_RETENTION_DAYS`: audit rows older than this window are eligible for explicit purge. Defaults to `365` and is clamped to `30..3650`.
- `CAIRN_AUDIT_PURGE_BATCH_SIZE`: maximum rows deleted by one `audit purge-expired` run. Defaults to `1000` and is clamped to `1..50000`.
- `CAIRN_AUDIT_EXPORT_MAX_ROWS`: maximum rows emitted by one admin audit export page. Defaults to `10000` and is clamped to `1..50000`.
- `CAIRN_EMAIL_BATCH_SIZE`: default `10`, clamped to `1..100`.
- `CAIRN_EMAIL_MAX_ATTEMPTS`: default `5`, clamped to `1..20`.
- `CAIRN_EMAIL_RETRY_SECONDS`: default `300`, clamped to `1..86400`.
- `CAIRN_EMAIL_SENDING_TIMEOUT_SECONDS`: default `900`, clamped to `30..86400`.
- `CAIRN_TRUSTED_PROXY_IPS`: optional comma-separated exact IP addresses for direct reverse proxy or CDN peers. Leave unset unless the direct peer is trusted to set forwarded IP headers. When the peer matches, the first `X-Forwarded-For` IP, falling back to `X-Real-IP`, becomes the audit and rate-limit client identity; otherwise the socket peer IP is used.

## Optional SCIM Setting

- `CAIRN_SCIM_BEARER_TOKEN_SHA256`: optional 64-character SHA-256 hex digest for the SCIM bearer token when provisioning is enabled; accepts up to four comma-separated hashes during rotation.

## Operator-Only Env Vars

Set these only in the operator shell or job that runs the named command, not as long-lived API runtime settings:

- `CAIRN_BREAK_GLASS_CONFIRM`: one-shot confirmation for `cairn-api admin break-glass-owner`.
- `CAIRN_OLD_KEY_ENCRYPTION_KEY` and `CAIRN_NEW_KEY_ENCRYPTION_KEY`: KEK rotation inputs for `cairn-api key-encryption rotate`.
- `CAIRN_OIDC_METADATA_SMOKE_ISSUER`, `CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL`, `CAIRN_BROWSER_ORIGIN_SMOKE_HOSTILE_ORIGIN`, `CAIRN_SECURITY_HEADERS_API_BASE_URL`, and `CAIRN_SECURITY_HEADERS_WEB_BASE_URL`: smoke-command target overrides.
- `CAIRN_SCIM_SMOKE_BASE_URL`, `CAIRN_SCIM_BEARER_TOKEN`, `CAIRN_SCIM_SECONDARY_BEARER_TOKEN`, and `CAIRN_SCIM_REJECTED_BEARER_TOKEN`: SCIM smoke inputs. The raw bearer-token values belong only in the command environment used for the smoke run.

## Operational Preflight

Run preflight after migrations, after restoring into a disaster-recovery database, after signing-key maintenance, and after KEK re-encryption:

```powershell
cairn-api operations preflight
```

The command is non-destructive. It verifies database reachability, that SQLx migrations have been applied, that an active OIDC signing source exists, that database-backed signing material can be decrypted with `CAIRN_KEY_ENCRYPTION_KEY`, that active database keys appear in JWKS, and that production lifecycle email delivery is configured with `CAIRN_EMAIL_PROVIDER=command`, a non-empty `CAIRN_EMAIL_COMMAND_PATH`, and `CAIRN_KEY_ENCRYPTION_KEY` for encrypted outbox action links. It also prints signing-key lifecycle posture, the configured audit retention/export ceilings, OpenID conformance preparation posture, and SCIM provisioning posture. It prints a JSON report and exits non-zero when a required check fails.

The `signing.lifecycle` block reports total, active, active-with-private-material, unretired, retired, rollover, and encrypted-private-material key counts, the active key creation timestamp, active key age in seconds, the oldest unretired key timestamp, the newest retired timestamp, the 90-day rotation recommendation threshold, whether rotation is recommended, and the `ensure`, `rotate`, `list`, and `retire` commands. Production preflight fails if more than one unretired database signing key is marked active because JWKS and ID-token signing must have one authoritative active key.

The `email_delivery` block reports the configured provider, production readiness, whether the command provider and command path are configured, whether the KEK is configured for lifecycle action-link decryption, batch size, max attempts, retry delay, stale-sending reclaim timeout, the delivery command, the provider-smoke command, whether provider smoke is required before production use, and a redacted `queue` summary. The queue summary includes counts for `queued`, `retry`, `retry_due`, `sending`, `stale_sending`, `failed`, `sent`, and `unfinished`, plus the oldest unfinished row timestamp and next future retry timestamp. It does not print lifecycle tokens, rendered email bodies, recipient addresses, subjects, provider credentials, provider message IDs, last errors, or the command path value.

Production preflight fails if `email_delivery.queue.failed` is non-zero. Resolve failed rows by reviewing provider logs and application audit context, correcting the provider issue, and re-queueing or otherwise handling the affected lifecycle messages before claiming production readiness. Queued, retry, and stale-sending rows are reported for worker scheduling review; stale `sending` rows are reclaimable by the next `cairn-api email-outbox deliver-once` run.

The `openid_conformance` block never prints client secrets. It reports the normalized issuer, whether the issuer is an externally reachable HTTPS origin, whether every static-client conformance environment variable is present, the missing variable names, the targeted Config OP and Basic OP profiles, the two conformance artifact commands, and that external OIDF suite results are still required as release evidence.

The `scim` block never prints bearer tokens or hashes. It reports whether SCIM is enabled, how many bearer-token hashes are active, whether the deployment is in a token-rotation window, the maximum configured hash count, the ServiceProviderConfig URL, and the connector-profile/smoke commands operators should run. A multi-hash rotation window is valid during rollout; remove retired hashes after every connector has moved and after `cairn-api scim smoke` proves retired-token rejection.

## OIDC Metadata Smoke

Run the OIDC metadata smoke against the deployed API origin before public beta, before OIDF suite execution, and after changing issuer, reverse-proxy, CDN, TLS, or signing-key exposure configuration:

```powershell
$env:CAIRN_OIDC_METADATA_SMOKE_ISSUER="https://id.example.com"
cairn-api operations oidc-metadata-smoke > oidc-metadata-smoke.json
```

When `CAIRN_OIDC_METADATA_SMOKE_ISSUER` is absent, the command uses `CAIRN_ISSUER`. The command sends no cookies, bearer tokens, client secrets, CSRF tokens, or session identifiers. It requires the issuer to be an HTTPS origin, fetches `/.well-known/openid-configuration` and `/.well-known/jwks.json` with redirects disabled, and verifies that deployed metadata matches the strict v1 posture: authorization code with query response mode, refresh token and client credentials grants, no password or implicit grant advertisement, PKCE `S256`, RS256 ID-token signing, request-object parameters disabled, RFC 9207 authorization response issuer support, issuer-relative endpoint URLs, and JWKS containing public RSA signing material without private JWK parameters.

## Browser Origin Smoke

Run the browser-origin smoke against the deployed API origin before public beta and after changing reverse-proxy, CDN, CORS, or security-header configuration:

```powershell
$env:CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL="https://id.example.com"
cairn-api operations browser-origin-smoke > browser-origin-smoke.json
```

When `CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL` is absent, the command uses `CAIRN_ISSUER`. The optional `CAIRN_BROWSER_ORIGIN_SMOKE_HOSTILE_ORIGIN` can override the default hostile origin for a controlled test domain. The command sends no cookies, bearer tokens, client secrets, or CSRF tokens. It probes every current mutating `/api/v1` endpoint class with hostile `Origin` and `Referer` headers and requires `403`, `Cache-Control: no-store`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`, and the standard `invalid request origin` API error before handler logic can run.

## Security Header Smoke

Run the security-header smoke against the deployed API and web origins before public beta and after changing reverse-proxy, CDN, TLS, CSP, or SvelteKit adapter configuration:

```powershell
$env:CAIRN_SECURITY_HEADERS_API_BASE_URL="https://id.example.com"
$env:CAIRN_SECURITY_HEADERS_WEB_BASE_URL="https://app.example.com"
cairn-api operations security-headers-smoke > security-headers-smoke.json
```

When those explicit smoke origins are absent, the command uses `CAIRN_ISSUER` and `CAIRN_PUBLIC_WEB_ORIGIN`. The command sends no cookies, bearer tokens, client secrets, or CSRF tokens. It probes API `/healthz`, API `/.well-known/openid-configuration`, web `/healthz`, and web `/login`, requiring HTTPS origins plus CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy` evidence. Web `/healthz` must also remain `Cache-Control: no-store`.

## Release Evidence Check

Before public beta, verify the release capture environment without printing secret values:

```powershell
cairn-api operations evidence-plan
```

The plan reports every required artifact, command, validator, safety flag, required environment variable names, and missing capture inputs. It exits non-zero until required variable names are present. It does not validate secret values or deployed behavior; `operations preflight`, the smoke commands, external conformance results, and `evidence-check` still own those checks.

Then initialize an access-controlled evidence directory:

```powershell
cairn-api operations evidence-init .\release-evidence
```

The initializer creates `release-evidence-manifest.json`, `README.md`, and a `.gitignore` that keeps evidence artifacts out of source control by default. `evidence-check` rejects missing, stale, or tampered scaffold files, so run the initializer before collecting artifacts. It refuses to replace an existing scaffold unless `--force` is passed:

```powershell
cairn-api operations evidence-init .\release-evidence --force
```

The manifest is a checklist, not proof that artifacts have been produced. It is generated from the same artifact specification as `evidence-plan` and `evidence-check`, and the checker requires it to match the current artifact contract so stale evidence directories cannot pass after release gates change. You can also print the token-free manifest without writing files:

```powershell
cairn-api operations evidence-manifest > release-evidence-manifest.json
```

Collect only the required JSON artifacts into the initialized directory and run:

```powershell
cairn-api operations evidence-status <evidence-dir>
cairn-api operations evidence-check <evidence-dir>
```

`evidence-status` runs the same validators as `evidence-check`, then emits a smaller JSON summary with passed, missing, and failed artifact counts plus the next command for every artifact that still needs work. It exits non-zero while the evidence set is incomplete. `evidence-check` remains the release gate and emits the full per-artifact check/failure detail. Both commands reject unexpected files, directories, symlinks, screenshots, logs, raw provider exports, and forbidden secret-bearing field names in token-free artifacts; failure text redacts obvious secret-looking values before printing.

The same read-only evidence plan, manifest, status, and check operations are available through the local `cairnid-mcp` stdio server. MCP status and check responses return sanitized counts and failure codes, not validator failure text. See [mcp.md](mcp.md) for tool names and path restrictions.

By default, artifact files, generated static OpenID artifact `generated_at` timestamps, receipt `completed_at` timestamps, and OpenID conformance-suite `exportedAt` timestamps must be no more than 30 days old. Timestamped artifacts more than five minutes in the future are also rejected, which catches clock or copy/paste mistakes before a public-beta gate is marked ready. Override the age window only for an explicitly approved release process:

```powershell
cairn-api operations evidence-status <evidence-dir> --max-age-days 14
cairn-api operations evidence-check <evidence-dir> --max-age-days 14
```

The command validates these required artifact names:

- `operations-preflight.json`: output from `cairn-api operations preflight`; must be production, `status="ok"`, no failures, applied migrations present, decryptable signing key, exactly one active database signing key, JWKS exposure, production email readiness, no failed outbox rows, HTTPS issuer posture, and complete static-client conformance environment.
- `dependency-policy-check.json`: output from `cairn-api operations dependency-policy-evidence`; must be `status="ok"`, include a valid `completed_at`, prove `Cargo.lock`, `bun.lock`, `package.json`, `deny.toml`, `.cargo/audit.toml`, and `docs/dependencies.md` are present, and show passed `cargo deny check`, `cargo audit`, and `bun run audit` checks with tool versions, exit codes, and byte counts only. The validator rejects archived stdout, stderr, token, secret, password, request-header, authorization-header, and cookie fields.
- `openid-static-registration.json`: output from `cairn-api conformance oidcc-static-registration`; must include a fresh RFC3339 `generated_at`, be `status="ready"`, use an HTTPS issuer origin, include Config OP and Basic OP profiles, include both OIDF run-plan commands, and describe primary plus secondary static clients with exact callback/logout URLs, code flow, refresh grant, `client_secret_basic`/`client_secret_post`, `S256`, and the required scopes.
- `cairn-oidcc-static.json`: output from `cairn-api conformance oidcc-static-config`; must include a fresh RFC3339 `generated_at`, the HTTPS discovery URL, and distinct primary/secondary confidential client IDs and secrets. This artifact contains client secrets and must stay in the access-controlled release-evidence directory.
- `oidc-metadata-smoke.json`: output from `cairn-api operations oidc-metadata-smoke`; must be `status="ok"`, use an HTTPS issuer origin, include a valid completion timestamp, and include passed checks for strict discovery metadata, issuer-relative endpoint URLs, PKCE `S256`, RS256, disabled request objects, RFC 9207 issuer support, and public-only JWKS signing material.
- `openid-config-op-result.json`: Config OP suite result; must be either a token-free OpenID conformance-suite plan export for `oidcc-config-certification-test-plan` with a fresh root `exportedAt`, root `exportedFrom` on `https://www.certification.openid.net`, every exported test carrying an export timestamp and matching suite origin, and every exported test `status="FINISHED"` with `result="PASSED"` or `result="WARNING"`, or a normalized result summary with `source="openid-conformance-suite"`, `certification_profile="Config OP"`, `plan_name="oidcc-config-certification-test-plan"`, `status="FINISHED"`, `result="PASSED"` or `result="WARNING"`, RFC3339 `completed_at`, and an HTTPS `published_result_url` on `www.certification.openid.net`. The validator rejects secret-bearing result fields in either format. `cairn-api conformance oidcc-result-template config-op` generates the token-free starting shape for normalized published-result summaries.
- `openid-basic-op-result.json`: Basic OP suite result with the same contract for `oidcc-basic-certification-test-plan` and `certification_profile="Basic OP"`. `cairn-api conformance oidcc-result-template basic-op` generates the token-free starting shape for normalized published-result summaries.
- `scim-generic-connector-profile.json`: output from `cairn-api scim connector-profile generic`; must include a fresh RFC3339 `generated_at`, HTTPS issuer and SCIM base URLs, bearer-token hash/rotation guidance, User and Group mapping guidance, supported operation coverage, unsupported feature disclosure, and smoke commands including primary, secondary, and rejected bearer-token variables.
- `scim-okta-connector-profile.json`: output from `cairn-api scim connector-profile okta`; must satisfy the same profile contract with Okta-specific connector settings.
- `scim-entra-connector-profile.json`: output from `cairn-api scim connector-profile entra`; must satisfy the same profile contract with Microsoft Entra-specific connector settings.
- `scim-smoke.json`: output from `cairn-api scim smoke`; must be `status="ok"`, use an HTTPS SCIM smoke base URL, include a valid `completed_at`, prove `secondary_token_checked=true` and `rejected_token_checked=true`, include exactly three created user IDs, exactly matching soft-deleted user IDs, a deleted group ID, and passed checks for metadata, User, Group, Bulk, token-rotation, and retired-token rejection flows.
- `scim-okta-connector-smoke.json`: normalized token-free summary captured after the Okta provisioning client runs against the production-like SCIM endpoint; `cairn-api scim connector-smoke-template okta` generates the token-free starting shape. The final artifact must be `status="ok"`, `source="external-scim-connector"`, `provider="okta"`, use an HTTPS SCIM base URL, include a valid `completed_at`, include non-empty connector application/job IDs, prove secondary-token acceptance and retired-token rejection, include two created user UUIDs, a deactivated user UUID matching one created user, a deleted group UUID, and named passed checks for connector enablement, ServiceProviderConfig, User, Group, Bulk, deactivation, deletion, and token-rotation flows. The validator rejects raw-token, bearer-token, authorization-header, password, and secret field names in this artifact.
- `scim-entra-connector-smoke.json`: normalized token-free summary captured after the Microsoft Entra provisioning client runs against the production-like SCIM endpoint; `cairn-api scim connector-smoke-template entra` generates the token-free starting shape. The final artifact must satisfy the same contract with `provider="entra"` and display name `Microsoft Entra SCIM 2.0`.
- `browser-origin-smoke.json`: output from `cairn-api operations browser-origin-smoke`; must be `status="ok"`, use an HTTPS API origin and HTTPS hostile origin, include a valid completion timestamp, and show `403` plus no-store/security-header evidence for every checked mutating `/api/v1` route class.
- `security-headers-smoke.json`: output from `cairn-api operations security-headers-smoke`; must be `status="ok"`, use HTTPS API and web origins, include a valid completion timestamp, and prove CSP, HSTS, hardening headers, and web health no-store behavior on deployed API and web responses.
- `email-provider-smoke.json`: output from `cairn-api email-outbox smoke-provider <recipient-email>`; must be `status="sent"`, provider `command`, include a valid `completed_at`, include a recipient address containing `@`, and use a non-empty `provider_message_id` when the provider returns one.
- `lifecycle-email-smoke.json`: output from `cairn-api email-outbox lifecycle-smoke-evidence`; must be `status="completed"`, provider `command`, include a valid `completed_at`, and include `sent` message evidence for `invitation`, `email_verification`, `password_recovery`, `password_recovered_notification`, `password_changed_notification`, and `new_login_notification`.
- `restore-drill.json`: output from `cairn-api operations restore-check`; must be `status="ok"`, no failures, include a valid `completed_at`, applied migrations present, configured default organization UUID present, and either decryptable restored database signing/JWKS material or configured legacy signing material.
- `signing-key-rotation-drill.json`: output from `cairn-api signing-key rotate`; must be `status="rotated"`, include a non-empty `active_kid`, set `active=true`, and include a valid `completed_at`.
- `kek-rotation-drill.json`: output from `cairn-api key-encryption rotate`; must be `status="rotated"`, include a valid `completed_at`, report at least one re-encrypted signing key, and include a non-negative lifecycle delivery token count.
- `break-glass-admin-recovery-drill.json`: output from `cairn-api admin break-glass-owner <user-email>`; must be `status="granted"`, include a valid `completed_at`, organization/user/admin group UUIDs, non-empty user email, valid before/final user statuses, final `user_status_after="active"`, final `membership_role_after="owner"`, and an audit event UUID.
- `audit-export-archive-drill.json`: output from `cairn-api audit export-ndjson <output-path>`; must be `status="ok"`, include a valid `completed_at`, organization UUID, create-only output path, row/byte counts, limit/ceiling values, cursor consistency with UUID `next_after_id` when `has_more=true`, and well-typed filters with UUID actor IDs when present.
- `audit-retention-purge-drill.json`: output from `cairn-api audit purge-expired`; must be `status="ok"`, include organization UUID, valid `completed_at`, valid cutoff timestamp, retention days within 30..3650, batch size within 1..50000, and `deleted <= batch_size`.

Lifecycle email smoke evidence must stay token-free. Generate it from sent outbox rows after the provider-specific lifecycle smoke:

```powershell
cairn-api email-outbox lifecycle-smoke-evidence > lifecycle-email-smoke.json
```

The command records whether each template included an action URL, but does not store the URL or token:

```json
{
  "status": "completed",
  "provider": "command",
  "completed_at": "2026-06-07T12:00:00Z",
  "messages": [
    {
      "kind": "invitation",
      "template": "invitation",
      "status": "sent",
      "action_url_present": true,
      "provider_message_id": "provider-message-id"
    },
    {
      "kind": "password_changed_notification",
      "template": "password_changed_notification",
      "status": "sent",
      "action_url_present": false
    }
  ]
}
```

`evidence-check` prints a token-free JSON report with per-artifact status, modified timestamps, checks, failures, and the command that should produce missing evidence. It exits non-zero until the scaffold is current, the directory contains no unapproved entries, token-free artifacts avoid forbidden secret-bearing field names, and every artifact passes. Failure text redacts obvious secret-looking echoed values, but malformed evidence files should still be treated as sensitive during cleanup. The only required artifact that is expected to contain secrets is `cairn-oidcc-static.json`; keep the evidence directory access-controlled and out of source control.

## OpenID Conformance Preparation

Use the conformance commands before running the OpenID Foundation suite so client registration and suite JSON are generated from the same environment values:

```powershell
cairn-api conformance oidcc-static-registration > openid-static-registration.json
cairn-api conformance oidcc-static-config > cairn-oidcc-static.json
cairn-api conformance oidcc-result-template config-op > openid-config-op-result.template.json
cairn-api conformance oidcc-result-template basic-op > openid-basic-op-result.template.json
```

`oidcc-static-registration` emits the exact callback URLs and static-client settings for the configured suite alias. `oidcc-static-config` emits the JSON shape used by the OIDF Config OP and Basic OP static-client plans. Both commands include a root `generated_at` timestamp for release evidence and require an HTTPS `CAIRN_ISSUER`; the registration command also requires `CAIRN_CONFORMANCE_SUITE_BASE_URL`. `oidcc-result-template` emits normalized result-summary templates that cannot pass unchanged because `operations evidence-check` rejects `status="template"`, `result="pending"`, placeholder timestamps, placeholder official result URLs, and secret-bearing field names in normalized OpenID result JSON. Run `cairn-api operations preflight` first to confirm the issuer posture and identify missing `CAIRN_CONFORMANCE_*` variables without printing secret values. See [openid-conformance.md](openid-conformance.md) for the full environment contract and evidence gate.

## SCIM Provisioning

SCIM is disabled when `CAIRN_SCIM_BEARER_TOKEN_SHA256` is absent. To enable it, generate a high-entropy raw bearer token and store only its SHA-256 hex digest in the API environment:

```powershell
$token = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($token))).ToLowerInvariant()
```

Set `CAIRN_SCIM_BEARER_TOKEN_SHA256` to `$hash`, restart the API, then configure the provisioning client with the raw `$token`.

Generate connector setup guidance without printing the raw token:

```powershell
$env:CAIRN_ISSUER="https://id.example.com"
cairn-api scim connector-profile generic
cairn-api scim connector-profile okta
cairn-api scim connector-profile entra
```

For release evidence, save those reports as `scim-generic-connector-profile.json`, `scim-okta-connector-profile.json`, and `scim-entra-connector-profile.json`. The reports are token-free, but `operations evidence-check` still requires fresh `generated_at` timestamps and validates the provider-specific mapping and smoke guidance before accepting SCIM smoke evidence.

Generate token-free templates for the external connector summaries before running the provider smokes:

```powershell
cairn-api scim connector-smoke-template okta > scim-okta-connector-smoke.template.json
cairn-api scim connector-smoke-template entra > scim-entra-connector-smoke.template.json
```

The templates preserve the exact field names and required check names expected by `operations evidence-check`. They are not release evidence until the external connector run is complete, `status` is changed to `ok`, placeholders are replaced, and every required check is marked `passed`.

Smoke-test the endpoint:

```powershell
$headers = @{ Authorization = "Bearer <raw-token>" }
Invoke-RestMethod -Headers $headers https://id.example.com/scim/v2/ServiceProviderConfig
Invoke-RestMethod -Headers $headers https://id.example.com/scim/v2/Users
```

Rotate the SCIM token with a two-deploy window:

1. Generate a new raw token and hash.
2. Deploy `CAIRN_SCIM_BEARER_TOKEN_SHA256="<old-hash>,<new-hash>"` and restart the API.
3. Run smoke with the new token as `CAIRN_SCIM_BEARER_TOKEN` and the old token as `CAIRN_SCIM_SECONDARY_BEARER_TOKEN` to prove both hashes are active.
4. Update every provisioning connector to the new raw token.
5. Deploy only `<new-hash>`, restart the API, and run smoke with the old token as `CAIRN_SCIM_REJECTED_BEARER_TOKEN` to prove retired-token rejection.

Run the built-in public-surface smoke before external connector smokes:

```powershell
$env:CAIRN_SCIM_SMOKE_BASE_URL="https://id.example.com"
$env:CAIRN_SCIM_BEARER_TOKEN="<raw-token>"
$env:CAIRN_SCIM_SECONDARY_BEARER_TOKEN="<old-or-new-token-during-rotation>"
$env:CAIRN_SCIM_REJECTED_BEARER_TOKEN="<old-or-invalid-token>"
cairn-api scim smoke
```

The command verifies metadata, optional secondary-token acceptance, optional rejected-token `401` behavior, User and Group create, exact-filter lookup, SearchRequest lookup, bounded projection, bounded PATCH including group member value paths, dependency-aware Bulk with forward `bulkId:` references, full replacement, soft user deprovisioning, group deletion, and response content types. For public-beta release evidence, run it with both `CAIRN_SCIM_SECONDARY_BEARER_TOKEN` and `CAIRN_SCIM_REJECTED_BEARER_TOKEN`; `operations evidence-check` requires both token checks, the RFC3339 completion timestamp, created-user cleanup evidence, deleted-group evidence, and every required SCIM smoke check.

After the built-in public-surface smoke passes, run controlled Okta and Microsoft Entra provisioning-client smokes against the same production-like HTTPS deployment. Save token-free normalized summaries as `scim-okta-connector-smoke.json` and `scim-entra-connector-smoke.json`. Each summary must use `source="external-scim-connector"`, include the provider, display name, HTTPS `scim_base_url`, `completed_at`, connector application/job IDs, secondary-token and retired-token checks, two created User UUIDs, the deactivated User UUID, the deleted Group UUID, and passed named checks for connector enablement, ServiceProviderConfig, User create/filter/SearchRequest/projection/PATCH/replace/deactivation, Group create/filter/SearchRequest/projection/member PATCH/replace/delete, Bulk forward-reference behavior, token-rotation acceptance, and retired-token rejection. Do not archive raw bearer tokens, authorization headers, provider credentials, screenshots, passwords, or client secrets in these JSON files. `operations evidence-check` rejects untouched templates with `status="template"` so placeholder files cannot pass the gate by mistake.

SCIM deprovisioning is soft: `DELETE /scim/v2/Users/{id}` suspends the user and revokes browser sessions, access tokens, and refresh tokens. Setting `active=false` through PUT or PATCH uses the same revocation path. It does not delete audit history, memberships, consent grants, or the user record.

Full connector setup and supported filter details are documented in [scim.md](scim.md).

## Break-Glass Admin Recovery

Use break-glass only when every normal administrator is locked out or demoted. It is an operator command backed by database credentials, so it intentionally bypasses browser admin authorization.

The target must already be an organization user. The command does not create a user and does not set or reset a password. It reactivates the user, ensures the built-in `administrators` group exists, grants `owner` membership, and writes a system audit event in the same database transaction.

```powershell
$env:CAIRN_BREAK_GLASS_CONFIRM="grant-admin-owner"
cairn-api admin break-glass-owner ops@example.com
Remove-Item Env:\CAIRN_BREAK_GLASS_CONFIRM
```

The command uses `CAIRN_DEFAULT_ORG_SLUG` to choose the organization. It prints a JSON report with `status="granted"`, the affected `organization_id`, `user_id`, `user_email`, previous and final user status, admin group id, whether the admin group was created, previous and final membership role, `audit_event_id`, and `completed_at`. The release-evidence checker validates this receipt shape for `break-glass-admin-recovery-drill.json`, including the completion timestamp, UUID-shaped organization/user/admin group/audit IDs, final active user status, final owner membership, and audit event evidence.

After recovery:

- Sign in as the recovered user and create or repair normal administrator memberships.
- Review the `operator.break_glass_owner_granted` audit event.
- Rotate any operator credentials or deployment secrets that were exposed during the emergency.
- Clear `CAIRN_BREAK_GLASS_CONFIRM` from the shell and platform environment.

## Backup

Back up Postgres before deploys that change migrations, before signing-key rotation, before KEK rotation, and before destructive maintenance:

```powershell
pg_dump --format=custom --no-owner --no-acl --file=cairnid.backup "$env:DATABASE_URL"
```

The backup contains encrypted signing private keys and encrypted lifecycle delivery tokens, but it is still sensitive because it contains users, sessions, audit data, token hashes, and email addresses. Store backups encrypted and access-controlled.

Minimum backup schedule before public beta:

- Daily full logical backup.
- Backup retention of at least 7 days.
- Restore drill after every migration-shape change.
- Manual backup immediately before KEK or signing-key maintenance.

## Audit Retention And Export

Audit events are organization-scoped investigation evidence. Keep enough history for incident response and compliance, then purge explicitly from an operator-controlled job.

Export filtered audit data from an operator shell for archive evidence:

```powershell
cairn-api audit export-ndjson .\evidence\cairn-audit-events.ndjson `
  --action admin. `
  --from 2026-01-01T00:00:00Z `
  > .\evidence\audit-export-archive-drill.json
```

The CLI runs migrations first, resolves `CAIRN_DEFAULT_ORG_SLUG`, writes one bounded NDJSON page using `CAIRN_AUDIT_EXPORT_MAX_ROWS`, and prints a JSON receipt containing `status`, `organization_id`, `output_path`, `rows_exported`, `bytes_written`, `limit`, `export_max_rows`, `has_more`, optional `next_after_created_at`/`next_after_id`, the filters used, and `completed_at`. The release-evidence checker validates this receipt shape for `audit-export-archive-drill.json`, including UUID-shaped organization ID, next cursor ID, and optional actor ID fields. The output file is opened with create-only semantics; an existing archive path fails instead of being overwritten. Continue a paged archive by passing the returned cursor fields back as `--after-created-at <rfc3339> --after-id <uuid>`.

Supported CLI filters:

- `--action <prefix>`
- `--target <prefix>`
- `--actor-kind user|client|system`
- `--actor-id <uuid>`
- `--from <rfc3339>`
- `--to <rfc3339>`
- `--limit <rows>`

Export filtered audit data through the admin API when a browser-admin download flow is preferred:

```powershell
curl -H "Cookie: cairn_session=<admin-session>" "https://id.example.com/api/v1/audit-events/export?action=admin.&from=2026-01-01T00:00:00Z" --output cairn-audit-events.ndjson
```

The export endpoint requires an administrator browser session, uses the same filters as `GET /api/v1/audit-events`, emits `application/x-ndjson`, and returns `x-cairn-next-cursor` when the next export page is available. Store CLI and API exports encrypted and access-controlled because audit rows can contain user identifiers, IP addresses, user agents, target IDs, and redacted-but-sensitive operational context.

Purge expired rows for the configured `CAIRN_DEFAULT_ORG_SLUG`:

```powershell
cairn-api audit purge-expired
```

The command runs migrations first, resolves `CAIRN_DEFAULT_ORG_SLUG`, deletes at most `CAIRN_AUDIT_PURGE_BATCH_SIZE` rows where `created_at` is older than `now - CAIRN_AUDIT_RETENTION_DAYS`, and prints a JSON report containing `status`, `organization_id`, `cutoff`, `retention_days`, `batch_size`, `deleted`, and `completed_at`. The release-evidence checker validates this receipt shape for `audit-retention-purge-drill.json`, including the organization UUID, completion timestamp, retention/batch bounds, and `deleted <= batch_size`.

Recommended schedule:

- Export and archive required audit evidence before purge if the deployment has an external retention requirement.
- Run a manual backup before changing retention settings or before the first production purge.
- Run `cairn-api audit purge-expired` from a scheduled job often enough that each run deletes a small batch, for example hourly or daily depending on event volume.
- Alert if repeated runs always delete exactly `CAIRN_AUDIT_PURGE_BATCH_SIZE`; that means the job is falling behind or retention was shortened.

## Restore

Restore into a fresh database, not over a live database:

```powershell
createdb cairn_identity_restore
pg_restore --clean --if-exists --no-owner --no-acl --dbname="$env:RESTORE_DATABASE_URL" cairnid.backup
```

After restore:

1. Configure the same `CAIRN_KEY_ENCRYPTION_KEY` that encrypted the stored signing keys.
2. Point `DATABASE_URL` at the restored database and run a read-only restore check:

```powershell
$env:DATABASE_URL=$env:RESTORE_DATABASE_URL
cairn-api operations restore-check > .\evidence\restore-drill.json
```

The command does not run migrations and does not write application rows. It verifies database reachability, applied SQLx migration history, the configured `CAIRN_DEFAULT_ORG_SLUG`, restored active JWKS/signing-key material, and whether OIDC signing can be served with either decryptable restored database key material or configured legacy `CAIRN_SIGNING_*` material. It prints a JSON drill report with `status`, `completed_at`, checks, and failures; this is the expected `restore-drill.json` release-evidence artifact.

3. Start the API against the restored database.
4. Run `cairn-api operations preflight`.
5. Run `cairn-api signing-key list`.
6. Check `GET /.well-known/jwks.json`.
7. Bootstrap/login through the web UI if this is a disaster-recovery environment.
8. Run `cairn-api email-outbox deliver-once` only after verifying the restored environment should send email.

## Signing-Key Rotation

Signing keys are RS256 keys stored in Postgres with encrypted private PEM material.

Generate or confirm the active key:

```powershell
cairn-api signing-key ensure
cairn-api signing-key list
```

Rotate:

```powershell
cairn-api signing-key rotate
cairn-api signing-key list
```

`cairn-api signing-key rotate` prints a token-free JSON receipt with `status`, `active_kid`, `active`, and RFC3339 `completed_at`. Save that output as `signing-key-rotation-drill.json` for release evidence; the evidence checker rejects generic manual notes for this artifact.

After rotation:

1. Confirm the new `kid` appears in `/.well-known/jwks.json`.
2. Keep the old key in JWKS until old ID tokens expire and relying parties have refreshed metadata.
3. Run `cairn-api operations preflight` and confirm `signing.lifecycle.active_key_count` is `1`, `rollover_key_count` includes the old unretired key, and `rotation_recommended` is `false` for the newly active key.
4. Retire the old key:

   ```powershell
   cairn-api signing-key retire <old-kid>
   ```

5. Confirm the retired key is absent from JWKS and appears in the preflight retired-key count.

Current ID tokens expire after 10 minutes. Keep a conservative overlap of at least 30 minutes before retiring old keys.

## KEK Rotation

The KEK encrypts database-backed signing private keys and lifecycle email delivery tokens. Rotate it in a maintenance window because the API and email worker must use the same KEK as the encrypted database rows.

Safe rotation procedure:

1. Take and verify a fresh backup.
2. Pause API writes and scheduled email delivery workers.
3. Drain or deliver queued lifecycle emails with the old KEK when possible:

   ```powershell
   cairn-api email-outbox deliver-once
   ```

4. Generate a new KEK:

   ```powershell
   cairn-api signing-key generate-kek
   ```

5. Run database re-encryption with both keys available:

   ```powershell
   $env:CAIRN_OLD_KEY_ENCRYPTION_KEY="<old value>"
   $env:CAIRN_NEW_KEY_ENCRYPTION_KEY="<new value>"
   cairn-api key-encryption rotate
   ```

   The command decrypts all encrypted signing-key rows and lifecycle delivery tokens with `CAIRN_OLD_KEY_ENCRYPTION_KEY`, re-encrypts them with `CAIRN_NEW_KEY_ENCRYPTION_KEY`, then applies the ciphertext/nonce updates in one database transaction. It prints a JSON report with `status="rotated"`, `signing_keys`, `email_delivery_tokens`, and RFC3339 `completed_at`; the release-evidence checker validates this receipt shape for `kek-rotation-drill.json`.

6. Configure `CAIRN_KEY_ENCRYPTION_KEY` to the new value for the API and email worker.
7. Restart services.
8. Run:

   ```powershell
   cairn-api operations preflight
   cairn-api signing-key list
   cairn-api email-outbox deliver-once
   ```

9. Clear `CAIRN_OLD_KEY_ENCRYPTION_KEY` and `CAIRN_NEW_KEY_ENCRYPTION_KEY` from the maintenance environment.

Do not discard the old KEK until the re-encryption command has completed successfully and the restored services have been verified with the new KEK.

## Lifecycle Email Delivery

Run from a scheduled job or worker:

```powershell
cairn-api email-outbox deliver-once
```

The command claims `queued`, due `retry`, and stale `sending` rows. It sends one batch and exits with a JSON report.

Run `cairn-api operations preflight` before enabling the worker. Production preflight fails when the command provider is not selected, `CAIRN_EMAIL_COMMAND_PATH` is blank or absent, `CAIRN_KEY_ENCRYPTION_KEY` is absent, or failed outbox rows are present. The preflight report also exposes worker batch/retry/reclaim settings and redacted queue-health counts so scheduled jobs can be reviewed before sending real lifecycle links.

Production provider contract:

- `CAIRN_EMAIL_PROVIDER=command`.
- `CAIRN_EMAIL_COMMAND_PATH` points to an executable, not a shell command string.
- The executable receives rendered email JSON on stdin.
- It exits `0` only after the provider accepts the message.
- It can print `{ "provider_message_id": "..." }` to stdout.
- It must not log raw lifecycle URLs or tokens in production.

Provider smoke:

```powershell
cairn-api email-outbox smoke-provider ops@example.com
```

The smoke command uses the configured provider with a synthetic `provider_smoke` payload. It does not connect to Postgres, does not create account tokens, and does not include lifecycle URLs or user secrets. It prints a JSON report with `status`, `provider`, `recipient_email`, RFC3339 `completed_at`, and optional `provider_message_id`, and exits non-zero if the provider command cannot accept the message.

Before public beta, first run `smoke-provider` against the chosen production provider command and a controlled recipient mailbox. Then run a provider-specific lifecycle and security-notification smoke that creates one invitation, one verification email, one recovery email, one password-recovered notification, one password-change notification, and one first-seen login notification, runs `deliver-once`, confirms the provider accepted all six real account messages, and records the token-free receipt with `cairn-api email-outbox lifecycle-smoke-evidence > lifecycle-email-smoke.json`.
