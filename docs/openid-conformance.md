# OpenID Conformance

Cairn Identity targets the OpenID Foundation Config OP and Basic OP profiles for v1. Implicit, hybrid, dynamic registration, and `response_mode=form_post` profiles stay out of scope because v1 intentionally supports only Authorization Code + PKCE with query response mode. The Basic OP authorization endpoint still accepts both GET query requests and `application/x-www-form-urlencoded` POST authorization requests.

Primary references:

- [OpenID Connect OP testing](https://openid.net/certification/connect_op_testing/)
- [OpenID conformance suite](https://gitlab.com/openid/conformance-suite/)

## Readiness Preflight

Run operational preflight before generating conformance artifacts:

```powershell
cairn-api operations preflight
```

The `openid_conformance` block reports:

- Whether `CAIRN_ISSUER` is an externally reachable HTTPS origin with no path, query, fragment, or credentials.
- Whether all static-client environment variables are present.
- The missing variable names, if any.
- The artifact commands for static registration and suite JSON generation.
- That external Config OP and Basic OP suite results are still required before public beta.

The block does not print client IDs, client secrets, or generated suite JSON. Keep the generated `cairn-oidcc-static.json` out of source control because it contains client secrets.

Run the deployed metadata smoke before suite execution so discovery and JWKS failures are caught before OIDF plans consume the static client configuration:

```powershell
$env:CAIRN_OIDC_METADATA_SMOKE_ISSUER="https://id.example.com"
cairn-api operations oidc-metadata-smoke > oidc-metadata-smoke.json
```

The receipt is token-free release evidence. It verifies the HTTPS issuer origin, strict code-flow discovery metadata, disabled request-object parameters, PKCE `S256`, RS256 signing metadata, RFC 9207 issuer support, issuer-relative endpoint URLs, and public-only JWKS signing material.

## Static Client Setup

Create two confidential OIDC clients in the admin UI before running the Basic OP plan. Both clients should use:

- Response types: `code`
- Grant types: `authorization_code`, `refresh_token`
- Token endpoint auth methods tested by the suite: `client_secret_basic`, `client_secret_post`
- PKCE method: `S256`
- Allowed scopes: `openid`, `profile`, `email`, `groups`, `offline_access`

Use the generated registration report to set exact callback URLs and keep the report as release evidence:

```powershell
$env:CAIRN_ISSUER="https://id.example.com"
$env:CAIRN_CONFORMANCE_ALIAS="cairn-basic-op"
$env:CAIRN_CONFORMANCE_SUITE_BASE_URL="https://www.certification.openid.net/"
$env:CAIRN_CONFORMANCE_CLIENT_ID="<primary client id>"
$env:CAIRN_CONFORMANCE_CLIENT2_ID="<secondary client id>"
cairn-api conformance oidcc-static-registration > openid-static-registration.json
```

The command uses only the conformance environment variables, so it can run before `DATABASE_URL` or signing keys are provisioned. It rejects non-HTTPS issuers, unsafe aliases, and malformed conformance-suite base URLs, and includes an RFC3339 `generated_at` timestamp so the output is suitable for release evidence.

## Suite Configuration

Generate the static configuration JSON that the OIDF suite expects:

```powershell
$env:CAIRN_CONFORMANCE_CLIENT_SECRET="<primary client secret>"
$env:CAIRN_CONFORMANCE_CLIENT2_SECRET="<secondary client secret>"
cairn-api conformance oidcc-static-config > cairn-oidcc-static.json
```

The output has this shape:

```json
{
  "generated_at": "2026-06-07T12:00:00Z",
  "alias": "cairn-basic-op",
  "description": "Cairn Identity OIDC static client certification",
  "server": {
    "discoveryUrl": "https://id.example.com/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "<primary client id>",
    "client_secret": "<primary client secret>"
  },
  "client2": {
    "client_id": "<secondary client id>",
    "client_secret": "<secondary client secret>"
  }
}
```

The OIDF runner reads the suite fields in this JSON, while `cairnid evidence check` also requires the root `generated_at` timestamp to be fresh. Keep this file out of source control because it contains client secrets.

Run these OIDF plan names against that JSON:

```powershell
python <openid-conformance-suite>/scripts/run-test-plan.py oidcc-config-certification-test-plan cairn-oidcc-static.json
python <openid-conformance-suite>/scripts/run-test-plan.py oidcc-basic-certification-test-plan cairn-oidcc-static.json
```

The hosted certification UI can use the same JSON from the suite's JSON configuration tab.

## Expected Basic OP Skips And Warnings

These notes describe the current Basic OP request-surface behavior so external OIDF results can be interpreted without overstating support:

- `/oauth2/authorize` accepts `application/x-www-form-urlencoded` POST requests with the same validation, session, consent, and redirect behavior as GET. JSON and other content types are rejected.
- Discovery continues to advertise `request_parameter_supported=false` and `request_uri_parameter_supported=false`. If Basic OP request-object modules send `request` or `request_uri`, Cairn returns `request_not_supported` or `request_uri_not_supported` through the registered redirect URI so the suite can skip those unsupported modules.
- Discovery continues to advertise `claims_parameter_supported=false`; Cairn only accepts the narrow Basic OP `claims={"userinfo":{"name":{"essential":true}}}` path. This is enough for `oidcc-claims-essential` to complete, but it is not general claims-parameter support.
- `phone` and `address` are intentionally absent from `scopes_supported`, so `oidcc-scope-phone`, `oidcc-scope-address`, and all-scope coverage that requires them are expected skips.
- `profile` and `email` are supported scopes, but Basic OP can still report warnings when the suite expects the full standard claim set. Cairn currently returns the implemented subset only: `name` for `profile`, and `email` plus `email_verified` for `email`.

Do not treat these notes as a certification claim. Public Basic OP readiness still requires an external OIDF run against the production-like issuer and archived token-free evidence.

## Result Templates

When archiving an official published result URL instead of a full suite export, generate token-free normalized summary templates before the external run:

```powershell
cairn-api conformance oidcc-result-template config-op > openid-config-op-result.template.json
cairn-api conformance oidcc-result-template basic-op > openid-basic-op-result.template.json
```

After the matching OIDF suite run is complete, save the final normalized files as `openid-config-op-result.json` and `openid-basic-op-result.json`. Replace the placeholder completion timestamp and official result URL, set `status="FINISHED"`, and set `result` to `PASSED` or `WARNING` only when the OIDF result supports that value. Do not include static-client secrets, cookies, request headers, passwords, screenshots, or browser session data in normalized result summaries; `cairnid evidence check` rejects secret-bearing field names in normalized OpenID result JSON.

## Evidence Gate

Public beta requires:

- Passing Config OP and Basic OP results for the production-like deployment under test.
- Published OIDF result links or token-free archived plan exports.
- The generated static configuration JSON and registration report attached to release evidence with fresh RFC3339 `generated_at` timestamps.
- The deployed OIDC metadata smoke receipt attached to release evidence.
- Release notes updated with the suite version, profile results, and any expected skips or failures.

Save normalized passing result JSON files into the release evidence directory as:

- `openid-static-registration.json`
- `cairn-oidcc-static.json`
- `oidc-metadata-smoke.json`
- `openid-config-op-result.json`
- `openid-basic-op-result.json`

The release evidence checker validates the generated static registration report and static suite config, including their root `generated_at` freshness, before accepting suite result files. For result files, it accepts either:

- OpenID conformance-suite plan export JSON with the expected `planInfo.planName`, a fresh root `exportedAt`, root `exportedFrom` on `https://www.certification.openid.net`, non-empty module instances, non-empty `testLogExports`, each exported test carrying an export timestamp and matching suite origin, and each exported test reporting `status="FINISHED"` with `result="PASSED"` or `result="WARNING"`. Plan exports must be token-free; use normalized published-result summaries when an export contains request headers, cookies, client secrets, passwords, or browser/session data.
- A normalized published-result summary with `source="openid-conformance-suite"`, the exact `plan_name`, the matching `certification_profile`, `status="FINISHED"`, `result="PASSED"` or `result="WARNING"`, RFC3339 `completed_at`, and an HTTPS `published_result_url` on `www.certification.openid.net`.

It rejects generic success-shaped JSON, wrong plan names, failed or unknown results, unfinished tests, untouched templates with `status="template"`, secret-bearing result fields in either accepted format, and non-empty root `failures` or `errors` arrays:

```powershell
cairnid evidence check <evidence-dir>
```
