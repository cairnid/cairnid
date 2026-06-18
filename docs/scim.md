# SCIM Provisioning

Cairn Identity exposes an initial SCIM 2.0 provisioning surface at `/scim/v2/*`. It is intended for server-to-server identity-provider provisioning jobs and directory integrations, not browser sessions.

This implementation follows the SCIM 2.0 protocol shape for service metadata, resource types, schemas, list responses, user/group resources, PatchOp requests, bounded Bulk mutations, and error responses while intentionally supporting a narrow v1 subset.

## Enablement

SCIM is disabled unless `CAIRN_SCIM_BEARER_TOKEN_SHA256` is configured. The variable accepts one SHA-256 hex digest normally and up to four comma-separated digests during a rotation window.

Generate a long random token and store only its SHA-256 hex digest in the API environment:

```powershell
$token = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($token))).ToLowerInvariant()
$hash
```

Configure the API:

```powershell
$env:CAIRN_SCIM_BEARER_TOKEN_SHA256="<64-char lowercase hex sha256>"
```

Configure the provisioning client with the raw `$token` value and send it as:

```http
Authorization: Bearer <raw-token>
```

Do not store the raw SCIM token in source control, application config files, CI logs, issue trackers, or screenshots. Rotate it by generating a new raw token and hash, deploying `CAIRN_SCIM_BEARER_TOKEN_SHA256="<old-hash>,<new-hash>"`, updating provisioning connectors to the new raw token, then deploying only `<new-hash>` after every connector has moved.

## Endpoints

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User`
- `GET /scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/ResourceTypes/User`
- `GET /scim/v2/ResourceTypes/Group`
- `POST /scim/v2/Bulk`
- `GET /scim/v2/Users`
- `POST /scim/v2/Users/.search`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/{user_id}`
- `PUT /scim/v2/Users/{user_id}`
- `PATCH /scim/v2/Users/{user_id}`
- `DELETE /scim/v2/Users/{user_id}`
- `GET /scim/v2/Groups`
- `POST /scim/v2/Groups/.search`
- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/{group_id}`
- `PUT /scim/v2/Groups/{group_id}`
- `PATCH /scim/v2/Groups/{group_id}`
- `DELETE /scim/v2/Groups/{group_id}`

All SCIM responses use `application/scim+json` and set `Cache-Control: no-store` plus `Pragma: no-cache`. Mutating request bodies must be `application/scim+json`; `application/json` is also accepted for compatibility with provisioning clients. JSON bodies are limited to 256 KiB and query strings are limited to 2 KiB.

## User Mapping

Cairn stores one login email per user. SCIM maps fields as follows:

| SCIM field | Cairn field | Notes |
| --- | --- | --- |
| `id` | `users.id` | Server-generated UUID. |
| `userName` | `users.email` | Required, normalized, unique per organization. |
| `externalId` | `users.scim_external_id` | Optional, unique per organization when present. |
| `displayName` | `users.display_name` | Preferred display name, max 160 characters. |
| `name.formatted` | `users.display_name` | Used when `displayName` is absent. |
| `name.givenName` + `name.familyName` | `users.display_name` | Joined when no formatted name is present. |
| `active` | `users.status` | `true` maps to `active`; `false` maps to `suspended`. |
| `emails[].value` | `users.email` | Optional, but every value must match `userName`. |
| `emails[].type` | Canonical work email type | Optional, but when present it must be `work`. |
| `emails[].primary` | Canonical primary marker | Optional on input; responses always return the stored work email as `primary=true`. |

`POST /Users` creates a user without a password. The user can later receive an invitation, verification, or recovery flow through the normal account lifecycle APIs.

`PUT /Users/{user_id}` is a full replacement of the supported SCIM fields. It updates email, external ID, display name, email verification state, and active/suspended status. Changing a user to non-active status revokes browser sessions, access tokens, and refresh tokens in the same transaction. The final active `administrators` owner cannot be deactivated through SCIM.

`PATCH /Users/{user_id}` supports a bounded SCIM PatchOp subset for the same persisted User fields. The request must include `schemas=["urn:ietf:params:scim:api:messages:2.0:PatchOp"]` and 1 to 20 operations. Supported `add` and `replace` paths are:

- `userName`
- `externalId`
- `displayName`
- `active`
- `name`
- `name.formatted`
- `name.givenName`
- `name.familyName`
- `emails`
- `emails.value`
- `emails.type`
- `emails.primary`
- `emails[type eq "work"]`
- `emails[type eq "work"].value`
- `emails[type eq "work"].type`
- `emails[type eq "work"].primary`
- `emails[primary eq true]`
- `emails[primary eq true].value`
- `emails[primary eq true].type`
- `emails[primary eq true].primary`
- `emails[value eq "current@example.com"]`
- `emails[value eq "current@example.com"].value`
- `emails[value eq "current@example.com"].type`
- `emails[value eq "current@example.com"].primary`

Omitting `path` for `add` or `replace` is supported when `value` is an object containing one or more supported attributes. Cairn stores exactly one primary work email: `emails.type` PATCH values must be `work`, and `emails.primary` PATCH values must be `true`; incompatible values are rejected instead of being silently discarded. `remove` is supported only for `externalId`; removing required local attributes such as `userName`, `emails`, `displayName`, or `active` returns a SCIM `mutability` error. Filtered email paths return `noTarget` when they do not match the stored primary work email.

`DELETE /Users/{user_id}` is a soft deprovision. It sets the user to `suspended` and revokes runtime credentials. It does not remove audit history, memberships, consent history, or the user row.

## Group Mapping

Cairn stores organization-scoped groups with user memberships. SCIM maps fields as follows:

| SCIM field | Cairn field | Notes |
| --- | --- | --- |
| `id` | `groups.id` | Server-generated UUID. |
| `displayName` | `groups.display_name` | Required, max 160 characters. |
| `externalId` | `groups.scim_external_id` | Optional, unique per organization when present. |
| `members[].value` | `memberships.user_id` | Must reference an existing user in the same organization. |
| `members[].type` | User-only membership type | Optional, but when present it must be `User`; nested groups are rejected. |

`POST /Groups` creates a group and optional user memberships. The local internal group slug is derived from `externalId` when present, otherwise from `displayName`, with a UUID fallback for names that do not produce ASCII slug characters.

`PUT /Groups/{group_id}` is a full replacement of the supported group fields. It updates display name, external ID, and the complete user membership set. Existing memberships are stored with the local `member` role; SCIM does not grant local group-owner privileges.

`PATCH /Groups/{group_id}` supports a bounded SCIM PatchOp subset. The request must include `schemas=["urn:ietf:params:scim:api:messages:2.0:PatchOp"]` and 1 to 20 operations. Supported `add` and `replace` paths are:

- `displayName`
- `externalId`
- `members`
- `members.value`
- `members[value eq "<user-uuid>"]`
- `members[value eq "<user-uuid>"].value`

Omitting `path` for `add` or `replace` is supported when `value` is an object containing one or more supported attributes. `replace members` replaces the full user membership set. `add members` appends missing user memberships and keeps existing members.

`members.value` accepts a UUID string or an array of UUID strings. Filtered member `add` is idempotent and requires the supplied member value to identify the same user as the path filter. Filtered member `replace` requires the path filter to match an existing member and replaces that single membership with the supplied user. Filtered member `add` and `replace` values must identify exactly one user. Generated member sub-attributes such as `members.display`, `members.type`, and `members.$ref` are not mutable.

Supported `remove` paths are:

- `externalId`
- `members`
- `members.value`
- `members[value eq "<user-uuid>"]`
- `members[value eq "<user-uuid>"].value`

Filtered member removals are idempotent and leave the resource unchanged when the user is not currently a member. `DELETE /Groups/{group_id}` deletes a non-protected group. SCIM can read the built-in `administrators` group, but cannot replace, patch, or delete it.

## Listing And Filters

`GET /Users` supports:

- `startIndex`: 1-based index, default `1`, max `10000`.
- `count`: page size, default `100`, max `200`; `0` returns no resources.
- `filter`: exact filters over `userName`, `externalId`, and `active`.
- `attributes`: comma-separated stored resource attributes to include in each returned User, plus the minimum `schemas` and `id` attributes.
- `excludedAttributes`: comma-separated stored resource attributes to remove from the default returned User attributes, while preserving minimum `schemas` and `id`.

`POST /Users/.search` accepts a SCIM SearchRequest JSON body with the SearchRequest schema and the same `startIndex`, `count`, `filter`, `attributes`, and `excludedAttributes` semantics. SearchRequest `attributes` and `excludedAttributes` may be arrays or comma-separated strings. Query parameters on `.search` are rejected to avoid ambiguous sources. `sortBy` and `sortOrder` are rejected because sorting is not advertised in ServiceProviderConfig.

Supported filters use `eq` and may be joined with `and`:

```text
userName eq "ada@example.com"
externalId eq "hr-123"
active eq true
userName eq "ada@example.com" and active eq true
```

`GET /Groups` and `POST /Groups/.search` support the same `startIndex`, `count`, `attributes`, and `excludedAttributes` behavior. Supported exact filters are:

```text
displayName eq "Engineering"
externalId eq "group-123"
displayName eq "Engineering" and externalId eq "group-123"
```

`attributes` and `excludedAttributes` are mutually exclusive. User projection supports `externalId`, `userName`, `displayName`, `active`, `name`, `name.formatted`, `name.givenName`, `name.familyName`, `emails`, `emails.value`, `emails.type`, `emails.primary`, `meta`, and `meta.resourceType`, `meta.created`, `meta.lastModified`, `meta.location`. Schema-qualified paths such as `urn:ietf:params:scim:schemas:core:2.0:User:userName` are accepted.

Group projection supports `externalId`, `displayName`, `members`, `members.value`, `members.$ref`, `members.display`, `members.type`, `meta`, and `meta.resourceType`, `meta.created`, `meta.lastModified`, `meta.location`. Schema-qualified Group paths are accepted.

Unsupported attributes, duplicate filter attributes, mutually exclusive projection parameters, unquoted string values, malformed filters, unsupported query parameters, duplicate query parameters, and oversized queries return SCIM error responses.

Example User SearchRequest:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  "filter": "userName eq \"ada@example.com\"",
  "startIndex": 1,
  "count": 25,
  "attributes": ["userName", "emails.value", "meta.location"]
}
```

Example Group SearchRequest:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  "filter": "displayName eq \"Engineering\"",
  "excludedAttributes": ["members.display", "members.type"]
}
```

## Bulk Operations

`POST /Bulk` supports a bounded SCIM Bulk envelope for the same User and Group mutations as the direct endpoints. The request must include `schemas=["urn:ietf:params:scim:api:messages:2.0:BulkRequest"]` and 1 to 50 operations.

Supported operation shapes:

- `POST /Users` with `bulkId` and User `data`.
- `PUT /Users/{user_id}` with User `data`.
- `PATCH /Users/{user_id}` with PatchOp `data`.
- `DELETE /Users/{user_id}` without `data`.
- `POST /Groups` with `bulkId` and Group `data`.
- `PUT /Groups/{group_id}` with Group `data`.
- `PATCH /Groups/{group_id}` with PatchOp `data`.
- `DELETE /Groups/{group_id}` without `data`.

Bulk paths are relative to the SCIM service root. `/Users`, `Users/{id}`, `/Groups`, and `Groups/{id}` are accepted; absolute URLs, query strings, fragments, malformed UUID resource IDs, unsupported resources, and unsupported methods return per-operation SCIM errors.

`failOnErrors` is optional. When supplied, it must be between `1` and `50`; processing stops after that many operation errors have been recorded. Without `failOnErrors`, the API attempts every resolvable operation and returns one response entry per attempted operation. Operations are not wrapped in one cross-operation database transaction; successful operations are not rolled back if a later operation fails.

`bulkId` is required for Bulk `POST` operations and must be unique in the request after trimming whitespace. Operations in the same Bulk request may reference a successful `POST` by using `bulkId:<bulk-id>` as a JSON string value or as a path segment, such as `/Users/bulkId:user-one`. The bounded scheduler resolves dependency order for same-request references, including forward references, while preserving response entries in the original request order. Unknown references, references to failed `POST` operations, empty references, and oversized references return SCIM `invalidValue` errors. Unresolved dependency cycles return per-operation `409 Conflict` errors. Nested group references remain rejected by the current User/Group subset.

Example Bulk user and group creation:

```powershell
$bulkBody = @{
  schemas = @("urn:ietf:params:scim:api:messages:2.0:BulkRequest")
  failOnErrors = 1
  Operations = @(
    @{
      method = "POST"
      bulkId = "group-one"
      path = "/Groups"
      data = @{
        schemas = @("urn:ietf:params:scim:schemas:core:2.0:Group")
        displayName = "Engineering"
        externalId = "group-456"
        members = @(@{ value = "bulkId:user-one"; type = "User" })
      }
    },
    @{
      method = "POST"
      bulkId = "user-one"
      path = "/Users"
      data = @{
        schemas = @("urn:ietf:params:scim:schemas:core:2.0:User")
        userName = "grace@example.com"
        externalId = "hr-456"
        displayName = "Grace Hopper"
        active = $true
        emails = @(@{ value = "grace@example.com"; type = "work"; primary = $true })
      }
    }
  )
} | ConvertTo-Json -Depth 8

Invoke-RestMethod `
  -Method Post `
  -Headers $headers `
  -ContentType "application/scim+json" `
  -Body $bulkBody `
  https://id.example.com/scim/v2/Bulk
```

## Unsupported In V1

The service provider metadata advertises these as unsupported:

- Sort.
- Change password.
- ETags.
- Cursor pagination.
- Shared Signals Framework events.
- Password synchronization.

Multi-valued PATCH semantics outside the stored User primary-work-email and Group user-member subset, nested group memberships, and certified directory templates remain tracked milestones.

## Connector Profiles

Generate token-free connector setup guidance before configuring a directory client:

```powershell
$env:CAIRN_ISSUER="https://id.example.com"
cairn-api scim connector-profile generic
cairn-api scim connector-profile okta
cairn-api scim connector-profile entra
```

The command emits a stable JSON report with an RFC3339 `generated_at` timestamp, the SCIM base URL, `ServiceProviderConfig` URL, bearer-header format, server-side token-hash environment variables, recommended User and Group mappings, validation checks, unsupported v1 features, and smoke commands. It does not read the database and does not print raw bearer-token values.

For first-public-RC release evidence, save the three generated reports as:

- `scim-generic-connector-profile.json`
- `scim-okta-connector-profile.json`
- `scim-entra-connector-profile.json`

`cairnid evidence check` validates that each profile is fresh, matches the expected provider, uses HTTPS SCIM URLs, includes token-hash rotation guidance, covers required User and Group mappings, discloses unsupported v1 features, and includes smoke commands for primary, secondary, and rejected bearer-token checks.

For first-public-RC connector evidence, also save token-free normalized external provisioning summaries as:

- `scim-okta-connector-smoke.json`
- `scim-entra-connector-smoke.json`

Generate token-free templates before the external connector runs:

```powershell
cairn-api scim connector-smoke-template okta > scim-okta-connector-smoke.template.json
cairn-api scim connector-smoke-template entra > scim-entra-connector-smoke.template.json
```

These summaries are captured after the Okta and Microsoft Entra provisioning clients run against the production-like SCIM endpoint. They must include `source="external-scim-connector"`, provider, display name, HTTPS `scim_base_url`, `completed_at`, connector application/job IDs, secondary-token acceptance, retired-token rejection, two created User UUIDs, a deactivated User UUID matching one created user, a deleted Group UUID, and named passed checks for connector enablement, ServiceProviderConfig, User create/filter/SearchRequest/projection/PATCH/replace/deactivation, Group create/filter/SearchRequest/projection/member PATCH/replace/delete, token-rotation acceptance, and retired-token rejection. Do not require provider-emitted Bulk in these Okta or Microsoft Entra summaries; `scim-smoke.json` is the release artifact that proves Cairn's bounded Bulk and forward-reference behavior. Do not include raw bearer tokens, authorization headers, provider credentials, screenshots, passwords, or client secrets in these JSON artifacts. `cairnid evidence check` rejects `status="template"` until placeholders are replaced, the external connector evidence is complete, and every required check is marked `passed`.

Profile-specific aliases:

- `generic`: standards-oriented SCIM 2.0 clients.
- `okta`: Okta SCIM connector setup terminology, user matching, and group push guidance.
- `entra`: Microsoft Entra provisioning terminology. `azure-ad` and `azuread` are accepted aliases.

Use stable directory object IDs for `externalId`, primary login email for `userName` and the primary work email value, and Cairn-returned User resource IDs for Group `members.value`. Do not map nested groups; they are rejected by the current User/Group subset.

## Smoke Test

After configuring `CAIRN_SCIM_BEARER_TOKEN_SHA256`, run the built-in smoke command against the deployed API:

```powershell
$env:CAIRN_SCIM_SMOKE_BASE_URL="https://id.example.com"
$env:CAIRN_SCIM_BEARER_TOKEN="<raw-token>"
$env:CAIRN_SCIM_SECONDARY_BEARER_TOKEN="<old-or-new-token-during-rotation>"
$env:CAIRN_SCIM_REJECTED_BEARER_TOKEN="<old-or-invalid-token>"
cairn-api scim smoke
```

`CAIRN_SCIM_SMOKE_BASE_URL` is optional and defaults to `CAIRN_ISSUER`. `CAIRN_SCIM_BEARER_TOKEN` is the raw token corresponding to the configured hash used for the mutating smoke flow. `CAIRN_SCIM_SECONDARY_BEARER_TOKEN` is optional for ad hoc smoke runs; when present, the smoke verifies a second configured raw token can read `ServiceProviderConfig` during rotation. `CAIRN_SCIM_REJECTED_BEARER_TOKEN` is optional for ad hoc smoke runs; when present, the smoke verifies it receives `401 Unauthorized`. First-public-RC release evidence must set both optional token variables so `cairnid evidence check` can prove rotation-window acceptance and retired-token rejection.

The smoke command exercises `ServiceProviderConfig`, `Schemas`, `ResourceTypes`, optional secondary-token acceptance, optional rejected-token denial, user create, exact-filter lookup, SearchRequest lookup, bounded projection, bounded PATCH, full replacement, soft deprovisioning, group create, exact-filter lookup, SearchRequest lookup, bounded projection, bounded PATCH including `members.value` and filtered member value paths, full replacement, group deletion, and bounded Bulk create/PATCH/delete mutations with same-request and forward `bulkId:` reference resolution through the public SCIM HTTP surface. It emits a token-free JSON evidence report with `base_url`, RFC3339 `completed_at`, token-check booleans, created user IDs, soft-deleted user IDs, deleted group ID, and named checks. It creates unique smoke users and unique smoke groups; the groups are deleted, and the smoke users are left as suspended users with audit history. Run external Okta and Entra connector smokes after this built-in smoke passes, then store the normalized connector-smoke summaries described above for release evidence.

Manual metadata and list checks can be useful while debugging:

```powershell
$headers = @{ Authorization = "Bearer <raw-token>" }
Invoke-RestMethod -Headers $headers https://id.example.com/scim/v2/ServiceProviderConfig
Invoke-RestMethod -Headers $headers https://id.example.com/scim/v2/Users
```

Create a user:

```powershell
$body = @{
  schemas = @("urn:ietf:params:scim:schemas:core:2.0:User")
  userName = "ada@example.com"
  externalId = "hr-123"
  displayName = "Ada Lovelace"
  active = $true
  emails = @(@{ value = "ada@example.com"; type = "work"; primary = $true })
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Method Post `
  -Headers $headers `
  -ContentType "application/scim+json" `
  -Body $body `
  https://id.example.com/scim/v2/Users
```

Patch a user:

```powershell
$patchBody = @{
  schemas = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
  Operations = @(
    @{ op = "replace"; path = "active"; value = $false },
    @{ op = "replace"; path = 'emails[type eq "work"].value'; value = "ada.lovelace@example.com" }
  )
} | ConvertTo-Json -Depth 6

Invoke-RestMethod `
  -Method Patch `
  -Headers $headers `
  -ContentType "application/scim+json" `
  -Body $patchBody `
  https://id.example.com/scim/v2/Users/<id>
```

Create a group after at least one user exists:

```powershell
$groupBody = @{
  schemas = @("urn:ietf:params:scim:schemas:core:2.0:Group")
  displayName = "Engineering"
  externalId = "group-123"
  members = @(@{ value = "<user-id>"; type = "User" })
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Method Post `
  -Headers $headers `
  -ContentType "application/scim+json" `
  -Body $groupBody `
  https://id.example.com/scim/v2/Groups
```

Patch group membership:

```powershell
$groupPatchBody = @{
  schemas = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
  Operations = @(
    @{ op = "add"; path = 'members[value eq "<second-user-id>"]'; value = @{ value = "<second-user-id>"; type = "User" } },
    @{ op = "add"; path = "members.value"; value = @("<third-user-id>") },
    @{ op = "remove"; path = 'members[value eq "<user-id>"].value' }
  )
} | ConvertTo-Json -Depth 6

Invoke-RestMethod `
  -Method Patch `
  -Headers $headers `
  -ContentType "application/scim+json" `
  -Body $groupPatchBody `
  https://id.example.com/scim/v2/Groups/<group-id>
```

Review the returned `id` values, then use `GET`, `PUT`, `PATCH`, and `DELETE` against `/scim/v2/Users/{id}` and `/scim/v2/Groups/{id}` as part of a controlled connector smoke.
