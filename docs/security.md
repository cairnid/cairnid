# Security Posture

Cairn Identity defaults to a narrow OIDC/OAuth surface:

- Authorization Code + PKCE S256 only for browser clients.
- Exact redirect URI matching.
- No implicit, hybrid, or password grants.
- Opaque access tokens stored as hashes.
- One-use authorization codes.
- Refresh tokens issued only for `offline_access` grants on clients that allow refresh tokens, with rotation and family plus linked access-token revocation on reuse.
- Authorization-code and refresh-token exchanges are bound to the client recorded on the stored grant.
- Token introspection and revocation require client authentication and are scoped to that client's tokens. Refresh-token revocation invalidates the refresh family and access tokens linked to that family.
- Admin OIDC client responses never expose stored `client_secret_hash` values; confidential-client creation and rotation return raw client secrets only once, and rotation requires CSRF plus an organization-owned confidential client.
- Admin OIDC client disable/reactivation requires CSRF plus tenant ownership. Disabling a client transactionally invalidates pending authorization codes, revokes active access and refresh tokens for that client, and blocks authorization, OAuth client authentication, UserInfo, consent, and logout redirect use. Reactivation never un-revokes old credentials.
- Admin and current-user consent revocation are scoped to the owning organization and consenting user, revoke active consent rows for the selected user-client pair, invalidate pending authorization codes, and revoke matching user access and refresh tokens.
- Reusable consent policy templates are organization-scoped and v1 only supports `required_once` or `always_required`; templates cannot disable consent, and `always_required` ignores prior active grants during authorization except for the immediate post-approval retry guarded by a five-minute one-use marker bound to the browser session and canonical authorize request hash.
- User claims are scope-gated: `email` emits email claims, `profile` emits display name, and `groups` emits tenant-scoped group claims loaded through membership joins.
- RS256 signing keys generated and rotated through explicit CLI operations, with operational preflight reporting lifecycle counts, active key age, rotation recommendation state, and command hints.
- Private signing PEMs encrypted with AES-256-GCM before database persistence.
- JWT signing uses the AWS-LC backend rather than the RustCrypto RSA signing path.
- Argon2 password hashing.
- Successful login stores bounded request context and queues a token-free `new_login_notification` email only for a first-seen IP/user-agent tuple for that user. The context check, session insert, and notification insert run in one database transaction with per-user locking so repeated known-context logins do not repeatedly notify.
- Self-service password change verifies the current password, uses the reauthentication throttle buckets for failures, requires recent MFA proof when an active TOTP/passkey credential exists, rotates the browser session, revokes old browser sessions plus user access and refresh tokens, consumes pending password-recovery tokens, queues a token-free password-change notification email in the same database transaction, and audits the change without logging password material.
- TOTP MFA enrollment and login verification with AES-256-GCM encrypted secrets bound to organization and user metadata.
- WebAuthn/passkey enrollment and login with server-side ceremony state, one-time challenge consumption, and per-organization active credential ID uniqueness.
- One-use recovery codes stored only as hashes, consumed on successful MFA fallback login, and regeneratable only after recent MFA proof.
- Current-user MFA credential management with session-rotating reauthentication for recent MFA proof before TOTP/passkey revocation, recovery-code regeneration, and recovery-code cleanup when the last active second factor is removed.
- Invitation, email verification, and password recovery tokens stored only as hashes and consumed atomically with account updates. Password recovery completion consumes sibling pending recovery links for the same user, revokes existing browser sessions plus user access and refresh tokens, and queues a token-free password-recovered notification in the same transaction as the password update.
- Admin-initiated email verification and password recovery use the same hash-only lifecycle-token and encrypted-outbox delivery model, require an organization-owner session plus CSRF, are limited to active organization users, and audit the admin actor with bounded request context.
- Lifecycle email delivery tokens encrypted with AES-256-GCM before entering `email_outbox`; token-free security notifications use the same delivery worker without storing action URL token material; development-only preview URLs are allowed only outside production.
- Operational email outbox delivery through `cairn-api email-outbox deliver-once`, with row claiming, retry state, and a shell-free command provider boundary; `cairn-api operations preflight` reports command-provider, command-path, KEK, batch, retry, timeout, worker, provider-smoke, and redacted queue-health posture and fails production readiness if command delivery or KEK-backed action-link decryption is not configured or failed outbox rows are present; `cairn-api email-outbox smoke-provider <recipient-email>` validates the configured provider with a synthetic token-free payload and timestamped receipt before real lifecycle delivery.
- Operational preflight through `cairn-api operations preflight` for database migration presence, signing-key decryptability, signing-key lifecycle posture, JWKS exposure, production lifecycle email delivery readiness, OpenID conformance issuer/static-client environment readiness, and SCIM provisioning posture. Production preflight rejects a database state with multiple active unretired signing keys.
- HttpOnly session cookies, with logout clearing both session and CSRF cookies.
- Reauthentication rotates the browser session after current-user password and configured MFA verification.
- Current-user browser session management exposes only active sessions owned by the signed-in user, stores bounded creation IP/user-agent context, rejects revoking the current session through the remote-session endpoint, and audits successful user-initiated revocation of another browser session.
- Admin browser session management exposes only active sessions for organization-owned users, rejects revoking the admin actor's current session through the targeted admin route, requires CSRF for revocation, and audits successful admin-initiated user session revocation.
- Admin user security activity review is tenant-scoped, owner-only, keyset-paginated, and aggregates indexed audit events where the selected organization user is the actor, target, `metadata.subject_user_id`, or `metadata.user_id`.
- Double-submit CSRF protection for cookie-authenticated browser mutations, with empty or malformed CSRF tokens rejected before constant-time comparison, the web client validating issued CSRF token syntax before reuse, unsafe `/api/v1/*` requests rejected when browser `Origin` or `Referer` does not match `CAIRN_PUBLIC_WEB_ORIGIN`, and with the CSRF cookie cleared during logout.
- Organization-admin APIs require `owner` membership in the built-in `administrators` group; bootstrap creates the first owner membership in a locked database transaction, and membership mutations cannot remove or demote the last administrator owner.
- Admin user deactivation is transactional: suspended or locked users lose browser sessions, opaque access tokens, and refresh tokens immediately; session loading, UserInfo, introspection, authorization-code exchange, and refresh-token exchange also reject non-active user subjects as defense in depth; and the final active administrator owner cannot be deactivated through normal APIs.
- SCIM provisioning is bearer-token only and disabled unless `CAIRN_SCIM_BEARER_TOKEN_SHA256` is configured. The API stores only bounded SHA-256 hashes of raw provisioning tokens in memory from the environment, accepts up to four active hashes during token rotation, compares presented token hashes against the full active set, rejects duplicate authorization headers, and does not accept browser cookies or CSRF tokens for SCIM.
- SCIM user replacement, bounded PATCH, and soft deprovisioning are tenant-scoped. Setting `active=false` or deleting a SCIM user maps to `suspended`, revokes browser sessions, access tokens, and refresh tokens in the same transaction, and cannot deactivate the final active administrator owner.
- SCIM group create, replacement, bounded PATCH, and deletion are tenant-scoped. Group members must be existing users in the same organization, nested group members are rejected, filtered member and `members.value` PATCH add/replace/remove is limited to user-member IDs, generated member sub-attributes are not mutable, SCIM membership writes use the local `member` role, and the built-in `administrators` group cannot be replaced, patched, or deleted through SCIM.
- SCIM list, SearchRequest, and resource queries are bounded and limited to exact `userName`, `externalId`, and `active` user filters plus exact `displayName` and `externalId` group filters. `attributes` and `excludedAttributes` projection is bounded to stored User/Group fields and known sub-attributes, preserves minimum resource identifiers, and fails closed for unsupported projection paths, unsupported SearchRequest fields, sorting requests, or mutually exclusive projection parameters.
- SCIM Bulk is bounded to 50 User/Group mutation operations, uses the same validation and side effects as direct SCIM endpoints, resolves same-request `bulkId:` references to successful `POST` operations including forward references when dependency order can be resolved, returns `409 Conflict` for unresolved dependency cycles, rejects unknown or failed `bulkId:` references, and returns per-operation SCIM error bodies without rolling back earlier successful operations.
- Persistent Postgres-backed brute-force throttling for login, bootstrap, reauthentication, and password recovery attempts, with blocked responses returning `429 Too Many Requests` plus `Retry-After`.
- Audit metadata redaction for nested password, secret, token, authorization-code, PKCE verifier, CSRF, MFA/recovery-code, lifecycle-link, WebAuthn assertion, private-key, and KEK key variants while preserving non-secret identifiers.
- Successful login, logout, reauthentication, password change, password recovery completion, user-initiated browser-session revocation, admin-initiated account lifecycle email, and admin-initiated user session revocation audit events with bounded request context for investigation evidence; login, password-change, and password-recovered audit metadata links to queued notification outbox rows when one is created.
- API request tracing uses method plus URI path only, so query strings carrying OAuth parameters, login hints, lifecycle tokens, or similar sensitive data are not added to default request spans.
- All `/api/v1/*` browser/admin API responses and all `/scim/v2/*` provisioning responses set `Cache-Control: no-store` and `Pragma: no-cache`.
- Tenant-scoped composite foreign keys for organization-bound users, groups, clients, sessions, consent grants, tokens, MFA credentials, memberships, and account lifecycle tokens.
- Dependency policy enforced by `cargo deny check`, `cargo audit`, `bun audit`, and token-free `cairn-api operations dependency-policy-evidence` receipts.
- Container buildability is checked in CI by validating Compose, building the API and web images, and running token-free runtime command smokes inside both images.
- Production-oriented security headers on both API and web responses. The web UI uses SvelteKit CSP generation so framework-generated inline scripts/styles receive nonces or hashes.

The formal threat model is maintained in [docs/threat-model.md](threat-model.md). Changes touching authentication, OIDC/OAuth behavior, secrets, cookies, persistence, deployment, or audit behavior must update that model when they add or change a trust boundary, protected asset, or required invariant.

## Not Ready For Public Beta Until Closed

The current release blockers are tracked in [release-gates.md](release-gates.md):

- OpenID Foundation conformance suite.
- `cairn-api operations dependency-policy-evidence` from the release workspace after the pinned `cargo-deny`, `cargo-audit`, and Bun audit checks pass.
- `cairn-api operations oidc-metadata-smoke` against the production-like HTTPS API deployment.
- `cairn-api scim smoke` against a production-like HTTPS deployment, followed by token-free normalized Okta and Entra connector-smoke evidence for user and group create, GET lookup, SearchRequest lookup, bounded projection, replacement, bounded PATCH, soft user deprovisioning, group deletion, Bulk forward-reference behavior, and token rotation with old/new overlap plus retired-token rejection.
- `cairn-api operations browser-origin-smoke` against the production-like HTTPS API deployment.
- `cairn-api operations security-headers-smoke` against the production-like HTTPS API and web deployments.
- End-to-end smoke against the chosen production email provider command.
- Restore drill, production signing-key rotation drill, and production KEK re-encryption drill, each with `cairn-api operations preflight` evidence captured.

Use `cairnid evidence plan` before evidence capture to confirm required capture environment variable names are present without printing values. Use `cairnid evidence init <evidence-dir>` to create the manifest, checklist README, and `.gitignore` guard for secret-bearing artifacts. Use `cairnid evidence status <evidence-dir>` during collection for counts and next commands, then use `cairnid evidence check <evidence-dir>` as the local release gate after those external runs. It validates scaffold integrity, strict directory inventory, required evidence artifacts, freshness, forbidden secret-bearing field names in token-free artifacts, and successful statuses without printing secrets; failure text redacts obvious secret-looking values before reporting.

## Reporting Security Issues

Do not open public issues for suspected vulnerabilities. Follow [SECURITY.md](../SECURITY.md).
