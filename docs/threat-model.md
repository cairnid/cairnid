# Threat Model

This model covers the current Cairn Identity codebase: Rust API, SvelteKit web UI, Postgres data store, container deployment shape, OIDC/OAuth provider surface, SCIM provisioning surface, and operator commands.

Update this document when a change adds or changes authentication, authorization, token handling, secrets, cookies, persistence, deployment, audit behavior, or trust boundaries.

## Assets

- User identities, password hashes, MFA credentials, WebAuthn ceremony state, recovery codes, and account lifecycle tokens.
- Browser sessions, CSRF tokens, authorization codes, access tokens, refresh tokens, consent grants, and OIDC clients.
- Signing keys, key-encryption keys, lifecycle email delivery tokens, and deployment secrets.
- Organization, group, membership, SCIM, and audit data.
- Release evidence and operational drill receipts.

## Trust Boundaries

- Browser to web UI.
- Web UI to API.
- API to Postgres.
- API to email provider command.
- SCIM provisioning client to API.
- OAuth/OIDC clients to public protocol endpoints.
- Operator shell to privileged CLI commands and environment variables.
- CI/release environment to dependency, container, and release-evidence checks.

## Core Invariants

- Never accept implicit, hybrid, or password grants.
- Never accept non-exact redirect URI matches.
- Never issue refresh tokens without an `offline_access` grant on a client that allows refresh tokens.
- Never reuse authorization codes or rotated refresh tokens.
- Never store raw passwords, bearer tokens, authorization codes, recovery codes, or lifecycle action tokens.
- Never log query strings, bearer tokens, cookies, CSRF tokens, password material, MFA secrets, private keys, or KEKs.
- Never allow a session, OAuth token, SCIM operation, admin API call, or consent grant to cross organization boundaries.
- Never let SCIM deactivate the final active administrator owner.
- Never expose browser/admin mutations without CSRF protection and origin checks.
- Never mark a release ready without current release-evidence validation.

## Threats And Controls

| Threat | Controls | Remaining work |
| --- | --- | --- |
| OAuth downgrade or redirect abuse | Strict discovery metadata, exact redirect matching, no implicit/hybrid/password grants, PKCE S256, bounded request parsing | OpenID Foundation conformance evidence |
| Token replay | One-use authorization codes, refresh-token rotation, reuse detection, token hashing, revocation, introspection auth | More cross-client integration tests |
| Cross-tenant access | Organization-scoped domain model, composite foreign keys, tenant-bound repository methods, session/org checks | Extend coverage as new integrations are added |
| Browser request forgery | HttpOnly cookies, double-submit CSRF, unsafe-method origin/referer checks, no-store responses | External browser-origin smoke evidence |
| MFA bypass | TOTP/WebAuthn state stored server-side, one-time challenge consumption, recovery-code hashing, reauthentication for destructive MFA changes | More hardware-key/manual browser coverage |
| Provisioning abuse | SCIM disabled by default, hash-configured bearer token, duplicate authorization-header rejection, bounded PATCH/Bulk, final-admin guard | External Okta/Entra connector smoke evidence |
| Secret leakage in logs or evidence | Trace labels use method/path only, audit metadata redaction, token-free evidence validators, forbidden field-name checks | External evidence capture review |
| Signing-key compromise | Database-backed encrypted signing keys, explicit rotation command, startup/preflight checks | Production rotation drill evidence |
| Database loss | SQLx migrations, restore-check command, documented backup/restore workflow | Production restore drill evidence |
| Dependency compromise | Lockfiles, cargo-deny, cargo-audit, Bun audit, dependency-policy evidence, public-surface check | Add additional scanner only when it is maintained and useful |

## Release Blockers

The current pre-beta blockers are listed in [release-gates.md](release-gates.md). The short version: pass CI, publish OIDC conformance evidence, run public HTTPS smoke checks, validate SCIM/email/restore/key/audit drills, and pass `cairn-api operations evidence-check`.
