# MFA

Cairn Identity implements TOTP, one-use recovery codes, and WebAuthn/passkey MFA for browser sessions. Password login accepts any active second factor configured for the user.

## TOTP Storage

TOTP secrets are generated server-side and encrypted before persistence:

- API requires `CAIRN_KEY_ENCRYPTION_KEY` for TOTP enrollment and verification.
- `mfa_credentials.secret_metadata` stores AES-256-GCM ciphertext and nonce, not a plaintext secret.
- Additional authenticated data binds each encrypted secret to `organization_id` and `user_id`.
- Pending enrollments are stored with `status=pending`; confirmation flips the same row to `status=active`.

## Recovery Codes

TOTP confirmation returns 10 one-use recovery codes. The API stores only SHA-256 hashes as `MfaKind::RecoveryCode` rows:

- Recovery codes are returned only once, in the TOTP confirmation or regeneration response.
- Confirming a new TOTP enrollment or regenerating recovery codes revokes older active recovery-code rows before storing the new code set.
- A successful recovery-code login marks that code `status=consumed` and sets `last_used_at`.
- Revoking the last active TOTP/passkey second factor revokes active recovery codes, so stale fallback codes cannot become valid again after a future enrollment.
- Recovery-code sessions use `amr=["pwd","recovery"]` and `acr="urn:cairn:acr:password+recovery_code"`.

## WebAuthn / Passkeys

Passkey ceremonies use `webauthn-rs` passkey flows with user verification required:

- `CAIRN_PUBLIC_WEB_ORIGIN` is the WebAuthn relying party origin; the relying party ID is derived from that origin host.
- Registration and authentication state is serialized only into the server-side `webauthn_challenges` table.
- Challenges are scoped to `organization_id`, `user_id`, and ceremony kind; they expire after 5 minutes and are consumed once under a row lock.
- Active passkeys are stored as WebAuthn public credential material in `mfa_credentials.secret_metadata`.
- `secret_metadata.credential_id` stores a stable base64url credential ID, and a partial unique index prevents duplicate active passkeys in the same organization.
- Successful passkey sessions use `amr=["pwd","mfa","user"]` and `acr="urn:cairn:acr:password+webauthn"`.

## Device Management

Current users can review and revoke their enrolled TOTP and passkey credentials:

- The list endpoint returns only browser-safe metadata: `id`, `kind`, `label`, `status`, `created_at`, `last_used_at`, and the active recovery-code count.
- Destructive credential revocation requires the current browser session to have completed TOTP, WebAuthn, or recovery-code MFA within the last 15 minutes.
- Recovery-code regeneration requires the same recent MFA proof and at least one active TOTP/passkey credential.
- Self-service password change requires the same recent MFA proof when the user has an active TOTP or passkey credential, then rotates the browser session without extending the original MFA authentication time.
- The account UI opens a reauthentication prompt when revocation or recovery-code regeneration needs fresh proof; successful reauthentication rotates the browser session before retrying the action.
- TOTP and passkey revocation sets `secret_metadata.status` to `revoked` rather than deleting the row, preserving auditability without allowing future use.
- Recovery codes are not listed individually and are never returned after initial generation.
- Revoking a credential writes `mfa.credential_revoked` to the audit log.
- Regenerating recovery codes writes `mfa.recovery_codes_regenerated` to the audit log.

## Endpoints

- `GET /api/v1/session/mfa/credentials`
  - Requires a valid browser session.
  - Returns `{ "credentials": [...], "recovery_code_count": 10 }`.

- `DELETE /api/v1/session/mfa/credentials/{credential_id}`
  - Requires a valid browser session, CSRF token, and recent MFA proof from the current session.
  - Revokes a current-user TOTP or passkey credential.
  - If no active TOTP/passkey credentials remain, active recovery codes are also revoked.

- `POST /api/v1/session/mfa/recovery-codes/regenerate`
  - Requires a valid browser session, CSRF token, recent MFA proof from the current session, and at least one active TOTP/passkey credential.
  - Revokes active recovery-code rows and stores a fresh set.
  - Returns `{ "status": "regenerated", "recovery_codes": [...] }`.

- `POST /api/v1/session/reauthenticate`
  - Requires a valid browser session and CSRF token.
  - Body accepts `password`, optional `mfa_code`/`totp_code`/`recovery_code`, or a `webauthn_challenge_id` plus `webauthn_credential`.
  - Returns `{ "status": "mfa_required", "methods": [...], "webauthn": { ... } }` when the password is valid but configured MFA is still needed.
  - A successful recovery-code reauthentication consumes that recovery code.
  - On success, revokes the previous browser session, sets a new `cairn_session` cookie, and returns `{ "status": "reauthenticated", "acr": "...", "amr": [...] }`.

- `POST /api/v1/session/mfa/totp/start`
  - Requires a valid browser session and CSRF token.
  - Body: `{ "label": "Authenticator app" }`.
  - Returns `credential_id`, `otpauth_url`, and `secret_base32`.

- `POST /api/v1/session/mfa/totp/confirm`
  - Requires a valid browser session and CSRF token.
  - Body: `{ "credential_id": "...", "code": "123456" }`.
  - Validates the pending secret, activates the credential, and returns one-use recovery codes.

- `POST /api/v1/session/mfa/webauthn/start`
  - Requires a valid browser session and CSRF token.
  - Body: `{ "label": "Work laptop" }`.
  - Returns `challenge_id` and WebAuthn creation `options` for `navigator.credentials.create`.

- `POST /api/v1/session/mfa/webauthn/finish`
  - Requires a valid browser session and CSRF token.
  - Body: `{ "challenge_id": "...", "label": "Work laptop", "credential": { ... } }`.
  - Consumes the pending challenge, verifies the browser credential, rejects duplicate active credential IDs, and stores the passkey.

- `POST /api/v1/session/login`
  - Body accepts optional `mfa_code`, `totp_code`, `recovery_code`, or a `webauthn_challenge_id` plus `webauthn_credential`.
  - If the password is valid and any active second factor exists but no factor is supplied, the response is `{ "status": "mfa_required", "methods": [...], "webauthn": { "challenge_id": "...", "options": { ... } } }` when passkeys are active.
  - If the TOTP code is valid, the browser session is created with `amr=["pwd","otp"]` and `acr="urn:cairn:acr:password+totp"`.
  - If a recovery code is valid, the code is consumed and the browser session is created with `amr=["pwd","recovery"]` and `acr="urn:cairn:acr:password+recovery_code"`.
  - If a passkey assertion is valid, the browser session is created with `amr=["pwd","mfa","user"]` and `acr="urn:cairn:acr:password+webauthn"`.

## Tests

Coverage includes:

- TOTP generation and verification in `crates/authn`.
- API metadata parsing and AAD binding tests.
- API recovery-code hashing/generation tests.
- API recent-MFA proof tests for destructive MFA credential revocation.
- API password-change tests for recent-MFA enforcement when a second factor is enrolled.
- API session-construction and reauthentication rate-limit key tests.
- Playwright account-page coverage for password-change reauthentication, stale-proof MFA credential revocation, inline reauthentication, retry, and recovery-code cleanup after the last second factor is removed.
- Playwright WebAuthn coverage for passkey enrollment and login with a Chromium virtual authenticator.
- Real-Postgres auth-session rotation invariant coverage.
- Real-Postgres recovery-code replacement invariant coverage.
- WebAuthn relying party origin derivation in `crates/authn`.
- Real-Postgres MFA credential scoping, TOTP metadata update, recovery-code consumption, MFA credential revocation, active recovery-code cleanup, WebAuthn challenge one-time consumption, WebAuthn challenge expiry, and tenant-scoped passkey credential ID lookup in `postgres_protocol_invariants`.
