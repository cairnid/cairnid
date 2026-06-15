# Account Lifecycle

Cairn Identity supports three account lifecycle flows:

- Invitations.
- Email verification.
- Password recovery.

Authenticated users can also change their own password from the account UI. That flow is not token-initiated, but it consumes any pending unexpired password-recovery tokens for the user after the current password and required MFA freshness checks pass, then queues a token-free password-change notification email in the same database transaction as the password/session/token update. Successful login also queues a token-free new-login notification when the bounded IP/user-agent tuple has not previously created a session for that user.

All three use the same server-side model:

- The browser receives or submits a high-entropy one-time token.
- Postgres stores only the SHA-256 token hash in `account_tokens`.
- Tokens have a kind, organization, expiry, optional user, optional creator, and `consumed_at`.
- Accepting or completing a token consumes it atomically with the user update.
- Email delivery is represented by `email_outbox`; raw lifecycle tokens are not stored in plaintext.

## Delivery Model

The API queues an `email_outbox` row when it creates a lifecycle token. If `CAIRN_KEY_ENCRYPTION_KEY` is configured, the outbox row stores the delivery token encrypted with AES-256-GCM in `delivery_token_ciphertext` and `delivery_token_nonce`. Password-change, password-recovered, and new-login security notifications use the same outbox/provider path but have no `action_path`, no delivery token ciphertext, and no delivery token nonce.

Production lifecycle email delivery uses the operational command:

```powershell
cairn-api email-outbox deliver-once
```

The command:

1. Reads queued `email_outbox` rows.
2. Decrypts the delivery token when the template body contains `{{action_url}}`, using `CAIRN_KEY_ENCRYPTION_KEY` and AAD:

   ```text
   cairnid:account-token-delivery:<kind>:<account_token_id>
   ```

3. Builds the action URL from `CAIRN_PUBLIC_WEB_ORIGIN`, `action_path`, and `?token=<decrypted-token>` for token-bearing lifecycle links. Token-free notifications are rendered without an action URL.
4. Sends the email through the chosen provider.
5. Marks delivery status as `sent`, `retry`, or `failed`.

The worker claims rows with `FOR UPDATE SKIP LOCKED`, so multiple delivery jobs can run without double-sending the same outbox row. Failed provider sends are retried using `CAIRN_EMAIL_RETRY_SECONDS` until `CAIRN_EMAIL_MAX_ATTEMPTS`, then marked `failed`. Rows left in `sending` after `CAIRN_EMAIL_SENDING_TIMEOUT_SECONDS` are reclaimed by a later run.

Run `cairn-api operations preflight` before enabling the delivery worker in production. The `email_delivery` block reports provider selection, command-path readiness, KEK readiness for encrypted lifecycle links, batch size, retry settings, stale-sending timeout, delivery command, provider-smoke command, whether provider smoke is required, and redacted queue-health counts for queued, retry, due retry, sending, stale sending, failed, sent, and unfinished rows. Production preflight fails when the command provider is not selected, non-empty `CAIRN_EMAIL_COMMAND_PATH` is missing, `CAIRN_KEY_ENCRYPTION_KEY` is missing, or failed outbox rows are present.

Use `CAIRN_EMAIL_PROVIDER=command` in production. The configured `CAIRN_EMAIL_COMMAND_PATH` executable receives this JSON payload on stdin:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "to": "user@example.com",
  "subject": "Reset your Cairn Identity password",
  "text": "Reset your Cairn Identity password.\n\nOpen this link to continue: https://id.example.com/reset-password?token=...",
  "template": "password_recovery",
  "metadata": {
    "kind": "password_recovery",
    "account_token_id": "00000000-0000-0000-0000-000000000000"
  }
}
```

The command must exit `0` after the provider accepts the email. It can optionally print a JSON receipt to stdout:

```json
{
  "provider_message_id": "provider-message-id"
}
```

Any non-zero exit code is treated as a provider failure. Stderr is stored in `last_error` after truncation. Do not write raw tokens to provider logs in production.

Validate a configured provider before sending real lifecycle links:

```powershell
cairn-api email-outbox smoke-provider ops@example.com
```

The smoke command sends the same command-provider JSON shape with `template="provider_smoke"` and synthetic metadata, but it does not read `email_outbox`, decrypt account tokens, or include action URLs.

`CAIRN_EMAIL_PROVIDER=stdout` is development-only and writes rendered payloads to stderr for local inspection. In development, API responses also include `preview_url` so the flow can be tested without SMTP.

## API Endpoints

- `POST /api/v1/invitations`: admin-only, requiring `owner` membership in the built-in `administrators` group; queues an invitation email for a new or passwordless user.
- `POST /api/v1/invitations/accept`: public browser endpoint, consumes an invitation token, sets password, and verifies email.
- `POST /api/v1/session/email-verification/request`: authenticated browser endpoint, queues a verification email for the current user.
- `POST /api/v1/session/email-verification/confirm`: public browser endpoint, consumes a verification token and marks email verified.
- `POST /api/v1/session/password-recovery/request`: public browser endpoint, rate-limited and enumeration-resistant, queues recovery email when an active password-bearing user exists.
- `POST /api/v1/session/password-recovery/complete`: public browser endpoint, consumes the submitted recovery token plus any other pending unexpired recovery tokens for the same user, sets a new password, verifies email, revokes existing browser sessions plus user access and refresh tokens, queues a token-free password-recovered notification, and writes an audit event with revocation counts.
- `POST /api/v1/session/password/change`: authenticated browser endpoint, verifies the current password, requires recent MFA proof when an active second factor exists, sets a new password, rotates the browser session, revokes old sessions/access/refresh tokens, consumes pending password-recovery tokens, queues a token-free password-change notification, and writes an audit event.
- `POST /api/v1/users/{user_id}/email-verification/request`: admin-only browser endpoint, requiring `owner` membership in the built-in `administrators` group and CSRF; queues a verification email for an active unverified organization user.
- `POST /api/v1/users/{user_id}/password-recovery/request`: admin-only browser endpoint, requiring `owner` membership in the built-in `administrators` group and CSRF; queues a password recovery email for an active password-bearing organization user.

All browser POST endpoints require the double-submit CSRF flow described in [api.md](api.md).

## Usage Examples

Create an invitation as an organization admin:

```json
{
  "email": "new.user@example.com",
  "display_name": "New User"
}
```

Development response:

```json
{
  "status": "queued",
  "email_outbox_id": "00000000-0000-0000-0000-000000000000",
  "recipient_email": "new.user@example.com",
  "expires_at": "2026-06-13T19:00:00Z",
  "preview_url": "http://localhost:5173/accept-invitation?token=..."
}
```

Accept an invitation:

```json
{
  "token": "...",
  "password": "correct horse battery staple"
}
```

Request password recovery:

```json
{
  "email": "user@example.com"
}
```

Complete password recovery:

```json
{
  "token": "...",
  "password": "correct horse battery staple"
}
```

Confirm email verification:

```json
{
  "token": "..."
}
```

## Expiry

- Invitation tokens expire after 7 days.
- Email verification tokens expire after 24 hours.
- Password recovery tokens expire after 1 hour.

## Audit Events

The API writes audit events for:

- `admin.invitation_created`
- `admin.email_verification_requested`
- `admin.password_recovery_requested`
- `account.invitation_accepted`
- `account.email_verification_requested`
- `account.email_verified`
- `account.password_recovery_requested`
- `account.password_recovered`
- `account.password_changed`

Audit metadata redaction still applies; lifecycle token values are never added to audit metadata.
